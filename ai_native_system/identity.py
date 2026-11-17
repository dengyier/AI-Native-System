"""Trusted enterprise bearer authentication and attenuated local delegation."""

import base64
import json
import math
import os
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from http.client import HTTPException
from urllib.error import HTTPError
from urllib.parse import quote_plus, urlencode, urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .registry import unique_keys


class IdentityError(PermissionError):
    """The caller's identity or delegated authority could not be established."""


def _name(value):
    return type(value) is str and bool(value.strip()) and len(value) <= 512 and not any(
        ord(char) < 32 or ord(char) == 127 for char in value
    )


def _require_name(value):
    if not _name(value):
        raise ValueError("Expected a nonempty identifier")


def _scope(scope):
    if not isinstance(scope, (tuple, list)) or len(scope) != 4:
        raise ValueError("Delegation scope needs operation, kind, resource ID and optional member")
    operation, kind, resource_id, member = scope
    if not all(map(_name, (operation, kind, resource_id))) or (member is not None and not _name(member)):
        raise ValueError("Invalid delegation scope")
    return operation, kind, resource_id, member or ""


@dataclass(frozen=True)
class IdentityContext:
    tenant: str
    actor: str
    service: str | None = None
    delegation_id: str | None = None
    expires_at: int | None = None

    def __post_init__(self):
        _require_name(self.tenant)
        _require_name(self.actor)
        for value in (self.service, self.delegation_id):
            if value is not None:
                _require_name(value)
        delegated = self.service is not None and self.service != self.actor
        if delegated != (self.delegation_id is not None):
            raise ValueError("A distinct service requires a delegation ID, and vice versa")
        if self.expires_at is not None and (type(self.expires_at) is not int or not 0 < self.expires_at <= 2**63 - 1):
            raise ValueError("Expected an integer token expiry")

    @property
    def principals(self):
        return (self.actor, self.service) if self.delegation_id is not None else (self.actor,)

    def as_document(self):
        return {
            "tenant": self.tenant, "actor": self.actor, "service": self.service,
            "delegation_id": self.delegation_id, "expires_at": self.expires_at,
        }

    @classmethod
    def from_document(cls, document):
        if not isinstance(document, Mapping) or not {"tenant", "actor"} <= document.keys() <= {
            "tenant", "actor", "service", "delegation_id", "expires_at"
        }:
            raise ValueError("Invalid persisted identity")
        return cls(**document)


@dataclass(frozen=True)
class IdentityBinding:
    """An operator-supplied mapping for a subject, client and optional actor."""

    subject: str
    client_id: str
    tenant: str
    actor: str
    service: str | None = None
    external_actor: str | None = None

    def __post_init__(self):
        for value in (self.subject, self.client_id, self.tenant, self.actor):
            _require_name(value)
        for value in (self.service, self.external_actor):
            if value is not None:
                _require_name(value)
        if (self.service is not None and self.service != self.actor) != (self.external_actor is not None):
            raise ValueError("A delegated binding must name both the local service and the external actor")


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class HttpIntrospector:
    """RFC 7662 POST to a single configured HTTPS endpoint."""

    def __init__(self, endpoint, client_id, client_secret, *, timeout=4):
        if not _name(endpoint) or any(not 33 <= ord(char) <= 126 or char in "?#\\" for char in endpoint):
            raise ValueError("Invalid introspection endpoint")
        uri = urlsplit(endpoint)
        if uri.scheme != "https" or not uri.hostname or uri.username is not None:
            raise ValueError("Introspection requires an HTTPS endpoint without credentials")
        if uri.port is not None and uri.port < 1:
            raise ValueError("Invalid introspection port")
        if not _name(client_id) or not _name(client_secret):
            raise ValueError("Introspection requires client credentials")
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 30:
            raise ValueError("Invalid introspection timeout")
        self._endpoint = endpoint
        self._timeout = timeout
        value = f"{quote_plus(client_id)}:{quote_plus(client_secret)}"
        self._authorization = "Basic " + base64.b64encode(value.encode("ascii")).decode("ascii")
        self._opener = build_opener(ProxyHandler({}), _NoRedirect())

    def __call__(self, token):
        request = Request(self._endpoint, method="POST", headers={
            "Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded",
        }, data=urlencode({"token": token, "token_type_hint": "access_token"}).encode("ascii"))
        request.add_unredirected_header("Authorization", self._authorization)
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                body = response.read(65537)
                if response.status != 200 or len(body) > 65536:
                    raise IdentityError("Token introspection unavailable")
                return json.loads(body.decode("utf-8"), object_pairs_hook=unique_keys)
        except HTTPError as exc:
            exc.close()
            raise IdentityError("Token introspection unavailable") from None
        except (OSError, HTTPException, ValueError, RecursionError):
            raise IdentityError("Token introspection unavailable") from None


class EnterpriseIdentity:
    def __init__(self, issuer, audience, bindings, introspect, *, required_scope="ai-native.access"):
        for value in (issuer, audience, required_scope):
            _require_name(value)
        if any(char.isspace() for char in required_scope) or not callable(introspect):
            raise ValueError("Expected a single access scope and a trusted introspector")
        self._issuer, self._audience, self._scope = issuer, audience, required_scope
        self._introspect = introspect
        self._bindings = {}
        for binding in bindings:
            if not isinstance(binding, IdentityBinding):
                raise ValueError("Expected an enterprise identity binding")
            key = binding.subject, binding.client_id, binding.external_actor
            if key in self._bindings:
                raise ValueError("Duplicate enterprise identity binding")
            self._bindings[key] = binding
        if not self._bindings:
            raise ValueError("Configure at least one enterprise identity binding")

    @classmethod
    def from_config(cls, document, env=None):
        env = os.environ if env is None else env
        required = {"issuer", "audience", "endpoint", "introspection_client_id", "introspection_secret_env", "bindings"}
        if not isinstance(document, dict) or not required <= document.keys() <= required | {"required_scope"}:
            raise ValueError("Invalid enterprise identity configuration")
        secret_name = document["introspection_secret_env"]
        _require_name(secret_name)
        if not isinstance(document["bindings"], list):
            raise ValueError("Expected an array of identity bindings")
        try:
            bindings = [IdentityBinding(**item) for item in document["bindings"]]
        except TypeError as exc:
            raise ValueError("Invalid enterprise identity binding") from exc
        transport = HttpIntrospector(document["endpoint"], document["introspection_client_id"], env.get(secret_name))
        return cls(document["issuer"], document["audience"], bindings, transport,
                   required_scope=document.get("required_scope", "ai-native.access"))

    def authenticate(self, token):
        if (type(token) is not str or not 1 <= len(token) <= 8192
                or not token.isascii() or any(not 33 <= ord(char) <= 126 for char in token)):
            raise IdentityError("Invalid enterprise bearer credential")
        try:
            claims = self._introspect(token)
        except Exception:
            raise IdentityError("Enterprise identity could not be verified") from None
        if not isinstance(claims, Mapping) or claims.get("active") is not True:
            raise IdentityError("Invalid enterprise bearer credential")
        if (claims.get("iss") != self._issuer or type(claims.get("token_type")) is not str
                or claims["token_type"].lower() != "bearer"
                or claims.get("token_use", "access") not in ("access", "access_token")):
            raise IdentityError("Invalid enterprise bearer credential")
        audience = claims.get("aud")
        if type(audience) is str:
            audience = [audience]
        scopes = claims.get("scope")
        if (not isinstance(audience, list) or not all(map(_name, audience)) or self._audience not in audience
                or type(scopes) is not str or self._scope not in scopes.split()):
            raise IdentityError("Invalid enterprise bearer credential")

        now = time.time()
        expires = claims.get("exp")
        if type(expires) is not int or not now < expires <= 2**63 - 1:
            raise IdentityError("Invalid enterprise bearer credential")
        for field in ("nbf", "iat"):
            if field in claims and (type(claims[field]) is not int or not 0 <= claims[field] <= now):
                raise IdentityError("Invalid enterprise bearer credential")

        subject, client = claims.get("sub"), claims.get("client_id")
        if not _name(subject) or not _name(client):
            raise IdentityError("Invalid enterprise bearer credential")
        delegation, external_actor = None, None
        if "act" in claims:
            actor_claim = claims["act"]
            delegation = claims.get("delegation_id")
            if (not isinstance(actor_claim, Mapping) or not _name(actor_claim.get("sub"))
                    or actor_claim.get("iss", self._issuer) != self._issuer or "act" in actor_claim
                    or not _name(delegation)):
                raise IdentityError("Invalid enterprise delegation")
            external_actor = actor_claim["sub"]
        elif "delegation_id" in claims:
            raise IdentityError("Invalid enterprise delegation")

        binding = self._bindings.get((subject, client, external_actor))
        if binding is None:
            raise IdentityError("Enterprise identity is not mapped")
        return IdentityContext(binding.tenant, binding.actor, binding.service, delegation, expires)


def require_identity(connection, context, scope=None):
    """Recheck an authenticated context, using the caller's tenant transaction."""
    if not isinstance(context, IdentityContext):
        raise IdentityError("Trusted identity required")
    for principal in context.principals:
        found = connection.execute("SELECT active FROM principals WHERE tenant=? AND id=?",
                                   (context.tenant, principal)).fetchone()
        if found is None or found[0] != 1:
            raise IdentityError("Identity unavailable")
    if context.expires_at is not None:
        database_time = getattr(connection, "database_time", None)
        now = database_time() if database_time is not None else time.time()
        if now >= context.expires_at:
            raise IdentityError("Enterprise identity expired")
    if context.delegation_id is None:
        return

    parameters = (context.tenant, context.delegation_id, context.actor, context.service)
    statement = """SELECT 1 FROM enterprise_delegations d
                   WHERE d.tenant=? AND d.id=? AND d.actor=? AND d.service=? AND d.revoked_at IS NULL
                     AND d.starts_at<=clock_timestamp() AND d.expires_at>clock_timestamp()"""
    if scope is not None:
        statement += """ AND EXISTS (
            SELECT 1 FROM enterprise_delegation_scopes s WHERE s.tenant=d.tenant AND s.delegation_id=d.id
                AND s.operation=? AND s.kind=? AND s.resource_id=? AND s.member=?)"""
        parameters += _scope(scope)
    if connection.execute(statement, parameters).fetchone() is None:
        raise IdentityError("Delegation unavailable or outside its scope")


def delegation_scopes(connection, context):
    """Return the exact allowed targets, or None for a direct identity."""
    require_identity(connection, context)
    if context.delegation_id is None:
        return None
    rows = connection.execute("""SELECT s.operation,s.kind,s.resource_id,s.member
        FROM enterprise_delegation_scopes s
        JOIN enterprise_delegations d ON d.tenant=s.tenant AND d.id=s.delegation_id
        WHERE d.tenant=? AND d.id=? AND d.actor=? AND d.service=? AND d.revoked_at IS NULL
          AND d.starts_at<=clock_timestamp() AND d.expires_at>clock_timestamp()""",
        (context.tenant, context.delegation_id, context.actor, context.service))
    return frozenset((operation, kind, resource_id, member or None) for operation, kind, resource_id, member in rows)


def _lock_tenant(connection, tenant):
    from .adapters.postgres_runtime import _tenant_lock

    connection.execute("SELECT pg_catalog.pg_advisory_xact_lock(?::bigint)", (_tenant_lock(tenant),))


def create_delegation(connection, identity, scopes, *, starts_at, expires_at):
    """Provision a delegation using an administrative transaction with separate grants."""
    if not isinstance(identity, IdentityContext) or identity.delegation_id is None:
        raise ValueError("Expected a delegated identity")
    if any(not isinstance(value, datetime) or value.utcoffset() is None for value in (starts_at, expires_at)):
        raise ValueError("Delegation times must include a timezone")
    if starts_at >= expires_at:
        raise ValueError("Delegation expiry must follow its start")
    scopes = tuple(_scope(scope) for scope in scopes)
    if not scopes or len(scopes) != len(set(scopes)):
        raise ValueError("A delegation needs distinct scopes")
    _lock_tenant(connection, identity.tenant)
    connection.execute("""INSERT INTO enterprise_delegations (tenant,id,actor,service,starts_at,expires_at)
                          VALUES (?,?,?,?,?,?)""",
                       (identity.tenant, identity.delegation_id, identity.actor, identity.service, starts_at, expires_at))
    for scope in scopes:
        connection.execute("""INSERT INTO enterprise_delegation_scopes (tenant,delegation_id,operation,kind,resource_id,member)
                              VALUES (?,?,?,?,?,?)""", (identity.tenant, identity.delegation_id, *scope))


def revoke_delegation(connection, tenant, delegation_id):
    """Return whether an active record was revoked by the administrative caller."""
    _require_name(tenant)
    _require_name(delegation_id)
    _lock_tenant(connection, tenant)
    return connection.execute("""UPDATE enterprise_delegations SET revoked_at=clock_timestamp()
                                 WHERE tenant=? AND id=? AND revoked_at IS NULL""", (tenant, delegation_id)).rowcount == 1
