"""Reference source service with transactional version guards and durable signed receipts.

The source database is independent of the framework. Every new source effect
requires the same transaction to hold the affected rows, check all presented
native versions and record the signed receipt and nonce.
"""

import json
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
from uuid import uuid4

from .adapters.owp import verify_authorization
from .source_receipt import (
    SOURCE_RECEIPT_PROFILE,
    sign_source_receipt,
    valid_digest,
    valid_name,
    valid_version,
    validate_operation,
)
from .storage import encode


_SCHEMA = """
CREATE SCHEMA IF NOT EXISTS p4_source;
CREATE TABLE IF NOT EXISTS p4_source.objects (
    tenant text NOT NULL,
    record_type text NOT NULL,
    record_id text NOT NULL,
    object_type text NOT NULL,
    object_id text NOT NULL,
    state text NOT NULL,
    version jsonb NOT NULL,
    PRIMARY KEY (tenant, record_type, record_id),
    UNIQUE (tenant, object_type, object_id)
);
CREATE TABLE IF NOT EXISTS p4_source.receipts (
    tenant text NOT NULL,
    source text NOT NULL,
    operation_id text NOT NULL,
    request_hash text NOT NULL,
    authorization_digest text NOT NULL,
    epoch text NOT NULL,
    nonce text NOT NULL,
    retain_until bigint NOT NULL,
    signed_document text NOT NULL,
    PRIMARY KEY (tenant, source, operation_id),
    UNIQUE (tenant, source, epoch, nonce)
);

CREATE OR REPLACE FUNCTION p4_source.require_version_for_state_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog AS $$
BEGIN
    IF (NEW.tenant, NEW.record_type, NEW.record_id, NEW.object_type, NEW.object_id)
       IS DISTINCT FROM (OLD.tenant, OLD.record_type, OLD.record_id, OLD.object_type, OLD.object_id) THEN
        RAISE EXCEPTION 'Source identity mappings are immutable' USING ERRCODE = '23514';
    END IF;
    IF NEW.state IS DISTINCT FROM OLD.state AND NEW.version IS NOT DISTINCT FROM OLD.version THEN
        RAISE EXCEPTION 'Source state changes require a distinct version' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
END;
$$;
DROP TRIGGER IF EXISTS versioned_source_state ON p4_source.objects;
CREATE TRIGGER versioned_source_state BEFORE UPDATE ON p4_source.objects
    FOR EACH ROW EXECUTE FUNCTION p4_source.require_version_for_state_change();

CREATE OR REPLACE FUNCTION p4_source.reject_receipt_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'Source operation records are immutable' USING ERRCODE = '42501';
END;
$$;
DROP TRIGGER IF EXISTS immutable_receipt ON p4_source.receipts;
CREATE TRIGGER immutable_receipt BEFORE UPDATE OR DELETE ON p4_source.receipts
    FOR EACH ROW EXECUTE FUNCTION p4_source.reject_receipt_change();
DROP TRIGGER IF EXISTS immutable_receipt_truncate ON p4_source.receipts;
CREATE TRIGGER immutable_receipt_truncate BEFORE TRUNCATE ON p4_source.receipts
    FOR EACH STATEMENT EXECUTE FUNCTION p4_source.reject_receipt_change();

ALTER TABLE p4_source.objects ENABLE ROW LEVEL SECURITY;
ALTER TABLE p4_source.receipts ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_scope ON p4_source.objects;
CREATE POLICY tenant_scope ON p4_source.objects
    USING (tenant = NULLIF(pg_catalog.current_setting('p4_source.tenant', true), ''))
    WITH CHECK (tenant = NULLIF(pg_catalog.current_setting('p4_source.tenant', true), ''));
DROP POLICY IF EXISTS tenant_scope ON p4_source.receipts;
CREATE POLICY tenant_scope ON p4_source.receipts
    USING (tenant = NULLIF(pg_catalog.current_setting('p4_source.tenant', true), ''))
    WITH CHECK (tenant = NULLIF(pg_catalog.current_setting('p4_source.tenant', true), ''));
REVOKE ALL ON SCHEMA p4_source FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA p4_source FROM PUBLIC;
"""


def initialize_source(dsn):
    """Install the independent source schema as its migration owner."""
    import psycopg

    with psycopg.connect(dsn, connect_timeout=5, target_session_attrs="read-write") as connection:
        connection.execute(_SCHEMA, prepare=False)


def seed_source_object(dsn, tenant, *, record_type, record_id, object_type, object_id, state, version):
    """Register one explicit canonical-to-native mapping using a trusted source operator."""
    if (not all(map(valid_name, (tenant, record_type, record_id, object_type, object_id, state)))
            or not valid_version(version)):
        raise ValueError("Invalid source object")
    with _transaction(dsn, tenant, write=True) as connection:
        connection.execute(
            """INSERT INTO p4_source.objects
               (tenant,record_type,record_id,object_type,object_id,state,version) VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb)""",
            (tenant, record_type, record_id, object_type, object_id, state, encode(version)),
        )


@contextmanager
def _transaction(dsn, tenant, *, write=False):
    import psycopg
    from psycopg.rows import dict_row

    with psycopg.connect(dsn, connect_timeout=5, target_session_attrs="read-write", row_factory=dict_row) as connection:
        connection.execute("SET TRANSACTION READ WRITE" if write else "SET TRANSACTION READ ONLY")
        connection.execute("SET LOCAL search_path TO pg_catalog, pg_temp")
        connection.execute("SET LOCAL lock_timeout TO '5s'")
        connection.execute("SET LOCAL statement_timeout TO '10s'")
        connection.execute("SELECT pg_catalog.set_config('p4_source.tenant', %s, true)", (tenant,))
        if write:
            material = f"p4-source/{tenant}".encode("utf-8")
            lock = int.from_bytes(sha256(material).digest()[:8], "big", signed=True)
            connection.execute("SELECT pg_catalog.pg_advisory_xact_lock(%s::bigint)", (lock,))
        yield connection


@dataclass(frozen=True)
class SourceAction:
    """A source-approved action and its only permitted transition."""

    version: str | int
    object_type: str
    from_state: str
    to_state: str
    max_targets: int = 1

    def __post_init__(self):
        if (not valid_version(self.version) or self.version == 0
                or not all(map(valid_name, (self.object_type, self.from_state, self.to_state)))
                or self.from_state == self.to_state or type(self.max_targets) is not int
                or not 1 <= self.max_targets <= 128):
            raise ValueError("Invalid source action declaration")


class SourceWrite:
    def __init__(self, dsn, *, tenant, source, destination_digest, actions, authority_keys, signing_key,
                 epoch, retention_seconds=86400, execute_principal="execute", lookup_principal="lookup",
                 lookup_dsn=None):
        if (not all(map(valid_name, (dsn, tenant, source, epoch, execute_principal, lookup_principal)))
                or (lookup_dsn is not None and not valid_name(lookup_dsn))
                or execute_principal == lookup_principal or not valid_digest(destination_digest)
                or type(actions) is not dict or not actions
                or not all(valid_name(name) and isinstance(action, SourceAction) for name, action in actions.items())
                or type(retention_seconds) is not int or not 1 <= retention_seconds <= 365 * 86400):
            raise ValueError("Invalid conditional source configuration")
        from .adapters.owp import key_id

        own_key = key_id(signing_key.public_key())
        if not isinstance(authority_keys, dict) or not authority_keys or own_key in authority_keys:
            raise ValueError("Use independent source and authorization signing keys")
        self._dsn = dsn
        self._lookup_dsn = lookup_dsn or dsn
        self.tenant = tenant
        self.source = source
        self._destination_digest = destination_digest
        self._actions = dict(actions)
        self._authority_keys = dict(authority_keys)
        self._key = signing_key
        self._epoch = epoch
        self._retention = retention_seconds
        self._execute_principal = execute_principal
        self._lookup_principal = lookup_principal

    def _conditions(self, operation):
        conditions = validate_operation(operation)
        if operation["tenant"] != self.tenant or conditions["source"] != self.source:
            raise PermissionError("The operation is outside the source identity")
        return conditions

    def _authorize(self, operation, conditions, authorization):
        claims = verify_authorization(authorization, self._authority_keys)
        scope = claims["scope"]
        action = self._actions.get(operation["action"])
        if action is None or len(conditions["targets"]) > action.max_targets:
            raise PermissionError("The source has not registered this action")
        if any((target["type"], target["from_state"], target["to_state"])
               != (action.object_type, action.from_state, action.to_state) for target in conditions["targets"]):
            raise PermissionError("The requested write exceeds the registered source action")
        if (claims["epoch"] != self._epoch or scope["action_kind"] != "write_remote"
                or type(scope["action_version"]) is not type(action.version)
                or scope["action_version"] != action.version
                or scope["tool"]["destination_digest"] != self._destination_digest
                or scope["parameters_digest"] != operation["request_hash"]
                or scope["requester"]["actor"] != operation["requester"]
                or scope["approver"]["actor"] != operation["approver"]
                or scope["task_id"] != operation["operation_id"]
                or any(scope[key] != operation[key] for key in
                       ("tenant", "operation_id", "action_instance_id", "action", "executor", "release_digest"))):
            raise PermissionError("The authorization does not bind this source operation")
        targets = {(t["type"], t["id"]) for t in conditions["targets"]}
        if {(target["type"], target["id"]) for target in scope["targets"]} != targets:
            raise PermissionError("The authorization does not cover these write targets")
        allowed = {("object", object_id, None) for _, object_id in targets}
        allowed.update(("metadata", object_id, field) for _, object_id in targets for field in ("state", "version"))
        if {(entry["kind"], entry["resource_id"], entry["member"]) for entry in scope["writes"]} != allowed:
            raise PermissionError("The authorization does not bind the exact fields being written")
        return claims

    def _prior(self, connection, operation):
        return connection.execute(
            """SELECT request_hash, authorization_digest, signed_document
               FROM p4_source.receipts WHERE tenant=%s AND source=%s AND operation_id=%s""",
            (self.tenant, self.source, operation["operation_id"]),
        ).fetchone()

    def _receipt(self, operation, now, status, *, authorization_digest=None, result=None, reason=None):
        return sign_source_receipt({
            "profile": SOURCE_RECEIPT_PROFILE, "source": self.source, "tenant": self.tenant,
            "operation_id": operation["operation_id"], "request_hash": operation["request_hash"],
            "authorization_digest": authorization_digest, "status": status, "recorded_at": now,
            "retain_until": now + self._retention if authorization_digest is not None else None,
            "result": result, "reason": reason,
        }, self._key)

    @staticmethod
    def _now(connection):
        return connection.execute(
            "SELECT floor(extract(epoch FROM pg_catalog.clock_timestamp()))::bigint AS seconds"
        ).fetchone()["seconds"]

    def _lock_and_check(self, connection, conditions, scope):
        checks = {(guard["type"], guard["id"]): guard["expected_version"] for guard in conditions["guards"]}
        checks.update({(target["record_type"], target["record_id"]): target["expected_version"]
                       for target in conditions["targets"]})
        rows = {}
        object_reads = {entry["resource_id"] for entry in scope["reads"]
                        if entry["kind"] == "object" and entry["member"] is None}
        guards = {(guard["type"], guard["id"]) for guard in conditions["guards"]}
        matched = True
        for key, expected in sorted(checks.items()):
            current = connection.execute(
                """SELECT object_type,object_id,state,version FROM p4_source.objects
                   WHERE tenant=%s AND record_type=%s AND record_id=%s FOR UPDATE""",
                (self.tenant, *key),
            ).fetchone()
            if current is None:
                matched = False
                continue
            if key in guards and current["object_id"] not in object_reads:
                raise PermissionError("The authorization does not cover a source read guard")
            if type(current["version"]) is not type(expected) or current["version"] != expected:
                matched = False
            rows[key] = current
        if not matched:
            return False
        for target in conditions["targets"]:
            current = rows[target["record_type"], target["record_id"]]
            if (current["object_type"], current["object_id"], current["state"]) != (
                target["type"], target["id"], target["from_state"],
            ):
                return False
        return True

    def execute(self, operation, authorization, *, principal):
        """Perform one atomic compare-and-set or return the original signed conclusion."""
        if principal != self._execute_principal:
            raise PermissionError("The source identity cannot execute an action")
        conditions = self._conditions(operation)
        claims = self._authorize(operation, conditions, authorization)
        authorization_digest = authorization["digest"]
        with _transaction(self._dsn, self.tenant, write=True) as connection:
            previous = self._prior(connection, operation)
            if previous is not None:
                if (previous["request_hash"], previous["authorization_digest"]) != (
                    operation["request_hash"], authorization_digest,
                ):
                    raise PermissionError("The operation ID is already bound to another request")
                return json.loads(previous["signed_document"])
            used = connection.execute(
                """SELECT 1 FROM p4_source.receipts WHERE tenant=%s AND source=%s AND epoch=%s AND nonce=%s""",
                (self.tenant, self.source, claims["epoch"], claims["nonce"]),
            ).fetchone()
            if used is not None:
                raise PermissionError("The source authorization was already consumed")
            matched = self._lock_and_check(connection, conditions, claims["scope"])
            now = self._now(connection)
            expiry = [claims["expires_at"], *(
                claims["scope"][role]["expires_at"] for role in ("requester", "approver")
                if claims["scope"][role]["expires_at"] is not None
            )]
            if not claims["issued_at"] <= now < min(expiry):
                raise PermissionError("The source authorization expired")
            if matched:
                affected = []
                for target in conditions["targets"]:
                    successor = uuid4().hex
                    connection.execute(
                        """UPDATE p4_source.objects SET state=%s,version=%s::jsonb
                           WHERE tenant=%s AND record_type=%s AND record_id=%s""",
                        (target["to_state"], encode(successor), self.tenant, target["record_type"], target["record_id"]),
                    )
                    affected.append({"type": target["type"], "id": target["id"],
                                     "previous_version": target["expected_version"],
                                     "version": successor, "state": target["to_state"]})
                envelope = self._receipt(operation, now, "succeeded", authorization_digest=authorization_digest,
                                         result={"objects": affected})
            else:
                envelope = self._receipt(operation, now, "rejected", authorization_digest=authorization_digest,
                                         reason="condition_mismatch")
            connection.execute(
                """INSERT INTO p4_source.receipts
                   (tenant,source,operation_id,request_hash,authorization_digest,epoch,nonce,retain_until,signed_document)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (self.tenant, self.source, operation["operation_id"], operation["request_hash"], authorization_digest,
                 claims["epoch"], claims["nonce"], envelope["payload"]["retain_until"], encode(envelope)),
            )
            return envelope

    def lookup(self, operation, *, principal):
        """Query the exact original operation without permission to perform another effect."""
        if principal != self._lookup_principal:
            raise PermissionError("The source identity cannot query receipts")
        self._conditions(operation)
        with _transaction(self._lookup_dsn, self.tenant) as connection:
            previous = self._prior(connection, operation)
            if previous is not None:
                if previous["request_hash"] != operation["request_hash"]:
                    raise PermissionError("The operation ID is already bound to another request")
                return json.loads(previous["signed_document"])
            return self._receipt(operation, self._now(connection), "not_found", reason="operation_unknown")
