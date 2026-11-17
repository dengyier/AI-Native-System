"""Pinned OpenWorkProof primitives for a separate enterprise action profile."""

import base64
import hmac
import json
import re
from collections.abc import Mapping
from functools import cache
from hashlib import sha256

from ..contracts import ActionKind
from ..fact_contracts import canonical_json
from ..identity import IdentityContext


OWP_VERSION = "1.6.1"
AUTHORIZATION_PROFILE = "ai-native-action/v0.1"
AUTHORIZATION_DOMAIN = b"ai-native-action/authorization/v0.1\x00"
_MAX_SIGNED_BYTES = 256 * 1024
_MAX_ENVELOPE_BYTES = _MAX_SIGNED_BYTES + 1024
_SAFE_INTEGER = 2**53 - 1
_DIGEST = re.compile(r"[0-9a-f]{64}")
_KEY_ID = re.compile(r"ed25519:[0-9a-f]{64}")
_SIGNATURE = re.compile(r"[A-Za-z0-9_-]{86}")
_AUTH_FIELDS = {"profile", "nonce", "epoch", "issued_at", "expires_at", "scope"}
_SCOPE_FIELDS = {
    "tenant", "task_id", "operation_id", "action_instance_id", "release_digest", "ontology_digest",
    "policy_version", "rule_versions", "rule_proof_digest", "fact_read_set_digest", "requester", "approver",
    "executor", "approval_digest", "action", "action_version", "action_kind", "targets", "reads", "writes",
    "parameters_digest", "tool",
}
_IDENTITY_FIELDS = {"tenant", "actor", "service", "delegation_id", "expires_at"}
_SIGNED_FIELDS = {"payload", "signer_key_id", "signature_alg", "digest", "signature"}


class ProfileError(ValueError):
    """A malformed, unsupported or untrusted enterprise profile."""


@cache
def _signing():
    try:
        from openworkproof import __version__, signing
    except ImportError as exc:
        raise ProfileError(f"Install the pinned OpenWorkProof {OWP_VERSION} integration") from exc
    if __version__ != OWP_VERSION:
        raise ProfileError(f"Expected OpenWorkProof {OWP_VERSION}")
    return signing


def key_id(public_key):
    """Return the OpenWorkProof SHA-256 fingerprint of an Ed25519 public key."""
    try:
        return _signing().key_id(public_key)
    except ValueError as exc:
        raise ProfileError(str(exc)) from exc


def load_private_key(pem):
    return _load_key(pem, private=True)


def load_public_key(pem):
    return _load_key(pem, private=False)


def _load_key(pem, *, private):
    signing = _signing()
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives import serialization

    if type(pem) is not bytes or not 1 <= len(pem) <= 4096:
        raise ProfileError("Expected a bounded Ed25519 PEM key")
    try:
        if private:
            key = serialization.load_pem_private_key(pem, password=None)
        else:
            key = serialization.load_pem_public_key(pem)
    except (TypeError, ValueError, UnsupportedAlgorithm) as exc:
        raise ProfileError("Invalid Ed25519 PEM key") from exc
    expected = signing.Ed25519PrivateKey if private else signing.Ed25519PublicKey
    if not isinstance(key, expected):
        raise ProfileError("Expected an Ed25519 key")
    return key


def profile_digest(value):
    """Bind an existing framework contract's canonical parameter or read-set document."""
    try:
        raw = canonical_json(value).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exc:
        raise ProfileError("Invalid canonical framework document") from exc
    return sha256(raw).hexdigest()


def _profile_bytes(body, domain, substrate):
    if (type(domain) is not bytes or not domain.startswith(b"ai-native-action/")
            or not domain.endswith(b"\x00") or domain.count(b"\x00") != 1 or len(domain) > 96):
        raise ProfileError("Invalid enterprise signature domain")
    try:
        canonical = _signing().canonical_bytes(substrate, body, version="0.1")
    except (TypeError, ValueError, OverflowError) as exc:
        raise ProfileError("Invalid OpenWorkProof canonical payload") from exc
    if len(domain) + len(canonical) > _MAX_SIGNED_BYTES:
        raise ProfileError("Signed payload exceeds its size limit")
    return domain + canonical


def _strict_pairs(pairs):
    data = {}
    for name, value in pairs:
        if name in data:
            raise ProfileError("Duplicate signed JSON key")
        data[name] = value
    return data


def _reject_constant(_):
    raise ProfileError("Non-finite signed JSON value")


def _read_envelope(envelope):
    if type(envelope) in (bytes, str):
        try:
            raw = envelope.encode("utf-8") if type(envelope) is str else envelope
            if not 1 <= len(raw) <= _MAX_ENVELOPE_BYTES:
                raise ProfileError("Signed envelope exceeds its size limit")
            envelope = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_pairs, parse_constant=_reject_constant)
        except (ValueError, RecursionError) as exc:
            raise ProfileError("Invalid signed JSON envelope") from exc
    if type(envelope) is not dict or envelope.keys() != _SIGNED_FIELDS:
        raise ProfileError("Invalid signed envelope shape")
    return envelope


def _body(payload, signer_key_id):
    return {"payload": payload, "signer_key_id": signer_key_id, "signature_alg": "Ed25519"}


def _detached_payload(encoded, domain):
    # The pinned API has already validated and snapshotted the input JSON.
    return json.loads(encoded[len(domain):])["payload"]["payload"]


def sign_profile(payload, private_key, *, domain, substrate):
    """Create an exclusive enterprise signature from pinned OWP canonical bytes."""
    if type(payload) is not dict or not isinstance(private_key, _signing().Ed25519PrivateKey):
        raise ProfileError("Expected an enterprise JSON object and an Ed25519 signing key")
    body = _body(payload, key_id(private_key.public_key()))
    encoded = _profile_bytes(body, domain, substrate)
    signature = base64.urlsafe_b64encode(private_key.sign(encoded)).decode("ascii").rstrip("=")
    return {**body, "payload": _detached_payload(encoded, domain), "digest": sha256(encoded).hexdigest(),
            "signature": signature}


def verify_profile(envelope, trusted_keys, *, domain, substrate):
    """Authenticate and return a detached payload under the expected domain and trust map."""
    signed = _read_envelope(envelope)
    signer, signature, digest = signed["signer_key_id"], signed["signature"], signed["digest"]
    if (type(signed["payload"]) is not dict or signed["signature_alg"] != "Ed25519"
            or type(signer) is not str or _KEY_ID.fullmatch(signer) is None
            or type(signature) is not str or _SIGNATURE.fullmatch(signature) is None
            or type(digest) is not str or _DIGEST.fullmatch(digest) is None):
        raise ProfileError("Invalid signature metadata")
    public_key = trusted_keys.get(signer) if isinstance(trusted_keys, Mapping) else None
    signing = _signing()
    if not isinstance(public_key, signing.Ed25519PublicKey) or key_id(public_key) != signer:
        raise ProfileError("Untrusted signing key")
    raw = base64.urlsafe_b64decode(signature + "==")
    if len(raw) != 64 or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != signature:
        raise ProfileError("Invalid signature encoding")
    encoded = _profile_bytes(_body(signed["payload"], signer), domain, substrate)
    if not hmac.compare_digest(digest, sha256(encoded).hexdigest()):
        raise ProfileError("Signed payload digest does not match")
    try:
        public_key.verify(raw, encoded)
    except signing.InvalidSignature as exc:
        raise ProfileError("Invalid enterprise signature") from exc
    return _detached_payload(encoded, domain)


def _identifier(value):
    return (type(value) is str and 1 <= len(value) <= 512 and bool(value.strip())
            and not any(ord(character) < 32 or 127 <= ord(character) <= 159 for character in value))


def _version(value):
    return (type(value) is int and 0 < value <= _SAFE_INTEGER) or _identifier(value)


def _timestamp(value):
    return type(value) is int and 0 < value <= _SAFE_INTEGER


def _digest(value, *, nullable=False):
    return (nullable and value is None) or (type(value) is str and _DIGEST.fullmatch(value) is not None)


def _identity(value, tenant):
    if type(value) is not dict or value.keys() != _IDENTITY_FIELDS or value["tenant"] != tenant:
        raise ProfileError("Invalid authorization identity")
    if not all(item is None or _identifier(item) for item in (value["service"], value["delegation_id"])):
        raise ProfileError("Invalid authorization delegation")
    if not _identifier(value["actor"]) or (value["expires_at"] is not None and not _timestamp(value["expires_at"])):
        raise ProfileError("Invalid authorization principal")
    try:
        return IdentityContext.from_document(value)
    except ValueError as exc:
        raise ProfileError("Invalid authorization identity") from exc


def _members(values, fields, required, maximum, *, nullable=()):
    if type(values) not in (list, tuple) or not required <= len(values) <= maximum:
        raise ProfileError("Invalid authorization resource scope")
    members = set()
    for entry in values:
        if type(entry) is not dict or entry.keys() != set(fields):
            raise ProfileError("Invalid authorization resource")
        key = tuple(entry[field] for field in fields)
        if not all((value is None and field in nullable) or _identifier(value)
                   for field, value in zip(fields, key)):
            raise ProfileError("Invalid authorization resource identifier")
        if key in members:
            raise ProfileError("Duplicate authorization resource")
        members.add(key)


def validate_authorization(payload):
    """Check the exact enterprise action contract before signing or use."""
    if (type(payload) is not dict or payload.keys() != _AUTH_FIELDS
            or payload["profile"] != AUTHORIZATION_PROFILE):
        raise ProfileError("Unsupported enterprise authorization profile")
    if not _identifier(payload["nonce"]) or not _identifier(payload["epoch"]):
        raise ProfileError("Invalid authorization nonce or epoch")
    start, end = payload["issued_at"], payload["expires_at"]
    if not _timestamp(start) or not _timestamp(end) or start >= end:
        raise ProfileError("Invalid authorization validity interval")

    scope = payload["scope"]
    if type(scope) is not dict or scope.keys() != _SCOPE_FIELDS:
        raise ProfileError("Invalid authorization scope")
    identifiers = ("tenant", "task_id", "operation_id", "action_instance_id", "executor", "action")
    if (not all(_identifier(scope[name]) for name in identifiers)
            or not _version(scope["policy_version"]) or not _version(scope["action_version"])):
        raise ProfileError("Invalid scoped identifier or version")
    if not all(_digest(scope[name]) for name in ("release_digest", "ontology_digest", "parameters_digest")):
        raise ProfileError("Invalid authorization digest")
    try:
        kind = ActionKind(scope["action_kind"])
    except ValueError as exc:
        raise ProfileError("Unsupported action kind") from exc
    writing = kind in (ActionKind.WRITE_LOCAL, ActionKind.WRITE_REMOTE)

    tenant = scope["tenant"]
    requester = _identity(scope["requester"], tenant)
    if scope["approver"] is None:
        if writing or scope["approval_digest"] is not None:
            raise ProfileError("A write authorization requires a signed approval binding")
    else:
        approver = _identity(scope["approver"], tenant)
        if (approver.actor == requester.actor or approver.service is not None
                or not _digest(scope["approval_digest"])):
            raise ProfileError("Authorization requires an independent human approval")

    rules = scope["rule_versions"]
    if (type(rules) is not dict or len(rules) > 128
            or not all(_identifier(name) and _version(version) for name, version in rules.items())):
        raise ProfileError("Invalid rule versions")
    if rules:
        if not _digest(scope["rule_proof_digest"]) or not _digest(scope["fact_read_set_digest"]):
            raise ProfileError("Rule versions require evidence and read-set digests")
    elif writing or scope["rule_proof_digest"] is not None or not _digest(scope["fact_read_set_digest"], nullable=True):
        raise ProfileError("A write authorization requires a bound rule proof")

    _members(scope["targets"], ("type", "id"), int(writing), 128)
    _members(scope["reads"], ("kind", "resource_id", "member"), 1, 512, nullable=("member",))
    _members(scope["writes"], ("kind", "resource_id", "member"), int(writing), 512, nullable=("member",))
    if scope["writes"] and not writing:
        raise ProfileError("Read and generation authorizations cannot write")

    tool = scope["tool"]
    if (type(tool) is not dict or tool.keys() != {"name", "version", "destination_digest"}
            or not _identifier(tool["name"]) or not _version(tool["version"])
            or not _digest(tool["destination_digest"], nullable=True)):
        raise ProfileError("Invalid tool binding")
    if ((kind == ActionKind.WRITE_REMOTE and tool["destination_digest"] is None)
            or (kind == ActionKind.WRITE_LOCAL and tool["destination_digest"] is not None)):
        raise ProfileError("The tool destination does not match the action kind")


def sign_authorization(payload, private_key):
    validate_authorization(payload)
    # Validation of the detached result also protects mutable caller inputs.
    signed = sign_profile(payload, private_key, domain=AUTHORIZATION_DOMAIN, substrate="capability-grant")
    validate_authorization(signed["payload"])
    return signed


def verify_authorization(envelope, trusted_keys):
    payload = verify_profile(envelope, trusted_keys, domain=AUTHORIZATION_DOMAIN, substrate="capability-grant")
    validate_authorization(payload)
    return payload
