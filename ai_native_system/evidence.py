"""Minimal durable post-commit evidence for an already recorded tool effect."""

import json
import re
from datetime import datetime, timezone

from .storage import digest, encode


_PROFILE = "ai-native-action/effect-evidence/v0.1"
_DOMAIN = b"ai-native-action/effect-evidence/v0.1\x00"
_SUBSTRATE = "action-receipt"
_OBSERVATIONS = frozenset(("local_transaction", "remote_receipt_observed"))
_MATERIAL = ("tenant", "task_id", "operation_id", "authorization_digest", "result_digest", "observation")
_HEX = re.compile(r"[0-9a-f]{64}")


def _timestamp(value):
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _validate(material):
    for field in ("tenant", "task_id", "operation_id"):
        name = material[field]
        if (type(name) is not str or not name.strip() or len(name) > 512
                or any(ord(char) < 32 or ord(char) == 127 for char in name)):
            raise ValueError("Invalid evidence identifier")
    for field in ("authorization_digest", "result_digest"):
        value = material[field]
        if type(value) is not str or not _HEX.fullmatch(value):
            raise ValueError("Evidence requires SHA-256 digests")
    if type(material["observation"]) is not str or material["observation"] not in _OBSERVATIONS:
        raise ValueError("Invalid evidence observation")


def _validate_body(body):
    if type(body) is not dict or set(body) != {*_MATERIAL, "profile", "recorded_at"} or body["profile"] != _PROFILE:
        raise ValueError("Invalid effect evidence profile")
    _validate(body)
    recorded_at = body["recorded_at"]
    if type(recorded_at) is not str or len(recorded_at) != 27 or not recorded_at.endswith("Z"):
        raise ValueError("Invalid effect evidence time")
    if _timestamp(datetime.fromisoformat(recorded_at)) != recorded_at:
        raise ValueError("Effect evidence time must use canonical UTC")


def sign_effect(body, private_key):
    """Sign observation metadata with the independent attestation key."""
    from .adapters.owp import sign_profile

    _validate_body(body)
    return sign_profile(body, private_key, domain=_DOMAIN, substrate=_SUBSTRATE)


def verify_effect(envelope, trusted_keys):
    """Verify against separately supplied attestation keys and return the signed facts."""
    from .adapters.owp import verify_profile

    body = verify_profile(envelope, trusted_keys, domain=_DOMAIN, substrate=_SUBSTRATE)
    _validate_body(body)
    return body


def _row(connection, tenant, operation_id):
    return connection.execute(
        "SELECT * FROM owp_effect_evidence WHERE tenant = ? AND operation_id = ?",
        (tenant, operation_id),
    ).fetchone()


def _body(row):
    return {"profile": _PROFILE, **{name: row[name] for name in _MATERIAL},
            "recorded_at": _timestamp(row["recorded_at"])}


def enqueue_effect(connection, *, tenant, task_id, operation_id, authorization_digest, result, observation):
    """Queue exact evidence in the existing effect transaction."""
    if type(result) is not dict:
        raise ValueError("Tool effect result must be an object")
    material = {
        "tenant": tenant, "task_id": task_id, "operation_id": operation_id,
        "authorization_digest": authorization_digest, "result_digest": digest(result), "observation": observation,
    }
    _validate(material)
    effect = connection.execute(
        """SELECT effects.receipt FROM effects JOIN tasks ON tasks.id = effects.operation_id
           WHERE tasks.tenant = ? AND tasks.id = ? AND effects.operation_id = ?""",
        (tenant, task_id, operation_id),
    ).fetchone()
    if effect is None or digest(json.loads(effect["receipt"])) != material["result_digest"]:
        raise ValueError("Evidence does not match the recorded tool effect")
    connection.execute(
        """INSERT INTO owp_effect_evidence
            (tenant, task_id, operation_id, authorization_digest, result_digest, observation)
           VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (tenant, operation_id) DO NOTHING""",
        tuple(material[name] for name in _MATERIAL),
    )
    queued = _row(connection, tenant, operation_id)
    if queued is None or any(queued[name] != material[name] for name in _MATERIAL):
        raise ValueError("Operation evidence is already bound to different facts")
    return _body(queued)


def evidence_status(connection, tenant, operation_id):
    """Read readiness without exposing a tool receipt or key material."""
    row = _row(connection, tenant, operation_id)
    if row is None:
        return None
    return "delivered" if row["signed_document"] is not None else "pending"


def pending_effects(store, tenant, *, limit=100):
    """List pending operation IDs for an operator or trusted signer worker."""
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Evidence listing limit must be in 1–100")
    with store.transaction(tenant=tenant) as connection:
        rows = connection.execute(
            """SELECT operation_id, attempts, last_error FROM owp_effect_evidence
               WHERE tenant = ? AND delivered_at IS NULL ORDER BY recorded_at, operation_id LIMIT ?""",
            (tenant, limit),
        ).fetchall()
    return tuple({name: row[name] for name in ("operation_id", "attempts", "last_error")} for row in rows)


def _checked_proof(envelope, body, trusted_keys):
    if verify_effect(envelope, trusted_keys) != body:
        raise ValueError("Signed evidence does not match the queued observation")
    return {"status": "delivered", "proof": envelope}


def deliver_effect(store, tenant, operation_id, signer, trusted_keys):
    """Sign outside the transaction and register at most one verified proof."""
    with store.transaction(tenant=tenant) as connection:
        row = _row(connection, tenant, operation_id)
    if row is None:
        raise LookupError("Effect evidence was not queued")
    body = _body(row)
    if row["signed_document"] is not None:
        return _checked_proof(json.loads(row["signed_document"]), body, trusted_keys)

    document = error = None
    try:
        envelope = signer(dict(body))
    except Exception:
        error = "signer_unavailable"
    else:
        try:
            # Freeze the exact representation to persist before checking its signature.
            document = encode(envelope)
            _checked_proof(json.loads(document), body, trusted_keys)
        except (TypeError, ValueError, RecursionError, OverflowError):
            document = None
            error = "invalid_proof"

    with store.transaction(tenant=tenant, write=True) as connection:
        current = _row(connection, tenant, operation_id)
        if current is None or _body(current) != body:
            raise ValueError("Queued evidence changed while the signer was working")
        if current["signed_document"] is not None:
            document = current["signed_document"]
        else:
            connection.execute(
                """UPDATE owp_effect_evidence
                   SET attempts = attempts + 1, last_error = ?, signed_document = ?,
                       delivered_at = CASE WHEN ?::text IS NULL THEN NULL ELSE clock_timestamp() END
                   WHERE tenant = ? AND operation_id = ? AND delivered_at IS NULL""",
                (error, document, document, tenant, operation_id),
            )
    if document is None:
        return {"status": "pending"}
    return _checked_proof(json.loads(document), body, trusted_keys)
