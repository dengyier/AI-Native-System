"""P4 source-authenticated conditional writes and detached receipts."""

from .adapters.owp import sign_profile, verify_profile
from .storage import digest


SOURCE_RECEIPT_PROFILE = "ai-native-action/source-receipt/v0.1"
_DOMAIN = b"ai-native-action/source-receipt/v0.1\x00"
_SUBSTRATE = "action-receipt"
_MAX_INTEGER = (1 << 53) - 1
_OPERATION = {
    "tenant", "operation_id", "action_instance_id", "request_hash", "action", "object_id", "expected_version",
    "from_state", "to_state", "requester", "approver", "executor", "release_digest", "source_conditions",
}
_TARGET = {"type", "id", "record_type", "record_id", "expected_version", "from_state", "to_state"}
_GUARD = {"type", "id", "expected_version"}
_RECEIPT = {
    "profile", "source", "tenant", "operation_id", "request_hash", "authorization_digest",
    "status", "recorded_at", "retain_until", "result", "reason",
}


def valid_name(value):
    return (type(value) is str and 0 < len(value) <= 512 and bool(value.strip())
            and not any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value))


def valid_digest(value):
    return type(value) is str and len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def valid_version(value):
    return valid_name(value) or type(value) is int and 0 <= value <= _MAX_INTEGER


def validate_operation(operation):
    """Validate the fixed write payload before signing or accepting it at a source."""
    if type(operation) is not dict or operation.keys() != _OPERATION:
        raise ValueError("Invalid source action request")
    names = _OPERATION - {"request_hash", "release_digest", "expected_version", "source_conditions"}
    if not all(valid_name(operation[key]) for key in names):
        raise ValueError("Invalid source action identifiers")
    if (type(operation["expected_version"]) is not int or not 1 <= operation["expected_version"] <= _MAX_INTEGER
            or not valid_digest(operation["release_digest"])
            or operation["request_hash"] != digest({key: value for key, value in operation.items()
                                                     if key != "request_hash"})):
        raise ValueError("The source action request does not match its digest")
    conditions = operation["source_conditions"]
    if (type(conditions) is not dict or conditions.keys() != {"source", "targets", "guards"}
            or not valid_name(conditions["source"])):
        raise ValueError("Invalid source conditions")
    targets, guards = conditions["targets"], conditions["guards"]
    if (type(targets) is not list or not 1 <= len(targets) <= 128
            or type(guards) is not list or not len(guards) <= 128):
        raise ValueError("Invalid source target or read guard count")
    canonical_ids = set()
    native = {}
    for target in targets:
        if (type(target) is not dict or target.keys() != _TARGET
                or not all(valid_name(target[key]) for key in _TARGET - {"expected_version"})
                or not valid_version(target["expected_version"]) or target["from_state"] == target["to_state"]):
            raise ValueError("Invalid source write target")
        record = (target["record_type"], target["record_id"])
        if target["id"] in canonical_ids or record in native:
            raise ValueError("Duplicate source write target")
        native[record] = target["expected_version"]
        canonical_ids.add(target["id"])
    primary = next((target for target in targets if target["id"] == operation["object_id"]), None)
    if primary is None or any(primary[key] != operation[key] for key in ("from_state", "to_state")):
        raise ValueError("Primary target differs from the framework action")
    guarded = set()
    for guard in guards:
        if (type(guard) is not dict or guard.keys() != _GUARD
                or not all(valid_name(guard[key]) for key in ("type", "id"))
                or not valid_version(guard["expected_version"])):
            raise ValueError("Invalid native read guard")
        record = (guard["type"], guard["id"])
        if record in guarded or (record in native and not _same_version(guard["expected_version"], native[record])):
            raise ValueError("Duplicate or inconsistent native read guard")
        guarded.add(record)
    return conditions


def _same_version(left, right):
    return type(left) is type(right) and left == right


def validate_source_receipt(body):
    if type(body) is not dict or body.keys() != _RECEIPT or body["profile"] != SOURCE_RECEIPT_PROFILE:
        raise ValueError("Invalid source receipt profile")
    if not all(valid_name(body[key]) for key in ("source", "tenant", "operation_id")):
        raise ValueError("Invalid source receipt identity")
    if not valid_digest(body["request_hash"]):
        raise ValueError("Invalid source receipt request digest")
    recorded = body["recorded_at"]
    if type(recorded) is not int or not 1 <= recorded <= _MAX_INTEGER:
        raise ValueError("Invalid source receipt time")
    status = body["status"]
    if status == "not_found":
        if (body["authorization_digest"] is not None or body["retain_until"] is not None
                or body["result"] is not None or body["reason"] != "operation_unknown"):
            raise ValueError("A missing operation has no execution evidence")
        return
    retained = body["retain_until"]
    if (not valid_digest(body["authorization_digest"]) or type(retained) is not int
            or not recorded < retained <= _MAX_INTEGER):
        raise ValueError("Invalid source receipt retention or authorization digest")
    if status == "rejected":
        if body["result"] is not None or body["reason"] != "condition_mismatch":
            raise ValueError("Invalid conditional rejection")
        return
    result = body["result"]
    if (status != "succeeded" or body["reason"] is not None or type(result) is not dict
            or result.keys() != {"objects"} or type(result["objects"]) is not list
            or not 1 <= len(result["objects"]) <= 128):
        raise ValueError("Invalid source result")
    seen = set()
    for item in result["objects"]:
        if (type(item) is not dict or item.keys() != {"type", "id", "previous_version", "version", "state"}
                or not all(valid_name(item[key]) for key in ("type", "id", "state"))
                or not all(valid_version(item[key]) for key in ("previous_version", "version"))
                or _same_version(item["previous_version"], item["version"])):
            raise ValueError("Invalid source affected object")
        key = item["type"], item["id"]
        if key in seen:
            raise ValueError("Duplicate affected object")
        seen.add(key)


def sign_source_receipt(body, private_key):
    validate_source_receipt(body)
    return sign_profile(body, private_key, domain=_DOMAIN, substrate=_SUBSTRATE)


def verify_source_receipt(envelope, trusted_keys, *, operation=None, source=None, authorization_digest=None):
    """Verify the original source signature and, when supplied, its exact dispatch binding."""
    body = verify_profile(envelope, trusted_keys, domain=_DOMAIN, substrate=_SUBSTRATE)
    validate_source_receipt(body)
    if source is not None and body["source"] != source:
        raise ValueError("The receipt identifies another source")
    if authorization_digest is not None and body["status"] != "not_found":
        if body["authorization_digest"] != authorization_digest:
            raise ValueError("The receipt identifies another authorization")
    if operation is None:
        return body
    conditions = validate_operation(operation)
    if (body["source"] != conditions["source"]
            or any(body[key] != operation[key] for key in ("tenant", "operation_id", "request_hash"))):
        raise ValueError("The receipt identifies another source operation")
    if body["status"] == "succeeded":
        expected = {(t["type"], t["id"]): t for t in conditions["targets"]}
        affected = {(item["type"], item["id"]): item for item in body["result"]["objects"]}
        if affected.keys() != expected.keys():
            raise ValueError("The receipt does not identify all and only the authorized targets")
        for key, target in expected.items():
            item = affected[key]
            if (not _same_version(item["previous_version"], target["expected_version"])
                    or item["state"] != target["to_state"]):
                raise ValueError("The receipt result violates the authorized transition")
    return body
