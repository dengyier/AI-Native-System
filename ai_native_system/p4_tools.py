"""Configured source bindings and precise source-side version guards."""

from dataclasses import dataclass
from types import MappingProxyType
import re

from .registry import is_name


_DIGEST = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class SourceBinding:
    source: str
    lookup_principal: str
    retention_seconds: int
    trusted_keys: dict

    def __post_init__(self):
        from .adapters.owp import key_id

        if not is_name(self.source) or not is_name(self.lookup_principal):
            raise ValueError("Declare the authoritative source and its receipt lookup identity")
        if type(self.retention_seconds) is not int or not 1 <= self.retention_seconds <= 7_776_000:
            raise ValueError("Declare the source's finite idempotency retention")
        if not isinstance(self.trusted_keys, dict) or not self.trusted_keys:
            raise ValueError("Source receipt verification requires pinned public keys")
        if any(identifier != key_id(key) for identifier, key in self.trusted_keys.items()):
            raise ValueError("A source public key does not match its pinned identifier")
        object.__setattr__(self, "trusted_keys", MappingProxyType(self.trusted_keys.copy()))

    @property
    def identity(self):
        return {
            "source": self.source, "lookup_principal": self.lookup_principal,
            "retention_seconds": self.retention_seconds, "receipt_key_ids": sorted(self.trusted_keys),
        }

    def verify(self, envelope, operation, authorization_digest):
        from .source_receipt import verify_source_receipt

        receipt = verify_source_receipt(envelope, self.trusted_keys, operation=operation,
                                        source=self.source, authorization_digest=authorization_digest)
        if receipt["status"] in ("succeeded", "rejected") and (
            receipt["retain_until"] is None or receipt["retain_until"] - receipt["recorded_at"] < self.retention_seconds
        ):
            raise ValueError("The signed receipt does not establish the registered retention")
        return receipt


def valid_source_identity(value):
    return (
        isinstance(value, dict) and value.keys() == {"source", "lookup_principal", "retention_seconds", "receipt_key_ids"}
        and is_name(value["source"]) and is_name(value["lookup_principal"])
        and type(value["retention_seconds"]) is int and 1 <= value["retention_seconds"] <= 7_776_000
        and isinstance(value["receipt_key_ids"], list) and bool(value["receipt_key_ids"])
        and all(isinstance(key, str) and bool(key.strip()) for key in value["receipt_key_ids"])
        and value["receipt_key_ids"] == sorted(set(value["receipt_key_ids"]))
    )


def valid_schema_digest(value):
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def source_conditions(connection, facts, evaluation, ground, source, definition):
    """Claim only versions enforceable by a single registered source transaction."""
    from .facts import MappingConflict
    from .fact_contracts import ObjectIdentity, canonical_json

    required = definition.registry.ontology().to_document()["rules"][definition.app["action"]]["conditions"]
    rules = definition.ontology.to_document()["rules"]
    observed = {canonical_json(condition) for name, _ in evaluation.versions for condition in rules[name]["conditions"]}
    if not all(canonical_json(condition) in observed for condition in required):
        return None
    subject = evaluation.subject
    scope_objects = {resource for kind, resource, _ in evaluation.resources if kind == "object"}
    guards = {}
    targets = []
    for proof in evaluation.read_set.reads:
        revision = proof.source_version
        if revision is None:
            # Source progress, policy revisions and evidence digests are framework proofs.
            # An unbacked selected assertion (e.g. a manual correction) cannot authorize CAS.
            if proof.kind == "assertion" and not proof.resource_id.startswith(("authority:", "progress:")):
                return None
            continue
        native = revision.identity
        if native.source != source or native.tenant != subject.tenant:
            return None
        key = (native.source_type, native.source_id)
        if key in guards:
            if guards[key]["expected_version"] != revision.token:
                return None
            continue
        try:
            mapping = facts.target_for(connection, native)
        except MappingConflict:
            return None
        target = mapping.target
        if not isinstance(target, ObjectIdentity) or target.object_id not in scope_objects:
            return None
        guards[key] = {"type": key[0], "id": key[1], "expected_version": revision.token}
        if target == subject:
            targets.append({
                "type": subject.object_type, "id": subject.object_id, "record_type": key[0], "record_id": key[1],
                "expected_version": revision.token, "from_state": ground["object"]["state"], "to_state": definition.action["to_state"],
            })
    if len(targets) != 1:
        return None
    written = (targets[0]["record_type"], targets[0]["record_id"])
    return {"source": source, "targets": targets, "guards": [guards[key] for key in sorted(guards) if key != written]}
