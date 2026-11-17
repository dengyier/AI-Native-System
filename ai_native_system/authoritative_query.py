"""Read authoritative facts and preview a published action in one authorized snapshot."""

import time
from datetime import datetime, timezone
from functools import cache

from .fact_contracts import FactField, ObjectIdentity
from .fact_gate import assess, binding_for
from .facts import EXISTS, STATE, Facts
from .identity import _name
from .ontology import _value
from .rules import MAX_RELATION_MEMBERS
from .semantic_query import MAX_RESPONSE_BYTES, QUERY_SECONDS, limit_query_transaction
from .storage import encode, object_data


MAX_FIELDS = 16


class AuthoritativeQuery:
    def __init__(self, store, policy, snapshot):
        self.store = store
        self.policy = policy
        self.snapshot = snapshot
        self.ontology = snapshot.ontology()
        self.definition = self.ontology.to_document()

    def query(self, connection, identity, object_type, object_id, options):
        deadline = time.monotonic() + QUERY_SECONDS
        if not _name(object_type) or not _name(object_id):
            raise ValueError("A canonical object type and ID are required")
        self.policy.require(connection, identity, "read", "object", object_id)
        item = object_data(connection, identity.tenant, object_id)
        if item is None or item["type"] != object_type or object_type not in self.definition["types"]:
            raise PermissionError("Resource access denied")

        shape = self.definition["types"][object_type]
        fields, relation, preview = self._options(options, object_type, shape)
        limit_query_transaction(connection)
        subject = ObjectIdentity(identity.tenant, object_type, object_id)
        facts = Facts(self.store, identity.tenant)
        now = datetime.fromtimestamp(connection.database_time(), timezone.utc)
        existence = facts.read_fact(connection, FactField(subject, EXISTS), as_of=now, known_at=now)
        if existence.deleted or (existence.available and existence.value is False):
            raise PermissionError("Resource access denied")
        details = {}
        for field in fields:
            kind, member = self._field_scope(field)
            if self.policy.permits(connection, identity, "read", kind, object_id, member):
                observed = facts.read_fact(connection, FactField(subject, field), as_of=now, known_at=now)
                result = self._field(observed, field, shape)
                if self.policy.permits(connection, identity, "read", "provenance", object_id, field):
                    result["provenance"] = self._provenance(observed)
                details[field] = result

        result = {"release_digest": self.snapshot.digest, "object": {"id": object_id, "type": object_type},
                  "facts": details}
        if relation is not None and self.policy.permits(connection, identity, "read", "edge", object_id, relation):
            @cache
            def can_read_target(member):
                return _name(member) and self.policy.permits(connection, identity, "read", "object", member)

            target_type = self.definition["relations"][relation]["target_type"]
            observed = facts.read_relation(connection, subject, relation, target_type=target_type,
                                           max_members=MAX_RELATION_MEMBERS, as_of=now, known_at=now,
                                           target_visible=can_read_target)
            result["relation"] = {"name": relation, "scope": "authorized_subset", "members": [
                {"id": member, "type": target_type} for member in observed.collection.member_ids
            ]}
            if self.policy.permits(connection, identity, "read", "provenance", object_id, relation):
                result["relation"]["coverage"] = observed.collection.coverage.value
        if preview:
            result["preview"] = self._preview(connection, identity, subject, now)

        if time.monotonic() >= deadline or len(encode(result).encode("utf-8")) > MAX_RESPONSE_BYTES:
            raise ValueError("Authoritative query exceeded its time or size limit")
        return result

    def _options(self, options, object_type, shape):
        if not isinstance(options, dict) or options.keys() - {"fields", "relation", "preview"}:
            raise ValueError("Invalid authoritative query options")
        fields = options.get("fields", [])
        if (not isinstance(fields, list) or len(fields) > MAX_FIELDS
                or not all(_name(field) and (field == STATE or field in shape["properties"]) for field in fields)
                or len(set(fields)) != len(fields)):
            raise ValueError("Select up to 16 distinct published fact fields")
        relation = options.get("relation")
        if "relation" in options:
            declaration = self.definition["relations"].get(relation) if _name(relation) else None
            if declaration is None or declaration["source_type"] != object_type:
                raise ValueError("Select one published relationship for this object type")
        preview = options.get("preview", False)
        if type(preview) is not bool:
            raise ValueError("Action preview must be boolean")
        return fields, relation, preview

    @staticmethod
    def _field_scope(field):
        return ("metadata", "state") if field == STATE else ("field", field)

    @staticmethod
    def _field(observed, name, shape):
        if observed.deleted:
            return {"status": "withdrawn"}
        if not observed.available:
            return {"status": "unavailable"}
        if name == STATE:
            if observed.value not in shape["states"]:
                return {"status": "unavailable"}
        else:
            try:
                _value(observed.value, shape["properties"][name], "Authoritative query field")
            except ValueError:
                return {"status": "unavailable"}
        return {"status": "available", "value": observed.value}

    @staticmethod
    def _provenance(observed):
        versions = {read.source_version for read in observed.reads if read.source_version is not None}
        sources = sorted({(version.identity.source, version.token) for version in versions})
        deadlines = [read.fresh_until for read in observed.reads if read.fresh_until is not None]
        return {"coverage": observed.coverage.value, "reason": observed.reason,
                "fresh_until": min(deadlines).isoformat() if deadlines else None,
                "sources": [{"source": name, "version": token} for name, token in sources]}

    def _preview(self, connection, identity, subject, now):
        registry = self.snapshot.registry()
        app, action, _ = registry.definition(self.snapshot.application)
        action_id = app["action"]
        withheld = {"status": "not_displayable"}
        if (action["object_type"] != subject.object_type
                or not self.policy.permits(connection, identity, "read", "action", action_id)
                or not self.policy.permits(connection, identity, "preview", "action", action_id)):
            return withheld
        binding = binding_for(connection, identity.tenant, self.snapshot.digest)
        if binding is None:
            return withheld
        evaluation = assess(connection, self.store, self.ontology, subject.tenant, subject.object_type,
                            subject.object_id, binding, observed_at=now)
        rules = self.definition["rules"]
        resources = set(evaluation.resources)
        for name, _ in evaluation.versions:
            for condition in rules[name]["conditions"]:
                kind, member = self._condition_scope(condition)
                resources.add((kind, subject.object_id, member))
        if "relationship_collection_incomplete" in evaluation.reasons:
            return withheld
        if not all(_name(resource) and self.policy.permits(connection, identity, "read", kind, resource, member)
                   for kind, resource, member in resources):
            return withheld

        result = {"status": evaluation.status.value, "action": action_id, "rule_versions": dict(evaluation.versions),
                  "reasons": list(evaluation.reasons), "conditions": []}
        if self.policy.permits(connection, identity, "read", "metadata", subject.object_id, "state"):
            result["effect"] = {"field": STATE, "value": action["to_state"]}
        for name, index, status in evaluation.conditions:
            condition = rules[name]["conditions"][index]
            kind, member = self._condition_scope(condition)
            field = "relation" if kind == "edge" else "field"
            result["conditions"].append({"rule": name, field: STATE if kind == "metadata" else member,
                                         "status": status.value})
        return result

    @staticmethod
    def _condition_scope(condition):
        if "relation" in condition:
            return "edge", condition["relation"]
        if "property" in condition:
            return "field", condition["property"]
        return "metadata", "state"
