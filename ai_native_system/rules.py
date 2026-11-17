"""Deterministic rule evaluation over the trusted, unfiltered fact store."""
import operator
from dataclasses import asdict, dataclass
from datetime import date, datetime, timezone
from decimal import Decimal
from enum import StrEnum
from graphlib import TopologicalSorter

from .fact_contracts import Coverage, FactField, FactReadSet, ObjectIdentity, _hash, _utc, json_data
from .ontology import OntologyRelease, _value


MAX_CONDITIONS = 128
MAX_INPUTS = 512
MAX_RELATION_MEMBERS = 200
_COMPARISONS = {
    "eq": operator.eq, "ne": operator.ne, "gt": operator.gt,
    "ge": operator.ge, "lt": operator.lt, "le": operator.le,
}
_CASTS = {"decimal": Decimal, "date": date.fromisoformat, "datetime": datetime.fromisoformat}


class RuleStatus(StrEnum):
    SATISFIED = "satisfied"
    NOT_SATISFIED = "not_satisfied"
    INSUFFICIENT = "insufficient"


@dataclass(frozen=True)
class RuleResult:
    """Internal proof. Its read IDs and rule outcome require independent disclosure authorization."""

    ontology_digest: str
    ontology_version: int | str
    rule_name: str
    subject: ObjectIdentity
    status: RuleStatus
    versions: tuple[tuple[str, int | str], ...]
    read_set: FactReadSet
    reasons: tuple[str, ...] = ()
    resources: tuple[tuple[str, str, str | None], ...] = ()
    conditions: tuple[tuple[str, int, RuleStatus], ...] = ()

    @property
    def fingerprint(self):
        """Bind proof contents while allowing a new observation time at recheck."""
        proof = self.read_set.as_payload()
        proof.pop("as_of")
        return _hash({
            "contract": "ontology-rule-result/1", "ontology": self.ontology_digest,
            "rule": self.rule_name, "versions": dict(self.versions), "subject": asdict(self.subject),
            "status": self.status.value, "evidence": proof,
        })


def _dependencies(rules, name):
    selected = {}
    pending = [name]
    conditions = 0
    while pending:
        current = pending.pop()
        if current in selected:
            continue
        rule = rules[current]
        conditions += len(rule["conditions"])
        if conditions > MAX_CONDITIONS:
            return None
        selected[current] = rule
        pending.extend(rule.get("depends_on", ()))
    return selected


def _known(truth):
    return RuleStatus.SATISFIED if truth else RuleStatus.NOT_SATISFIED


def _combine(results, quantifier):
    # Keep affirmative and negative conclusions inside a complete, current input set.
    if RuleStatus.INSUFFICIENT in results:
        return RuleStatus.INSUFFICIENT
    matches = tuple(result == RuleStatus.SATISFIED for result in results)
    return _known(bool(matches) and all(matches) if quantifier == "all" else any(matches))


def _typed_value(value, definition):
    value = json_data(value)
    _value(value, definition, "Rule input")
    if value is None:
        return None
    if "unit" in definition:
        value = value["value"]
    convert = _CASTS.get(definition["type"])
    return convert(value) if convert is not None else value


class _Evaluation:
    def __init__(self, facts, connection, subject, definition, as_of, known_at):
        self.facts = facts
        self.connection = connection
        self.subject = subject
        self.definition = definition
        self.as_of = as_of
        self.known_at = known_at
        self.reads = {}
        self.collections = {}
        self.cursors = {}
        self.reasons = set()
        self.inputs = {}
        self.resources = set()

    def insufficient(self, reason):
        self.reasons.add(reason)
        return RuleStatus.INSUFFICIENT

    def _collect(self, collection, values, key):
        for value in values:
            identity = key(value)
            prior = collection.setdefault(identity, value)
            if prior != value:
                self.insufficient("evidence_changed_during_read")

    def _record(self, observation):
        self._collect(self.reads, observation.reads, lambda read: (read.kind, read.resource_id))
        self._collect(self.cursors, observation.source_cursors, lambda cursor: (cursor.source, cursor.stream))

    def _observe(self, key, read, *args, **options):
        if key not in self.inputs:
            if len(self.inputs) >= MAX_INPUTS:
                self.insufficient("input_limit")
                return None
            value = read(self.connection, *args, as_of=self.as_of, known_at=self.known_at, **options)
            if value is not None:
                self._record(value)
            self.inputs[key] = value
        return self.inputs[key]

    def fact(self, subject, name):
        field = FactField(subject, name)
        if name == "$exists":
            self.resources.add(("object", subject.object_id, None))
        elif name == "$state":
            self.resources.add(("metadata", subject.object_id, "state"))
        else:
            self.resources.add(("field", subject.object_id, name))
        return self._observe(field, self.facts.read_fact, field)

    def exists(self, subject):
        fact = self.fact(subject, "$exists")
        return fact is not None and fact.available and bool(fact.reads) and fact.value is True

    def state(self, subject, expected):
        fact = self.fact(subject, "$state")
        states = self.definition["types"][subject.object_type]["states"]
        if fact is None or not fact.available or not fact.reads or fact.value not in states:
            return self.insufficient("state_unavailable")
        return _known(fact.value == expected)

    def property(self, condition):
        name, operation = condition["property"], condition["operator"]
        fact = self.fact(self.subject, name)
        if fact is None or not fact.available or not fact.reads:
            return self.insufficient("property_unavailable")
        schema = self.definition["types"][self.subject.object_type]["properties"][name]
        try:
            actual = _typed_value(fact.value, schema)
            expected = _typed_value(condition["value"], schema)
        except (ValueError, TypeError):
            return self.insufficient("property_schema_mismatch")
        if actual is None and operation not in ("eq", "ne"):
            return self.insufficient("ordered_property_is_null")
        return _known(_COMPARISONS[operation](actual, expected))

    def relation(self, condition):
        name = condition["relation"]
        self.resources.add(("edge", self.subject.object_id, name))
        declaration = self.definition["relations"][name]
        target_type = declaration["target_type"]
        value = self._observe((self.subject, name), self.facts.read_relation, self.subject, name,
                              target_type=target_type, max_members=MAX_RELATION_MEMBERS)
        collection = value.collection if value is not None else None
        if collection is None:
            return self.insufficient("relationship_collection_unavailable")
        self._collect(self.collections, (collection,), lambda item: item.scope_digest)
        for target_id in getattr(value, "dependency_targets", ()):
            self.resources.add(("object", target_id, None))
        if not value.available or collection.coverage != Coverage.COMPLETE:
            return self.insufficient("relationship_collection_incomplete")
        members = collection.member_ids
        if len(members) > MAX_RELATION_MEMBERS:
            return self.insufficient("relationship_member_limit")
        bounds = declaration["targets_per_source"]
        if len(members) < bounds["min"] or (bounds["max"] is not None and len(members) > bounds["max"]):
            return self.insufficient("relationship_cardinality_violation")
        results = []
        for member_id in members:
            target = ObjectIdentity(self.subject.tenant, target_type, member_id)
            if not self.exists(target):
                results.append(self.insufficient("relationship_target_unavailable"))
            else:
                results.append(self.state(target, condition["target_state"]))
        # Both positive relationship quantifiers require at least one member.
        return _combine(results, condition.get("quantifier", "any"))

    def condition(self, condition):
        if "state" in condition:
            return self.state(self.subject, condition["state"])
        if "relation" in condition:
            return self.relation(condition)
        return self.property(condition)

    def read_set(self):
        return FactReadSet(
            self.subject.tenant, tuple(self.reads.values()), tuple(self.collections.values()), self.as_of,
            tuple(self.cursors.values()),
        )


class RuleEvaluator:
    """Evaluate a published ontology against same-transaction authoritative facts."""

    def __init__(self, facts):
        self.facts = facts

    def evaluate(self, connection, ontology, rule_name, subject, *, as_of=None, known_at=None):
        if (not isinstance(ontology, OntologyRelease) or not isinstance(subject, ObjectIdentity)
                or not isinstance(rule_name, str) or not rule_name.strip()):
            raise ValueError("A validated ontology, rule name, and canonical object identity are required")
        known_at = (datetime.fromtimestamp(connection.database_time(), timezone.utc)
                    if known_at is None else _utc(known_at))
        as_of = known_at if as_of is None else _utc(as_of)
        definition = ontology.to_document()
        rule = definition["rules"].get(rule_name)
        if rule is None or rule["object_type"] != subject.object_type:
            raise ValueError("The rule is unavailable for this object type")
        selected = _dependencies(definition["rules"], rule_name)
        evaluation = _Evaluation(self.facts, connection, subject, definition, as_of, known_at)
        versions = ((rule_name, rule["version"]),)
        status = RuleStatus.INSUFFICIENT
        conditions = []
        if selected is None:
            evaluation.insufficient("condition_limit")
        else:
            versions = tuple(sorted((name, item["version"]) for name, item in selected.items()))
            if evaluation.exists(subject):
                dependencies = {name: item.get("depends_on", []) for name, item in selected.items()}
                results = {}
                for name in TopologicalSorter(dependencies).static_order():
                    local = [evaluation.condition(condition) for condition in selected[name]["conditions"]]
                    conditions.extend((name, index, result) for index, result in enumerate(local))
                    results[name] = _combine(local + [results[dependency] for dependency in dependencies[name]], "all")
                status = results[rule_name]
            else:
                evaluation.insufficient("object_existence_unavailable")
        if evaluation.reasons:
            status = RuleStatus.INSUFFICIENT
        resources = tuple(sorted(evaluation.resources, key=lambda item: (item[0], item[1], item[2] or "")))
        return RuleResult(ontology.digest, definition["version"], rule_name, subject, status,
                          versions, evaluation.read_set(), tuple(sorted(evaluation.reasons)), resources, tuple(conditions))

    def is_current(self, connection, ontology, prior):
        """Only the originally satisfied decision and unchanged proof are eligible to execute."""
        if prior.status != RuleStatus.SATISFIED or prior.ontology_digest != ontology.digest:
            return False
        current = self.evaluate(connection, ontology, prior.rule_name, prior.subject)
        return current.status == RuleStatus.SATISFIED and current.fingerprint == prior.fingerprint
