"""Versioned domain declarations and validation of complete fact snapshots."""

import hashlib
import json
import math
import re
from collections import Counter
from copy import deepcopy
from datetime import date, datetime
from graphlib import CycleError, TopologicalSorter
from pathlib import Path


_NUMERIC = ("integer", "number", "decimal")
_VALUE_TYPES = (*_NUMERIC, "string", "boolean", "date", "datetime")


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _name(value):
    return isinstance(value, str) and bool(value.strip())


def _version(value):
    return (type(value) is int and value > 0) or _name(value)


def _mapping(value, label):
    _require(isinstance(value, dict) and all(map(_name, value)), f"{label} must be an object with named keys")
    return value


def _shape(value, label, required, optional=()):
    _mapping(value, label)
    _require(value.keys() >= set(required) and value.keys() <= set(required) | set(optional),
             f"Invalid fields for {label}")


def _json_object(pairs):
    obj = dict(pairs)
    _require(len(obj) == len(pairs), "Duplicate JSON key in ontology release")
    return obj


def _names(value, label):
    _require(isinstance(value, list) and all(map(_name, value)) and len(value) == len(set(value)),
             f"{label} must be a list of distinct names")


def _instant(value):
    _require(isinstance(value, str) and "T" in value, "Expected ISO 8601 datetime with an offset")
    result = datetime.fromisoformat(value)
    _require(result.utcoffset() is not None, "Expected ISO 8601 datetime with an offset")
    return result


def _scalar(value, definition):
    kind = definition["type"]
    if kind == "number":
        return type(value) is int or (type(value) is float and math.isfinite(value))
    if kind == "decimal":
        if not isinstance(value, str) or not re.fullmatch(r"[+-]?[0-9]+(?:\.[0-9]+)?", value):
            return False
        whole, _, fraction = value.lstrip("+-").partition(".")
        return (len(fraction) <= definition["scale"]
                and len(whole.lstrip("0")) <= definition["precision"] - definition["scale"])
    if kind in ("date", "datetime"):
        if not isinstance(value, str):
            return False
        try:
            return date.fromisoformat(value).isoformat() == value if kind == "date" else _instant(value) is not None
        except ValueError:
            return False
    return type(value) is {"integer": int, "string": str, "boolean": bool}[kind]


def _value(value, definition, label, *, check_enum=True):
    if value is None:
        _require(definition.get("nullable", False), f"{label} cannot be null")
        return
    scalar = value
    if "unit" in definition:
        _shape(value, label, ("value", "unit"))
        _require(value["unit"] == definition["unit"], f"{label} must use unit {definition['unit']!r}")
        scalar = value["value"]
    _require(_scalar(scalar, definition), f"{label} must be a valid {definition['type']}")
    if check_enum and "enum" in definition:
        _require(value in definition["enum"], f"{label} is outside its enum")


def _property_definitions(definitions):
    for name, definition in _mapping(definitions, "Property definitions").items():
        _shape(definition, name, ("type",), ("unit", "precision", "scale", "required", "nullable", "enum", "sensitive"))
        kind = definition["type"]
        _require(kind in _VALUE_TYPES, f"Unknown property type for {name!r}")
        for flag in ("required", "nullable", "sensitive"):
            _require(flag not in definition or type(definition[flag]) is bool, f"{name}.{flag} must be boolean")
        _require("unit" not in definition or (kind in _NUMERIC and _name(definition["unit"])),
                 f"Unit requires a numeric property: {name!r}")
        if kind == "decimal":
            precision, scale = definition.get("precision"), definition.get("scale")
            _require(type(precision) is int and type(scale) is int and precision > 0 and 0 <= scale <= precision,
                     f"Decimal property {name!r} requires valid precision and scale")
        else:
            _require("precision" not in definition and "scale" not in definition, f"{name!r} is not decimal")
        if "enum" in definition:
            choices = definition["enum"]
            _require(isinstance(choices, list) and bool(choices), f"{name}.enum must be a nonempty list")
            for index, choice in enumerate(choices):
                _require(choice is not None and choice not in choices[:index], f"Invalid enum value for {name!r}")
                _value(choice, definition, name, check_enum=False)


def _properties(values, definitions):
    _mapping(values, "Properties")
    required = {name for name, definition in definitions.items() if definition.get("required", True)}
    _require(required <= values.keys() <= definitions.keys(), "Missing required property or unknown property")
    for name, value in values.items():
        _value(value, definitions[name], name)


def _bounds(bounds):
    _shape(bounds, "cardinality", ("min", "max"))
    lower, upper = bounds["min"], bounds["max"]
    _require(type(lower) is int and lower >= 0 and (upper is None or type(upper) is int and upper >= lower),
             "Invalid relation cardinality")


def _lookup(items, name, label):
    _require(_name(name) and name in items, f"Unknown {label} {name!r}")
    return items[name]


def _rule_definitions(rules, types, relations):
    for name, rule in rules.items():
        _shape(rule, f"rule {name!r}", ("version", "object_type", "conditions"), ("depends_on",))
        _require(_version(rule["version"]), f"Invalid rule version for {name!r}")
        subject = _lookup(types, rule["object_type"], "rule object type")
        conditions = rule["conditions"]
        _require(isinstance(conditions, list) and bool(conditions), f"Rule {name!r} requires conditions")
        _names(rule.get("depends_on", []), f"Rule {name!r} dependencies")
        for condition in conditions:
            _mapping(condition, "Rule condition")
            if condition.keys() == {"state"}:
                _require(condition["state"] in subject["states"], "Unknown rule state")
            elif condition.keys() in ({"relation", "target_state"}, {"relation", "target_state", "quantifier"}):
                relation = _lookup(relations, condition["relation"], "rule relation")
                _require(relation["source_type"] == rule["object_type"]
                         and condition["target_state"] in types[relation["target_type"]]["states"],
                         "Rule relation does not match its declared source and target state")
                if "quantifier" in condition or relation["targets_per_source"]["max"] != 1:
                    _require(condition.get("quantifier") in ("any", "all"), "Relation condition requires an any/all quantifier")
            else:
                _shape(condition, "Property condition", ("property", "operator", "value"))
                prop = _lookup(subject["properties"], condition["property"], "rule property")
                operator = condition["operator"]
                if operator not in ("eq", "ne"):
                    _require(operator in ("gt", "ge", "lt", "le") and condition["value"] is not None
                             and prop["type"] in (*_NUMERIC, "date", "datetime"), "Invalid ordered rule comparison")
                _value(condition["value"], prop, condition["property"])
    for rule in rules.values():
        for dependency in rule.get("depends_on", []):
            _require(_lookup(rules, dependency, "rule dependency")["object_type"] == rule["object_type"],
                     "Rule dependency requires the same object type")
    try:
        TopologicalSorter({name: rule.get("depends_on", []) for name, rule in rules.items()}).prepare()
    except CycleError as error:
        raise ValueError("Rule dependency cycle") from error


def _release_metadata(definition):
    if "compatibility" in definition:
        _require(definition["compatibility"] in ("initial", "compatible", "breaking"), "Invalid compatibility class")
    if "publisher" in definition:
        publisher = definition["publisher"]
        _shape(publisher, "publisher", ("tenant", "actor"))
        _require(all(map(_name, publisher.values())), "Publisher requires tenant and actor")
    dependencies = definition.get("dependencies", [])
    _require(isinstance(dependencies, list), "Release dependencies must be a list")
    seen = {(definition["namespace"], definition["version"])}
    for dependency in dependencies:
        _shape(dependency, "release dependency", ("namespace", "version", "digest"))
        namespace, version, digest = dependency["namespace"], dependency["version"], dependency["digest"]
        _require(_name(namespace) and _version(version) and isinstance(digest, str)
                 and re.fullmatch(r"[0-9a-f]{64}", digest), "Invalid release dependency")
        reference = (namespace, version)
        _require(reference not in seen, "Duplicate or self-referencing release dependency")
        seen.add(reference)


class OntologyRelease:
    """A validated and fingerprinted domain release with independent instance validation."""

    def __init__(self, document):
        _shape(document, "Ontology release", ("namespace", "version", "types"),
               ("schema_version", "relations", "rules", "events", "actions", "compatibility", "publisher", "dependencies"))
        definition = deepcopy(document)
        _require(_name(definition["namespace"]) and _version(definition["version"]), "Invalid ontology namespace or version")
        schema_version = definition.setdefault("schema_version", 1)
        _require(type(schema_version) is int and schema_version == 1, "Unsupported ontology schema version")
        _release_metadata(definition)
        types = _mapping(definition["types"], "Object types")
        for name, obj in types.items():
            _shape(obj, f"type {name!r}", ("states", "properties"))
            _names(obj["states"], f"{name} states")
            _require(bool(obj["states"]), f"Type {name!r} requires at least one state")
            _property_definitions(obj["properties"])

        relations = _mapping(definition.setdefault("relations", {}), "Relation types")
        for name, relation in relations.items():
            _shape(relation, f"relation {name!r}",
                   ("source_type", "target_type", "direction", "targets_per_source", "sources_per_target"), ("properties",))
            _lookup(types, relation["source_type"], "relation source type")
            _lookup(types, relation["target_type"], "relation target type")
            _require(relation["direction"] in ("directed", "bidirectional"), "Invalid relation direction")
            _bounds(relation["targets_per_source"])
            _bounds(relation["sources_per_target"])
            _property_definitions(relation.setdefault("properties", {}))

        rules = _mapping(definition.setdefault("rules", {}), "Rule definitions")
        _rule_definitions(rules, types, relations)
        for name, event in _mapping(definition.setdefault("events", {}), "Events").items():
            _shape(event, f"event {name!r}", ("version", "object_type", "properties"))
            _require(_version(event["version"]), f"Invalid event version for {name!r}")
            _lookup(types, event["object_type"], "event object type")
            _property_definitions(event["properties"])
        actions = _mapping(definition.setdefault("actions", {}), "Actions")
        if actions:
            from .contracts import ActionDefinition

            for name, declaration in actions.items():
                action = ActionDefinition.from_document(name, declaration)
                if action.target_type is not None:
                    target = _lookup(types, action.target_type, "action target type")
                    field_names = {*target["properties"], "state"}
                    _require(set((*action.read_fields, *action.write_fields)) <= field_names, "Unknown action target field")
                for relation_name in (*action.read_relations, *action.write_relations):
                    relation = _lookup(relations, relation_name, "action relation")
                    _require(action.target_type in (relation["source_type"], relation["target_type"]),
                             "Action relation does not connect to target type")
                for rule_name in (*action.preconditions, *action.postconditions):
                    rule = _lookup(rules, rule_name, "action rule")
                    _require(action.target_type == rule["object_type"], "Action rule does not match target type")

        self._document = definition
        canonical = json.dumps(definition, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        self._digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @classmethod
    def from_document(cls, document):
        return cls(document)

    @classmethod
    def load(cls, path):
        return cls(json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=_json_object))

    @property
    def digest(self):
        return self._digest

    def to_document(self):
        return deepcopy(self._document)

    def validate_object(self, obj):
        _shape(obj, "ontology object", ("tenant", "id", "type", "state", "version", "properties"))
        _require(_name(obj["tenant"]) and _name(obj["id"]), "Object requires tenant and ID")
        _require(type(obj["version"]) is int and obj["version"] > 0, "Object version must be a positive integer")
        definition = _lookup(self._document["types"], obj["type"], "object type")
        _require(obj["state"] in definition["states"], "Unknown object state")
        _properties(obj["properties"], definition["properties"])

    def _relation(self, edge):
        _shape(edge, "ontology relation", ("tenant", "id", "type", "source_id", "target_id", "properties"),
               ("valid_from", "valid_to"))
        _require(all(_name(edge[key]) for key in ("tenant", "id", "source_id", "target_id")), "Relation requires named identities")
        definition = _lookup(self._document["relations"], edge["type"], "relation type")
        _properties(edge["properties"], definition["properties"])
        start, end = (_instant(edge[key]) if edge.get(key) is not None else None for key in ("valid_from", "valid_to"))
        _require(start is None or end is None or start < end, "Relation validity interval is empty or reversed")
        return definition, start, end

    @staticmethod
    def _endpoints(edge, definition, source, target):
        for endpoint, side in ((source, "source"), (target, "target")):
            _require(endpoint is not None and endpoint["tenant"] == edge["tenant"]
                     and endpoint["id"] == edge[f"{side}_id"] and endpoint["type"] == definition[f"{side}_type"],
                     f"Relation {side} endpoint does not match tenant, ID and type")

    def validate_relation(self, edge, source, target):
        self.validate_object(source)
        self.validate_object(target)
        definition, _, _ = self._relation(edge)
        self._endpoints(edge, definition, source, target)

    def validate_event(self, event, obj):
        self.validate_object(obj)
        _shape(event, "ontology event", ("tenant", "id", "type", "object_id", "occurred_at", "recorded_at", "properties"))
        definition = _lookup(self._document["events"], event["type"], "event type")
        _require(_name(event["id"]) and event["tenant"] == obj["tenant"] and event["object_id"] == obj["id"]
                 and definition["object_type"] == obj["type"], "Event object does not match tenant, ID and type")
        _instant(event["occurred_at"])
        _instant(event["recorded_at"])
        _properties(event["properties"], definition["properties"])

    def validate_snapshot(self, objects, relations, *, as_of=None):
        """Validate all supplied instances and cardinalities over the complete snapshot."""
        observation = _instant(as_of) if as_of is not None else None
        indexed = {}
        for obj in objects:
            self.validate_object(obj)
            key = (obj["tenant"], obj["id"])
            _require(key not in indexed, f"Duplicate ontology object {key!r}")
            indexed[key] = obj
        identities, pairs = set(), set()
        counts = {"source": Counter(), "target": Counter()}
        for edge in relations:
            definition, start, end = self._relation(edge)
            tenant, name = edge["tenant"], edge["type"]
            source = (tenant, edge["source_id"])
            target = (tenant, edge["target_id"])
            self._endpoints(edge, definition, indexed.get(source), indexed.get(target))
            identity = (tenant, edge["id"])
            _require(identity not in identities, f"Duplicate ontology relation {identity!r}")
            identities.add(identity)
            if start is not None or end is not None:
                _require(observation is not None, "Temporal relations require an as_of instant")
                if (start is not None and observation < start) or (end is not None and observation >= end):
                    continue
            pair = (name, source, target)
            _require(pair not in pairs, f"Duplicate active relation pair for {name!r}")
            pairs.add(pair)
            counts["source"][name, source] += 1
            counts["target"][name, target] += 1
        for name, relation in self._document["relations"].items():
            for side, bounds_key in (("source", "targets_per_source"), ("target", "sources_per_target")):
                bounds = relation[bounds_key]
                for key, obj in indexed.items():
                    if obj["type"] == relation[f"{side}_type"]:
                        count = counts[side][name, key]
                        _require(count >= bounds["min"] and (bounds["max"] is None or count <= bounds["max"]),
                                 f"Invalid {side} cardinality for {name!r} on {key!r}")
