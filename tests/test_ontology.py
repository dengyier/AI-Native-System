import unittest
from copy import deepcopy
from pathlib import Path

from ai_native_system.ontology import OntologyRelease
from ai_native_system.registry import Registry


ROOT = Path(__file__).resolve().parents[1]


def object_row(identifier, object_type, state, properties):
    return {"tenant": "demo", "id": identifier, "type": object_type, "state": state,
            "version": 1, "properties": properties}


class OntologyTests(unittest.TestCase):
    def setUp(self):
        self.document = {
            "namespace": "specimen-catalog", "version": 1,
            "types": {
                "sample": {"states": ["prepared", "archived"], "properties": {
                    "mass": {"type": "decimal", "unit": "g", "precision": 5, "scale": 2},
                    "label": {"type": "string", "nullable": True},
                    "form": {"type": "string", "enum": ["solid", "liquid"], "required": False},
                }},
                "batch": {"states": ["open"], "properties": {}},
            },
            "relations": {"belongs_to": {
                "source_type": "sample", "target_type": "batch", "direction": "directed",
                "targets_per_source": {"min": 1, "max": 2},
                "sources_per_target": {"min": 0, "max": 2},
                "properties": {"note": {"type": "string", "required": False}},
            }},
            "rules": {"positive_mass": {
                "object_type": "sample", "version": 1, "conditions": [
                    {"property": "mass", "operator": "gt", "value": {"value": "0.00", "unit": "g"}},
                ],
            }},
            "events": {"sample_archived": {"object_type": "sample", "version": 1,
                                            "properties": {"date": {"type": "date"}}}},
        }
        self.a = object_row("a", "sample", "prepared", {"mass": {"value": "2.10", "unit": "g"}, "label": None})
        self.b = object_row("b", "sample", "prepared", {"mass": {"value": "3.00", "unit": "g"}, "label": "Sample"})
        self.x = object_row("x", "batch", "open", {})
        self.y = object_row("y", "batch", "open", {})

    def edge(self, source, target, **extra):
        return {"tenant": "demo", "id": f"{source}-{target}", "type": "belongs_to", "source_id": source,
                "target_id": target, "properties": {"note": "linked"}, **extra}

    def test_same_metamodel_accepts_a_second_domain_and_fingerprints_release(self):
        release = OntologyRelease.from_document(self.document)
        second = OntologyRelease.from_document({
            "namespace": "translation-catalog", "version": "2026.1",
            "types": {"translation": {"states": ["draft", "approved"], "properties": {
                "language": {"type": "string", "enum": ["zh", "en"]},
                "received_at": {"type": "datetime"},
            }}},
        })
        second.validate_object(object_row("translation-1", "translation", "draft", {
            "language": "zh", "received_at": "2026-11-16T20:00:00+08:00",
        }))
        self.assertNotEqual(release.digest, second.digest)
        exported = release.to_document()
        self.assertEqual(OntologyRelease.from_document(exported).digest, release.digest)
        exported["types"].clear()
        release.validate_object(self.a)

    def test_units_precision_enum_and_missing_are_distinct_from_null(self):
        release = OntologyRelease.from_document(self.document)
        release.validate_object(self.a)
        invalid = [
            {"mass": {"value": "2.10", "unit": "kg"}, "label": None},
            {"mass": {"value": "2.103", "unit": "g"}, "label": None},
            {"mass": {"value": "2000", "unit": "g"}, "label": None},
            {"mass": {"value": "2.10", "unit": "g"}},
            {**self.a["properties"], "form": None},
            {**self.a["properties"], "form": "gas"},
        ]
        for props in invalid:
            with self.subTest(props=props), self.assertRaises(ValueError):
                release.validate_object({**self.a, "properties": props})

    def test_many_to_many_and_both_cardinality_bounds(self):
        release = OntologyRelease.from_document(self.document)
        objects = [self.a, self.b, self.x, self.y]
        edges = [self.edge(a, b) for a in ("a", "b") for b in ("x", "y")]
        release.validate_snapshot(objects, edges)
        with self.assertRaisesRegex(ValueError, "cardinality"):
            release.validate_snapshot(objects, edges[:2])
        third = object_row("z", "batch", "open", {})
        with self.assertRaisesRegex(ValueError, "cardinality"):
            release.validate_snapshot([*objects, third], [*edges, self.edge("a", "z")])
        third_sample = {**self.a, "id": "c"}
        with self.assertRaisesRegex(ValueError, "cardinality"):
            release.validate_snapshot([*objects, third_sample], [*edges, self.edge("c", "x")])
        invalid_definition = deepcopy(self.document)
        invalid_definition["relations"]["belongs_to"]["targets_per_source"] = {"min": 3, "max": 2}
        with self.assertRaises(ValueError):
            OntologyRelease.from_document(invalid_definition)

    def test_relation_endpoint_visibility_and_time_window(self):
        release = OntologyRelease.from_document(self.document)
        with self.assertRaises(ValueError):
            release.validate_relation(self.edge("x", "a"), self.x, self.a)
        with self.assertRaises(ValueError):
            release.validate_relation(self.edge("a", "x"), self.a, {**self.x, "tenant": "other"})
        edge = self.edge("a", "x", valid_from="2026-01-01T00:00:00Z", valid_to="2027-01-01T00:00:00Z")
        release.validate_snapshot([self.a, self.x], [edge], as_of="2026-11-16T00:00:00Z")
        with self.assertRaisesRegex(ValueError, "cardinality"):
            release.validate_snapshot([self.a, self.x], [edge], as_of="2027-01-01T00:00:00Z")
        with self.assertRaises(ValueError):
            release.validate_snapshot([self.a, self.x], [edge])

    def test_rules_reject_inconsistent_units_unknown_properties_and_cycles(self):
        for field, value in (("value", {"value": "0.00", "unit": "kg"}), ("property", "unknown")):
            invalid = deepcopy(self.document)
            invalid["rules"]["positive_mass"]["conditions"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                OntologyRelease.from_document(invalid)
        invalid = deepcopy(self.document)
        rule = invalid["rules"]["positive_mass"]
        rule["depends_on"] = ["second"]
        invalid["rules"]["second"] = {**rule, "depends_on": ["positive_mass"]}
        with self.assertRaisesRegex(ValueError, "cycle"):
            OntologyRelease.from_document(invalid)

    def test_event_instances_and_explicit_relation_quantifier(self):
        event = {"tenant": "demo", "id": "event-1", "type": "sample_archived", "object_id": "a",
                 "occurred_at": "2026-11-16T20:00:00+08:00", "recorded_at": "2026-11-17T00:00:00+08:00",
                 "properties": {"date": "2026-11-16"}}
        release = OntologyRelease.from_document(self.document)
        release.validate_event(event, self.a)
        with self.assertRaises(ValueError):
            release.validate_event({**event, "recorded_at": "2026-11-17T00:00:00"}, self.a)
        with self.assertRaises(ValueError):
            release.validate_event(event, self.x)

        condition = {"relation": "belongs_to", "target_state": "open"}
        self.document["rules"]["positive_mass"]["conditions"].append(condition)
        with self.assertRaisesRegex(ValueError, "quantifier"):
            OntologyRelease.from_document(self.document)
        condition["quantifier"] = "all"
        OntologyRelease.from_document(self.document)

    def test_actions_reference_declared_semantics(self):
        action = {"kind": "read", "version": 1, "target_type": "sample", "read_fields": ["mass"],
                  "read_relations": ["belongs_to"], "preconditions": ["positive_mass"]}
        self.document["actions"] = {"inspect_sample": action}
        OntologyRelease.from_document(self.document)
        for field, unknown in (("target_type", "unknown"), ("read_fields", ["unknown"]),
                               ("read_relations", ["unknown"]), ("preconditions", ["unknown"])):
            with self.subTest(field=field), self.assertRaises(ValueError):
                OntologyRelease.from_document({**self.document, "actions": {"inspect_sample": {**action, field: unknown}}})

    def test_release_metadata_and_malformed_definitions(self):
        release = OntologyRelease.from_document(self.document)
        dependency = {"namespace": "common", "version": "1.0", "digest": release.digest}
        self.document.update(compatibility="compatible", publisher={"tenant": "demo", "actor": "owner"},
                             dependencies=[dependency])
        tagged = OntologyRelease.from_document(self.document)
        self.assertNotEqual(release.digest, tagged.digest)
        for change in ({"dependencies": [dependency, dependency]}, {"dependencies": [{**dependency, "digest": "bad"}]},
                       {"publisher": {"tenant": "demo"}}, {"compatibility": []}, {"schema_version": 99}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                OntologyRelease.from_document({**self.document, **change})
        for field, value in (("type", []), ("enum", [{}]), ("nullable", 1)):
            malformed = deepcopy(self.document)
            malformed["types"]["sample"]["properties"]["label"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                OntologyRelease.from_document(malformed)

    def test_legacy_projection_preserves_current_executable_fingerprint(self):
        registry = Registry.load(ROOT / "fixtures/conformance.json")
        before = registry.definition("collaboration")[2]
        release = registry.ontology()
        self.assertEqual(registry.definition("collaboration")[2], before)
        rule = release.to_document()["rules"]["publish_artifact"]
        self.assertIn({"relation": "artifact.source", "target_state": "verified"}, rule["conditions"])
        self.assertEqual(registry.seed["objects"][2]["links"], {"source": "asset-1"})
