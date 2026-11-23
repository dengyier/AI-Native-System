"""Captured observations are immutable metadata objects, not invented source facts."""

import json
import tempfile
import unittest
from pathlib import Path

from ai_native_system.fdesage_readonly import (
    import_observation, observation_ontology, observation_registry, observation_row,
)
from ai_native_system.storage import database, initialize, object_data
from test_fdesage_readonly_capture import sample, scope


class ObservationProjectionTests(unittest.TestCase):
    def setUp(self):
        self.directory = self.enterContext(tempfile.TemporaryDirectory())
        self.path = Path(self.directory) / "observations.sqlite"
        initialize(self.path, observation_registry().seed)

    def test_projection_has_no_executable_application_action_or_model_and_preserves_native_unknowns(self):
        registry = observation_registry()
        self.assertEqual(registry.applications, {})
        self.assertEqual(registry.actions, {})
        row = observation_row("shadow-review", sample(), scope())
        registry.validate_object(row)
        observation_ontology().validate_object({key: value for key, value in row.items() if key != "links"})
        self.assertEqual(row["version"], 1)  # Local immutable record version, not a source stream sequence.
        self.assertEqual(row["state"], "captured")
        properties = row["properties"]
        self.assertEqual(properties["coverage"], "selected_object")
        self.assertEqual(properties["ontology_digest"], observation_ontology().digest)
        captured = json.loads(properties["snapshot_json"])
        self.assertIsNone(captured["sourceVersion"])
        self.assertIsNone(captured["streamPosition"])
        self.assertIsNone(captured["cursor"])
        self.assertEqual(captured["capturedAt"], sample()["capturedAt"])

    def test_identical_snapshot_import_is_idempotent_and_does_not_create_work(self):
        with database(self.path, write=True) as connection:
            first = import_observation(connection, "shadow-review", sample(), scope())
            second = import_observation(connection, "shadow-review", sample(), scope())
            self.assertEqual(first, second)
            self.assertEqual(connection.execute("SELECT count(*) FROM objects").fetchone()[0], 1)
            self.assertEqual(object_data(connection, "shadow-review", first),
                             observation_row("shadow-review", sample(), scope()))
            for table in ("tasks", "steps", "events", "effects", "remote_operations"):
                with self.subTest(table=table):
                    self.assertEqual(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0], 0)

    def test_a_later_capture_is_a_separate_historical_observation_and_never_updates_the_old_one(self):
        later = {**sample(), "capturedAt": "2026-11-24T01:03:03.000Z"}
        with database(self.path, write=True) as connection:
            first = import_observation(connection, "shadow-review", sample(), scope())
            second = import_observation(connection, "shadow-review", later, scope())
            self.assertNotEqual(first, second)
            self.assertEqual(connection.execute("SELECT count(*) FROM objects").fetchone()[0], 2)
            self.assertEqual(object_data(connection, "shadow-review", first)["properties"]["captured_at"],
                             sample()["capturedAt"])

    def test_existing_same_id_with_changed_metadata_is_rejected_instead_of_silently_accepted(self):
        with database(self.path, write=True) as connection:
            object_id = import_observation(connection, "shadow-review", sample(), scope())
            connection.execute("UPDATE objects SET state='forged' WHERE tenant=? AND id=?", ("shadow-review", object_id))
            with self.assertRaisesRegex(ValueError, "immutable"):
                import_observation(connection, "shadow-review", sample(), scope())

    def test_source_cannot_select_another_subject_or_smuggle_content_into_projection(self):
        tampered = sample()
        tampered["authorization"]["subjectUserId"] = "6"
        with database(self.path, write=True) as connection:
            for snapshot in (tampered, {**sample(), "markdown": "raw dialogue"}):
                with self.subTest(snapshot=snapshot), self.assertRaises(ValueError):
                    import_observation(connection, "shadow-review", snapshot, scope())
            self.assertEqual(connection.execute("SELECT count(*) FROM objects").fetchone()[0], 0)

    def test_checked_in_contract_declarations_equal_the_runtime_projection(self):
        root = Path(__file__).resolve().parents[1] / "fixtures" / "pilots" / "fdesage-readonly"
        registry = json.loads((root / "registry.json").read_text())
        expected = observation_registry()
        self.assertEqual(registry, {"applications": expected.applications, "actions": expected.actions,
                                   "types": expected.types, "seed": expected.seed})
        self.assertEqual(json.loads((root / "ontology.json").read_text()), observation_ontology().to_document())


if __name__ == "__main__":
    unittest.main()
