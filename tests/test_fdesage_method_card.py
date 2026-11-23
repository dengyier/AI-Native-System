import json
import unittest
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

from ai_native_system.fdesage_method_card import intent_registry, intent_snapshot


VECTOR = Path(__file__).resolve().parents[1] / "fixtures/pilots/fdesage-method-card/golden-profile.json"


def sample_intent():
    vector = json.loads(VECTOR.read_text())
    target, = vector["operation"]["source_conditions"]["targets"]
    guard, = vector["operation"]["source_conditions"]["guards"]
    return {
        "id": guard["id"], "namespace": "fdesage-ops", "recordProfile": "fde-method-card-submission/1",
        "payloadVersion": 1, "cardId": 7, "cardKey": "合成方法卡", "cardRevision": 7,
        "nativeVersion": target["expected_version"], "contentDigest": vector["content_digest"],
        "submissionDigest": guard["expected_version"], "sourceEpoch": "test-method-source-epoch",
        "requester": {"userId": 7, "actor": "fde-user:7", "service": None, "delegationId": None},
        "expiresAt": 1800000900, "revokedAt": None, "operations": [],
        "sourceSnapshot": {
            "profile": "fdesage-method-card-intent-snapshot/1", "stream": "method-card-review:7",
            "snapshotRevision": 7, "bookmark": guard["expected_version"], "coverage": "selected_records",
            "capturedAt": "2027-01-15T08:00:00.000Z", "records": [
                {"recordType": "method_cards", "recordId": "7", "nativeVersion": target["expected_version"],
                 "sequence": 7, "state": "draft"},
                {"recordType": "method_card_submissions", "recordId": guard["id"],
                 "nativeVersion": guard["expected_version"], "sequence": 1, "state": "recorded"},
            ],
        },
    }


class FDEMethodIntentTests(unittest.TestCase):
    def test_only_source_declared_two_record_scope_supplies_versions_bookmark_and_capture_time(self):
        intent = sample_intent()
        snapshot = intent_snapshot(intent)
        self.assertEqual(snapshot.boundary.resume_cursor.token, intent["submissionDigest"])
        self.assertEqual(snapshot.boundary.resume_cursor.stream, "method-card-review:7")
        self.assertEqual(snapshot.position, 7)
        self.assertEqual(snapshot.boundary.finished_at, datetime(2027, 1, 15, 8, tzinfo=timezone.utc))
        self.assertEqual([event.version.sequence for event in snapshot.events], [7, 1])
        self.assertEqual([event.version.token for event in snapshot.events],
                         [intent["nativeVersion"], intent["submissionDigest"]])
        self.assertEqual({event.identity.source_type for event in snapshot.events},
                         {"method_cards", "method_card_submissions"})

    def test_missing_or_expanded_scope_coverage_or_native_version_cannot_be_promoted(self):
        cases = []
        for name, value in (("coverage", "complete"), ("snapshotRevision", 2), ("stream", "all-method-cards"),
                            ("bookmark", "0" * 64)):
            intent = sample_intent()
            intent["sourceSnapshot"][name] = value
            cases.append(intent)
        missing = sample_intent()
        del missing["sourceSnapshot"]
        cases.append(missing)
        extra = sample_intent()
        extra["sourceSnapshot"]["records"].append(deepcopy(extra["sourceSnapshot"]["records"][0]))
        cases.append(extra)
        wrong = sample_intent()
        wrong["sourceSnapshot"]["records"][0]["nativeVersion"] = "revision:8:sha256:" + wrong["contentDigest"]
        cases.append(wrong)
        for intent in cases:
            with self.subTest(intent=intent), self.assertRaises(ValueError):
                intent_snapshot(intent)

    def test_immutable_payload_version_is_not_card_revision_or_revocation_state(self):
        for change in ({"payloadVersion": 7}, {"recordProfile": "arbitrary"}, {"namespace": "another"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                intent_snapshot({**sample_intent(), **change})
        intent = sample_intent()
        intent["revokedAt"] = "2027-01-15T08:01:00.000Z"
        # The closed snapshot remains a historical payload; the source gate owns current revocation.
        self.assertEqual(intent_snapshot(intent).events[1].payload["state"], "recorded")

    def test_registered_action_binds_card_content_and_recorded_submission_without_a_second_approval(self):
        intent = sample_intent()
        registry = intent_registry(intent, reviewer_actor="fde-user:8")
        action = registry.actions["verify_method_card"]
        self.assertEqual(action["version"], "1")
        self.assertEqual(action["requires_properties"], {})
        self.assertEqual(action["requires_link_states"], {"submission": "recorded"})
        self.assertEqual(registry.applications["fde-method-card-verification"]["executor"], "fde-method-executor")
        actors = registry.seed["actors"]
        self.assertEqual(len(actors), 3)
        with self.assertRaises(ValueError):
            intent_registry(intent, reviewer_actor="fde-user:7")

    def test_new_intent_changes_native_data_while_application_ontology_and_rules_stay_fixed(self):
        original = sample_intent()
        later = deepcopy(original)
        later["id"] = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
        later["cardRevision"] = 8
        later["contentDigest"] = "9" * 64
        later["nativeVersion"] = "revision:8:sha256:" + later["contentDigest"]
        later["submissionDigest"] = "8" * 64
        later["sourceSnapshot"].update(snapshotRevision=8, bookmark=later["submissionDigest"], records=[
            {"recordType": "method_cards", "recordId": "7", "nativeVersion": later["nativeVersion"], "sequence": 8, "state": "draft"},
            {"recordType": "method_card_submissions", "recordId": later["id"], "nativeVersion": later["submissionDigest"], "sequence": 1, "state": "recorded"},
        ])
        first, second = [intent_registry(value, reviewer_actor="fde-user:8") for value in (original, later)]
        self.assertEqual(first.definition("fde-method-card-verification")[2], second.definition("fde-method-card-verification")[2])
        self.assertEqual(first.ontology().digest, second.ontology().digest)
        self.assertEqual(intent_snapshot(original).boundary.resume_cursor.stream, intent_snapshot(later).boundary.resume_cursor.stream)
        self.assertNotEqual(first.seed["objects"], second.seed["objects"])


if __name__ == "__main__":
    unittest.main()
