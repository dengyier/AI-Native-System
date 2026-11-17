import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone

from ai_native_system.fact_contracts import (
    Capability, ChangeKind, CollectionKind, CollectionRead, ConnectorCapabilities,
    ConnectorContract, Coverage, EvidenceRef, EvidenceRevocation, FactAssertion,
    FactChange, FactConflict, FactField, FactFreshness, FactOrigin, FactQuality,
    FactRead, FactReadSet, FieldAuthority, IdentityChange, IdentityChangeKind,
    IdentityMapping, ObjectIdentity, ReadKind, SnapshotBoundary, SourceCursor,
    SourceEvent, SourceIdentity, SourceVersion, canonical_json,
)


class FactContractTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 11, 17, 1, tzinfo=timezone.utc)
        self.source_a = SourceIdentity("tenant", "inventory", "asset", "same-id")
        self.source_b = SourceIdentity("tenant", "catalog", "record", "same-id")
        self.asset = ObjectIdentity("tenant", "asset", "asset-1")
        self.field = FactField(self.asset, "measured_capacity")
        self.cursor = SourceCursor("tenant", "inventory", "changes", "epoch-1", "cursor-10")

    def test_cross_source_ids_keep_distinct_mappings_and_explicit_merge_split_history(self):
        other_asset = replace(self.asset, object_id="asset-2")
        first = IdentityMapping(self.source_a, self.asset, 1, self.now)
        second = IdentityMapping(self.source_b, other_asset, 1, self.now)
        source_index = {mapping.source: mapping.target for mapping in (first, second)}
        self.assertEqual(len(source_index), 2)
        self.assertNotEqual(source_index[self.source_a], source_index[self.source_b])

        merged_at = self.now + timedelta(minutes=1)
        moved = replace(second, target=self.asset, revision=2, recorded_at=merged_at)
        merge = IdentityChange("merge-1", IdentityChangeKind.MERGE, (second, first), (first, moved), merged_at)
        self.assertIn(second, merge.before)
        self.assertIn(moved, merge.after)
        split_at = merged_at + timedelta(minutes=1)
        restored = replace(second, revision=3, recorded_at=split_at)
        split = IdentityChange("split-1", "split", merge.after, (first, restored), split_at)
        self.assertEqual({mapping.target for mapping in split.after}, {self.asset, other_asset})
        with self.assertRaisesRegex(ValueError, "new mapping revision"):
            replace(merge, after=(first, replace(moved, revision=1)))
        with self.assertRaisesRegex(ValueError, "cross tenants"):
            replace(second, target=replace(other_asset, tenant="other"))

    def test_only_versions_in_the_same_order_domain_compare(self):
        current = SourceVersion(self.source_a, "epoch-1", "etag-z", 3)
        newer = SourceVersion(self.source_a, "epoch-1", "etag-a", 4)
        self.assertEqual(current.compare(newer), -1)
        self.assertEqual(current.compare(current), 0)
        self.assertIsNone(current.compare(replace(newer, sequence=None)))
        self.assertIsNone(current.compare(replace(newer, sequence=3)))
        self.assertIsNone(current.compare(replace(newer, epoch="epoch-2")))
        self.assertIsNone(current.compare(replace(newer, identity=self.source_b)))

    def test_assertion_keeps_both_times_and_conflicting_provenance(self):
        value = {"value": 3, "unit": "GB", "tags": ["declared"]}
        assertion = FactAssertion("capacity-1", 1, self.field, FactOrigin.SOURCE, value, self.now,
                                  source=self.source_a, valid_from=self.now - timedelta(days=10),
                                  fresh_until=self.now + timedelta(minutes=1), conflict=FactConflict.CONFLICTING)
        value["tags"].append("mutated")
        self.assertEqual(assertion.value["tags"], ("declared",))
        self.assertLess(assertion.valid_from, assertion.recorded_at)
        self.assertEqual(assertion.freshness_at(self.now), FactFreshness.FRESH)
        self.assertEqual(assertion.freshness_at(assertion.fresh_until), FactFreshness.STALE)
        self.assertEqual(assertion.freshness_at(assertion.valid_from), FactFreshness.UNKNOWN)
        self.assertEqual(assertion.conflict, FactConflict.CONFLICTING)
        authority = FieldAuthority(self.field, ("inventory",), 1)
        self.assertEqual(authority.source_names, (assertion.source.source,))
        with self.assertRaisesRegex(ValueError, "source record"):
            replace(assertion, source_version=SourceVersion(self.source_b, "epoch-1", "1"))
        with self.assertRaisesRegex(ValueError, "same tenant"):
            replace(assertion, source=replace(self.source_a, tenant="other"))
        with self.assertRaisesRegex(ValueError, "follow start"):
            replace(assertion, valid_to=assertion.valid_from)

    def test_imports_and_model_claims_do_not_gain_provenance_or_verification(self):
        imported = FactAssertion("old-snapshot", 1, self.field, "imported_snapshot", None, self.now)
        self.assertIsNone(imported.source)
        self.assertIsNone(imported.valid_from)
        self.assertEqual(imported.freshness_at(self.now), FactFreshness.UNKNOWN)
        with self.assertRaisesRegex(ValueError, "requires provenance"):
            replace(imported, origin=FactOrigin.SOURCE)
        with self.assertRaisesRegex(ValueError, "model output"):
            replace(imported, origin=FactOrigin.MODEL_CANDIDATE, quality=FactQuality.VERIFIED)
        with self.assertRaises(ValueError):
            replace(imported, origin=FactOrigin.HUMAN_CORRECTION)
        corrected = replace(imported, origin=FactOrigin.HUMAN_CORRECTION,
                            authorization_ref="review-1", correction_reason="Checked the actual capacity")
        self.assertEqual(corrected.authorization_ref, "review-1")

    def test_connector_capability_unknown_and_retention_are_explicit(self):
        connector = ConnectorContract("tenant", "inventory", 1)
        self.assertEqual(connector.capabilities.conditional_write, Capability.UNKNOWN)
        with self.assertRaises(ValueError):
            replace(connector, idempotency_window_seconds=60)
        with self.assertRaisesRegex(ValueError, "key scope"):
            replace(connector, capabilities=ConnectorCapabilities(idempotency="supported"))
        declared = replace(connector, capabilities=ConnectorCapabilities(idempotency="supported",
                                deletion="unsupported", result_lookup="supported"),
                           idempotency_scope="operation-id", idempotency_window_seconds=60)
        self.assertEqual(declared.capabilities.deletion, Capability.UNSUPPORTED)
        self.assertIsNone(declared.result_lookup_window_seconds)

    def test_cursor_epoch_and_snapshot_completion_are_checked(self):
        ongoing = SnapshotBoundary("tenant", "inventory", "snap-1", "epoch-1", self.now,
                                   resume_cursor=self.cursor)
        self.assertEqual(ongoing.coverage, Coverage.UNKNOWN)
        with self.assertRaisesRegex(ValueError, "unfinished snapshot"):
            replace(ongoing, coverage=Coverage.COMPLETE)
        with self.assertRaisesRegex(ValueError, "source epoch"):
            replace(ongoing, resume_cursor=replace(self.cursor, epoch="epoch-2"))
        finished = replace(ongoing, coverage=Coverage.COMPLETE, finished_at=self.now + timedelta(seconds=1))
        self.assertEqual(finished.resume_cursor, self.cursor)

    def test_source_event_delivery_metadata_does_not_hide_content_conflicts(self):
        version = SourceVersion(self.source_a, self.cursor.epoch, "etag-10", 10)
        event = SourceEvent("event-1", self.source_a, ChangeKind.UPSERT, self.now,
                            {"capacity": 3}, version, self.cursor, operation_id="operation-1")
        retry = replace(event, received_at=self.now + timedelta(seconds=5),
                        cursor=replace(self.cursor, token="retry-delivery-cursor"))
        self.assertEqual(event.dedupe_key, retry.dedupe_key)
        self.assertEqual(event.content_digest, retry.content_digest)
        altered = replace(event, payload={"capacity": 8})
        self.assertEqual(event.dedupe_key, altered.dedupe_key)
        self.assertNotEqual(event.content_digest, altered.content_digest)
        self.assertNotEqual(event.dedupe_key, replace(event, identity=self.source_b,
                                                        version=None, cursor=None).dedupe_key)
        deletion = replace(event, kind=ChangeKind.DELETE, payload=None)
        self.assertIsNone(deletion.payload)
        with self.assertRaisesRegex(ValueError, "tombstone"):
            replace(event, kind=ChangeKind.DELETE)
        with self.assertRaisesRegex(ValueError, "epoch"):
            replace(event, cursor=replace(self.cursor, epoch="epoch-2"))
        unversioned = replace(event, version=None)
        reset_source = replace(unversioned, cursor=replace(self.cursor, epoch="epoch-2"))
        self.assertNotEqual(unversioned.content_digest, reset_source.content_digest)

    def test_fact_changes_and_evidence_revocations_preserve_reference_identity(self):
        reference = EvidenceRef("tenant", "evidence-1", 2, self.source_b, "section:3", "digest", self.now,
                                ("reviewer",))
        revocation = EvidenceRevocation("revoke-1", reference.tenant, reference.evidence_id,
                                        reference.revision, self.now + timedelta(days=1), "Source withdrawn")
        withdrawn = replace(reference, revoked_at=revocation.revoked_at)
        self.assertEqual((withdrawn.evidence_id, withdrawn.revision),
                         (revocation.evidence_id, revocation.revision))
        change = FactChange("fact-1", self.field, 3, ChangeKind.DELETE, self.now, "op-1")
        self.assertEqual(change.field.subject, self.asset)
        with self.assertRaisesRegex(ValueError, "same tenant"):
            replace(reference, tenant="other")

    def test_read_set_changes_when_members_change_with_identical_object_reads(self):
        read = FactRead("tenant", ReadKind.OBJECT, "asset-1", 3)
        scope = {"origin": "asset-1", "relation": "connected-to", "direction": "out"}
        members = CollectionRead("tenant", CollectionKind.RELATIONSHIP, scope, 1, ("edge-1", "edge-2"),
                                 Coverage.COMPLETE)
        initial = FactReadSet("tenant", (read,), (members,), self.now, (self.cursor,))
        added = replace(initial, collections=(replace(members, member_ids=("edge-1", "edge-2", "edge-3")),))
        self.assertEqual(initial.reads, added.reads)
        self.assertNotEqual(initial.digest, added.digest)
        for adjusted in (replace(members, revision=2), replace(members, coverage=Coverage.PARTIAL),
                         replace(members, scope={**scope, "direction": "in"})):
            self.assertNotEqual(initial.digest, replace(initial, collections=(adjusted,)).digest)
        advanced = replace(initial, source_cursors=(replace(self.cursor, token="next"),))
        self.assertNotEqual(initial.digest, advanced.digest)
        reordered = replace(initial, collections=(replace(members, member_ids=("edge-2", "edge-1")),))
        self.assertEqual(initial.digest, reordered.digest)
        other_source = replace(self.source_a, tenant="other")
        with self.assertRaisesRegex(ValueError, "same tenant"):
            replace(read, source_version=SourceVersion(other_source, "epoch-1", "1"))
        with self.assertRaisesRegex(ValueError, "cross tenants"):
            replace(initial, reads=(replace(read, tenant="other"),))
        with self.assertRaisesRegex(ValueError, "Duplicate key"):
            replace(initial, reads=(read, replace(read, revision=4)))

    def test_canonical_json_rejects_lossy_key_and_number_coercion(self):
        for invalid in ({1: "key"}, {"value": float("nan")}, {"value": float("inf")}, {"value": b"bytes"}):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                canonical_json(invalid)
        self.assertEqual(canonical_json({"b": [None, 2], "a": True}), '{"a":true,"b":[null,2]}')
