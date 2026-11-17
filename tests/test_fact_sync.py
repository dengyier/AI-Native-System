"""PostgreSQL coverage for the source synchronization boundary."""
import json
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from uuid import uuid4

from ai_native_system.fact_contracts import (
    ChangeKind, Coverage, FactField, FieldAuthority, IdentityMapping, ObjectIdentity,
    SnapshotBoundary, SourceCursor, SourceEvent, SourceIdentity, SourceVersion,
)
from ai_native_system.facts import Facts
from ai_native_system.sync import FactSync

from p2b_support import TEST_DSN, restricted_role


@unittest.skipUnless(TEST_DSN, "Run deployment/local-postgres/verify_p2b.py on disposable PostgreSQL")
class PostgreSQLFactSyncTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from ai_native_system.adapters.postgres import migrate_postgres
        from ai_native_system.adapters.postgres_runtime import PostgresRuntimeStore

        migrate_postgres(TEST_DSN)
        cls.store_type = PostgresRuntimeStore
        reads = """SELECT ON ai_native.identity_mappings, ai_native.fact_authorities,
            ai_native.fact_assertions, ai_native.fact_observations, ai_native.fact_projections,
            ai_native.source_events, ai_native.source_cursors, ai_native.source_sync_streams,
            ai_native.source_sync_snapshots, ai_native.source_sync_deliveries, ai_native.source_sync_conflicts,
            ai_native.source_sync_records, ai_native.source_sync_progress, ai_native.fact_feedback_expectations, ai_native.fact_feedback_observations,
            ai_native.fact_invalidation_outbox"""
        cls.sync_dsn = restricted_role([
            reads, """INSERT ON ai_native.fact_assertions, ai_native.fact_observations, ai_native.fact_invalidation_outbox,
              ai_native.source_events, ai_native.source_sync_snapshots, ai_native.source_sync_conflicts, ai_native.source_sync_progress,
              ai_native.fact_feedback_observations""",
            """INSERT, UPDATE ON ai_native.source_sync_streams, ai_native.source_sync_deliveries,
              ai_native.source_cursors, ai_native.source_sync_records""",
            "INSERT, UPDATE, DELETE ON ai_native.fact_projections",
        ])
        cls.control_dsn = restricted_role([
            reads, "INSERT ON ai_native.identity_mappings, ai_native.fact_authorities, ai_native.fact_invalidation_outbox",
            "INSERT, UPDATE, DELETE ON ai_native.fact_projections",
        ])

    def setUp(self):
        self.tenant = "p2b-sync-" + uuid4().hex
        self.store = self.enterContext(self.store_type(self.sync_dsn))
        self.control = self.enterContext(self.store_type(self.control_dsn))
        self.facts = Facts(self.store, self.tenant)
        self.object = ObjectIdentity(self.tenant, "asset", "canonical-asset")
        self.a = FactSync(self.store, self.tenant, "source-a", "inventory", self.facts)
        self.b = FactSync(self.store, self.tenant, "source-b", "inventory", self.facts)
        self.now = datetime.now(timezone.utc) - timedelta(minutes=1)
        self.mapping(self.a)
        self.mapping(self.b)
        with self.control.transaction(tenant=self.tenant, write=True) as tx:
            self.facts.set_authority(tx, FieldAuthority(FactField(self.object, "quantity"), ("source-a",), 1),
                                     actor="operator", reason="Primary inventory source")

    def mapping(self, sync, *, native="item-1", target=None, revision=1, expected=None):
        source = SourceIdentity(self.tenant, sync.source, "native-asset", native)
        mapping = IdentityMapping(source, target or self.object, revision, self.now)
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.facts.bind_mapping(connection, mapping, expected=expected, actor="operator", reason="Catalog binding")
        return mapping

    def cursor(self, sync, position, *, epoch="epoch-1"):
        return SourceCursor(self.tenant, sync.source, sync.stream, epoch, f"cursor-{position}")

    def event(self, sync, event_id, position, record_version, *, native="item-1", value=4, epoch="epoch-1",
              kind=ChangeKind.UPSERT, occurred_at=None, unsequenced=False):
        identity = SourceIdentity(self.tenant, sync.source, "native-asset", native)
        version = SourceVersion(identity, epoch, f"native-v{record_version}", None if unsequenced else record_version)
        return SourceEvent(event_id, identity, kind, self.now + timedelta(seconds=1),
                           {"properties": {"quantity": value}, "state": "ready"} if kind == ChangeKind.UPSERT else None,
                           version, self.cursor(sync, position, epoch=epoch),
                           self.now if occurred_at is None else occurred_at)

    def boundary(self, sync, snapshot_id, position, *, epoch="epoch-1", coverage=Coverage.COMPLETE, watermark=True):
        return SnapshotBoundary(self.tenant, sync.source, snapshot_id, epoch, self.now, self.now + timedelta(seconds=1),
                                coverage, self.cursor(sync, position, epoch=epoch) if watermark else None)

    def bootstrap(self, sync, *, position=0, value=4):
        record = self.event(sync, "bootstrap", position, 10, value=value)
        boundary = self.boundary(sync, "snapshot-0", position)
        self.assertEqual(sync.snapshot(boundary, (record,), position=position).status, "applied")
        return boundary, record

    def sql(self, statement, arguments=(), *, tenant=None):
        with self.store.transaction(tenant=self.tenant if tenant is None else tenant) as connection:
            return connection.execute(statement, arguments).fetchall()

    def counts(self):
        return tuple(self.sql(f"SELECT count(*) FROM {table}")[0][0] for table in (
            "fact_assertions", "fact_invalidation_outbox", "fact_projections", "source_events",
            "source_sync_deliveries", "source_sync_records", "source_sync_progress",
        ))

    def payload(self, sync):
        row, = self.sql("SELECT document FROM source_sync_records WHERE source=? AND source_id='item-1'", (sync.source,))
        return json.loads(row[0])["payload"]

    def test_two_sources_gap_resume_and_retired_epoch(self):
        a_snapshot, _ = self.bootstrap(self.a, position=10)
        self.bootstrap(self.b, value=21)
        self.assertEqual((self.payload(self.a)["properties"]["quantity"], self.payload(self.b)["properties"]["quantity"]),
                         (4, 21))
        old = self.event(self.a, "late-native-version", 11, 9, value=1)
        self.assertEqual(self.a.apply(old, position=11, predecessor=a_snapshot.resume_cursor).status, "stale")
        self.assertEqual(self.payload(self.a)["properties"]["quantity"], 4)
        with self.store_type(self.sync_dsn) as store:
            restarted = FactSync(store, self.tenant, self.a.source, self.a.stream, Facts(store, self.tenant))
            self.assertEqual(restarted.status()["position"], 11)
            self.assertEqual(restarted.apply(old, position=11, predecessor=a_snapshot.resume_cursor).status, "duplicate")
        ahead = self.event(self.a, "gapped", 13, 13, value=100)
        blocked = self.a.apply(ahead, position=13, predecessor=self.cursor(self.a, 11))
        self.assertEqual((blocked.status, blocked.reason), ("blocked", "cursor_gap"))
        self.assertEqual((self.a.status()["position"], self.a.status()["coverage"], self.a.status()["fresh_until"]),
                         (11, "unknown", None))
        self.assertEqual(self.b.status()["status"], "ready")
        history = self.sql("""SELECT status, position, coverage, updated_at FROM source_sync_progress
                              WHERE source='source-a' ORDER BY revision""")
        self.assertEqual([tuple(row)[:3] for row in history],
                         [("ready", 10, "complete"), ("ready", 11, "complete"), ("blocked", 11, "unknown")])
        self.assertLess(history[1]["updated_at"], history[2]["updated_at"])
        outbox = self.sql("""SELECT document FROM fact_invalidation_outbox
                             WHERE document::jsonb ->> 'kind' = 'source.coverage'""")
        self.assertIn(("blocked", "cursor_gap"), [(event["status"], event["reason"])
                      for row in outbox for event in (json.loads(row[0])["event"],)])
        reset = self.boundary(self.a, "snapshot-reset", 0, epoch="epoch-2")
        new = self.event(self.a, "reset-record", 0, 1, value=12, epoch="epoch-2")
        self.assertEqual(self.a.snapshot(reset, (new,), position=0, predecessor=self.cursor(self.a, 11)).status, "applied")
        self.assertEqual(self.a.apply(ahead, position=13, predecessor=self.cursor(self.a, 11)).reason, "retired_epoch")
        self.assertEqual((self.a.status()["epoch"], self.payload(self.a)["properties"]["quantity"]), ("epoch-2", 12))
        self.assertEqual(self.a.snapshot(self.boundary(self.a, "retired-cut", 20), (ahead,), position=20,
                                         predecessor=reset.resume_cursor).reason, "retired_epoch")
        self.assertEqual(self.a.status()["status"], "ready")

    def test_partial_resnapshot_does_not_infer_deletion_complete_resnapshot_does(self):
        self.mapping(self.a, native="omitted", target=ObjectIdentity(self.tenant, "asset", "omitted"))
        initial = self.boundary(self.a, "initial", 0)
        present = self.event(self.a, "present", 0, 10)
        omitted = self.event(self.a, "missing-later", 0, 8, native="omitted")
        self.assertEqual(self.a.snapshot(initial, (present, omitted), position=0).status, "applied")
        partial = self.boundary(self.a, "partial", 1, coverage=Coverage.PARTIAL)
        self.assertEqual(self.a.snapshot(partial, (present,), position=1, predecessor=initial.resume_cursor).status, "applied")
        self.assertEqual((self.a.status()["status"], self.a.status()["fresh_until"]), ("partial", None))
        self.assertFalse(self.sql("SELECT tombstone FROM source_sync_records WHERE source_id='omitted'")[0][0])
        full = self.boundary(self.a, "full", 2)
        self.assertEqual(self.a.snapshot(full, (present,), position=2, predecessor=partial.resume_cursor).status, "applied")
        self.assertTrue(self.sql("SELECT tombstone FROM source_sync_records WHERE source_id='omitted'")[0][0])
        self.assertGreater(self.a.status()["fresh_until"], self.now)
        self.assertEqual(self.a.snapshot(full, (present,), position=2, predecessor=partial.resume_cursor).status, "duplicate")
        withdrawals = self.sql("""SELECT count(*) FROM fact_assertions JOIN fact_observations USING (tenant,assertion_id,revision_key)
                                  WHERE object_id='omitted' AND deleted""")[0][0]
        self.assertGreater(withdrawals, 0)
        self.assertEqual(self.sql("SELECT count(*) FROM source_events WHERE event_id LIKE 'snapshot-delete:%'")[0][0], 1)

    def test_retry_and_crash_roll_back_inbox_history_projection_and_cursor(self):
        initial, _ = self.bootstrap(self.a)
        original = self.counts()
        event = self.event(self.a, "atomic", 1, 11, value=6)
        with patch.object(self.a, "_checkpoint", side_effect=RuntimeError("crash before checkpoint")):
            with self.assertRaisesRegex(RuntimeError, "crash before checkpoint"):
                self.a.apply(event, position=1, predecessor=initial.resume_cursor)
        self.assertEqual(self.counts(), original)
        self.assertEqual(self.a.status()["position"], 0)
        self.assertEqual(self.payload(self.a)["properties"]["quantity"], 4)
        result = self.a.apply(event, position=1, predecessor=initial.resume_cursor)
        self.assertEqual(result.status, "applied")
        after = self.counts()
        self.assertGreater(after[0], original[0])
        self.assertGreater(after[1], original[1])
        self.assertEqual(self.a.apply(event, position=1, predecessor=initial.resume_cursor).status, "duplicate")
        self.assertEqual(self.counts(), after)

    def test_concurrent_duplicate_and_same_event_id_conflict(self):
        initial, _ = self.bootstrap(self.a)
        event = self.event(self.a, "concurrent", 1, 11, value=5)

        def delivery(sync):
            return sync.apply(event, position=1, predecessor=initial.resume_cursor).status

        with self.store_type(self.sync_dsn) as another_store, ThreadPoolExecutor(max_workers=2) as executor:
            another = FactSync(another_store, self.tenant, self.a.source, self.a.stream, Facts(another_store, self.tenant))
            self.assertCountEqual(executor.map(delivery, (self.a, another)), ("applied", "duplicate"))
        collision = self.event(self.a, "concurrent", 2, 12, value=55)
        self.assertEqual(self.a.apply(collision, position=2, predecessor=event.cursor).reason, "event_id_collision")
        self.assertEqual(self.payload(self.a)["properties"]["quantity"], 5)
        self.assertEqual(self.a.status()["position"], 1)
        self.assertEqual(self.a.conflicts()[0]["reason"], "event_id_collision")
        event_doc, = self.sql("SELECT document FROM source_events WHERE event_id='concurrent'")
        self.assertEqual(json.loads(event_doc[0])["payload"]["properties"]["quantity"], 5)
        self.assertEqual(self.sql("SELECT count(*) FROM source_sync_records", tenant="other")[0][0], 0)

    def test_missing_watermark_version_or_mapping_never_sets_complete(self):
        no_watermark = self.boundary(self.a, "no-watermark", 0, watermark=False)
        result = self.a.snapshot(no_watermark, (), position=None)
        self.assertEqual(result.reason, "unsequenced_snapshot")
        self.assertIsNone(self.a.status())
        initial, _ = self.bootstrap(self.a)
        event = self.event(self.a, "unknown-order", 1, 11, unsequenced=True)
        self.assertEqual(self.a.apply(event, position=None, predecessor=initial.resume_cursor).reason, "unsequenced_delivery")
        self.assertIsNone(self.a.status()["fresh_until"])
        self.assertIsNone(self.sql("SELECT position FROM source_sync_deliveries WHERE event_id='unknown-order'")[0][0])
        reset = self.boundary(self.a, "mapping-check", 2)
        unknown = self.event(self.a, "unknown-id", 2, 12, native="not-mapped")
        result = self.a.snapshot(reset, (unknown,), position=2, predecessor=initial.resume_cursor)
        self.assertEqual(result.reason, "identity_mapping_conflict")
        self.assertEqual(self.a.status()["position"], 0)
        self.assertEqual(self.a.status()["status"], "blocked")
        self.assertEqual(self.payload(self.a)["properties"]["quantity"], 4)
        self.assertEqual({record["reason"] for record in self.a.conflicts()},
                         {"unsequenced_snapshot", "unsequenced_delivery", "identity_mapping_conflict"})

    def test_identity_reassignment_requires_explicit_mapping_and_complete_snapshot(self):
        initial, _ = self.bootstrap(self.a)
        alternate = ObjectIdentity(self.tenant, "asset", "reassigned")
        self.mapping(self.a, target=alternate, revision=2, expected=1)
        pending = self.event(self.a, "remap-event", 1, 11, value=7)
        result = self.a.apply(pending, position=1, predecessor=initial.resume_cursor)
        self.assertEqual(result.reason, "identity_mapping_changed")
        boundary = self.boundary(self.a, "remap-snapshot", 1)
        self.assertEqual(self.a.snapshot(boundary, (pending,), position=1, predecessor=initial.resume_cursor).status, "applied")
        record, = self.sql("SELECT object_id,mapping_revision FROM source_sync_records")
        self.assertEqual((record["object_id"], record["mapping_revision"]), ("reassigned", "2"))
        self.assertEqual(self.sql("SELECT count(*) FROM identity_mappings WHERE source='source-a'")[0][0], 2)

    def test_provider_rejecting_current_token_marks_coverage_blocked(self):
        initial, _ = self.bootstrap(self.a)
        event = self.event(self.a, "next-after-cut", 1, 11)
        self.assertEqual(self.a.apply(event, position=1, predecessor=initial.resume_cursor).status, "applied")
        self.assertEqual(self.a.invalidate(initial.resume_cursor).status, "stale")
        self.assertEqual(self.a.status()["status"], "ready")

        result = self.a.invalidate(event.cursor)
        self.assertEqual((result.status, result.reason), ("blocked", "cursor_invalidated"))
        self.assertEqual((self.a.status()["status"], self.a.status()["position"]), ("blocked", 1))
        history = self.counts()
        self.assertEqual(self.a.invalidate(event.cursor), result)
        self.assertEqual(self.counts(), history)
        replacement = self.boundary(self.a, "after-invalidation", 2)
        self.assertEqual(self.a.snapshot(replacement, (event,), position=2, predecessor=event.cursor).status, "applied")

    def test_explicit_delete_at_next_position_keeps_source_history(self):
        initial, _ = self.bootstrap(self.a)
        event = self.event(self.a, "explicit-delete", 1, 11, kind=ChangeKind.DELETE)
        self.assertEqual(self.a.apply(event, position=1, predecessor=initial.resume_cursor).status, "applied")
        self.assertTrue(self.sql("SELECT tombstone FROM source_sync_records WHERE source_id='item-1'")[0][0])
        self.assertEqual(self.sql("SELECT count(*) FROM source_events WHERE source='source-a'")[0][0], 2)
        older = self.event(self.a, "obsolete-upsert", 2, 9, value=14)
        self.assertEqual(self.a.apply(older, position=2, predecessor=event.cursor).status, "stale")
        self.assertTrue(self.sql("SELECT tombstone FROM source_sync_records WHERE source_id='item-1'")[0][0])


if __name__ == "__main__":
    unittest.main()
