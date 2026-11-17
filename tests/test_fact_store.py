import json
import unittest
from datetime import timedelta
from uuid import uuid4

from ai_native_system.fact_contracts import (
    Coverage, EvidenceRevocation, FactField, FieldAuthority, IdentityMapping, ObjectIdentity, SourceEvent,
    SourceIdentity, SourceVersion,
)
from ai_native_system.facts import EXISTS, Facts, MappingConflict
from ai_native_system.identity import IdentityContext
from ai_native_system.policy import Policy

from p2b_support import TEST_DSN, restricted_role


@unittest.skipUnless(TEST_DSN, "Run deployment/local-postgres/verify_p2b.py")
class PostgresFactStoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from ai_native_system.adapters.postgres import migrate_postgres

        migrate_postgres(TEST_DSN)
        cls.dsn = restricted_role([
            "SELECT ON ALL TABLES IN SCHEMA ai_native",
            "INSERT ON ai_native.fact_authorities, ai_native.fact_assertions, ai_native.fact_observations, "
            "ai_native.identity_mappings, ai_native.fact_invalidation_outbox, ai_native.principals, ai_native.resource_grants",
            "INSERT ON ai_native.source_sync_progress",
            "INSERT, UPDATE ON ai_native.source_sync_streams",
            "INSERT, UPDATE, DELETE ON ai_native.fact_projections",
        ])

    def setUp(self):
        from ai_native_system.adapters.postgres_runtime import PostgresRuntimeStore

        self.tenant = "fact-" + uuid4().hex[:12]
        self.store = self.enterContext(PostgresRuntimeStore(self.dsn))
        self.facts = Facts(self.store, self.tenant, freshness=timedelta(minutes=2))
        self.obj = self.identity("inspection")
        self.field = FactField(self.obj, "passed")

    def identity(self, object_id):
        return ObjectIdentity(self.tenant, "observation", object_id)

    def native(self, source, object_id="inspection"):
        return SourceIdentity(self.tenant, source, "record", object_id)

    @staticmethod
    def now(connection):
        return connection.execute("SELECT clock_timestamp()").fetchone()[0]

    def configure(self, connection, source, object_id="inspection", *, epoch="one", coverage="complete"):
        now = self.now(connection)
        status = "ready" if coverage == Coverage.COMPLETE else "partial"
        connection.execute(
            """INSERT INTO source_sync_streams(tenant,source,stream,epoch,position,token,status,coverage,updated_at,fresh_until)
               VALUES (?,?, 'all',?,0, 'start',?,?,?,?)
               ON CONFLICT (tenant,source,stream) DO UPDATE SET epoch=excluded.epoch, status=excluded.status,
                  coverage=excluded.coverage, updated_at=excluded.updated_at, fresh_until=excluded.fresh_until""",
            (self.tenant, source, epoch, status, coverage, now, now + timedelta(minutes=2)),
        )
        connection.execute(
            """INSERT INTO source_sync_progress(tenant,source,stream,epoch,position,token,snapshot_id,status,coverage,
                                                updated_at,fresh_until,revision)
               SELECT s.*,coalesce((SELECT max(p.revision) FROM source_sync_progress p
                                    WHERE p.tenant=s.tenant AND p.source=s.source AND p.stream=s.stream),0)+1
               FROM source_sync_streams s WHERE s.tenant=? AND s.source=? AND s.stream='all'""",
            (self.tenant, source),
        )
        mapping = IdentityMapping(self.native(source, object_id), self.identity(object_id), 1, now)
        self.facts.bind_mapping(connection, mapping, actor="operator", reason="initial authority mapping")

    def authority(self, connection, field, sources, revision=1, expected=None):
        return self.facts.set_authority(connection, FieldAuthority(field, sources, revision), expected=expected,
                                        actor="operator", reason="verified source jurisdiction")

    def write(self, connection, source, sequence, values, *, object_id="inspection", occurred_at=None, epoch="one",
              observed_at=None):
        when = self.now(connection)
        native = self.native(source, object_id)
        event = SourceEvent(
            f"{object_id}-{epoch}-{sequence}", native, "delete" if values is None else "upsert", when,
            None if values is None else {"receipt": "source raw event"},
            SourceVersion(native, epoch, str(sequence), sequence), occurred_at=occurred_at or when,
        )
        self.facts.write_source(connection, event, stream="all", changes=values, observed_at=observed_at)

    def read(self, connection, field=None, *, at=None):
        instant = at or self.now(connection)
        return self.facts.read_fact(connection, self.field if field is None else field, as_of=instant, known_at=instant)

    def test_authority_selection_and_equal_authority_conflict(self):
        with self.store.transaction(write=True, tenant=self.tenant) as connection:
            self.configure(connection, "inventory")
            self.configure(connection, "report")
            self.authority(connection, self.field, ("inventory",))
            self.write(connection, "inventory", 1, {("passed", None): True})
            self.write(connection, "report", 1, {("passed", None): False})
            chosen = self.read(connection)
            self.assertTrue(chosen.available)
            self.assertIs(chosen.value, True)
            self.assertEqual(chosen.reason, "authority_preferred")
            self.assertEqual(len(chosen.conflicts), 1)
            self.assertEqual({cursor.source for cursor in chosen.source_cursors}, {"inventory"})
            projected = connection.execute(
                "SELECT assertion_id FROM fact_projections WHERE field_name='passed'"
            ).fetchone()[0]
            self.assertEqual(projected, chosen.selected)
            self.authority(connection, self.field, ("inventory", "report"), 2, 1)
            conflict = self.read(connection)
            self.assertFalse(conflict.available)
            self.assertEqual(conflict.reason, "source_conflict")
            self.assertEqual(len(conflict.conflicts), 2)
            self.assertIsNone(connection.execute(
                "SELECT assertion_id FROM fact_projections WHERE field_name='passed'"
            ).fetchone())
            outbox = connection.execute(
                "SELECT document FROM fact_invalidation_outbox WHERE document::jsonb#>>'{selection,reason}'='source_conflict'"
            ).fetchone()
            self.assertEqual(len(json.loads(outbox[0])["selection"]["conflicts"]), 2)

    def test_history_keeps_valid_time_and_time_learned_and_deletion(self):
        with self.store.transaction(write=True, tenant=self.tenant) as connection:
            self.configure(connection, "primary")
            self.authority(connection, self.field, ("primary",))
            exists = FactField(self.obj, EXISTS)
            self.authority(connection, exists, ("primary",))
            valid_first = self.now(connection) - timedelta(days=3)
            valid_second = self.now(connection) - timedelta(days=2)
            self.write(connection, "primary", 1, {("passed", None): True},
                       occurred_at=valid_first, observed_at=self.now(connection))
            known_first = self.now(connection)
            self.write(connection, "primary", 2, {("passed", None): False},
                       occurred_at=valid_second, observed_at=self.now(connection))
            self.assertTrue(self.read(connection).available)
            self.assertIs(self.read(connection).value, False)
            old_knowledge = self.facts.history(connection, self.field, known_at=known_first)
            self.assertEqual([row["value"] for row in old_knowledge], [True])
            historical = self.facts.history(connection, self.field, as_of=valid_first + timedelta(hours=4))
            self.assertEqual([row["value"] for row in historical], [True])
            self.assertEqual(len(self.facts.history(connection, self.field)), 2)
            self.write(connection, "primary", 3, None)
            self.assertFalse(self.read(connection).available)
            self.assertTrue(self.read(connection).deleted)
            self.assertIs(self.read(connection, exists).value, False)
            self.assertTrue(self.read(connection, exists).available)
            self.assertTrue(self.facts.history(connection, self.field)[0]["deleted"])

    def test_manual_correction_expiry_and_evidence_revocation(self):
        with self.store.transaction(write=True, tenant=self.tenant) as connection:
            self.configure(connection, "primary")
            self.authority(connection, self.field, ("primary",))
            self.write(connection, "primary", 1, {("passed", None): False})
            original = self.read(connection)
            end = self.now(connection) + timedelta(seconds=10)
            connection.execute("INSERT INTO principals (tenant,id,roles) VALUES (?, 'human', '[]')", (self.tenant,))
            human = IdentityContext(self.tenant, "human")
            with self.assertRaises(PermissionError):
                self.facts.correct(connection, self.field, human, True, reason="operator review",
                                   expires_at=end, correction_id="correction-1")
            policy = Policy()
            policy.grant(connection, self.tenant, "human", "correct", "field", self.obj.object_id, "passed")
            older = self.facts.correct(connection, self.field, human, True, reason="earlier operator review",
                                        expires_at=end + timedelta(seconds=5), correction_id="correction-0")
            applied = self.facts.correct(connection, self.field, human, True, reason="operator review",
                                         expires_at=end, correction_id="correction-1")
            replay = self.facts.correct(connection, self.field, human, True, reason="operator review",
                                        expires_at=end, correction_id="correction-1")
            self.assertEqual(applied, replay)
            self.assertGreater(applied.recorded_at, older.recorded_at)
            self.assertIs(self.read(connection).value, True)
            self.assertEqual(self.read(connection).reason, "human_correction")
            self.assertIs(self.read(connection, at=end + timedelta(seconds=1)).value, False)
            ref = next(proof for proof in original.reads if proof.kind == "evidence")
            policy.grant(connection, self.tenant, "human", "revoke", "evidence", ref.resource_id)
            revoke_at = self.now(connection)
            self.facts.revoke_evidence(
                connection, EvidenceRevocation("withdraw-1", self.tenant, ref.resource_id, ref.revision,
                                               revoke_at, "source retracted verification"), human,
            )
            self.assertFalse(self.read(connection, at=end + timedelta(seconds=1)).available)
            record = next(row for row in self.facts.history(connection, self.field) if row["assertion_id"] == "correction-1")
            self.assertEqual(record["authorization_ref"], "principal:human")
            self.assertEqual(record["correction_reason"], "operator review")

    def test_withdrawal_removes_active_projection_but_preserves_history(self):
        with self.store.transaction(write=True, tenant=self.tenant) as connection:
            self.configure(connection, "primary")
            self.authority(connection, self.field, ("primary",))
            self.write(connection, "primary", 1, {("passed", None): True})
            connection.execute("INSERT INTO principals (tenant,id,roles) VALUES (?, 'human', '[]')", (self.tenant,))
            human = IdentityContext(self.tenant, "human")
            original = self.read(connection)
            evidence = next(proof for proof in original.reads if proof.kind == "evidence")
            Policy().grant(connection, self.tenant, human.actor, "revoke", "evidence", evidence.resource_id)
            cutoff = self.now(connection)
            revoked = EvidenceRevocation("withdraw-live", self.tenant, evidence.resource_id, evidence.revision,
                                         cutoff, "source withdrew")
            self.facts.revoke_evidence(connection, revoked, human)
            self.facts.revoke_evidence(connection, revoked, human)
            self.assertFalse(self.read(connection).available)
            self.assertTrue(self.read(connection, at=cutoff - timedelta(microseconds=1)).available)
            self.assertIsNone(connection.execute("SELECT assertion_id FROM fact_projections WHERE field_name='passed'").fetchone())
            self.assertEqual(self.facts.history(connection, self.field)[0]["assertion_id"], original.selected)

    def test_mapping_revision_invalidates_old_projection_and_remains_auditable(self):
        with self.store.transaction(write=True, tenant=self.tenant) as connection:
            self.configure(connection, "inventory")
            self.authority(connection, self.field, ("inventory",))
            self.write(connection, "inventory", 1, {("passed", None): True})
            self.assertTrue(self.read(connection).available)
            next_identity = self.identity("new-canonical-id")
            mapping = IdentityMapping(self.native("inventory"), next_identity, 2, self.now(connection))
            with self.assertRaises(MappingConflict):
                self.facts.bind_mapping(connection, mapping, expected=0, actor="operator", reason="verified remap")
            before = self.now(connection)
            self.facts.bind_mapping(connection, mapping, expected=1, actor="operator", reason="verified remap")
            self.assertEqual(self.facts.target_for(connection, mapping.source).target, next_identity)
            self.assertEqual(self.facts.target_for(connection, mapping.source, known_at=before).target, self.obj)
            self.assertIsNone(connection.execute(
                "SELECT assertion_id FROM fact_projections WHERE field_name='passed'"
            ).fetchone())
            self.assertFalse(self.read(connection).available)
            self.assertEqual(len(self.facts.history(connection, self.field)), 1)

    def test_collection_needs_complete_source_and_tracks_target_tombstone(self):
        with self.store.transaction(write=True, tenant=self.tenant) as connection:
            self.configure(connection, "inventory")
            self.configure(connection, "inventory", "child")
            self.authority(connection, FactField(self.obj, "component"), ("inventory",))
            self.authority(connection, FactField(self.identity("child"), EXISTS), ("inventory",))
            self.write(connection, "inventory", 1,
                       {("component", "edge-1"): {"target_type": "observation", "target_id": "child", "properties": {}}})
            now = self.now(connection)
            unknown = self.facts.read_relation(connection, self.obj, "component", as_of=now, known_at=now)
            self.assertFalse(unknown.available)
            self.write(connection, "inventory", 1, {}, object_id="child")
            now = self.now(connection)
            full = self.facts.read_relation(connection, self.obj, "component", as_of=now, known_at=now)
            self.assertTrue(full.available)
            self.assertEqual(full.collection.member_ids, ("child",))
            self.write(connection, "inventory", 2, None, object_id="child")
            now = self.now(connection)
            removed = self.facts.read_relation(connection, self.obj, "component", as_of=now, known_at=now)
            self.assertTrue(removed.available)
            self.assertEqual(removed.collection.member_ids, ())
            self.assertNotEqual(full.collection.revision, removed.collection.revision)
            observed_complete = now
            self.configure(connection, "inventory", coverage="partial")
            now = self.now(connection)
            partial = self.facts.read_relation(connection, self.obj, "component", as_of=now, known_at=now)
            self.assertFalse(partial.available)
            self.assertEqual(partial.collection.coverage, Coverage.PARTIAL)
            historical = self.facts.read_relation(connection, self.obj, "component",
                                                  as_of=observed_complete, known_at=observed_complete)
            self.assertTrue(historical.available)
            self.assertEqual(historical.collection.revision, removed.collection.revision)
