import os
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from threading import Barrier
from uuid import uuid4

from ai_native_system.fact_contracts import (
    ChangeKind, EvidenceRef, EvidenceRevocation, FactAssertion, FactChange, FactField, FactOrigin,
    IdentityMapping, ObjectIdentity, SourceCursor, SourceEvent, SourceIdentity, SourceVersion,
)
from ai_native_system.ontology import OntologyRelease


TEST_DSN = os.environ.get("AI_NATIVE_PG_TEST_DSN")
EARLY = datetime(2026, 1, 1, tzinfo=timezone.utc)
LATER = EARLY + timedelta(days=7)


@unittest.skipUnless(TEST_DSN, "Run deployment/local-postgres/verify_facts.py for real PostgreSQL tests")
class PostgreSQLFactsTests(unittest.TestCase):
    def setUp(self):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo

        from ai_native_system.adapters.postgres import migrate_postgres
        from ai_native_system.adapters.postgres_facts import PostgresFacts, SemanticConflictError
        from ai_native_system.migrations import REVISIONS

        self.connect = psycopg.connect
        self.conflict = SemanticConflictError
        suffix = uuid4().hex[:12]
        dbname, role, password = f"facts_{suffix}", f"facts_writer_{suffix}", uuid4().hex
        with self.connect(TEST_DSN, autocommit=True) as admin:
            admin.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(sql.Identifier(role), sql.Literal(password)))
            self.addCleanup(self._drop, "ROLE", role)
            admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(dbname)))
            self.addCleanup(self._drop, "DATABASE", dbname)
        admin_dsn = make_conninfo(TEST_DSN, dbname=dbname)
        with self.connect(admin_dsn) as admin:
            admin.execute("CREATE SCHEMA ai_native")
        self.assertEqual(migrate_postgres(admin_dsn), REVISIONS[-1])
        with self.connect(admin_dsn) as admin:
            admin.execute(sql.SQL("GRANT USAGE ON SCHEMA ai_native TO {}").format(sql.Identifier(role)))
            admin.execute(sql.SQL("GRANT SELECT ON ai_native.schema_migrations TO {}").format(sql.Identifier(role)))
            admin.execute(sql.SQL(
                "GRANT SELECT, INSERT ON ai_native.ontology_releases, ai_native.identity_mappings, "
                "ai_native.fact_assertions, ai_native.source_events, ai_native.fact_invalidation_outbox TO {}"
            ).format(sql.Identifier(role)))
            admin.execute(sql.SQL(
                "GRANT SELECT, INSERT, UPDATE ON ai_native.fact_projections, ai_native.source_cursors TO {}"
            ).format(sql.Identifier(role)))
        self.dsn = make_conninfo(admin_dsn, user=role, password=password)
        self.store = PostgresFacts(self.dsn, "alpha")
        self.other_store = PostgresFacts(self.dsn, "beta")
        self.identity = SourceIdentity("alpha", "catalog", "asset-row", "foreign-7")
        self.target = ObjectIdentity("alpha", "Asset", "asset-4")
        self.field = FactField(self.target, "label")

    def _drop(self, kind, name):
        from psycopg import sql

        with self.connect(TEST_DSN, autocommit=True) as admin:
            admin.execute(sql.SQL("DROP {} {}").format(sql.SQL(kind), sql.Identifier(name)))

    @staticmethod
    def _release(tenant, version=1, state="active"):
        return OntologyRelease.from_document({
            "namespace": "assets", "version": version, "publisher": {"tenant": tenant, "actor": "designer"},
            "types": {"Asset": {"states": [state], "properties": {"label": {"type": "string"}}}},
        })

    def test_ontology_releases_keep_digest_version_types_and_tenant_boundaries(self):
        release = self._release("alpha")
        self.assertTrue(self.store.save_release(release).created)
        self.assertFalse(self.store.save_release(release).created)
        self.assertEqual(self.store.get_release("assets", 1).digest, release.digest)
        self.assertTrue(self.store.save_release(self._release("alpha", "1")).created)
        self.assertIsNone(self.other_store.get_release("assets", 1))
        self.assertTrue(self.other_store.save_release(self._release("beta")).created)
        self.assertNotEqual(self.other_store.get_release("assets", 1).digest, release.digest)
        with self.assertRaises(self.conflict):
            self.store.save_release(self._release("alpha", state="changed"))
        with self.assertRaisesRegex(ValueError, "tenant"):
            self.other_store.save_release(release)

    def test_identity_history_preserves_revisions_and_separates_source_names(self):
        first = IdentityMapping(self.identity, self.target, 1, EARLY)
        second = IdentityMapping(self.identity, replace(self.target, object_id="asset-9"), 2, LATER)
        self.assertTrue(self.store.append_mapping(second).created)
        self.assertTrue(self.store.append_mapping(first).created)
        self.assertFalse(self.store.append_mapping(first).created)
        with self.assertRaises(self.conflict):
            self.store.append_mapping(replace(second, revision=1))
        other_identity = replace(self.identity, source="other-catalog")
        self.assertTrue(self.store.append_mapping(replace(first, source=other_identity)).created)
        history = self.store.mapping_history(self.identity)
        self.assertEqual([(row["revision"], row["target"]["object_id"]) for row in history], [(1, "asset-4"), (2, "asset-9")])
        self.assertEqual(len(self.store.mapping_history(other_identity)), 1)
        self.assertEqual(self.other_store.mapping_history(replace(self.identity, tenant="beta")), ())
        with self.assertRaisesRegex(ValueError, "tenant"):
            self.other_store.mapping_history(self.identity)

    def test_assertion_history_round_trips_provenance_and_distinct_business_times(self):
        evidence = EvidenceRef("alpha", "proof", 1, self.identity, "loc:7", "digest-A", LATER)
        assertion = FactAssertion(
            "assertion-1", 1, self.field, FactOrigin.SOURCE, {"标签": ["旧", 1.0]}, LATER,
            source=self.identity, source_version=SourceVersion(self.identity, "epoch-1", "etag-71"),
            valid_from=EARLY, valid_to=LATER, evidence=(evidence,),
        )
        self.assertTrue(self.store.append_assertion(assertion).created)
        self.assertFalse(self.store.append_assertion(assertion).created)
        with self.assertRaises(self.conflict):
            self.store.append_assertion(replace(assertion, value={"标签": ["覆盖", 1.0]}))
        self.store.append_assertion(replace(assertion, revision=2, value="新", recorded_at=LATER + timedelta(days=1)))
        history = self.store.assertion_history(self.field)
        self.assertEqual(len(history), 2)
        self.assertEqual(history[0]["value"], {"标签": ["旧", 1.0]})
        self.assertIs(type(history[0]["value"]["标签"][1]), float)
        self.assertEqual(history[0]["source_version"]["token"], "etag-71")
        self.assertEqual(history[0]["evidence"][0]["evidence_id"], "proof")
        self.assertEqual((history[0]["valid_from"], history[0]["recorded_at"]), (EARLY.isoformat(), LATER.isoformat()))
        with self.connect(self.dsn) as connection:
            connection.execute("SELECT set_config('ai_native.tenant', 'alpha', true)")
            values = connection.execute(
                "SELECT valid_from,valid_to,recorded_at FROM ai_native.fact_assertions WHERE revision_key='1'"
            ).fetchone()
        self.assertEqual(values, (EARLY, LATER, LATER))
        self.assertEqual(self.other_store.assertion_history(FactField(replace(self.target, tenant="beta"), "label")), ())
        with self.assertRaisesRegex(ValueError, "tenant"):
            self.other_store.append_assertion(assertion)

    def _event(self, **options):
        event = SourceEvent("event-1", self.identity, ChangeKind.UPSERT, LATER, {"label": "新增"},
                            cursor=SourceCursor("alpha", "catalog", "stream", "epoch-1", "before"))
        return replace(event, **options)

    def test_inbox_retains_first_delivery_and_rejects_changed_body_or_epoch(self):
        event = self._event()
        first = self.store.receive_event(event)
        self.assertTrue(first.created)
        duplicate = self.store.receive_event(replace(event, received_at=LATER + timedelta(seconds=5),
                                                    cursor=replace(event.cursor, token="next")))
        self.assertFalse(duplicate.created)
        self.assertEqual((duplicate.document, duplicate.digest), (first.document, first.digest))
        for changed in (replace(event, payload={"label": "改写"}), replace(event, cursor=replace(event.cursor, epoch="epoch-2"))):
            with self.assertRaises(self.conflict):
                self.store.receive_event(changed)
        self.assertEqual(self.store.get_event("catalog", "event-1").document, first.document)
        self.assertIsNone(self.other_store.get_event("catalog", "event-1"))
        self.assertTrue(self.other_store.receive_event(replace(event, identity=replace(self.identity, tenant="beta"),
                                                              cursor=replace(event.cursor, tenant="beta"))).created)
        with self.assertRaisesRegex(ValueError, "tenant"):
            self.other_store.receive_event(event)

    def test_inbox_concurrent_retries_insert_one_record(self):
        barrier = Barrier(2, timeout=5)
        event = self._event()

        def receive():
            barrier.wait()
            return self.store.receive_event(event)

        with ThreadPoolExecutor(max_workers=2) as workers:
            results = [workers.submit(receive) for _ in range(2)]
            stored = [result.result(timeout=12) for result in results]
        self.assertEqual(sorted(result.created for result in stored), [False, True])
        self.assertEqual({result.digest for result in stored}, {event.content_digest})

    def test_insert_only_role_cannot_overwrite_records(self):
        from psycopg.errors import InsufficientPrivilege

        self.store.receive_event(self._event())
        with self.assertRaises(InsufficientPrivilege), self.connect(self.dsn) as connection:
            connection.execute("SELECT set_config('ai_native.tenant', 'alpha', true)")
            connection.execute("UPDATE ai_native.source_events SET document='{}'")
        with self.assertRaises(InsufficientPrivilege), self.connect(self.dsn) as connection:
            connection.execute("SELECT set_config('ai_native.tenant', 'alpha', true)")
            connection.execute("DELETE FROM ai_native.source_events")
        self.assertEqual(self.store.get_event("catalog", "event-1").document["payload"], {"label": "新增"})

    def test_projection_requires_exact_existing_assertion_and_expected_predecessor(self):
        from psycopg.errors import ForeignKeyViolation

        from ai_native_system.adapters.postgres_facts import AssertionRef

        initial = FactAssertion("reported", 1, self.field, FactOrigin.IMPORTED_SNAPSHOT, "old", EARLY)
        replacement = replace(initial, revision="1", value="new", recorded_at=LATER)
        relation_field = replace(self.field, relationship_id="edge-2")
        related = replace(initial, assertion_id="relation-label", field=relation_field)
        for assertion in (initial, replacement, related):
            self.store.append_assertion(assertion)
        old, new = AssertionRef("reported", 1), AssertionRef("reported", "1")
        relation = AssertionRef("relation-label", 1)
        self.assertIsNone(self.store.get_projection(self.field))
        for invalid in (AssertionRef("missing", 1), relation):
            with self.assertRaisesRegex(ValueError, "same tenant and field"):
                self.store.set_projection(self.field, invalid, expected=None)
        self.store.set_projection(self.field, old, expected=None)
        self.store.set_projection(self.field, new, expected=old)
        with self.assertRaises(self.conflict):
            self.store.set_projection(self.field, old, expected=old)
        self.store.set_projection(relation_field, relation, expected=None)
        self.assertEqual(self.store.get_projection(self.field), new)
        self.assertEqual(self.store.get_projection(relation_field), relation)
        beta_field = replace(self.field, subject=replace(self.target, tenant="beta"))
        self.assertIsNone(self.other_store.get_projection(beta_field))
        with self.assertRaisesRegex(ValueError, "same tenant and field"):
            self.other_store.set_projection(beta_field, old, expected=None)
        with self.assertRaises(ForeignKeyViolation), self.connect(self.dsn) as connection:
            connection.execute("SELECT set_config('ai_native.tenant', 'alpha', true)")
            connection.execute("UPDATE ai_native.fact_projections SET assertion_id='relation-label', revision_key='1' "
                               "WHERE tenant='alpha' AND relationship_key=''")

    def test_cursor_checkpoints_reject_stale_predecessor_and_implicit_epoch_reset(self):
        first_cursor = SourceCursor("alpha", "catalog", "stream", "epoch-1", "a")
        first = self.store.checkpoint_cursor(first_cursor, expected=None)
        self.assertEqual(first.revision, 1)
        with self.assertRaises(self.conflict):
            self.store.checkpoint_cursor(first_cursor, expected=None)
        second = self.store.checkpoint_cursor(replace(first_cursor, token="b"), expected=first)
        # Opaque tokens can repeat. The revision still distinguishes a stale predecessor.
        third = self.store.checkpoint_cursor(first_cursor, expected=second)
        self.assertEqual(third.revision, 3)
        with self.assertRaises(self.conflict):
            self.store.checkpoint_cursor(replace(first_cursor, token="stale"), expected=first)
        with self.assertRaisesRegex(ValueError, "epoch"):
            self.store.checkpoint_cursor(replace(first_cursor, epoch="epoch-2"), expected=third)
        with self.assertRaisesRegex(ValueError, "tenant"):
            self.other_store.checkpoint_cursor(first_cursor, expected=None)
        self.assertIsNone(self.other_store.get_cursor("catalog", "stream"))
        self.assertEqual(self.store.get_cursor("catalog", "stream"), third)

    def test_pending_invalidation_outbox_deduplicates_and_scopes_tenant(self):
        change = FactChange("change-1", self.field, 1, ChangeKind.DELETE, EARLY, "operation-1")
        revoke = EvidenceRevocation("revoke-1", "alpha", "proof", 1, LATER, "superseded")
        self.assertTrue(self.store.enqueue_invalidation(change).created)
        self.assertFalse(self.store.enqueue_invalidation(change).created)
        with self.assertRaises(self.conflict):
            self.store.enqueue_invalidation(replace(change, revision=2))
        self.assertTrue(self.store.enqueue_invalidation(revoke).created)
        self.assertEqual(self.other_store.pending_invalidations(), ())
        with self.assertRaisesRegex(ValueError, "tenant"):
            self.other_store.enqueue_invalidation(revoke)
        records = [record.document for record in self.store.pending_invalidations()]
        self.assertEqual({record["kind"] for record in records}, {"fact.change", "evidence.revocation"})
        event = next(record["event"] for record in records if record["kind"] == "fact.change")
        self.assertEqual((event["kind"], event["operation_id"]), ("delete", "operation-1"))
        self.assertEqual(len(self.store.pending_invalidations(limit=1)), 1)
