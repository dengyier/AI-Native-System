import secrets
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from ai_native_system.fact_contracts import (
    ChangeKind, Coverage, EvidenceRevocation, FactField, FieldAuthority, IdentityMapping, ObjectIdentity, SnapshotBoundary,
    SourceCursor, SourceEvent, SourceIdentity, SourceVersion,
)
from ai_native_system.fact_gate import bind_rule
from ai_native_system.governance import activate
from ai_native_system.identity import IdentityContext
from ai_native_system.model import DemoModel
from ai_native_system.policy import Policy, tool_resource_id
from ai_native_system.registry import Registry
from ai_native_system.releases import ReleaseSnapshot, ReleaseStore
from ai_native_system.remote import HttpRemote
from ai_native_system.runtime import Runtime
from ai_native_system.storage import database
from ai_native_system.tools import ToolRegistry
from p2b_support import TEST_DSN, restricted_role
from remote_server import RemoteFixture


FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "conformance.json"


class FactWorkflowFixture:
    test_dsn = TEST_DSN
    owp_profile = None
    tool_remote = True
    checksum_source = "quality"
    runtime_grants = ()
    control_grants = ()
    issuer_grants = ()

    def make_ledgers(self):
        return {}

    def make_model(self):
        return DemoModel()

    def make_tools(self):
        tools = ToolRegistry()
        if self.tool_remote:
            self.registry.actions["verify_asset"].update(tool="remote.verify", tool_version="1")
            tools.register_remote("remote.verify", "1", HttpRemote(self.remote.endpoint))
        return tools

    @classmethod
    def setUpClass(cls):
        from ai_native_system.adapters.postgres import migrate_postgres
        from ai_native_system.adapters.postgres_runtime import PostgresRuntimeStore

        migrate_postgres(cls.test_dsn)
        cls.store_type = PostgresRuntimeStore
        cls.runtime_dsn = restricted_role((
            "SELECT ON ALL TABLES IN SCHEMA ai_native",
            "USAGE ON ALL SEQUENCES IN SCHEMA ai_native",
            """INSERT ON ai_native.principals, ai_native.objects, ai_native.knowledge, ai_native.knowledge_history,
               ai_native.events, ai_native.task_governance, ai_native.fact_feedback_expectations""",
            "INSERT, UPDATE ON ai_native.tasks, ai_native.steps, ai_native.remote_operations, ai_native.effects",
            "INSERT, UPDATE, DELETE ON ai_native.execution_claims",
            "UPDATE (state, version) ON ai_native.objects",
            "UPDATE (approver_context) ON ai_native.task_governance",
            "UPDATE (receipt_status) ON ai_native.fact_feedback_expectations",
            *cls.runtime_grants,
        ), cls.test_dsn)
        cls.control_dsn = restricted_role((
            "SELECT ON ALL TABLES IN SCHEMA ai_native",
            """INSERT ON ai_native.governed_tenants, ai_native.resource_grants, ai_native.application_releases,
               ai_native.application_release_lifecycle, ai_native.application_release_selections,
               ai_native.identity_mappings, ai_native.fact_authorities, ai_native.fact_rule_bindings,
               ai_native.fact_invalidation_outbox""",
            "INSERT, UPDATE, DELETE ON ai_native.fact_projections",
            "UPDATE (status, changed_at, changed_by, migration_ref) ON ai_native.application_release_lifecycle",
            "UPDATE (digest, changed_at, changed_by) ON ai_native.application_release_selections",
            *cls.control_grants,
        ), cls.test_dsn)
        if cls.issuer_grants:
            cls.issuer_dsn = restricted_role(cls.issuer_grants, cls.test_dsn)
        cls.sync_dsn = restricted_role((
            "SELECT ON ALL TABLES IN SCHEMA ai_native",
            """INSERT ON ai_native.source_events, ai_native.source_sync_snapshots, ai_native.source_sync_progress,
               ai_native.source_sync_conflicts, ai_native.fact_assertions, ai_native.fact_observations,
               ai_native.fact_invalidation_outbox, ai_native.fact_feedback_observations""",
            """INSERT, UPDATE ON ai_native.source_sync_streams, ai_native.source_sync_records, ai_native.source_cursors,
               ai_native.source_sync_deliveries""",
            "INSERT, UPDATE, DELETE ON ai_native.fact_projections",
        ), cls.test_dsn)

    def setUp(self):
        from ai_native_system.facts import Facts
        from ai_native_system.sync import FactSync

        self.tenant = "workflow-" + secrets.token_hex(6)
        local = Path(self.enterContext(tempfile.TemporaryDirectory())) / "source.sqlite"
        self.remote = self.enterContext(RemoteFixture(local))
        with database(local, write=True) as connection:
            connection.execute("UPDATE remote_objects SET tenant = ?", (self.tenant,))
        self.control = self.enterContext(self.store_type(self.control_dsn))
        self.store = self.enterContext(self.store_type(self.runtime_dsn))
        sync_store = self.enterContext(self.store_type(self.sync_dsn))
        self.facts = Facts(sync_store, self.tenant)
        self.registry = Registry.load(FIXTURE)
        for section, rows in self.registry.seed.items():
            self.registry.seed[section] = [{**row, "tenant": self.tenant} for row in rows if row["tenant"] == "local"]
        ledgers = self.make_ledgers()
        tools = self.make_tools()
        model = self.make_model()
        self.runtime = Runtime(self.store, self.registry, model, tools, owp_ledgers=ledgers)
        self.runtime.initialize()
        self.object = ObjectIdentity(self.tenant, "asset", "asset-1")
        self.identity = {actor: IdentityContext(self.tenant, actor) for actor in ("requester", "reviewer")}
        self.sources = {src: SourceIdentity(self.tenant, src, "record", f"{src}-ref") for src in ("inventory", "quality")}
        self.sync = {src: FactSync(sync_store, self.tenant, src, "main", self.facts) for src in self.sources}
        snapshot = ReleaseSnapshot.capture(self.registry, "single", model, tools, owp_profile=self.owp_profile)
        self.release = snapshot.digest
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            for src in self.sources.values():
                self.facts.bind_mapping(connection, IdentityMapping(src, self.object, 1, self.now()),
                                        actor="operator", reason="Source identity checked")
            for name, src in (("$exists", "inventory"), ("$state", "inventory"), ("checksum_ok", self.checksum_source)):
                self.facts.set_authority(connection, FieldAuthority(FactField(self.object, name), (src,), 1),
                                         actor="operator", reason="Declared owner")
            ReleaseStore.draft(connection, self.tenant, snapshot, publisher="operator")
            bind_rule(connection, self.tenant, self.release, "verify_asset", actor="operator",
                      feedback_source="inventory" if self.tool_remote else None,
                      feedback_stream="main" if self.tool_remote else None)
            ReleaseStore.publish(connection, self.tenant, self.release, publisher="operator")
            ReleaseStore.select(connection, self.tenant, "single", self.release, publisher="operator")
            activate(connection, self.tenant)
            self.grant(connection, "requester", "submit", "app", "single")
            self.grant(connection, "requester", "read", "release", self.release)
            self.grant(connection, "worker", "execute", "action", "verify_asset")
            tool = tools.resolve(self.registry.actions["verify_asset"])
            self.grant(connection, "worker", "execute", "tool", tool_resource_id(tool.name, tool.version))
            self.grant(connection, "worker", "write", "object", self.object.object_id)
            self.grant(connection, "worker", "write", "metadata", self.object.object_id, "state")
            if self.owp_profile is not None:
                self.grant(connection, "worker", "write", "metadata", self.object.object_id, "version")
            for actor in ("requester", "reviewer", "worker"):
                self.grant(connection, actor, "read", "object", self.object.object_id)
                self.grant(connection, actor, "read", "document", "asset-policy")
                for member in ("state", "version"):
                    self.grant(connection, actor, "read", "metadata", self.object.object_id, member)
                for member in ("label", "checksum_ok"):
                    self.grant(connection, actor, "read", "field", self.object.object_id, member)
        for source, payload in (("inventory", self.inventory("pending")), ("quality", self.quality(True))):
            initial = self.event(source, 1, payload)
            boundary = SnapshotBoundary(self.tenant, source, f"{source}-snapshot", "e1", initial.occurred_at,
                                        self.now(), Coverage.COMPLETE, self.cursor(source, 1))
            self.sync[source].snapshot(boundary, [initial], position=1)

    @staticmethod
    def now():
        return datetime.now(timezone.utc)

    @staticmethod
    def inventory(state):
        return {"state": state, "properties": {"label": "Current inventory label"}, "relations": []}

    @staticmethod
    def quality(checksum_ok):
        return {"state": "pending", "properties": {"checksum_ok": checksum_ok}, "relations": []}

    def cursor(self, source, position):
        return SourceCursor(self.tenant, source, "main", "e1", str(position))

    def event(self, source, position, payload, operation_id=None):
        identity = self.sources[source]
        now = self.now()
        return SourceEvent(
            f"{source}-{position}", identity, ChangeKind.UPSERT, now, payload,
            SourceVersion(identity, "e1", f"v{position}", position), self.cursor(source, position),
            now, operation_id,
        )

    def deliver(self, source, payload, operation_id=None):
        event = self.event(source, 2, payload, operation_id)
        result = self.sync[source].apply(event, position=2, predecessor=self.cursor(source, 1))
        self.assertEqual(result.status, "applied")
        return event

    def grant(self, connection, actor, operation, kind, resource, member=None):
        Policy().grant(connection, self.tenant, actor, operation, kind, resource, member)

    def approved(self, key="run"):
        task = self.runtime.submit(self.tenant, "single", self.object.object_id, "requester", key,
                                   identity=self.identity["requester"])
        task_id = task["id"]
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.grant(connection, "requester", "read", "task", task_id)
            self.grant(connection, "requester", "export", "evidence", task_id)
            self.grant(connection, "reviewer", "read", "task", task_id)
            self.grant(connection, "reviewer", "approve", "task", task_id)
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "awaiting_approval")
        view = self.runtime.inspect(self.tenant, task_id, identity=self.identity["reviewer"])["review"]
        self.assertNotIn("_fact_fingerprint", view["grounding"])
        decision = self.runtime.decide(self.tenant, task_id, "reviewer", "approve",
                                       identity=self.identity["reviewer"], proposal_digest=view["proposal_digest"])
        self.assertEqual(decision["status"], "ready")
        return task_id

    def feedback(self, task_id):
        view = self.runtime.inspect(self.tenant, task_id, identity=self.identity["requester"], evidence=True)
        return view["source_feedback"], view["effect_recorded"]


@unittest.skipUnless(TEST_DSN, "Use verify_p2b.py for real PostgreSQL tests")
class FactRuntimeTests(FactWorkflowFixture, unittest.TestCase):
    def test_authoritative_delta_invalidates_outstanding_approval(self):
        task_id = self.approved()
        self.deliver("quality", self.quality(False))
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "blocked")
        self.assertEqual(self.remote.calls, [])
        self.assertEqual(self.feedback(task_id), (None, False))

    def test_new_proof_needs_new_approval_even_with_the_same_value(self):
        task_id = self.approved()
        self.deliver("quality", self.quality(True))
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "blocked")
        self.assertEqual(self.remote.calls, [])

    def test_revoked_evidence_prevents_an_approved_remote_write(self):
        task_id = self.approved()
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            history = self.facts.history(connection, FactField(self.object, "checksum_ok"))
            evidence = history[0]["evidence"][0]
            self.grant(connection, "reviewer", "revoke", "evidence", evidence["evidence_id"])
            event = EvidenceRevocation("quality-revocation", self.tenant, evidence["evidence_id"],
                                       evidence["revision"], self.now(), "Source certification withdrawn")
            self.facts.revoke_evidence(connection, event, self.identity["reviewer"])
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "blocked")
        self.assertEqual(self.remote.calls, [])
        self.assertEqual(self.feedback(task_id), (None, False))

    def test_legacy_revocation_waits_for_the_execution_transaction(self):
        import psycopg
        from psycopg.conninfo import make_conninfo

        from ai_native_system.adapters.postgres_facts import PostgresFacts

        task_id = self.approved()
        with self.control.transaction(tenant=self.tenant) as connection:
            evidence = self.facts.history(connection, FactField(self.object, "checksum_ok"))[0]["evidence"][0]
        event = EvidenceRevocation("legacy-revocation", self.tenant, evidence["evidence_id"],
                                   evidence["revision"], self.now(), "Source certification withdrawn")
        application_name = f"revoke-{self.tenant}"
        legacy = PostgresFacts(make_conninfo(self.control_dsn, application_name=application_name), self.tenant)
        with ThreadPoolExecutor(max_workers=1) as workers:
            with self.store.transaction(tenant=self.tenant, write=True) as connection:
                future = workers.submit(legacy.enqueue_invalidation, event)
                with psycopg.connect(TEST_DSN, autocommit=True) as admin:
                    deadline = time.monotonic() + 3
                    while time.monotonic() < deadline and not future.done():
                        waiting = admin.execute(
                            """SELECT 1 FROM pg_stat_activity
                               WHERE application_name = %s AND wait_event = 'advisory'""", (application_name,),
                        ).fetchone()
                        if waiting:
                            break
                        time.sleep(0.01)
                    else:
                        self.fail("Legacy writer did not wait for the tenant write lock")
                self.assertIsNone(connection.execute(
                    "SELECT event_id FROM fact_invalidation_outbox WHERE event_id = ?", (event.event_id,),
                ).fetchone())
            self.assertTrue(future.result(timeout=5).created)
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "blocked")
        self.assertEqual(self.remote.calls, [])

    def test_source_event_before_receipt_matches_without_second_effect(self):
        task_id = self.approved()
        self.remote.drop_after_commit = True
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "reconciling")
        self.assertEqual(self.feedback(task_id), ("waiting_both", False))
        event = self.deliver("inventory", self.inventory("verified"), task_id)
        self.assertEqual(self.feedback(task_id), ("waiting_receipt", False))
        self.assertEqual(self.runtime.reconcile(self.tenant, task_id)["status"], "completed")
        self.assertEqual(self.feedback(task_id), ("matched", True))
        self.sync["inventory"].apply(event, position=2, predecessor=self.cursor("inventory", 1))
        self.assertEqual([path for path, _ in self.remote.calls], ["/execute", "/lookup"])
        self.assertEqual(len(self.remote.operation_states()), 1)

    def test_receipt_first_and_disagreeing_source_remain_visible(self):
        task_id = self.approved()
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "completed")
        self.assertEqual(self.feedback(task_id), ("waiting_source", True))
        self.deliver("quality", self.quality(True), task_id)
        self.assertEqual(self.feedback(task_id), ("waiting_source", True))
        self.deliver("inventory", self.inventory("pending"), task_id)
        self.assertEqual(self.feedback(task_id), ("conflict", True))
        self.assertEqual([path for path, _ in self.remote.calls], ["/execute"])
        with self.store.transaction(tenant=self.tenant) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM effects").fetchone()[0], 1)
