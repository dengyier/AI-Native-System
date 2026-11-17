"""Real PostgreSQL graph workflow and independent authority recovery tests."""

import os
import subprocess
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from textwrap import dedent
from threading import Event
from unittest.mock import patch

from ai_native_system.adapters.langgraph import GraphVersionError, LangGraphDriver
from ai_native_system.adapters.langgraph_postgres import PostgresGraphStore, setup_graph_postgres
from ai_native_system.fact_gate import bind_rule
from ai_native_system.gateway import configured_gateway
from ai_native_system.model_accounting import ModelAccounting, ModelBudgetError
from ai_native_system.releases import ReleaseSnapshot, ReleaseStore
from ai_native_system.runtime import Runtime
from ai_native_system.storage import row_data, task_data

from test_langgraph_postgres import graph_role
from test_model import model_server
from test_model_backend import completion_response
from test_security_entry import SecureWorkflowFixture


TEST_DSN = os.environ.get("AI_NATIVE_P6_TEST_DSN")


@unittest.skipUnless(TEST_DSN, "Use verify_p6.py for real PostgreSQL graph workflow tests")
class GraphRuntimeTests(SecureWorkflowFixture, unittest.TestCase):
    test_dsn = TEST_DSN
    tool_remote = False
    graph_version = "workflow.1"
    runtime_grants = SecureWorkflowFixture.runtime_grants + (
        "INSERT ON ai_native.model_calls, ai_native.model_attempts, ai_native.model_trace_outbox",
        "UPDATE (outcome, input_tokens, output_tokens, actual_provider, actual_model, finished_at) ON ai_native.model_attempts",
    )

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        setup_graph_postgres(cls.test_dsn)
        cls.checkpoint_dsn = graph_role(cls.test_dsn)

    def make_model(self):
        app = self.registry.applications["single"]
        app["agents"].append({"id": "review-agent", "instructions": "Review the bounded proposed action."})
        app["graph"] = {"version": self.graph_version, "deadline_seconds": 120,
                        "checks": ["object_grounded", "knowledge_grounded"]}
        if self._testMethodName == "test_failed_parallel_check_stops_at_the_published_round_limit":
            app["graph"].update(checks=["object_grounded", "relationships_grounded"],
                                on_check_failure="retry", max_rounds=3)
        if self._testMethodName == "test_graph_deadline_prevents_any_model_or_effect":
            app["graph"]["deadline_seconds"] = 1
        if self._testMethodName == "test_graph_tasks_share_the_p5_provider_concurrency_budget":
            self.enterContext(patch.dict(os.environ, {"AI_NATIVE_P6_TEST_MODEL_KEY": "graph-fixture-key"}))
            endpoint, self.requests = self.enterContext(model_server(
                result=completion_response(action="verify_asset", evidence=["asset-policy"]),
            ))
            return configured_gateway({
                "default": "primary", "allow_providers": ["openai"], "max_context_bytes": 4096,
                "limits": {"max_active": 1, "max_attempts": 1, "max_tokens": 1000, "max_cost_nanos": 10000,
                           "deadline_seconds": 20},
                "routes": {"primary": {"adapter": "litellm", "provider": "openai", "base_url": endpoint,
                                       "model": "fixture-model", "api_key_env": "AI_NATIVE_P6_TEST_MODEL_KEY",
                                       "timeout": 8, "max_output_tokens": 24, "version": "fixture.1",
                                       "policy": {"data": {"object_fields": ["checksum_ok"],
                                                           "knowledge_ids": ["asset-policy"]},
                                                  "accounting": {"price_version": "prices-a", "input_nanos": 2,
                                                                 "output_nanos": 3, "max_input_tokens": 100}}}},
            })
        return super().make_model()

    def setUp(self):
        super().setUp()
        self.checkpoints = self.enterContext(PostgresGraphStore(self.checkpoint_dsn))
        self.runtime = self.runtime_for(self.checkpoints)

    def runtime_for(self, graph_store, *, store=None, ledgers=None, queue_limit=100):
        return Runtime(store or self.store, self.registry, self.runtime.model, self.runtime.tools,
                       owp_ledgers=ledgers if ledgers is not None else self.runtime.owp_ledgers,
                       graph_store=graph_store, graph_queue_limit=queue_limit)

    def restart_runtime(self):
        return self.runtime_for(self.enterContext(PostgresGraphStore(self.checkpoint_dsn)),
                                store=self.enterContext(self.store_type(self.runtime_dsn)))

    def submit_task(self, key="request", *, runtime=None):
        runtime = runtime or self.runtime
        task = runtime.submit(self.tenant, "single", self.object.object_id, "requester", key,
                              identity=self.identity["requester"])
        with self.control.transaction(tenant=self.tenant, write=True) as tx:
            for role, operation, kind in (("requester", "read", "task"), ("requester", "cancel", "task"),
                                          ("requester", "export", "evidence"), ("reviewer", "read", "task"),
                                          ("reviewer", "approve", "task")):
                self.grant(tx, role, operation, kind, task["id"])
        return task["id"]

    def plan_to_approval(self, task_id, *, runtime=None):
        runtime = runtime or self.runtime
        for _ in range(3):
            task = runtime.advance(self.tenant, task_id)
            if task["status"] != "planning":
                break
        self.assertEqual(task["status"], "awaiting_approval")
        return runtime.inspect(self.tenant, task_id, identity=self.identity["reviewer"])["review"]

    def approve(self, task_id, review, *, runtime=None):
        runtime = runtime or self.runtime
        task = runtime.decide(self.tenant, task_id, "reviewer", "approve", identity=self.identity["reviewer"],
                              proposal_digest=review["proposal_digest"])
        self.assertEqual(task["status"], "ready")

    def checkpoint_config(self, task_id):
        thread = LangGraphDriver.thread_id(self.tenant, task_id)
        return {"configurable": {"thread_id": thread}}

    def persisted_checkpoint(self, task_id):
        config = self.checkpoint_config(task_id)
        with self.checkpoints.claim(config["configurable"]["thread_id"]) as saver:
            self.assertIsNotNone(saver)
            return saver.get_tuple(config)

    def test_legacy_task_keeps_its_backend_after_selecting_graph_release(self):
        app = self.registry.applications["single"]
        graph = app.pop("graph")
        try:
            legacy = ReleaseSnapshot.capture(self.registry, "single", self.runtime.model, self.runtime.tools,
                                             owp_profile=self.owp_profile)
        finally:
            app["graph"] = graph
        with self.control.transaction(tenant=self.tenant, write=True) as tx:
            ReleaseStore.draft(tx, self.tenant, legacy, publisher="operator")
            bind_rule(tx, self.tenant, legacy.digest, "verify_asset", actor="operator")
            ReleaseStore.publish(tx, self.tenant, legacy.digest, publisher="operator", migration_ref="P6 parity")
            ReleaseStore.select(tx, self.tenant, "single", legacy.digest, publisher="operator")
            self.grant(tx, "requester", "read", "release", legacy.digest)
        old = self.submit_task("before-selection", runtime=self.runtime_for(None))
        with self.control.transaction(tenant=self.tenant, write=True) as tx:
            ReleaseStore.select(tx, self.tenant, "single", self.release, publisher="operator")
        new = self.submit_task("after-selection")
        legacy_review = self.plan_to_approval(old)
        graph_review = self.plan_to_approval(new)
        fields = ("action", "rationale", "evidence_ids", "object_id", "from_state", "to_state")
        self.assertEqual({key: legacy_review["proposal"][key] for key in fields},
                         {key: graph_review["proposal"][key] for key in fields})
        self.assertEqual(legacy_review["proposal"]["release_digest"], legacy.digest)
        self.assertEqual(graph_review["proposal"]["release_digest"], self.release)
        self.assertIsNone(self.persisted_checkpoint(old))
        self.assertIsNotNone(self.persisted_checkpoint(new))
        for current, review in ((old, legacy_review), (new, graph_review)):
            self.approve(current, review)
            self.assertEqual(self.runtime.advance(self.tenant, current)["authorization"]["verdict"], "manual")
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_resume_approval_with_fresh_stores_preserves_one_effect_and_proof(self):
        task_id = self.submit_task()
        with patch.object(self.runtime.model, "propose", wraps=self.runtime.model.propose) as propose:
            first_stage = self.runtime.advance(self.tenant, task_id)
            self.assertEqual((first_stage["status"], first_stage["next_stage"]), ("planning", 1))
            fresh = self.restart_runtime()
            review = self.plan_to_approval(task_id, runtime=fresh)
            self.assertEqual(fresh.advance(self.tenant, task_id)["status"], "awaiting_approval")
            self.assertEqual(propose.call_count, 2)
        checkpoint = self.persisted_checkpoint(task_id)
        self.assertEqual(checkpoint.checkpoint["channel_values"]["stage"], 2)
        self.assertEqual(checkpoint.checkpoint["channel_values"]["status"], "awaiting_approval")
        self.assertNotIn("proposal", checkpoint.checkpoint["channel_values"])
        with self.assertRaisesRegex(ValueError, "proposal digest"):
            fresh.decide(self.tenant, task_id, "reviewer", "approve", identity=self.identity["reviewer"],
                         proposal_digest="0" * 64)
        self.assertEqual(fresh.advance(self.tenant, task_id)["status"], "awaiting_approval")
        self.approve(task_id, review, runtime=fresh)
        self.assertEqual(fresh.advance(self.tenant, task_id)["authorization"]["verdict"], "manual")
        self.assertEqual(self.counts(), (0, 0, 0))
        self.authorize(task_id)
        with ThreadPoolExecutor(max_workers=3) as pool:
            jobs = [pool.submit(fresh.advance, self.tenant, task_id) for _ in range(3)]
            for job in jobs:
                job.result(timeout=10)
        self.assertEqual(self.restart_runtime().advance(self.tenant, task_id)["status"], "completed")
        self.assertEqual(self.counts(), (1, 1, 1))
        view = fresh.inspect(self.tenant, task_id, identity=self.identity["requester"], evidence=True)
        self.assertTrue(view["effect_recorded"])
        self.assertEqual(view["owp_evidence"], "pending")

    def test_lost_reply_after_authority_commit_never_reexecutes_action(self):
        from cryptography.hazmat.primitives import serialization

        task_id = self.submit_task()
        self.approve(task_id, self.plan_to_approval(task_id))
        self.authorize(task_id)
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        trust_file = directory / "authority.pem"
        trust_file.write_bytes(self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
        script = dedent("""\
            import os
            import sys
            from pathlib import Path
            from cryptography.hazmat.primitives.serialization import load_pem_public_key
            from ai_native_system.adapters.langgraph_postgres import PostgresGraphStore
            from ai_native_system.adapters.owp import key_id, verify_authorization
            from ai_native_system.adapters.postgres_runtime import PostgresRuntimeStore
            from ai_native_system.gateway import ModelGateway
            from ai_native_system.model import DemoModel
            from ai_native_system.registry import Registry
            from ai_native_system.runtime import Runtime
            from ai_native_system.security import AuthorizationLedger

            class StopAfterCommit(Runtime):
                def _execute(self, *args, **kwargs):
                    task, wrote = super()._execute(*args, **kwargs)
                    if wrote and task['status'] == 'completed':
                        os._exit(73)
                    return task, wrote

            tenant, task_id, public_file = sys.argv[1:]
            public_key = load_pem_public_key(Path(public_file).read_bytes())
            ledger = AuthorizationLedger('deployment-1', lambda envelope: verify_authorization(
                envelope, {key_id(public_key): public_key},
            ))
            model = ModelGateway(default='default', max_context_bytes=65536)
            model.register('default', DemoModel())
            with PostgresRuntimeStore(os.environ['AI_NATIVE_POSTGRES_DSN']) as authority:
                with PostgresGraphStore(os.environ['AI_NATIVE_P6_CHILD_GRAPH_DSN']) as graph:
                    runtime = StopAfterCommit(authority, Registry.load('fixtures/conformance.json'), model,
                                              graph_store=graph, owp_ledgers={tenant: ledger})
                    runtime.advance(tenant, task_id)
            """)
        environment = {**os.environ, "AI_NATIVE_POSTGRES_DSN": self.runtime_dsn,
                       "AI_NATIVE_P6_CHILD_GRAPH_DSN": self.checkpoint_dsn}
        crashed = subprocess.run([sys.executable, "-B", "-c", script, self.tenant, task_id, str(trust_file)],
                                 cwd=Path(__file__).resolve().parents[1], env=environment, capture_output=True,
                                 text=True, timeout=20)
        self.assertEqual(crashed.returncode, 73, crashed.stderr)
        self.assertEqual(self.counts(), (1, 1, 1))
        fresh = self.restart_runtime()
        with patch.object(fresh, "_execute", wraps=fresh._execute) as execute:
            self.assertEqual(fresh.advance(self.tenant, task_id)["status"], "completed")
            execute.assert_not_called()
        self.assertEqual(self.counts(), (1, 1, 1))

    def test_committed_stage_is_reused_after_graph_node_crash(self):
        task_id = self.submit_task()
        plan = self.runtime._plan

        def after_stage_commit(*args, **kwargs):
            plan(*args, **kwargs)
            raise OSError("simulated process loss before graph checkpoint")

        with patch.object(self.runtime, "_plan", side_effect=after_stage_commit), self.assertRaises(OSError):
            self.runtime.advance(self.tenant, task_id)
        fresh = self.restart_runtime()
        with patch.object(fresh.model, "propose", wraps=fresh.model.propose) as propose:
            self.plan_to_approval(task_id, runtime=fresh)
            self.assertEqual(propose.call_count, 1)
        with self.store.transaction(tenant=self.tenant) as tx:
            stages = [row[0] for row in tx.execute("SELECT stage FROM steps WHERE task_id = ? ORDER BY stage", (task_id,))]
            self.assertEqual(stages, [0, 1])

    def test_failed_parallel_check_stops_at_the_published_round_limit(self):
        task_id = self.submit_task()
        with patch.object(self.runtime.model, "propose", wraps=self.runtime.model.propose) as propose:
            self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "blocked")
            propose.assert_not_called()
        saved = self.persisted_checkpoint(task_id).checkpoint["channel_values"]
        self.assertEqual(saved["round"], 3)
        self.assertTrue(saved["object_grounded"])
        self.assertFalse(saved["relationships_grounded"])
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_changed_checkpoint_binding_cannot_resume_the_task(self):
        task_id = self.submit_task()
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "planning")
        config = self.checkpoint_config(task_id)
        with self.checkpoints.claim(config["configurable"]["thread_id"]) as saver:
            saved = saver.get_tuple(config)
            saver.put(saved.config, saved.checkpoint, {**saved.metadata, "graph_binding": "x" * 64}, {})
        fresh = self.restart_runtime()
        with patch.object(fresh.model, "propose", wraps=fresh.model.propose) as propose:
            with self.assertRaisesRegex(GraphVersionError, "does not match"):
                fresh.advance(self.tenant, task_id)
            propose.assert_not_called()
        with self.store.transaction(tenant=self.tenant) as tx:
            self.assertEqual(task_data(tx, self.tenant, task_id)["next_stage"], 1)
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_revoked_openworkproof_scope_stays_blocked_after_resume(self):
        task_id = self.submit_task()
        self.approve(task_id, self.plan_to_approval(task_id))
        self.authorize(task_id)
        with self.control.transaction(tenant=self.tenant, write=True) as tx:
            self.assertTrue(self.ledger.revoke(tx, self.tenant, task_id, actor="operator", reason="Test revocation"))
        self.assertEqual(self.restart_runtime().advance(self.tenant, task_id)["status"], "blocked")
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_graph_deadline_prevents_any_model_or_effect(self):
        task_id = self.submit_task()
        stop = time.monotonic() + 4
        while True:
            with self.store.transaction(tenant=self.tenant) as tx:
                now = tx.database_time()
                deadline = task_data(tx, self.tenant, task_id)["graph_deadline"]
            if now >= deadline:
                break
            self.assertLess(time.monotonic(), stop)
            time.sleep(0.05)
        with patch.object(self.runtime.model, "propose", wraps=self.runtime.model.propose) as propose:
            self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "blocked")
            propose.assert_not_called()
        with self.store.transaction(tenant=self.tenant) as tx:
            event = tx.execute("SELECT detail FROM events WHERE task_id = ? AND event = 'policy.blocked'",
                               (task_id,)).fetchone()
        self.assertEqual(row_data(event, "detail")["detail"]["reason"], "graph_deadline")
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_queue_is_tenant_bounded_and_other_tenant_can_progress(self):
        from ai_native_system.graph_runtime import GraphQueueFull

        other = GraphRuntimeTests(self._testMethodName)
        self.addCleanup(other.doCleanups)
        other.setUp()
        ledgers = {**self.runtime.owp_ledgers, **other.runtime.owp_ledgers}
        limited = self.runtime_for(self.checkpoints, ledgers=ledgers, queue_limit=1)
        first = self.submit_task("first", runtime=limited)
        self.assertEqual(self.submit_task("first", runtime=limited), first)
        with self.assertRaises(GraphQueueFull):
            self.submit_task("over-limit", runtime=limited)
        another = other.submit_task("other-tenant", runtime=limited)
        progress = limited.work_graph((self.tenant, other.tenant), per_tenant=1)
        self.assertEqual({(row["tenant"], row["id"]) for row in progress},
                         {(self.tenant, first), (other.tenant, another)})
        self.assertEqual(limited.cancel(self.tenant, first, "requester", identity=self.identity["requester"])["status"],
                         "cancelled")
        self.assertNotEqual(self.submit_task("over-limit", runtime=limited), first)

    def test_cancellation_while_agent_runs_does_not_record_a_late_stage(self):
        task_id = self.submit_task()
        started, release = Event(), Event()
        propose = self.runtime.model.propose

        def held(*args, **kwargs):
            response = propose(*args, **kwargs)
            started.set()
            if not release.wait(10):
                raise TimeoutError("test model reply was not released")
            return response

        with patch.object(self.runtime.model, "propose", side_effect=held), ThreadPoolExecutor() as pool:
            job = pool.submit(self.runtime.advance, self.tenant, task_id)
            try:
                self.assertTrue(started.wait(10))
                self.assertEqual(self.runtime.cancel(self.tenant, task_id, "requester",
                                                     identity=self.identity["requester"])["status"], "cancelled")
            finally:
                release.set()
            self.assertEqual(job.result(timeout=10)["status"], "cancelled")
        with self.store.transaction(tenant=self.tenant) as tx:
            self.assertEqual(task_data(tx, self.tenant, task_id)["next_stage"], 0)
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_graph_tasks_share_the_p5_provider_concurrency_budget(self):
        with self.control.transaction(tenant=self.tenant, write=True) as tx:
            for actor in ("requester", "worker"):
                self.grant(tx, actor, "use", "model", "primary")
        first, second = self.submit_task("first"), self.submit_task("second")
        started, release = Event(), Event()
        adapter = self.runtime.model._routes["primary"].adapter
        original = adapter.propose

        def held(*args, **kwargs):
            response = original(*args, **kwargs)
            started.set()
            if not release.wait(10):
                raise TimeoutError("test provider reply was not released")
            return response

        accounting = ModelAccounting(self.store)
        with patch.object(adapter, "propose", side_effect=held), ThreadPoolExecutor(max_workers=1) as pool:
            active = pool.submit(self.runtime.advance, self.tenant, first)
            try:
                self.assertTrue(started.wait(10))
                self.assertEqual(accounting.usage(self.tenant)["totals"]["active_attempts"], 1)
                with self.assertRaisesRegex(ModelBudgetError, "concurrency"):
                    self.runtime.advance(self.tenant, second)
                self.assertEqual(len(self.requests), 1)
            finally:
                release.set()
            self.assertEqual(active.result(timeout=10)["next_stage"], 1)
        self.assertEqual(self.runtime.advance(self.tenant, second)["next_stage"], 1)
        totals = accounting.usage(self.tenant)["totals"]
        self.assertEqual((totals["attempts"], totals["active_attempts"], totals["known_cost_nanos"]), (2, 0, 232))
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(self.counts(), (0, 0, 0))
