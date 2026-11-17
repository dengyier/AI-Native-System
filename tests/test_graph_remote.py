"""Verify that graph recovery preserves remote intent, deadline and receipt semantics."""

import os
import time
import unittest
from unittest.mock import patch

from ai_native_system.adapters.langgraph_postgres import PostgresGraphStore, setup_graph_postgres
from ai_native_system.remote_execution import call_and_record, operation
from ai_native_system.runtime import Runtime
from ai_native_system.storage import task_data

from test_langgraph_postgres import graph_role
from test_security_entry import SecureWorkflowFixture


DSN = os.environ.get("AI_NATIVE_P6_TEST_DSN")


@unittest.skipUnless(DSN, "Use verify_p6.py for real PostgreSQL graph workflow tests")
class GraphRemoteTests(SecureWorkflowFixture, unittest.TestCase):
    test_dsn = DSN

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        setup_graph_postgres(DSN)
        cls.graph_dsn = graph_role(DSN)

    def make_model(self):
        expires = self._testMethodName == "test_expired_prepared_remote_intent_never_dispatches"
        self.registry.applications["single"]["graph"] = {"version": "source-p6", "deadline_seconds": 5 if expires else 120}
        return super().make_model()

    def setUp(self):
        super().setUp()
        self.runtime = self.restart(self.ledger)

    def restart(self, ledger):
        return Runtime(self.enterContext(self.store_type(self.runtime_dsn)), self.registry,
                       self.runtime.model, self.runtime.tools, owp_ledgers={self.tenant: ledger},
                       graph_store=self.enterContext(PostgresGraphStore(self.graph_dsn)))

    def test_lost_remote_reply_recovers_by_lookup_after_graph_and_worker_restart(self):
        task_id = self.approved()
        self.authorize(task_id)
        self.remote.drop_after_commit = True
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "reconciling")
        self.assertEqual(self.counts(), (0, 1, 0))
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.assertTrue(self.ledger.revoke(connection, self.tenant, task_id, actor="operator", reason="Recalled"))
        recovered = self.restart(self.ledger_at("deployment-2"))
        self.assertEqual(recovered.advance(self.tenant, task_id)["status"], "completed")
        self.assertEqual(recovered.advance(self.tenant, task_id)["status"], "completed")
        self.assertEqual(self.counts(), (1, 1, 1))
        self.assertEqual([path for path, _ in self.remote.calls], ["/execute", "/lookup"])

    def test_expired_prepared_remote_intent_never_dispatches(self):
        task_id = self.approved()
        self.authorize(task_id)
        with patch.object(self.runtime, "_dispatch_remote", side_effect=TimeoutError("process lost after prepare")):
            with self.assertRaises(TimeoutError):
                self.runtime.advance(self.tenant, task_id)
        with self.store.transaction(tenant=self.tenant) as connection:
            self.assertEqual(operation(connection, task_id)["status"], "prepared")
            remaining = task_data(connection, self.tenant, task_id)["graph_deadline"] - connection.database_time()
        time.sleep(max(remaining, 0) + 0.04)
        self.assertEqual(self.restart(self.ledger).advance(self.tenant, task_id)["status"], "blocked")
        with self.store.transaction(tenant=self.tenant) as connection:
            self.assertEqual(operation(connection, task_id)["status"], "cancelled")
        self.assertEqual(self.counts(), (0, 0, 0))
        self.assertEqual(self.remote.calls, [])

    def test_deadline_reached_after_dispatch_commit_allows_only_lookup(self):
        task_id = self.approved()
        self.authorize(task_id)

        def delayed(*args, send_before, **kwargs):
            self.assertIsNotNone(send_before)
            return call_and_record(*args, send_before=0, **kwargs)

        with patch("ai_native_system.remote_execution.call_and_record", side_effect=delayed):
            self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "reconciling")
        self.assertEqual(self.remote.calls, [])
        with self.store.transaction(tenant=self.tenant) as connection:
            self.assertEqual(operation(connection, task_id)["status"], "unknown")
        self.restart(self.ledger).advance(self.tenant, task_id)
        self.assertEqual([path for path, _ in self.remote.calls], ["/lookup"])
        self.assertEqual(self.counts(), (0, 1, 0))
