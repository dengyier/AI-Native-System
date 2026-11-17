"""Run a protected LangGraph task through the P4 signed MCP recovery path."""

import os
import unittest

from ai_native_system.adapters.langgraph_postgres import PostgresGraphStore, setup_graph_postgres
from ai_native_system.runtime import Runtime
from ai_native_system.source_receipt import verify_source_receipt

import test_p4_workflow as p4
from test_langgraph_postgres import graph_role


DSN = os.environ.get("AI_NATIVE_P6_TEST_DSN")


@unittest.skipUnless(DSN and p4.SOURCE_DSN, "Use verify_p6.py with the signed remote suite")
class GraphSignedRemoteTests(p4.P4WorkflowTests):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        setup_graph_postgres(DSN)
        cls.graph_dsn = graph_role(DSN)

    def make_model(self):
        self.registry.applications["single"]["graph"] = {"version": "signed-mcp-v1", "deadline_seconds": 120}
        return super().make_model()

    def new_runtime(self):
        return Runtime(self.enterContext(self.store_type(self.runtime_dsn)), self.registry,
                       self.runtime.model, self.runtime.tools, owp_ledgers=self.runtime.owp_ledgers,
                       graph_store=self.enterContext(PostgresGraphStore(self.graph_dsn)))

    def test_graph_keeps_the_signed_remote_operation_after_restart(self):
        self.runtime = self.new_runtime()
        task_id = self.approved()
        authorization = self.authorize(task_id)
        (self.directory / "drop_after_commit").touch()
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "reconciling")
        self.source_process.wait(timeout=5)
        item, count = self.native()
        self.assertEqual((item[0], count), ("verified", 1))
        self.assertEqual(self.counts(), (0, 1, 0))

        self.start_source()
        self.runtime = self.new_runtime()
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["authorization"]["reason"], "reconciliation_queued")
        self.assertEqual(self.process_reconciliation()[0]["status"], "completed")
        stored = self.stored(task_id)
        self.assertEqual(stored["attempts"], 1)
        proof = verify_source_receipt(stored["response"], self.source_keys, operation=stored["payload"],
                                      authorization_digest=authorization["digest"])
        self.assertEqual(proof["result"]["objects"][0]["version"], item[1])
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "completed")
        self.assertEqual((self.counts(), self.native()), ((1, 1, 1), (item, 1)))


def load_tests(loader, _tests, _pattern):
    # The P4 fixture includes its own standalone suite. Exercise its graph entry here.
    return loader.loadTestsFromName("GraphSignedRemoteTests.test_graph_keeps_the_signed_remote_operation_after_restart",
                                    module=__import__(__name__))
