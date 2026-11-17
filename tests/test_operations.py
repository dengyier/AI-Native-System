import sqlite3
import unittest
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import test_runtime
from ai_native_system.model import DemoModel, ModelError
from ai_native_system.runtime import Runtime
from ai_native_system.tools import ToolRegistry


class OperationsTests(unittest.TestCase):
    setUp = test_runtime.RuntimeTests.setUp
    submit = test_runtime.RuntimeTests.submit
    trace = test_runtime.RuntimeTests.trace

    def test_concurrent_stage_calls_once_and_cancel_discards_late_result(self):
        entered, release = threading.Event(), threading.Event()
        class SlowModel:
            calls = 0
            def propose(self, context):
                self.calls += 1
                entered.set()
                if not release.wait(5):
                    raise ModelError("test timeout")
                return DemoModel().propose(context)
        provider = SlowModel()
        runtime = Runtime(self.path, self.registry, provider)
        task = self.submit()
        with ThreadPoolExecutor(max_workers=2) as pool:
            pending = pool.submit(runtime.advance, "local", task["id"])
            self.assertTrue(entered.wait(2))
            runtime.advance("local", task["id"])
            self.assertEqual(provider.calls, 1)
            runtime.cancel("local", task["id"], "requester")
            release.set()
            self.assertEqual(pending.result()["status"], "cancelled")
        self.assertEqual(self.trace(task)["steps"], [])
        self.assertEqual(self.trace(task)["effects"], [])

    def test_expired_claim_is_recovered_and_budget_stops_retry(self):
        self.registry.applications["single"]["max_model_calls"] = 1
        task = self.submit()
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("INSERT INTO execution_claims VALUES (?, 'dead', ?)", (task["id"], time.time()-1))
        class Failed:
            def propose(self, context):
                raise ModelError("offline")
        runtime = Runtime(self.path, self.registry, Failed())
        self.assertEqual(runtime.work("local")[0]["status"], "retryable")
        self.assertEqual(runtime.work("local")[0]["status"], "blocked")
        self.assertEqual(self.trace(task)["events"][-1]["detail"]["reason"], "model_call_budget")

    def test_custom_transactional_tool_rolls_back_on_error(self):
        def fail(connection, task, action, ground):
            connection.execute("UPDATE objects SET state = 'verified' WHERE tenant='local' AND id='asset-1'")
            raise ValueError("tool failed")
        tools = ToolRegistry()
        tools.register("test", "1", fail)
        self.registry.actions["verify_asset"].update(tool="test", tool_version="1")
        runtime = Runtime(self.path, self.registry, DemoModel(), tools)
        task = self.submit()
        runtime.advance("local", task["id"])
        runtime.decide("local", task["id"], "reviewer", "approve")
        with self.assertRaises(ValueError):
            runtime.advance("local", task["id"])
        self.assertEqual(self.trace(task)["task"]["status"], "ready")
        self.assertEqual(self.trace(task)["effects"], [])
        with closing(sqlite3.connect(self.path)) as connection, connection:
            self.assertEqual(connection.execute("SELECT state FROM objects WHERE tenant='local' AND id='asset-1'").fetchone()[0], "pending")

    def test_worker_and_metrics_are_tenant_scoped(self):
        task = self.submit()
        self.assertEqual(self.runtime.work("local")[0]["status"], "awaiting_approval")
        self.assertEqual(self.runtime.work("other"), [])
        metrics = self.runtime.metrics("local")
        self.assertEqual(metrics["model_calls_completed"], 1)
        self.assertEqual(metrics["calls_without_usage"], 1)
        self.assertEqual(self.runtime.metrics("other")["model_calls_completed"], 0)

    def test_model_routes_are_used_by_runtime_stages(self):
        from ai_native_system.gateway import ModelGateway
        calls = []
        class Named:
            def __init__(self, name):
                self.name = name
            def propose(self, context):
                calls.append((self.name, context["agent"]["id"]))
                return DemoModel().propose(context)
        gateway = ModelGateway(default="default")
        gateway.register("default", Named("default"))
        gateway.register("review", Named("review"))
        self.registry.applications["collaboration"]["agents"][1]["model"] = "review"
        runtime = Runtime(self.path, self.registry, gateway)
        source = self.submit("source")
        runtime.advance("local", source["id"])
        runtime.decide("local", source["id"], "reviewer", "approve")
        runtime.advance("local", source["id"])
        task = self.submit("multi", "collaboration", "artifact-1")
        runtime.advance("local", task["id"])
        runtime.advance("local", task["id"])
        self.assertEqual(calls, [("default", "planner"), ("default", "analyst"), ("review", "review_agent")])
        self.assertEqual(self.trace(task)["task"]["status"], "awaiting_approval")

    def test_database_without_claim_table_migrates_without_resetting_tasks(self):
        task = self.submit()
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("DROP TABLE execution_claims")
        migrated = Runtime(self.path, self.registry, DemoModel())
        self.assertEqual(migrated.advance("local", task["id"])["status"], "awaiting_approval")
