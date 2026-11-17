import threading
import unittest
from contextlib import contextmanager
from dataclasses import replace
from importlib.util import find_spec

from ai_native_system.adapters.langgraph import GraphVersionError, LangGraphDriver
from ai_native_system.graph_contract import GraphSpec


class _MemoryStore:
    def __init__(self):
        from langgraph.checkpoint.memory import InMemorySaver

        self.saver = InMemorySaver()

    @contextmanager
    def claim(self, thread):
        yield self.saver


@unittest.skipUnless(find_spec("langgraph"), "Install the pinned LangGraph integration")
class LangGraphDriverTests(unittest.TestCase):
    def setUp(self):
        self.store = _MemoryStore()
        self.task = {"status": "planning", "next_stage": 0, "private": "never-checkpoint-this-field"}
        self.spec = GraphSpec.from_document({"version": "v1"})
        self.calls = []

    def observe(self):
        return dict(self.task)

    def plan(self, stage):
        self.assertEqual(stage, self.task["next_stage"])
        self.calls.append(("plan", stage))
        self.task["next_stage"] += 1
        if self.task["next_stage"] == 2:
            self.task["status"] = "awaiting_approval"
        return self.observe()

    def execute(self, status):
        self.assertEqual(status, self.task["status"])
        self.calls.append(("execute", status))
        self.task["status"] = "completed"
        return self.observe()

    def block(self, reason):
        self.calls.append(("block", reason))
        self.task["status"] = "blocked"
        return self.observe()

    def advance(self, *, check=lambda _: True, plan=None, execute=None, release="published-release", tenant="tenant"):
        driver = LangGraphDriver(self.store)
        return driver.advance(tenant, "task", self.spec, release_digest=release, observe=self.observe,
                              plan=plan or self.plan, execute=execute or self.execute, check=check, block=self.block)

    def test_sequential_resume_waits_for_authoritative_human_approval(self):
        self.assertEqual(self.advance()["next_stage"], 1)
        self.assertEqual(self.advance()["status"], "awaiting_approval")
        self.assertEqual(self.advance()["status"], "awaiting_approval")
        checkpoint = self.store.saver.get_tuple({"configurable": {"thread_id": LangGraphDriver.thread_id("tenant", "task")}})
        self.assertNotIn("never-checkpoint-this-field", repr(checkpoint))
        self.task["status"] = "ready"
        self.assertEqual(self.advance()["status"], "completed")
        self.assertEqual(self.advance()["status"], "completed")
        self.assertEqual(self.calls, [("plan", 0), ("plan", 1), ("execute", "ready")])

    def test_replay_does_not_plan_a_committed_stage_or_execute_a_committed_effect(self):
        def lost_stage_response(stage):
            self.plan(stage)
            raise TimeoutError("commit response lost")

        with self.assertRaises(TimeoutError):
            self.advance(plan=lost_stage_response)
        self.assertEqual(self.advance()["next_stage"], 1)
        self.assertEqual(self.calls, [("plan", 0)])
        self.assertEqual(self.advance()["status"], "awaiting_approval")
        self.task["status"] = "ready"

        def lost_effect_response(status):
            self.execute(status)
            raise TimeoutError("commit response lost")

        with self.assertRaises(TimeoutError):
            self.advance(execute=lost_effect_response)
        self.assertEqual(self.advance()["status"], "completed")
        self.assertEqual(self.calls, [("plan", 0), ("plan", 1), ("execute", "ready")])

    def test_check_rounds_fan_out_and_retry_finitely_before_stopping(self):
        checks = ("object_grounded", "relationships_grounded")
        self.spec = GraphSpec.from_document({"version": "v1", "checks": list(checks),
                                              "on_check_failure": "retry", "max_rounds": 2})
        barrier = threading.Barrier(2)
        called = []

        def check(name):
            called.append(name)
            barrier.wait(5)
            return name == "object_grounded"

        self.assertEqual(self.advance(check=check)["status"], "blocked")
        self.assertCountEqual(called, checks * 2)
        self.assertEqual(self.calls, [("block", "graph_checks_failed")])

    def test_ready_replay_defers_to_authoritative_reconciliation(self):
        self.task.update(status="ready", next_stage=2)

        def lost_remote_response(status):
            self.calls.append(("dispatch", status))
            self.task["status"] = "reconciling"
            raise TimeoutError("remote response lost")

        with self.assertRaises(TimeoutError):
            self.advance(execute=lost_remote_response)
        self.assertEqual(self.advance()["status"], "reconciling")
        self.assertEqual(self.calls, [("dispatch", "ready")])
        self.assertEqual(self.advance()["status"], "completed")
        self.assertEqual(self.calls, [("dispatch", "ready"), ("execute", "reconciling")])

    def test_successful_checks_admit_only_one_stage(self):
        self.spec = GraphSpec.from_document({"version": "v1", "checks": ["knowledge_grounded", "object_grounded"]})
        checked = []

        def check(name):
            checked.append(name)
            return True

        self.assertEqual(self.advance(check=check)["next_stage"], 1)
        self.assertCountEqual(checked, self.spec.checks)
        self.assertEqual(self.calls, [("plan", 0)])

    def test_reject_or_cancel_from_pending_human_approval_has_no_effect(self):
        for tenant, state in (("tenant-a", "rejected"), ("tenant-b", "cancelled")):
            with self.subTest(state=state):
                self.task.update(status="planning", next_stage=1)
                self.assertEqual(self.advance(tenant=tenant)["status"], "awaiting_approval")
                self.task["status"] = state
                self.assertEqual(self.advance(tenant=tenant)["status"], state)
        self.assertEqual(self.calls, [("plan", 1), ("plan", 1)])

    def test_release_and_graph_version_mismatch_fail_closed(self):
        self.advance()
        with self.assertRaises(GraphVersionError):
            self.advance(release="different-release")
        self.spec = replace(self.spec, version="v2")
        with self.assertRaises(GraphVersionError):
            self.advance()
        self.assertEqual(self.calls, [("plan", 0)])
        self.assertEqual(self.advance(tenant="different-tenant")["status"], "awaiting_approval")
