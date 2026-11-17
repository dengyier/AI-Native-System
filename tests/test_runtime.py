import json
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path

from ai_native_system.model import DemoModel, ModelError, Proposal
from ai_native_system.registry import Registry
from ai_native_system.runtime import Runtime

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "conformance.json"


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name) / "state.sqlite"
        self.registry = Registry.load(FIXTURE)
        self.runtime = Runtime(self.path, self.registry, DemoModel())
        self.runtime.initialize()

    def submit(self, key="sample", app="single", object_id="asset-1", actor="requester"):
        return self.runtime.submit("local", app, object_id, actor, key)

    def plan(self, task, runtime=None):
        return (runtime or self.runtime).advance("local", task["id"])

    def ready(self, key="sample"):
        task = self.submit(key)
        self.assertEqual(self.plan(task)["status"], "awaiting_approval")
        return self.runtime.decide("local", task["id"], "reviewer", "approve")

    def trace(self, task):
        return self.runtime.inspect("local", task["id"])

    def test_request_key_deduplicates_and_rejects_mismatched_payload(self):
        task = self.submit()
        self.assertEqual(task["id"], self.submit()["id"])
        with self.assertRaises(ValueError):
            self.submit(object_id="asset-stale")
        self.assertEqual(len(self.trace(task)["events"]), 1)

    def test_same_kernel_runs_single_and_two_stage_configurations(self):
        single = self.ready()
        self.assertEqual(self.plan(single)["status"], "completed")
        collaboration = self.submit("multi", "collaboration", "artifact-1")
        progressed = self.plan(collaboration)
        self.assertEqual((progressed["status"], progressed["next_stage"]), ("planning", 1))
        restarted = Runtime(self.path, self.registry, DemoModel())
        proposed = self.plan(collaboration, restarted)
        self.assertEqual(proposed["status"], "awaiting_approval")
        restarted.decide("local", collaboration["id"], "reviewer", "approve")
        self.assertEqual(self.plan(collaboration, restarted)["status"], "completed")
        for task, expected in [(single, ["planner"]), (collaboration, ["analyst", "review_agent"])]:
            trace = self.trace(task)
            self.assertEqual([step["agent_id"] for step in trace["steps"]], expected)
            self.assertEqual(len(trace["effects"]), 1)
            events = {event["event"] for event in trace["events"]}
            self.assertTrue({"model.completed", "approval.recorded", "policy.allowed", "tool.committed"} <= events)
        self.assertIn("handoff.received", [e["event"] for e in self.trace(collaboration)["events"]])

    def test_cross_tenant_access_and_unauthorized_approval_blocked(self):
        self.assertEqual(self.submit("foreign", object_id="asset-2")["status"], "blocked")
        task = self.submit()
        self.plan(task)
        with self.assertRaises(ValueError):
            self.runtime.inspect("other", task["id"])
        with self.assertRaises(PermissionError):
            self.runtime.decide("local", task["id"], "requester", "approve")
        self.assertEqual(self.trace(task)["task"]["status"], "awaiting_approval")

    def test_reject_and_invalid_business_state_do_not_write(self):
        task = self.submit()
        self.plan(task)
        self.runtime.decide("local", task["id"], "reviewer", "reject")
        self.assertEqual(self.plan(task)["status"], "rejected")
        self.assertEqual(self.trace(task)["effects"], [])
        stale = self.submit("stale", object_id="asset-stale")
        self.assertEqual(self.plan(stale)["status"], "blocked")

    def test_pending_approval_binds_version_and_configuration(self):
        first = self.ready("A")
        second = self.ready("B")
        self.assertEqual(self.plan(first)["status"], "completed")
        self.assertEqual(self.plan(second)["status"], "blocked")
        self.assertEqual(self.trace(second)["effects"], [])

    def test_registry_change_does_not_run_old_approval(self):
        task = self.ready()
        self.registry.applications["single"]["version"] = 999
        self.assertEqual(self.plan(task)["status"], "blocked")
        self.assertEqual(self.trace(task)["effects"], [])

    def test_rechecks_revoked_approver_at_write(self):
        task = self.ready()
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("UPDATE principals SET active = 0 WHERE id = 'reviewer' AND tenant = 'local'")
        self.assertEqual(self.plan(task)["status"], "blocked")

    def test_approval_digest_binds_exact_proposal(self):
        task = self.ready()
        tampered = {**task["proposal"], "action": "unexpected"}
        with closing(sqlite3.connect(self.path)) as connection, connection:
            connection.execute("UPDATE tasks SET proposal = ? WHERE id = ?", (json.dumps(tampered), task["id"]))
        self.assertEqual(self.plan(task)["status"], "blocked")

    def test_timeouts_and_duplicates_commit_once(self):
        task = self.ready()
        with self.assertRaises(TimeoutError):
            self.runtime.advance("local", task["id"], "before-commit")
        self.assertEqual(self.trace(task)["task"]["status"], "ready")
        self.assertEqual(self.trace(task)["effects"], [])
        restarted = Runtime(self.path, self.registry, DemoModel())
        with self.assertRaises(TimeoutError):
            restarted.advance("local", task["id"], "after-commit")
        with ThreadPoolExecutor(max_workers=4) as pool:
            completed = list(pool.map(lambda _: self.plan(task)["status"], range(4)))
        self.assertEqual(completed, ["completed"] * 4)
        self.assertEqual(len(self.trace(task)["effects"]), 1)

    def test_untrusted_model_cannot_invent_action_or_evidence(self):
        class InventedAction:
            def propose(self, context):
                return Proposal("admin-write", "untrusted", ("unknown",))
        task = self.submit()
        runtime = Runtime(self.path, self.registry, InventedAction())
        self.assertEqual(self.plan(task, runtime)["status"], "blocked")
        self.assertEqual(self.trace(task)["effects"], [])

    def test_provider_can_abstain_without_creating_approval_or_write(self):
        class Abstain:
            def propose(self, context):
                return Proposal(None, "Not enough evidence for a proposal", ())
        task = self.submit()
        state = self.plan(task, Runtime(self.path, self.registry, Abstain()))
        self.assertEqual(state["status"], "no_action")
        self.assertIsNone(state["proposal"])
        with self.assertRaises(ValueError):
            self.runtime.decide("local", task["id"], "reviewer", "approve")
        self.assertEqual(self.trace(task)["effects"], [])

    def test_domain_preconditions_block_a_model_from_offering_an_invalid_action(self):
        linked = self.submit("unverified", "collaboration", "artifact-1")
        self.assertEqual(self.plan(linked)["status"], "blocked")
        self.assertEqual(self.trace(linked)["steps"], [])
        with closing(sqlite3.connect(self.path)) as connection, connection:
            properties = json.dumps({"label": "Invalid check", "checksum_ok": False})
            connection.execute("UPDATE objects SET properties = ? WHERE tenant = 'local' AND id = 'asset-1'",
                               (properties,))
        invalid = self.submit("bad-property")
        self.assertEqual(self.plan(invalid)["status"], "blocked")
        self.assertEqual(self.trace(invalid)["steps"], [])

    def test_model_error_can_resume_without_losing_prior_agent_output(self):
        self.plan(self.ready("source"))
        task = self.submit("multi", "collaboration", "artifact-1")
        self.plan(task)
        class Intermittent:
            def propose(self, context):
                if context["handoff"]["agent_id"] != "analyst":
                    raise AssertionError("missing upstream result")
                raise ModelError("timeout")
        with self.assertRaises(ModelError):
            self.plan(task, Runtime(self.path, self.registry, Intermittent()))
        self.assertEqual(self.trace(task)["task"]["next_stage"], 1)
        self.assertEqual(self.plan(task)["status"], "awaiting_approval")
        self.assertEqual(len(self.trace(task)["steps"]), 2)


if __name__ == "__main__":
    unittest.main()
