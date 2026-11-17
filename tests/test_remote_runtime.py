import json
import os
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from ai_native_system.model import DemoModel
from ai_native_system.registry import Registry
from ai_native_system.remote import HttpRemote, RemoteError
from ai_native_system.runtime import Runtime
from ai_native_system.storage import database, digest, object_data
from ai_native_system.tools import ToolRegistry
from remote_server import RemoteFixture


FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "conformance.json"


class RemoteRuntimeTests(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.path = Path(directory) / "runtime.sqlite"
        self.remote = self.enterContext(RemoteFixture(Path(directory) / "downstream.sqlite"))
        self.registry = Registry.load(FIXTURE)
        self.registry.actions["remote_verify"] = {
            **self.registry.actions["verify_asset"], "tool": "remote.verify", "tool_version": "1",
        }
        self.registry.applications["remote_single"] = {
            **self.registry.applications["single"], "id": "remote_single", "action": "remote_verify",
        }
        self.runtime = self.open_runtime()
        self.runtime.initialize()

    def open_runtime(self, endpoint=None):
        tools = ToolRegistry()
        tools.register_remote("remote.verify", "1", HttpRemote(endpoint or self.remote.endpoint, timeout=5))
        return Runtime(self.path, self.registry, DemoModel(), tools)

    def ready(self, application="remote_single"):
        task_id = self.runtime.submit("local", application, "asset-1", "requester", "remote-test")["id"]
        self.assertEqual(self.runtime.advance("local", task_id)["status"], "awaiting_approval")
        self.assertEqual(self.runtime.decide("local", task_id, "reviewer", "approve")["status"], "ready")
        return task_id

    def calls_to(self, path):
        return [payload for route, payload in self.remote.calls if route == path]

    def prepare_without_dispatch(self, task_id):
        with patch("ai_native_system.remote_execution.dispatch", side_effect=RuntimeError("worker stopped")):
            with self.assertRaisesRegex(RuntimeError, "worker stopped"):
                self.runtime.advance("local", task_id)
        receipt, = self.runtime.inspect("local", task_id)["operations"]
        self.assertEqual((receipt["status"], receipt["attempts"]), ("prepared", 0))
        self.assertEqual(self.remote.calls, [])

    def test_real_commit_with_lost_response_is_reconciled_after_restart(self):
        registry_path = self.path.with_name("remote-registry.json")
        registry_path.write_text(json.dumps({section: getattr(self.registry, section)
                                            for section in ("types", "actions", "applications", "seed")}))
        tools_path = self.path.with_name("tools.json")
        tools_path.write_text(json.dumps({"tools": [{
            "name": "remote.verify", "version": "1", "transport": "http",
            "endpoint": self.remote.endpoint, "idempotent": True, "timeout": 5,
        }]}))
        clean_environment = {key: value for key, value in os.environ.items() if not key.startswith("AI_NATIVE_MODEL_")}
        clean_environment["PYTHONDONTWRITEBYTECODE"] = "1"

        def cli(*args):
            result = subprocess.run([
                sys.executable, "-m", "ai_native_system", "--db", str(self.path), "--registry", str(registry_path),
                "--tools-config", str(tools_path), *args,
            ], capture_output=True, text=True, env=clean_environment, cwd=FIXTURE.parents[1], timeout=12)
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)

        submitted = cli("submit", "remote_single", "asset-1", "--actor", "requester", "--request-key", "cli-remote")
        task_id = submitted["id"]
        self.assertEqual(cli("advance", task_id)["status"], "awaiting_approval")
        self.assertEqual(cli("decide", task_id, "approve", "--actor", "reviewer")["status"], "ready")
        self.remote.drop_after_commit = True
        self.assertEqual(cli("advance", task_id)["status"], "reconciling")
        self.assertEqual(self.remote.object_status(), {"state": "verified", "version": 2})
        initial = cli("inspect", task_id)
        self.assertEqual(initial["effects"], [])

        self.assertEqual(cli("reconcile", task_id)["status"], "completed")
        self.assertEqual(cli("advance", task_id)["status"], "completed")
        trace = cli("inspect", task_id)
        self.assertEqual(len(trace["operations"]), 1)
        self.assertEqual(len(trace["effects"]), 1)
        self.assertEqual(len(self.remote.operation_states()), 1)
        execution, = self.calls_to("/execute")
        lookup, = self.calls_to("/lookup")
        self.assertEqual(lookup["operation_id"], execution["operation_id"])
        self.assertEqual(lookup["request_hash"], execution["request_hash"])
        self.assertEqual({key: execution[key] for key in ("requester", "approver", "executor")},
                         {"requester": "requester", "approver": "reviewer", "executor": "worker"})
        self.assertEqual(execution["expected_version"], 1)

    def test_query_outage_and_cross_tenant_attempt_cannot_advance_an_unknown_effect(self):
        task_id = self.ready()
        self.remote.drop_after_commit = True
        self.assertEqual(self.runtime.advance("local", task_id)["status"], "reconciling")
        restarted = self.open_runtime()
        with self.assertRaises(ValueError):
            restarted.reconcile("other", task_id)
        self.assertEqual(self.calls_to("/lookup"), [])
        self.remote.lookup_unavailable = True
        self.assertEqual(restarted.reconcile("local", task_id)["status"], "reconciling")
        self.assertEqual(restarted.inspect("local", task_id)["effects"], [])
        self.assertEqual(len(self.calls_to("/execute")), 1)
        self.remote.lookup_unavailable = False
        self.assertEqual(restarted.reconcile("local", task_id)["status"], "completed")

    def test_not_found_remains_in_reconciliation_without_automatic_replay(self):
        task_id = self.ready()
        self.remote.drop_before_commit = True
        self.assertEqual(self.runtime.advance("local", task_id)["status"], "reconciling")
        self.remote.drop_before_commit = False
        self.assertEqual(self.runtime.reconcile("local", task_id)["status"], "reconciling")
        self.assertEqual(self.runtime.advance("local", task_id)["status"], "reconciling")
        self.assertEqual(len(self.calls_to("/execute")), 1)
        self.assertEqual(self.remote.operation_states(), [])
        self.assertEqual(self.remote.object_status(), {"state": "pending", "version": 1})

    def test_explicit_retry_reuses_the_same_request_after_missing_receipt(self):
        task_id = self.ready()
        self.remote.drop_before_commit = True
        self.assertEqual(self.runtime.advance("local", task_id)["status"], "reconciling")
        self.remote.drop_before_commit = False
        self.assertEqual(self.runtime.retry_remote("local", task_id, "requester")["status"], "completed")
        first, retry = self.calls_to("/execute")
        self.assertEqual(first, retry)
        self.assertEqual(len(self.remote.operation_states()), 1)
        self.assertEqual(len(self.runtime.inspect("local", task_id)["effects"]), 1)

    def test_downstream_deduplicates_committed_replay_and_rejects_a_rebound_key(self):
        task_id = self.ready()
        self.assertEqual(self.runtime.advance("local", task_id)["status"], "completed")
        request, = self.calls_to("/execute")
        committed, = self.remote.operation_states()
        adapter = HttpRemote(self.remote.endpoint)
        self.assertEqual(adapter.execute(request), committed)

        conflicting = dict(request, to_state="another-state")
        with self.assertRaises(RemoteError):
            adapter.execute(conflicting)
        del conflicting["request_hash"]
        conflicting["request_hash"] = digest(conflicting)
        with self.assertRaises(RemoteError):
            adapter.execute(conflicting)
        with self.assertRaises(RemoteError):
            adapter.lookup(dict(request, tenant="other"))
        self.assertEqual(self.remote.operation_states(), [committed])
        self.assertEqual(self.remote.object_status(), {"state": "verified", "version": 2})

    def test_lost_approval_permission_prevents_explicit_remote_retry(self):
        task_id = self.ready()
        self.remote.drop_before_commit = True
        self.assertEqual(self.runtime.advance("local", task_id)["status"], "reconciling")
        self.remote.drop_before_commit = False
        with database(self.path, write=True) as connection:
            connection.execute("UPDATE principals SET active=0 WHERE tenant='local' AND id='reviewer'")
        with self.assertRaises(PermissionError):
            self.runtime.retry_remote("local", task_id, "requester")
        self.assertEqual(len(self.calls_to("/execute")), 1)
        self.assertEqual(self.remote.operation_states(), [])
        self.assertEqual(self.runtime.inspect("local", task_id)["effects"], [])

    def test_concurrent_advances_dispatch_one_remote_execution(self):
        task_id = self.ready()
        self.remote.hold_execute_response = True
        with ThreadPoolExecutor(max_workers=2) as executor:
            original = executor.submit(self.runtime.advance, "local", task_id)
            try:
                self.assertTrue(self.remote.committed.wait(3), "remote write never committed")
                second = executor.submit(self.open_runtime().advance, "local", task_id)
                self.assertEqual(second.result(timeout=3)["status"], "completed")
            finally:
                self.remote.release_response.set()
            self.assertEqual(original.result(timeout=6)["status"], "completed")
        self.assertEqual(len(self.calls_to("/execute")), 1)
        self.assertEqual(len(self.remote.operation_states()), 1)
        self.assertEqual(len(self.runtime.inspect("local", task_id)["effects"]), 1)

    def test_cancellation_after_remote_commit_defers_to_reconciliation(self):
        task_id = self.ready()
        self.remote.hold_execute_response = True
        self.remote.drop_after_commit = True
        with ThreadPoolExecutor(max_workers=1) as executor:
            advance = executor.submit(self.runtime.advance, "local", task_id)
            try:
                self.assertTrue(self.remote.committed.wait(3), "remote write never committed")
                self.assertEqual(self.runtime.cancel("local", task_id, "requester")["status"], "reconciling")
            finally:
                self.remote.release_response.set()
            self.assertEqual(advance.result(timeout=6)["status"], "reconciling")
        self.assertEqual(self.runtime.reconcile("local", task_id)["status"], "completed")
        self.assertEqual(len(self.calls_to("/execute")), 1)
        self.assertEqual(len(self.runtime.inspect("local", task_id)["effects"]), 1)

    def test_prepared_intent_is_not_looked_up_and_resumes_first_dispatch(self):
        task_id = self.ready()
        self.prepare_without_dispatch(task_id)
        restarted = self.open_runtime()
        self.assertEqual(restarted.reconcile("local", task_id)["status"], "reconciling")
        receipt, = restarted.inspect("local", task_id)["operations"]
        self.assertEqual(receipt["status"], "prepared")
        self.assertEqual(self.remote.calls, [])
        self.assertEqual(restarted.advance("local", task_id)["status"], "completed")
        self.assertEqual([path for path, _ in self.remote.calls], ["/execute"])

    def test_prepared_intent_cancels_before_any_remote_dispatch(self):
        task_id = self.ready()
        self.prepare_without_dispatch(task_id)
        self.assertEqual(self.runtime.cancel("local", task_id, "requester")["status"], "cancelled")
        restarted = self.open_runtime()
        self.assertEqual(restarted.advance("local", task_id)["status"], "cancelled")
        receipt, = restarted.inspect("local", task_id)["operations"]
        self.assertEqual((receipt["status"], receipt["attempts"]), ("cancelled", 0))
        self.assertEqual(self.remote.calls, [])

    def test_changed_remote_endpoint_is_not_covered_by_existing_proposal(self):
        task_id = self.runtime.submit("local", "remote_single", "asset-1", "requester", "changed-destination")["id"]
        self.assertEqual(self.runtime.advance("local", task_id)["status"], "awaiting_approval")
        changed = self.open_runtime(self.remote.endpoint + "/different-endpoint")
        self.assertEqual(changed.decide("local", task_id, "reviewer", "approve")["status"], "blocked")
        self.assertEqual(self.remote.calls, [])
        self.assertEqual(changed.inspect("local", task_id)["operations"], [])

    def test_mismatched_remote_receipt_requires_a_verified_readback(self):
        task_id = self.ready()
        self.remote.wrong_execute_hash = True
        self.remote.wrong_lookup_hash = True
        self.assertEqual(self.runtime.advance("local", task_id)["status"], "reconciling")
        self.assertEqual(self.runtime.reconcile("local", task_id)["status"], "reconciling")
        self.assertEqual(self.runtime.inspect("local", task_id)["effects"], [])
        self.remote.wrong_lookup_hash = False
        self.assertEqual(self.runtime.reconcile("local", task_id)["status"], "completed")
        self.assertEqual(len(self.calls_to("/execute")), 1)

    def test_confirmed_remote_effect_does_not_overwrite_a_changed_local_projection(self):
        task_id = self.ready()
        self.remote.drop_after_commit = True
        self.assertEqual(self.runtime.advance("local", task_id)["status"], "reconciling")
        with database(self.path, write=True) as connection:
            connection.execute("UPDATE objects SET version=7 WHERE tenant='local' AND id='asset-1'")
        self.assertEqual(self.runtime.reconcile("local", task_id)["status"], "reconciliation_conflict")
        self.assertEqual(len(self.runtime.inspect("local", task_id)["effects"]), 1)
        with database(self.path) as connection:
            current = object_data(connection, "local", "asset-1")
        self.assertEqual((current["state"], current["version"]), ("pending", 7))
        self.assertEqual(self.remote.object_status(), {"state": "verified", "version": 2})

    def test_registered_remote_tool_leaves_the_existing_local_path_intact(self):
        task_id = self.ready("single")
        self.assertEqual(self.runtime.advance("local", task_id)["status"], "completed")
        self.assertEqual(len(self.runtime.inspect("local", task_id)["effects"]), 1)
        self.assertEqual(self.remote.calls, [])
