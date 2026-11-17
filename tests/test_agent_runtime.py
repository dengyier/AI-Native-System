"""Real executor/P5/OWP integration with a separate Agent process."""

import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from ai_native_system.agent_process import AgentProcessClient
from ai_native_system.gateway import configured_gateway
from ai_native_system.model import ModelError, Proposal
from ai_native_system.model_accounting import ModelAccounting
from ai_native_system.releases import ReleaseStore

from test_model import model_server
from test_model_backend import completion_response
from test_security_entry import SecureWorkflowFixture


ROOT = Path(__file__).resolve().parents[1]
TEST_DSN = os.environ.get("AI_NATIVE_P9_TEST_DSN")
_KEY = "AI_NATIVE_P9_TEST_MODEL_ONLY_KEY"


@unittest.skipUnless(TEST_DSN, "Use verify_p9_recovery.py --only agent against PostgreSQL")
class AgentRuntimeTests(SecureWorkflowFixture, unittest.TestCase):
    test_dsn = TEST_DSN
    tool_remote = False
    runtime_grants = SecureWorkflowFixture.runtime_grants + (
        "INSERT ON ai_native.model_calls, ai_native.model_attempts, ai_native.model_trace_outbox",
        "UPDATE (outcome, input_tokens, output_tokens, actual_provider, actual_model, finished_at) ON ai_native.model_attempts",
    )

    def make_model(self):
        self.directory = Path(self.enterContext(TemporaryDirectory(prefix="ai9-")))
        self.directory.chmod(0o700)
        self.socket = self.directory / "agent.sock"
        answer = completion_response(action="verify_asset", evidence=["asset-policy"])
        endpoint, self.provider_requests = self.enterContext(model_server(result=answer))
        self.config = {
            "default": "default", "allow_providers": ["openai"], "max_context_bytes": 4096,
            "limits": {"max_active": 2, "max_attempts": 1, "max_tokens": 5000, "max_cost_nanos": 100000,
                       "deadline_seconds": 15},
            "routes": {"default": {"adapter": "litellm", "version": "model-v1", "base_url": endpoint,
                                   "model": "configured-agent-model", "timeout": 10, "provider": "openai",
                                   "api_key_env": _KEY, "max_output_tokens": 32,
                                   "policy": {"data": {"object_fields": ["checksum_ok"], "knowledge_ids": ["asset-policy"]},
                                              "accounting": {"price_version": "sample-price", "input_nanos": 2,
                                                             "output_nanos": 3, "max_input_tokens": 100}}}},
        }
        self.models_path = self.directory / "models.json"
        self.models_path.write_text(json.dumps(self.config), encoding="utf-8")
        self.models_path.chmod(0o600)
        return configured_gateway(self.config, agent=AgentProcessClient(self.socket))

    def setUp(self):
        super().setUp()
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            for actor in ("requester", "worker"):
                self.grant(connection, actor, "use", "model", "default")

    def start_agent(self):
        env = {"PATH": os.defpath, _KEY: "fixture-key-in-agent-process-only"}
        process = subprocess.Popen((sys.executable, "-B", "-m", "ai_native_system.agent_process",
                                    "--socket", str(self.socket), "--models", str(self.models_path)),
                                   cwd=ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.stop_agent, process)
        stop = time.monotonic() + 15
        while process.poll() is None and time.monotonic() < stop:
            if self.socket.is_socket():
                return process
            time.sleep(0.025)
        self.fail(f"Agent process did not open its private socket (status {process.poll()})")

    @staticmethod
    def stop_agent(process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

    def test_managed_agent_proposal_only_reaches_tool_through_original_authority(self):
        self.start_agent()
        gateway = self.runtime.model
        adapter = gateway._routes["default"].adapter
        with self.control.transaction(tenant=self.tenant) as connection:
            snapshot = ReleaseStore.get(connection, self.tenant, self.release).snapshot
            snapshot.check_adapters(configured_gateway(self.config), self.runtime.tools)
        with patch.object(adapter, "_invoke", side_effect=AssertionError("Executor used the direct provider transport")):
            task_id = self.approved()
        self.assertEqual(self.counts(), (0, 0, 0))
        self.authorize(task_id)
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "completed")
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "completed")
        self.assertEqual(self.counts(), (1, 1, 1))
        request, = self.provider_requests
        self.assertEqual(request[1], "Bearer fixture-key-in-agent-process-only")
        user = request[2]["messages"][1]["content"]
        self.assertEqual(json.loads(user)["object"]["properties"], {"checksum_ok": True})
        self.assertNotIn("Source fixture", user)
        self.assertNotIn(task_id, user)
        self.assertEqual(ModelAccounting(self.store).usage(self.tenant)["totals"]["known_cost_nanos"], 116)

    def test_agent_unavailability_and_invalid_proposal_are_fail_closed(self):
        task_id = self.runtime.submit(self.tenant, "single", "asset-1", "requester", "agent-unavailable",
                                      identity=self.identity["requester"])["id"]
        with self.assertRaises(ModelError):
            self.runtime.advance(self.tenant, task_id)
        self.assertEqual((self.provider_requests, self.counts()), ([], (0, 0, 0)))
        adapter = self.runtime.model._routes["default"].adapter
        with patch.object(adapter._agent, "propose", return_value=Proposal(
            "unregistered_action", "arbitrary proposal", ("asset-policy",), "openai", "agent-model", 1, 1,
        )):
            with self.assertRaisesRegex(ModelError, "invalid isolated Agent proposal"):
                self.runtime.advance(self.tenant, task_id)
        self.assertEqual(self.counts(), (0, 0, 0))
        self.start_agent()
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "awaiting_approval")
