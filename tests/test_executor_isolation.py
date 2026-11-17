"""Observe the process, filesystem, network and RPC boundaries in a Linux deployment."""

import importlib.util
import json
import os
import unittest
from pathlib import Path


ISOLATION = Path(__file__).resolve().parents[1] / "deployment" / "isolation"


@unittest.skipUnless(os.environ.get("AI_NATIVE_P9_ISOLATION_SUITE") == "1", "Run deployment/isolation/verify.py")
class ExecutorIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("p9_isolation_harness", ISOLATION / "verify.py")
        harness = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(harness)
        cls.deployment = cls.enterClassContext(harness.disposable_isolation())

    def test_agent_has_no_authority_network_route(self):
        network = self.deployment.inspect_network("agent")
        self.assertTrue(network["Internal"])
        self.assertFalse(network["EnableIPv6"])
        self.assertEqual(network["Options"]["com.docker.network.bridge.gateway_mode_ipv4"], "isolated")
        targets = self.deployment.targets()
        reachable = {name: True for name in targets}
        self.assertEqual(self.deployment.probe("executor-fixture", "network", json.dumps(targets)), reachable)
        targets["model"] = ("127.0.0.1", 18789)
        self.assertEqual(self.deployment.probe("agent", "network", json.dumps(targets)),
                         {"postgres": False, "executor-fixture": False, "source-fixture": False, "model": True})

    def test_agent_lacks_business_files_credentials_and_runtime_code(self):
        result = self.deployment.probe("agent", "filesystem")
        self.assertEqual(result, {"uid": 65532, "capabilities": 0, "no_new_privileges": True, "seccomp": 2,
                                  "source_secret_readable": False, "docker_socket_exists": False,
                                  "business_environment": False, "model_environment": True,
                                  "image_root_readonly": True, "executor_module": False})
        executor = self.deployment.probe("executor-fixture", "filesystem")
        self.assertTrue(executor["source_secret_readable"])
        self.assertTrue(executor["business_environment"])
        self.assertFalse(executor["model_environment"])
        agent = self.deployment.inspect("agent")
        mounts = {item["Destination"] for item in agent["Mounts"]}
        self.assertEqual(mounts, {"/run/agent", "/run/config/agent.json"})
        self.assertTrue(agent["HostConfig"]["ReadonlyRootfs"])
        self.assertEqual(agent["HostConfig"]["PidsLimit"], 64)
        self.assertEqual(agent["HostConfig"]["Memory"], 512 * 1024 * 1024)
        self.assertEqual(agent["HostConfig"]["NanoCpus"], 1_000_000_000)
        self.assertEqual(self.deployment.probe("executor-fixture", "trusted_source", "socket_read_only"),
                         {"socket_volume_readonly": True})

    def test_only_valid_advisory_proposals_cross_the_shared_socket(self):
        before = self.deployment.probe("agent", "model_count")["requests"]
        for forged in ("method", "manifest"):
            self.assertEqual(self.deployment.probe("executor-fixture", "agent", forged), {"blocked": True})
        self.assertEqual(self.deployment.probe("agent", "model_count")["requests"], before)
        valid = self.deployment.probe("executor-fixture", "agent", "safe")
        self.assertFalse(valid["blocked"])
        self.assertEqual((valid["action"], valid["evidence_ids"], valid["input_tokens"], valid["output_tokens"]),
                         ("verify_asset", ["policy"], 11, 3))
        self.assertTrue(self.deployment.probe("executor-fixture", "agent", "inject")["blocked"])
        self.assertEqual(self.deployment.probe("agent", "model_count")["requests"], before + 2)
        self.assertEqual(self.deployment.probe("executor-fixture", "trusted_source", "state"),
                         {"status": 200, "mutations": 0})
        self.assertEqual(self.deployment.probe("executor-fixture", "trusted_source", "untrusted"), {"status": 403})
        self.assertEqual(self.deployment.probe("executor-fixture", "trusted_source", "trusted"),
                         {"status": 200, "mutations": 1})
