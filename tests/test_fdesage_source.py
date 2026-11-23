"""Cross-runtime signatures and real loopback transport for the FDE source bridge."""

import asyncio
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from copy import deepcopy
from importlib.util import find_spec
from pathlib import Path
from unittest.mock import patch

from ai_native_system.adapters.mcp_sdk import MCPSDKRemote
from ai_native_system.adapters.owp import (
    key_id, load_private_key, load_public_key, sign_authorization, verify_authorization,
)
from ai_native_system.fdesage_source import (
    EXECUTE_TOOL, LOOKUP_TOOL, FDESourceUnavailable, NodeSourceGateway, build_server, tool_schema_pins,
)
from ai_native_system.remote import RemoteError
from ai_native_system.source_receipt import sign_source_receipt, verify_source_receipt
from ai_native_system.storage import digest
from test_remote_transport import endpoint, json_response


ROOT = Path(__file__).resolve().parents[1]
VECTOR = ROOT / "fixtures/pilots/fdesage-method-card/golden-profile.json"
NODE_EXECUTE = "node-execute-test-" + "e" * 32
NODE_LOOKUP = "node-lookup-test-" + "l" * 32
MCP_EXECUTE = "mcp-execute-test-" + "x" * 32
MCP_LOOKUP = "mcp-lookup-test-" + "q" * 32


class _SourceFixture:
    def setUp(self):
        self.vector = json.loads(VECTOR.read_text())
        self.operation = self.vector["operation"]
        self.authorization = self.vector["authorization"]
        self.source = load_public_key(self.vector["source"]["public_pem"].encode())
        self.source_trust = {key_id(self.source): self.source}


@unittest.skipUnless(find_spec("openworkproof"), "Install pinned OpenWorkProof integration")
class FDESourceProfileTests(_SourceFixture, unittest.TestCase):
    def test_python_produces_the_exact_cross_runtime_authorization_and_request_bytes(self):
        authority = load_private_key(self.vector["authority"]["test_private_pem"].encode())
        expected = self.vector["authorization"]
        self.assertEqual(sign_authorization(expected["payload"], authority), expected)
        self.assertEqual(verify_authorization(expected, {key_id(authority.public_key()): authority.public_key()}),
                         expected["payload"])
        operation = {name: value for name, value in self.operation.items() if name != "request_hash"}
        self.assertEqual(digest(operation), self.operation["request_hash"])
        self.assertEqual(hashlib.sha256(self.vector["operation_canonical_utf8"].encode()).hexdigest(),
                         self.operation["request_hash"])
        self.assertEqual(hashlib.sha256(bytes.fromhex(self.vector["authorization_canonical_hex"])).hexdigest(),
                         expected["digest"])

    def test_all_three_terminal_receipt_shapes_bind_the_exact_operation_and_source(self):
        private = load_private_key(self.vector["source"]["test_private_pem"].encode())
        for status, expected in self.vector["receipts"].items():
            with self.subTest(status=status):
                self.assertEqual(sign_source_receipt(expected["payload"], private), expected)
                self.assertEqual(verify_source_receipt(expected, self.source_trust, operation=self.operation,
                                                      authorization_digest=self.authorization["digest"])["status"], status)
                encoded = bytes.fromhex(self.vector["receipt_canonical_hex"][status])
                self.assertEqual(hashlib.sha256(encoded).hexdigest(), expected["digest"])

    def test_native_version_and_submission_replacement_cannot_reuse_a_signed_receipt(self):
        for field, value in (("expected_version", "revision:8:sha256:" + "f" * 64),
                             ("id", "method-card:8")):
            operation = deepcopy(self.operation)
            operation["source_conditions"]["targets"][0][field] = value
            operation["request_hash"] = digest({key: val for key, val in operation.items() if key != "request_hash"})
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify_source_receipt(self.vector["receipts"]["succeeded"], self.source_trust, operation=operation)


@unittest.skipUnless(find_spec("openworkproof") and find_spec("httpx2"), "Install pinned source transport dependencies")
class FDESourceGatewayTests(_SourceFixture, unittest.TestCase):
    def gateway(self, origin, **options):
        return NodeSourceGateway(origin, execute_token=NODE_EXECUTE, lookup_token=NODE_LOOKUP,
                                 receipt_keys=self.source_trust, **options)

    def test_real_http_uses_exact_paths_and_separate_credentials_with_no_environment_proxy(self):
        with endpoint(lambda *args: json_response(self.vector["receipts"]["succeeded"])) as (origin, calls):
            service = self.gateway(origin)
            with patch.dict(os.environ, HTTP_PROXY="http://127.0.0.1:9", ALL_PROXY="http://127.0.0.1:9", NO_PROXY=""):
                result = asyncio.run(service.execute(self.operation, self.authorization))
                self.assertEqual(asyncio.run(service.lookup(self.operation)), result)
            self.assertEqual([item[:2] for item in calls], [
                ("POST", "/api/integrations/ains/method-cards/execute"),
                ("POST", "/api/integrations/ains/method-cards/lookup"),
            ])
            self.assertEqual([item[2]["authorization"] for item in calls],
                             ["Bearer " + NODE_EXECUTE, "Bearer " + NODE_LOOKUP])
            self.assertEqual(calls[0][3], {"operation": self.operation, "authorization": self.authorization})
            self.assertEqual(calls[1][3], {"operation": self.operation})

    def test_pending_503_redirect_oversize_and_unsigned_results_do_not_become_not_found_or_retry(self):
        cases = [
            lambda *args: (503, {"Content-Type": "application/json"}, b'{"error":"receipt_pending"}'),
            lambda *args: (307, {"Location": "/not-allowed"}, b""),
            lambda *args: (200, {"Content-Type": "application/json"}, b" " * (256 * 1024 + 1)),
            lambda *args: json_response({"status": "pending"}),
        ]
        for respond in cases:
            with endpoint(respond) as (origin, calls):
                with self.assertRaises(FDESourceUnavailable) as raised:
                    asyncio.run(self.gateway(origin).execute(self.operation, self.authorization))
                self.assertEqual(len(calls), 1)
                self.assertNotIn(NODE_EXECUTE, str(raised.exception))

    def test_wrong_source_signature_or_operation_is_not_accepted_as_terminal_evidence(self):
        for change in ({"signature": "A" * 86}, {"digest": "0" * 64}):
            result = {**self.vector["receipts"]["succeeded"], **change}
            with endpoint(lambda *args: json_response(result)) as (origin, calls):
                with self.assertRaises(FDESourceUnavailable):
                    asyncio.run(self.gateway(origin).execute(self.operation, self.authorization))
                self.assertEqual(len(calls), 1)

    def test_not_found_is_only_a_lookup_result_and_cannot_acknowledge_an_execution(self):
        with endpoint(lambda *args: json_response(self.vector["receipts"]["not_found"])) as (origin, calls):
            service = self.gateway(origin)
            self.assertEqual(asyncio.run(service.lookup(self.operation)), self.vector["receipts"]["not_found"])
            with self.assertRaises(FDESourceUnavailable):
                asyncio.run(service.execute(self.operation, self.authorization))
            self.assertEqual(len(calls), 2)

    def test_source_network_budget_includes_waiting_for_response_headers(self):
        def respond(*args):
            time.sleep(0.4)
            return json_response(self.vector["receipts"]["succeeded"])

        with endpoint(respond) as (origin, _):
            started = time.monotonic()
            with self.assertRaises(FDESourceUnavailable):
                asyncio.run(self.gateway(origin, timeout=0.08).lookup(self.operation))
            self.assertLess(time.monotonic() - started, 0.3)

    def test_unsupported_origins_scope_and_shared_credentials_fail_before_network(self):
        for origin in ("http://example.com", "https://key@example.com", "https://example.com/path",
                       "https://example.com?token=x", "https://example.com#fragment"):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                self.gateway(origin)
        with self.assertRaises(ValueError):
            NodeSourceGateway("http://127.0.0.1", execute_token=NODE_EXECUTE, lookup_token=NODE_EXECUTE,
                              receipt_keys=self.source_trust)
        operation = {**self.operation, "tenant": "another-tenant"}
        operation["request_hash"] = digest({key: val for key, val in operation.items() if key != "request_hash"})
        with self.assertRaises(ValueError):
            asyncio.run(self.gateway("http://127.0.0.1:9").lookup(operation))


@unittest.skipUnless(find_spec("mcp") and find_spec("openworkproof"), "Install pinned official MCP integration")
class FDESourceMCPTests(_SourceFixture, unittest.TestCase):
    def start_bridge(self, source_origin):
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        public = directory / "source-public.pem"
        public.write_text(self.vector["source"]["public_pem"])
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        config = directory / "source.json"
        config.write_text(json.dumps({
            "source_origin": source_origin, "port": port, "receipt_public_keys": [str(public)],
            "node_execute_token_env": "FDE_TEST_NODE_EXECUTE", "node_lookup_token_env": "FDE_TEST_NODE_LOOKUP",
            "mcp_execute_token_env": "FDE_TEST_MCP_EXECUTE", "mcp_lookup_token_env": "FDE_TEST_MCP_LOOKUP",
        }))
        process = subprocess.Popen(
            [sys.executable, "-B", "-m", "ai_native_system.fdesage_source", "--config", str(config)], cwd=ROOT,
            env={**os.environ, "FDE_TEST_NODE_EXECUTE": NODE_EXECUTE, "FDE_TEST_NODE_LOOKUP": NODE_LOOKUP,
                 "FDE_TEST_MCP_EXECUTE": MCP_EXECUTE, "FDE_TEST_MCP_LOOKUP": MCP_LOOKUP},
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        self.addCleanup(self.stop_bridge, process)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and process.poll() is None:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    return f"http://127.0.0.1:{port}/mcp"
            except OSError:
                time.sleep(0.03)
        self.fail("Official FDE source bridge did not open its loopback endpoint")

    @staticmethod
    def stop_bridge(process):
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)

    def test_official_mcp_adapter_keeps_both_hops_credentials_separate_and_rejects_cross_role_calls(self):
        with endpoint(lambda *args: json_response(self.vector["receipts"]["succeeded"])) as (origin, calls):
            endpoint_url = self.start_bridge(origin)
            pins = tool_schema_pins()
            settings = {"endpoint": endpoint_url, "profile": "source-write/v1", "execute_tool": EXECUTE_TOOL,
                        "lookup_tool": LOOKUP_TOOL, "execute_schema_digest": pins[EXECUTE_TOOL],
                        "lookup_schema_digest": pins[LOOKUP_TOOL], "timeout": 5}
            adapter = MCPSDKRemote(**settings, token=MCP_EXECUTE, lookup_token=MCP_LOOKUP)
            self.assertEqual(adapter.execute_authorized(self.operation, self.authorization),
                             self.vector["receipts"]["succeeded"])
            self.assertEqual(adapter.lookup(self.operation), self.vector["receipts"]["succeeded"])
            crossed = MCPSDKRemote(**settings, token=MCP_LOOKUP, lookup_token=MCP_EXECUTE)
            for invoke in (lambda: crossed.execute_authorized(self.operation, self.authorization),
                           lambda: crossed.lookup(self.operation)):
                with self.assertRaises(RemoteError):
                    invoke()
            self.assertEqual(len(calls), 2)
            self.assertEqual([call[2]["authorization"] for call in calls],
                             ["Bearer " + NODE_EXECUTE, "Bearer " + NODE_LOOKUP])

    def test_programmatic_server_builder_cannot_reuse_a_node_credential_at_the_mcp_hop(self):
        gateway = NodeSourceGateway("http://127.0.0.1:9", execute_token=NODE_EXECUTE, lookup_token=NODE_LOOKUP,
                                    receipt_keys=self.source_trust)
        with self.assertRaises(ValueError):
            build_server(gateway, execute_token=NODE_EXECUTE, lookup_token=MCP_LOOKUP)


if __name__ == "__main__":
    unittest.main()
