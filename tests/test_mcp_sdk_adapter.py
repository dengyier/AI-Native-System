import asyncio
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from importlib.util import find_spec
from pathlib import Path
from unittest.mock import patch

from ai_native_system.adapters.mcp_sdk import MCPSDKRemote, StdioLaunch, tool_schema_digest
from ai_native_system.remote import RemoteError
from test_remote_transport import endpoint, json_response


SERVER_SOURCE = """
import json
import os
import sys
from typing import Any
from mcp.server import MCPServer
from mcp.server.mcpserver import Context
from mcp.types import ToolAnnotations

server = MCPServer("contract-test", log_level="ERROR")

@server.tool(name="write", annotations=ToolAnnotations(read_only_hint=False), structured_output=True)
def execute(operation: dict[str, Any], authorization: dict[str, Any], ctx: Context) -> dict[str, Any]:
    return {
        "operation": operation,
        "authorization": authorization,
        "own_env": os.environ.get("CONNECTOR_SCOPE"),
        "ambient_secret": "AI_NATIVE_OWP_PRIVATE_KEY" in os.environ,
        "parent_home": os.environ.get("HOME"),
        "cwd": os.getcwd(),
        "auth": (ctx.headers or {}).get("authorization"),
    }

@server.tool(name="lookup", annotations=ToolAnnotations(read_only_hint=True), structured_output=True)
def lookup(operation: dict[str, Any], ctx: Context) -> dict[str, Any]:
    return {"operation": operation, "auth": (ctx.headers or {}).get("authorization")}

@server.tool(name="legacy_write", structured_output=False)
def legacy_write(operation_id: str, source_version: str) -> str:
    return json.dumps({"operation_id": operation_id, "source_version": source_version})

@server.tool(name="legacy_lookup", structured_output=False)
def legacy_lookup(operation_id: str, source_version: str) -> str:
    return legacy_write(operation_id, source_version)

@server.tool(name="unregistered", structured_output=True)
def unregistered() -> dict[str, Any]:
    raise RuntimeError("unregistered tool called")

if __name__ == "__main__":
    if len(sys.argv) == 2:
        server.run("streamable-http", host="127.0.0.1", port=int(sys.argv[1]),
                   stateless_http=True, json_response=False)
    else:
        server.run("stdio")
"""


class MCPSDKContractTests(unittest.TestCase):
    def test_tool_schema_pins_inputs_and_outputs(self):
        shape = {"type": "object", "properties": {"enabled": {"type": "boolean"}}}
        same = {"properties": {"enabled": {"type": "boolean"}}, "type": "object"}
        self.assertEqual(tool_schema_digest(shape), tool_schema_digest(same))
        self.assertNotEqual(tool_schema_digest(shape), tool_schema_digest(shape, shape))
        with self.assertRaisesRegex(ValueError, "inside the schema"):
            tool_schema_digest({"type": "object", "properties": {"target": {"$ref": "https://invalid.test/schema"}}})
        with self.assertRaisesRegex(ValueError, "message body"):
            tool_schema_digest({"type": "object", "properties": {"secret": {"type": "string", "x-mcp-header": True}}})

    def test_unapproved_launch_or_endpoint_refused_before_network(self):
        with self.assertRaisesRegex(ValueError, "absolute"):
            StdioLaunch("python", ["app.py"], Path.cwd())
        with self.assertRaisesRegex(ValueError, "absolute"):
            StdioLaunch(sys.executable, ["app.py"], ".")
        with self.assertRaisesRegex(ValueError, "explicit MCP launch environment"):
            StdioLaunch(sys.executable, [], Path.cwd(), {"bad=key": "injected"})
        for remote in ("http://example.org/mcp", "https://key@example.org/mcp",
                       "http://127.0.0.1/mcp?token=one", "http://127.0.0.1/mcp#fragment"):
            with self.subTest(remote=remote), self.assertRaises(ValueError):
                MCPSDKRemote(endpoint=remote, execute_tool="write", lookup_tool="lookup",
                             execute_schema_digest="0" * 64, lookup_schema_digest="1" * 64)


@unittest.skipUnless(find_spec("mcp"), "Official MCP SDK optional dependencies are required")
class MCPSDKTests(unittest.TestCase):
    def setUp(self):
        directory = Path(self.enterContext(tempfile.TemporaryDirectory())).resolve()
        self.directory = directory
        self.script = directory / "fixture.py"
        self.script.write_text(SERVER_SOURCE)
        namespace = {"__name__": "mcp_fixture"}
        exec(compile(SERVER_SOURCE, str(self.script), "exec"), namespace)
        tools = asyncio.run(namespace["server"].list_tools())
        self.tools = {tool.name: tool.model_dump(by_alias=True, mode="json", exclude_none=True) for tool in tools}
        self.pins = {tool.name: tool_schema_digest(tool.input_schema, tool.output_schema) for tool in tools}
        self.operation = {"operation_id": "p4-once", "source_version": "2026:asset/7"}
        self.authorization = {"digest": "sample-grant"}

    def adapter(self, **options):
        settings = {
            "execute_tool": "write", "lookup_tool": "lookup", "profile": "source-write/v1",
            "execute_schema_digest": self.pins["write"], "lookup_schema_digest": self.pins["lookup"],
            "timeout": 8,
        }
        return MCPSDKRemote(**{**settings, **options})

    def stop(self, process):
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)

    def mcp_http(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        process = subprocess.Popen(
            [sys.executable, "-B", str(self.script), str(port)],
            cwd=self.directory, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        self.addCleanup(self.stop, process)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and process.poll() is None:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    return f"http://127.0.0.1:{port}/mcp"
            except OSError:
                time.sleep(0.02)
        self.fail("The official MCP fixture did not open its loopback endpoint")

    def test_stdio_uses_exact_workdir_argv_and_explicit_environment(self):
        env = {"CONNECTOR_SCOPE": "write-scope"}
        launch = StdioLaunch(sys.executable, ["-B", self.script.as_posix()], self.directory, env)
        with patch.dict(os.environ, {"AI_NATIVE_OWP_PRIVATE_KEY": "runtime-secret-sentinel",
                                     "HOME": "/path/to/private/runtime-home"}):
            adapter = self.adapter(launch=launch)
            env["CONNECTOR_SCOPE"] = "late mutation"
            result = adapter.execute_authorized(self.operation, self.authorization)
            self.assertEqual(adapter.lookup(self.operation)["operation"], self.operation)
        self.assertEqual(result["operation"], self.operation)
        self.assertEqual(result["authorization"], self.authorization)
        self.assertEqual(result["cwd"], str(self.directory))
        self.assertEqual(result["own_env"], "write-scope")
        self.assertFalse(result["ambient_secret"])
        self.assertEqual(result["parent_home"], "")
        self.assertNotIn("write-scope", repr(adapter.identity))
        self.assertNotIn("write-scope", repr(launch))
        self.assertEqual(adapter.identity["type"], "mcp-sdk-stdio")

    def test_streamable_http_uses_separate_query_credentials_and_ignores_proxy_variables(self):
        url = self.mcp_http()
        with patch.dict(os.environ, {"HTTP_PROXY": "http://127.0.0.1:9", "ALL_PROXY": "http://127.0.0.1:9",
                                     "NO_PROXY": ""}):
            adapter = self.adapter(endpoint=url, token="p4-write-token", lookup_token="p4-query-token")
            self.assertEqual(adapter.execute_authorized(self.operation, self.authorization)["auth"],
                             "Bearer p4-write-token")
            self.assertEqual(adapter.lookup(self.operation)["auth"], "Bearer p4-query-token")
        self.assertEqual(adapter.identity["type"], "mcp-sdk-http")
        self.assertNotIn("p4-write-token", repr(adapter.identity))
        self.assertNotIn("p4-query-token", repr(adapter.identity))
        with self.assertRaisesRegex(RemoteError, "signed authorization"):
            adapter.execute(self.operation)

    def test_registered_legacy_message_and_json_text_receipt_remain_supported(self):
        launch = StdioLaunch(sys.executable, ["-B", str(self.script)], self.directory)
        adapter = self.adapter(launch=launch, profile=None, execute_tool="legacy_write", lookup_tool="legacy_lookup",
                               execute_schema_digest=self.pins["legacy_write"],
                               lookup_schema_digest=self.pins["legacy_lookup"])
        self.assertEqual(adapter.execute(self.operation), self.operation)
        self.assertEqual(adapter.lookup(self.operation), self.operation)

    def test_schema_drift_rejected_before_call(self):
        launch = StdioLaunch(sys.executable, ["-B", str(self.script)], self.directory)
        adapter = self.adapter(launch=launch, lookup_schema_digest="0" * 64)
        with self.assertRaisesRegex(RemoteError, "registered tool schema changed"):
            adapter.execute_authorized(self.operation, self.authorization)

    def test_input_does_not_pass_when_it_conflicts_with_pinned_schema(self):
        launch = StdioLaunch(sys.executable, ["-B", str(self.script)], self.directory)
        adapter = self.adapter(launch=launch)
        with self.assertRaises(RemoteError):
            adapter.execute_authorized("not-an-operation-object", self.authorization)

    def test_query_identity_only_needs_its_registered_lookup_tool(self):
        def query_only(method, path, headers, body):
            if body is None or body["method"].startswith("notifications/"):
                return 202, {}, b""
            rpc_id = body["id"]
            response = {"jsonrpc": "2.0", "id": rpc_id}
            match body["method"]:
                case "server/discover":
                    response["error"] = {"code": -32601, "message": "Method not found"}
                case "initialize":
                    response["result"] = {"protocolVersion": "2025-11-25", "capabilities": {"tools": {}},
                                          "serverInfo": {"name": "restricted", "version": "1"}}
                case "tools/list":
                    response["result"] = {"tools": [self.tools["lookup"]]}
                case "tools/call":
                    if body["params"]["name"] != "lookup":
                        raise AssertionError("Query identity invoked a write")
                    response["result"] = {"content": [], "structuredContent": {"operation": self.operation}}
                case _:
                    raise AssertionError("Unexpected MCP method")
            return json_response(response)

        with endpoint(query_only) as (base, calls):
            adapter = self.adapter(endpoint=base + "/mcp", lookup_token="query-only")
            self.assertEqual(adapter.lookup(self.operation)["operation"], self.operation)
            with self.assertRaisesRegex(RemoteError, "did not list the registered tool"):
                adapter.execute_authorized(self.operation, self.authorization)
        tool_calls = [body for _, _, _, body in calls if body and body.get("method") == "tools/call"]
        self.assertEqual([body["params"]["name"] for body in tool_calls], ["lookup"])

    def test_http_redirect_never_follows_even_same_origin(self):
        def respond(method, path, headers, body):
            return 307, {"Location": "/redirected"}, b""

        with endpoint(respond) as (base, calls):
            adapter = self.adapter(endpoint=base + "/mcp")
            with self.assertRaises(RemoteError):
                adapter.lookup(self.operation)
        self.assertEqual([call[1] for call in calls], ["/mcp"])
