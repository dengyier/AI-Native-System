import tempfile
import unittest
from pathlib import Path

from ai_native_system.model import DemoModel
from ai_native_system.registry import Registry
from ai_native_system.runtime import Runtime
from ai_native_system.tools import ToolRegistry
from ai_native_system.remote import MCPRemote
from remote_server import RemoteFixture
from test_remote_transport import endpoint, mcp_server, json_response

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "conformance.json"


class MCPRuntimeTests(unittest.TestCase):
    def test_committed_mcp_operation_with_lost_reply_reconciles_after_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            remote = RemoteFixture(root / "remote.sqlite")
            fallback = mcp_server(sse=True)
            def handler(method, path, headers, body):
                if method == "POST" and body.get("method") == "tools/call":
                    arguments = body["params"]["arguments"]
                    if body["params"]["name"] == "execute_tool":
                        remote.execute(arguments)
                        # The server committed, then returned an unavailable response.
                        return 503, {}, b""
                    _, result = remote.lookup(arguments)
                    return json_response({"jsonrpc": "2.0", "id": body["id"], "result": {
                        "structuredContent": result, "content": [],
                    }})
                return fallback(method, path, headers, body)
            with endpoint(handler) as (base, calls):
                tools = ToolRegistry()
                tools.register_remote("mcp.transition", "1", MCPRemote(base + "/mcp", "execute_tool", "lookup_tool"))
                registry = Registry.load(FIXTURE)
                registry.actions["verify_asset"].update(tool="mcp.transition", tool_version="1")
                runtime = Runtime(root / "local.sqlite", registry, DemoModel(), tools)
                runtime.initialize()
                task = runtime.submit("local", "single", "asset-1", "requester", "mcp-test")
                runtime.advance("local", task["id"])
                runtime.decide("local", task["id"], "reviewer", "approve")
                self.assertEqual(runtime.advance("local", task["id"])["status"], "reconciling")
                restored = Runtime(root / "local.sqlite", registry, DemoModel(), tools)
                self.assertEqual(restored.reconcile("local", task["id"])["status"], "completed")
                self.assertEqual(restored.advance("local", task["id"])["status"], "completed")
                self.assertEqual(len(restored.inspect("local", task["id"])["effects"]), 1)
                self.assertEqual(len(remote.operation_states()), 1)
                self.assertEqual(remote.object_status()["version"], 2)
                invocations = [body["params"]["name"] for _, _, _, body in calls
                               if body and body.get("method") == "tools/call"]
                self.assertEqual(invocations, ["execute_tool", "lookup_tool"])
