import asyncio
import json
import sys
import unittest
from importlib.util import find_spec
from pathlib import Path

from test_client import TOKEN, receiver, reply


@unittest.skipUnless(find_spec("mcp"), "The MCP SDK is required")
class FrameworkMCPServerTests(unittest.IsolatedAsyncioTestCase):
    async def test_stdio_tools_preserve_existing_api_access(self):
        from mcp import Client, StdioServerParameters

        applications = {"applications": [{"id": "reference-action"}]}
        task = {"id": "task-1", "status": "proposed"}

        def respond(handler):
            if handler.path == "/v1/applications":
                reply(handler, raw=json.dumps(applications).encode())
            elif handler.path == "/v1/tasks/task-1":
                reply(handler, raw=json.dumps(task).encode())
            else:
                reply(handler, status=403, raw=json.dumps({"error": TOKEN}).encode())

        with receiver(respond) as (origin, requests):
            server = StdioServerParameters(
                command=sys.executable,
                args=["-B", "-m", "ai_native_system.mcp_server"],
                cwd=Path(__file__).resolve().parents[1],
                env={"AI_NATIVE_API_URL": origin, "AI_NATIVE_API_TOKEN": TOKEN},
            )
            async with asyncio.timeout(15), Client(server) as client:
                tools = {tool.name: tool for tool in (await client.list_tools()).tools}
                self.assertEqual(set(tools), {"list_applications", "get_task"})
                self.assertTrue(all(tool.annotations.read_only_hint for tool in tools.values()))
                listed = await client.call_tool("list_applications")
                self.assertFalse(listed.is_error)
                self.assertEqual(listed.structured_content, applications)
                fetched = await client.call_tool("get_task", {"task_id": "task-1"})
                self.assertFalse(fetched.is_error)
                self.assertEqual(fetched.structured_content, task)
                denied = await client.call_tool("get_task", {"task_id": "other-task"})
                self.assertTrue(denied.is_error)
                self.assertIn("API returned HTTP 403", denied.content[0].text)
                self.assertNotIn(TOKEN, repr(denied))

        self.assertEqual(requests, [
            ("GET", "/v1/applications", "Bearer " + TOKEN, None),
            ("GET", "/v1/tasks/task-1", "Bearer " + TOKEN, None),
            ("GET", "/v1/tasks/other-task", "Bearer " + TOKEN, None),
        ])
