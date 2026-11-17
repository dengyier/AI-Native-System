"""Expose the authenticated framework's read-only API over MCP stdio."""

import os
from asyncio import to_thread

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from ai_native_sdk import APIError, Client


async def _read(operation, *arguments):
    try:
        return await to_thread(operation, *arguments)
    except (APIError, ValueError) as error:
        raise ToolError(str(error)) from None


def build_server(client: Client) -> MCPServer:
    server = MCPServer("ai-native-system", log_level="WARNING")
    read_only = ToolAnnotations(read_only_hint=True, idempotent_hint=True)

    @server.tool(annotations=read_only, structured_output=True)
    async def list_applications() -> dict[str, object]:
        """List applications visible to the configured identity."""
        return await _read(client.applications)

    @server.tool(annotations=read_only, structured_output=True)
    async def get_task(task_id: str) -> dict[str, object]:
        """Read an existing task if the configured identity can access it."""
        return await _read(client.task, task_id)

    return server


def main():
    try:
        client = Client(os.environ["AI_NATIVE_API_URL"], os.environ["AI_NATIVE_API_TOKEN"])
    except (KeyError, ValueError):
        raise SystemExit("Set a valid AI_NATIVE_API_URL and AI_NATIVE_API_TOKEN before starting MCP.") from None
    build_server(client).run("stdio")


if __name__ == "__main__":
    main()
