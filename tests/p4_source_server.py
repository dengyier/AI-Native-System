"""Independent MCP SDK process used by the P4 integration suite."""

import asyncio
import hmac
import json
import os
import sys
from pathlib import Path

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from mcp.server import MCPServer
from mcp.server.mcpserver import Context
from mcp_types import ToolAnnotations

from ai_native_system.adapters.owp import key_id, load_private_key, load_public_key
from ai_native_system.source_write import SourceAction, SourceWrite


EXECUTE_TOOL = "apply_source_action"
LOOKUP_TOOL = "lookup_source_action"


def _allow(context, config, principal):
    request = context.request_context.request
    if request is None:
        if config.get("stdio_principal") != principal:
            raise PermissionError("Source tool access denied")
        return
    actual = request.headers.get("Authorization", "")
    expected = "Bearer " + config[principal + "_token"]
    if not hmac.compare_digest(actual.encode("utf-8"), expected.encode("utf-8")):
        raise PermissionError("Source tool access denied")


def _consume_flag(config, key):
    flag = config.get(key)
    if flag is None:
        return False
    try:
        Path(flag).unlink()
    except FileNotFoundError:
        return False
    return True


def build_server(service, config):
    server = MCPServer("P4 independent source fixture", log_level="WARNING")

    @server.tool(
        name=EXECUTE_TOOL, structured_output=True,
        annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=True),
        meta={"ai-native.profile": "source-write/v1"},
    )
    async def execute(operation: dict[str, object], authorization: dict[str, object], ctx: Context) -> dict[str, object]:
        _allow(ctx, config, "execute")
        result = await asyncio.to_thread(service.execute, operation, authorization, principal="execute")
        if _consume_flag(config, "drop_after_commit_file"):
            os._exit(91)
        return result

    @server.tool(
        name=LOOKUP_TOOL, structured_output=True,
        annotations=ToolAnnotations(read_only_hint=True, idempotent_hint=True),
        meta={"ai-native.profile": "source-write/v1"},
    )
    async def lookup(operation: dict[str, object], ctx: Context) -> dict[str, object]:
        _allow(ctx, config, "lookup")
        result = await asyncio.to_thread(service.lookup, operation, principal="lookup")
        if _consume_flag(config, "fail_lookup_file"):
            raise OSError("Source lookup unavailable")
        if _consume_flag(config, "tamper_lookup_file"):
            result["payload"]["request_hash"] = "0" * 64
        return result

    return server


def tool_schema_pins():
    """Return the SDK-generated schema fingerprints without starting an endpoint."""
    from ai_native_system.adapters.mcp_sdk import tool_schema_digest

    tools = asyncio.run(build_server(None, {}).list_tools())
    return {tool.name: tool_schema_digest(tool.input_schema, tool.output_schema) for tool in tools}


def main():
    config = json.loads(Path(os.environ["AI_NATIVE_P4_SOURCE_CONFIG"]).read_text())
    if not config.get("stdio_principal") and (
        not config.get("execute_token") or not config.get("lookup_token")
        or config["execute_token"] == config["lookup_token"]
    ):
        raise ValueError("Source execute and lookup identities must differ")
    authority_keys = {}
    for path in config["authority_public_keys"]:
        key = load_public_key(Path(path).read_bytes())
        authority_keys[key_id(key)] = key
    service = SourceWrite(
        config["dsn"], tenant=config["tenant"], source=config["source"], destination_digest=config["destination_digest"],
        actions={name: SourceAction(**action) for name, action in config["actions"].items()}, authority_keys=authority_keys,
        signing_key=load_private_key(Path(config["signing_key"]).read_bytes()), epoch=config["epoch"],
        retention_seconds=config["retention_seconds"], lookup_dsn=config.get("lookup_dsn"),
    )
    server = build_server(service, config)
    if "port" in config:
        server.run("streamable-http", host="127.0.0.1", port=config["port"], json_response=True, stateless_http=True)
    else:
        server.run("stdio")


if __name__ == "__main__":
    main()
