"""Official MCP transport for FDE's source-owned method-card verification.

This bridge neither approves nor signs actions. FDE owns the MySQL transaction
and signed source receipt; AINS keeps its existing task and OpenWorkProof chain.
"""

import argparse
import asyncio
import hmac
import json
import math
import os
from pathlib import Path
from urllib.parse import urlsplit

from .adapters.owp import key_id, load_public_key
from .registry import unique_keys
from .source_receipt import valid_digest, validate_operation, verify_source_receipt
from .storage import encode


TENANT = "fdesage-ops"
SOURCE = "fdesage-method-cards"
EXECUTE_TOOL = "apply_fdesage_method_card"
LOOKUP_TOOL = "lookup_fdesage_method_card"
_BASE_PATH = "/api/integrations/ains/method-cards/"
_MAX_BYTES = 256 * 1024


class FDESourceUnavailable(RuntimeError):
    """No authenticated terminal result was obtained; reconcile the same operation."""


def _origin(value):
    if (type(value) is not str or not value or len(value) > 2048
            or any(not 33 <= ord(char) <= 126 or char == "\\" for char in value)):
        raise ValueError("Expected an explicit FDE source origin")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise ValueError("Invalid FDE source origin") from None
    if (parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username is not None
            or parsed.path not in ("", "/") or parsed.query or parsed.fragment or port == 0
            or (parsed.scheme == "http" and parsed.hostname not in ("127.0.0.1", "::1"))):
        raise ValueError("Use HTTPS, or numeric loopback HTTP for an isolated source")
    return value.rstrip("/")


def _token(value):
    return (type(value) is str and 32 <= len(value) <= 8192
            and all(33 <= ord(char) <= 126 for char in value))


def _reject_constant(_):
    raise ValueError("Non-finite source response")


def _selected_operation(operation):
    conditions = validate_operation(operation)
    if (operation["tenant"] != TENANT or conditions["source"] != SOURCE
            or operation["action"] != "verify_method_card" or operation["from_state"] != "draft"
            or operation["to_state"] != "verified" or len(conditions["targets"]) != 1
            or len(conditions["guards"]) != 1):
        raise ValueError("Operation is outside the registered FDE method-card action")
    target, = conditions["targets"]
    guard, = conditions["guards"]
    if (target["type"] != "method_card" or target["record_type"] != "method_cards"
            or target["id"] != operation["object_id"] or target["id"] != "method-card:" + target["record_id"]
            or not target["record_id"].isascii() or not target["record_id"].isdigit()
            or target["record_id"].startswith("0") or guard["type"] != "method_card_submissions"
            or not valid_digest(guard["expected_version"])):
        raise ValueError("Operation target or submission guard is outside the registered source")


class NodeSourceGateway:
    """Fixed-origin, bounded calls with separate source execute and lookup identities."""

    def __init__(self, origin, *, execute_token, lookup_token, receipt_keys, timeout=5):
        self._origin = _origin(origin)
        if (not _token(execute_token) or not _token(lookup_token)
                or hmac.compare_digest(execute_token, lookup_token)):
            raise ValueError("Configure distinct bounded FDE execute and lookup credentials")
        if (type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 30
                or type(receipt_keys) is not dict or not receipt_keys
                or any(key_id(public) != identifier for identifier, public in receipt_keys.items())):
            raise ValueError("Configure pinned source receipt trust and a bounded network budget")
        self._execute_token, self._lookup_token = execute_token, lookup_token
        self._keys, self._timeout = dict(receipt_keys), timeout

    async def execute(self, operation, authorization):
        _selected_operation(operation)
        if type(authorization) is not dict or not valid_digest(authorization.get("digest")):
            raise ValueError("An exact signed authorization is required")
        document = await self._call("execute", {"operation": operation, "authorization": authorization},
                                    self._execute_token)
        return self._verified(document, operation, authorization["digest"])

    async def lookup(self, operation):
        _selected_operation(operation)
        document = await self._call("lookup", {"operation": operation}, self._lookup_token)
        return self._verified(document, operation)

    def _verified(self, document, operation, authorization_digest=None):
        try:
            receipt = verify_source_receipt(document, self._keys, operation=operation, source=SOURCE,
                                            authorization_digest=authorization_digest)
            if authorization_digest is not None and receipt["status"] == "not_found":
                raise ValueError("Execution requires a retained terminal operation record")
        except (ValueError, TypeError):
            raise FDESourceUnavailable("FDE returned no trusted terminal source receipt") from None
        return document

    async def _call(self, action, document, token):
        import httpx2

        raw = encode(document).encode("utf-8")
        if len(raw) > _MAX_BYTES:
            raise ValueError("FDE source request exceeds the registered size limit")
        try:
            async with asyncio.timeout(self._timeout):
                async with httpx2.AsyncClient(trust_env=False, follow_redirects=False,
                                              timeout=self._timeout) as client:
                    async with client.stream(
                        "POST", self._origin + _BASE_PATH + action, content=raw,
                        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json",
                                 "Accept": "application/json", "Accept-Encoding": "identity"},
                    ) as response:
                        if (response.status_code != 200
                                or response.headers.get("Content-Type", "").split(";", 1)[0].strip() != "application/json"
                                or response.headers.get("Content-Encoding", "identity") != "identity"):
                            raise FDESourceUnavailable("FDE source did not return a terminal receipt")
                        chunks, size = [], 0
                        async for block in response.aiter_raw():
                            size += len(block)
                            if size > _MAX_BYTES:
                                raise FDESourceUnavailable("FDE source receipt exceeds the size limit")
                            chunks.append(block)
                        payload = b"".join(chunks)
        except Exception:
            # Third-party exceptions may include the endpoint or supplied headers.
            raise FDESourceUnavailable("FDE source call failed or exceeded its deadline") from None
        try:
            return json.loads(payload.decode("utf-8"), object_pairs_hook=unique_keys,
                              parse_constant=_reject_constant)
        except (ValueError, UnicodeError, RecursionError):
            raise FDESourceUnavailable("FDE source returned an invalid receipt document") from None


def build_server(gateway, *, execute_token, lookup_token):
    """Expose only the two registered source-write/v1 tools over official MCP."""
    from mcp.server import MCPServer
    from mcp.server.mcpserver import Context
    from mcp.server.mcpserver.exceptions import ToolError
    from mcp.types import ToolAnnotations

    if not _token(execute_token) or not _token(lookup_token) or hmac.compare_digest(execute_token, lookup_token):
        raise ValueError("Configure distinct MCP execute and lookup credentials")
    if isinstance(gateway, NodeSourceGateway) and len({
        execute_token, lookup_token, gateway._execute_token, gateway._lookup_token,
    }) != 4:
        raise ValueError("MCP and Node transport credentials must remain separate")
    server = MCPServer("FDE method-card source bridge", log_level="WARNING")

    def allow(context, expected):
        actual = (context.headers or {}).get("authorization", "")
        if not hmac.compare_digest(actual.encode("utf-8"), ("Bearer " + expected).encode("utf-8")):
            raise ToolError("Source tool access denied")

    @server.tool(name=EXECUTE_TOOL, structured_output=True,
                 annotations=ToolAnnotations(read_only_hint=False, destructive_hint=True, idempotent_hint=True),
                 meta={"ai-native.profile": "source-write/v1"})
    async def execute(operation: dict[str, object], authorization: dict[str, object], ctx: Context) -> dict[str, object]:
        allow(ctx, execute_token)
        try:
            return await gateway.execute(operation, authorization)
        except Exception:
            raise ToolError("FDE source execution unavailable; reconcile the same operation") from None

    @server.tool(name=LOOKUP_TOOL, structured_output=True,
                 annotations=ToolAnnotations(read_only_hint=True, idempotent_hint=True),
                 meta={"ai-native.profile": "source-write/v1"})
    async def lookup(operation: dict[str, object], ctx: Context) -> dict[str, object]:
        allow(ctx, lookup_token)
        try:
            return await gateway.lookup(operation)
        except Exception:
            raise ToolError("FDE source lookup unavailable; do not redispatch execution") from None

    return server


def tool_schema_pins():
    from .adapters.mcp_sdk import tool_schema_digest

    tools = asyncio.run(build_server(None, execute_token="e" * 32, lookup_token="l" * 32).list_tools())
    return {tool.name: tool_schema_digest(tool.input_schema, tool.output_schema) for tool in tools}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, help="Controlled configuration; credentials are environment names")
    arguments = parser.parse_args()
    settings = json.loads(Path(arguments.config).read_text(), object_pairs_hook=unique_keys,
                          parse_constant=_reject_constant)
    keys = {}
    for path in settings["receipt_public_keys"]:
        public = load_public_key(Path(path).read_bytes())
        keys[key_id(public)] = public
    names = [settings[name] for name in ("node_execute_token_env", "node_lookup_token_env",
                                       "mcp_execute_token_env", "mcp_lookup_token_env")]
    credentials = [os.environ[name] for name in names]
    if len(set(credentials)) != 4:
        raise ValueError("Use separate credentials for each source transport role")
    gateway = NodeSourceGateway(settings["source_origin"], execute_token=credentials[0], lookup_token=credentials[1],
                                receipt_keys=keys, timeout=settings.get("timeout", 5))
    server = build_server(gateway, execute_token=credentials[2], lookup_token=credentials[3])
    port = settings["port"]
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("Use an explicit loopback MCP port")
    server.run("streamable-http", host="127.0.0.1", port=port, json_response=True, stateless_http=True)


if __name__ == "__main__":
    main()
