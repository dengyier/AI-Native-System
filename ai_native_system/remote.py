"""Adapters for registered HTTP and MCP operation transports."""

import json
import math
import re
from contextlib import contextmanager
from http.client import HTTPException
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .registry import unique_keys


_MAX_MESSAGE_BYTES = 256 * 1024
_MCP_VERSION = "2025-11-25"
_MCP_ACCEPT = "application/json, text/event-stream"
_MAX_TOOL_PAGES = 16


class RemoteError(Exception):
    """The adapter could not obtain a usable remote result."""


class _RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def _visible_ascii(value):
    return isinstance(value, str) and all(0x21 <= ord(char) <= 0x7E for char in value)


def _json_object(raw):
    try:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        document = json.loads(raw, object_pairs_hook=unique_keys)
    except (ValueError, TypeError, RecursionError):
        raise RemoteError("remote response contains invalid JSON") from None
    if not isinstance(document, dict):
        raise RemoteError("remote response must be a JSON object")
    return document


def _read_json(response):
    body = response.read(_MAX_MESSAGE_BYTES + 1)
    if len(body) > _MAX_MESSAGE_BYTES:
        raise RemoteError("remote response exceeds the size limit")
    return _json_object(body)


class _HTTPTransport:
    def __init__(self, endpoint: str, token: str, timeout: float):
        try:
            url = urlsplit(endpoint)
            port = url.port
        except (TypeError, ValueError):
            raise RemoteError("invalid remote endpoint") from None
        if not _visible_ascii(endpoint) or any(char in endpoint for char in ("?", "#", "\\")):
            raise RemoteError("remote endpoint must not contain query, fragment, or control characters")
        local = url.hostname in {"localhost", "127.0.0.1", "::1"}
        if not url.hostname or port == 0 or url.username is not None or (
            url.scheme != "https" and not (url.scheme == "http" and local)
        ):
            raise RemoteError("remote endpoint must use HTTPS or loopback HTTP without credentials")
        if not _visible_ascii(token):
            raise RemoteError("invalid remote bearer token")
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
            raise RemoteError("remote timeout must be positive")
        self._endpoint = endpoint
        self._token = token
        self._timeout = timeout
        handlers = [_RejectRedirects()]
        if local:
            handlers.append(ProxyHandler({}))
        self._opener = build_opener(*handlers)

    @contextmanager
    def _open(self, url, method, *, payload=None, headers=None, accept="application/json"):
        request_headers = {"Accept": accept, **(headers or {})}
        data = None
        if payload is not None:
            try:
                data = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
            except (TypeError, ValueError, RecursionError):
                raise RemoteError("remote request must be JSON serializable") from None
            if len(data) > _MAX_MESSAGE_BYTES:
                raise RemoteError("remote request exceeds the size limit")
            request_headers["Content-Type"] = "application/json"
        request = Request(url, data=data, headers=request_headers, method=method)
        if self._token:
            request.add_unredirected_header("Authorization", f"Bearer {self._token}")
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                yield response
        except HTTPError as error:
            error.close()
            raise RemoteError(f"remote HTTP request failed ({error.code})") from None
        except (OSError, HTTPException, ValueError):
            raise RemoteError("remote HTTP connection failed or timed out") from None


class HttpRemote(_HTTPTransport):
    """Send the operation object as JSON to an execute or lookup endpoint."""

    def __init__(self, endpoint: str, token: str = "", timeout: float = 5):
        super().__init__(endpoint, token, timeout)
        self._endpoint = self._endpoint.rstrip("/")

    @property
    def identity(self) -> dict:
        return {"type": "http", "endpoint": self._endpoint}

    def execute(self, operation: dict) -> dict:
        return self._call("execute", operation)

    def lookup(self, operation: dict) -> dict:
        return self._call("lookup", operation)

    def _call(self, method, operation):
        if not isinstance(operation, dict):
            raise RemoteError("remote operation must be a JSON object")
        with self._open(f"{self._endpoint}/{method}", "POST", payload=operation) as response:
            if response.headers.get_content_type() != "application/json":
                raise RemoteError("remote response must use application/json")
            return _read_json(response)


def _rpc_result(packet, request_id):
    if packet.get("jsonrpc") != "2.0" or type(packet.get("id")) is not int or packet["id"] != request_id:
        raise RemoteError("MCP response does not match the request")
    if "error" in packet:
        raise RemoteError("MCP server returned a protocol error")
    result = packet.get("result")
    if not isinstance(result, dict):
        raise RemoteError("MCP response result must be a JSON object")
    return result


def _sse_lines(response):
    remaining = _MAX_MESSAGE_BYTES
    partial = bytearray()
    skip_lf = False
    while remaining > 0:
        chunk = response.read1(min(remaining, 8192))
        if not chunk:
            return
        remaining -= len(chunk)
        if skip_lf:
            chunk = chunk.removeprefix(b"\n")
            skip_lf = False
        start = 0
        for boundary in re.finditer(rb"\r\n|\r|\n", chunk):
            partial.extend(chunk[start:boundary.start()])
            yield bytes(partial)
            partial.clear()
            start = boundary.end()
            skip_lf = start == len(chunk) and boundary.group() == b"\r"
        partial.extend(chunk[start:])
    raise RemoteError("MCP event stream exceeds the size limit")


def _read_sse_result(response, request_id):
    event_data = []
    for index, line in enumerate(_sse_lines(response)):
        if index == 0:
            line = line.removeprefix(b"\xef\xbb\xbf")
        if line == b"data" or line.startswith(b"data:"):
            event_data.append(line[5:].removeprefix(b" "))
        elif not line:
            payload = b"\n".join(event_data)
            event_data.clear()
            if not payload:
                continue
            packet = _json_object(payload)
            if "method" in packet:
                if packet.get("jsonrpc") == "2.0" and "id" not in packet and isinstance(packet["method"], str):
                    continue
                raise RemoteError("MCP event stream contains an unsupported server request")
            return _rpc_result(packet, request_id)
    raise RemoteError("MCP event stream ended without a matching response")


class MCPRemote(_HTTPTransport):
    """Use MCP Streamable HTTP POST requests, accepting JSON and SSE replies.

    Every operation gets a fresh session. This client declares no server-request
    capabilities and does not resume interrupted SSE streams or retry tool calls.
    """

    def __init__(
        self, endpoint: str, execute_tool: str, lookup_tool: str, token: str = "", timeout: float = 5
    ):
        super().__init__(endpoint, token, timeout)
        if not all(isinstance(tool, str) and tool.strip() for tool in (execute_tool, lookup_tool)):
            raise RemoteError("MCP execute and lookup tool names are required")
        self._execute_tool = execute_tool
        self._lookup_tool = lookup_tool

    @property
    def identity(self) -> dict:
        return {
            "type": "mcp",
            "endpoint": self._endpoint,
            "execute_tool": self._execute_tool,
            "lookup_tool": self._lookup_tool,
        }

    def execute(self, operation: dict) -> dict:
        return self._invoke(self._execute_tool, operation)

    def lookup(self, operation: dict) -> dict:
        return self._invoke(self._lookup_tool, operation)

    def _post(self, payload, headers):
        return self._open(self._endpoint, "POST", payload=payload, headers=headers, accept=_MCP_ACCEPT)

    def _request(self, method, params, request_id, headers):
        packet = {"jsonrpc": "2.0", "method": method, "id": request_id, "params": params}
        with self._post(packet, headers) as response:
            session = response.headers.get("Mcp-Session-Id")
            content_type = response.headers.get_content_type()
            if content_type == "application/json":
                result = _rpc_result(_read_json(response), request_id)
            elif content_type == "text/event-stream":
                result = _read_sse_result(response, request_id)
            else:
                raise RemoteError("MCP endpoint must return JSON or a Streamable HTTP event stream")
        return result, session

    def _invoke(self, tool, operation):
        if not isinstance(operation, dict):
            raise RemoteError("remote operation must be a JSON object")

        result, session = self._request("initialize", {
            "protocolVersion": _MCP_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "AI Native System", "version": "1"},
        }, 1, {})
        if result.get("protocolVersion") != _MCP_VERSION:
            raise RemoteError("MCP server negotiated an unsupported protocol version")
        headers = {"MCP-Protocol-Version": _MCP_VERSION}
        if session is not None:
            if not 1 <= len(session) <= 2048 or not _visible_ascii(session):
                raise RemoteError("MCP server provided an invalid session ID")
            headers["Mcp-Session-Id"] = session

        try:
            capabilities = result.get("capabilities")
            if not isinstance(capabilities, dict) or not isinstance(capabilities.get("tools"), dict):
                raise RemoteError("MCP server did not advertise tools")
            notification = {"jsonrpc": "2.0", "method": "notifications/initialized"}
            with self._post(notification, headers) as response:
                if response.status != 202:
                    raise RemoteError("MCP initialized notification was not accepted")
            request_id = self._discover_tools(headers)
            result, _ = self._request(
                "tools/call", {"name": tool, "arguments": operation}, request_id, headers,
            )
            return self._tool_result(result)
        finally:
            if session is not None:
                self._close(headers)

    def _discover_tools(self, headers):
        required = {self._execute_tool, self._lookup_tool}
        seen_cursors = set()
        params = {}
        for request_id in range(2, 2 + _MAX_TOOL_PAGES):
            result, _ = self._request("tools/list", params, request_id, headers)
            tools = result.get("tools")
            if not isinstance(tools, list):
                raise RemoteError("MCP tool directory is invalid")
            for tool in tools:
                if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
                    raise RemoteError("MCP tool directory is invalid")
                required.discard(tool["name"])
            if not required:
                return request_id + 1

            cursor = result.get("nextCursor")
            if cursor is None:
                raise RemoteError("MCP endpoint did not advertise the registered tools")
            if not isinstance(cursor, str) or not cursor or cursor in seen_cursors:
                raise RemoteError("MCP tool directory returned an invalid cursor")
            seen_cursors.add(cursor)
            params = {"cursor": cursor}
        raise RemoteError("MCP tool directory exceeded its page limit")

    @staticmethod
    def _tool_result(result):
        if result.get("isError", False) is not False:
            raise RemoteError("MCP tool reported an execution error")
        if "structuredContent" in result:
            structured = result["structuredContent"]
            if not isinstance(structured, dict):
                raise RemoteError("MCP structured tool result must be a JSON object")
            return structured

        content = result.get("content")
        if isinstance(content, list) and len(content) == 1:
            block = content[0]
            if isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str):
                return _json_object(block["text"])
        raise RemoteError("MCP tool must return a structured object or a single JSON text block")

    def _close(self, headers):
        try:
            with self._open(self._endpoint, "DELETE", headers=headers, accept=_MCP_ACCEPT):
                pass
        except RemoteError:
            # Optional cleanup must not mask whether the operation returned a receipt.
            pass
