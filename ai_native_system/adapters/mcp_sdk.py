"""Registered operation calls through the pinned, official MCP Python SDK."""

import asyncio
import math
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from hashlib import sha256
from importlib.metadata import version
from pathlib import Path
from types import MappingProxyType
from urllib.parse import urlsplit

from ..fact_contracts import canonical_json
from ..remote import RemoteError, _json_object


_SDK_VERSION = "2.3.0"
_MAX_MESSAGE_BYTES = 256 * 1024
_MAX_WIRE_BYTES = 768 * 1024
_MAX_DIRECTORY_PAGES = 16
_MAX_DIRECTORY_TOOLS = 1024
_CONDITIONAL_PROFILE = "source-write/v1"
_HEX_DIGEST = re.compile(r"[a-f0-9]{64}\Z")
_ENV_NAME = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]*\Z")
_TOOL_NAME = re.compile(r"[a-zA-Z0-9_.-]{1,128}\Z")


def _text(value, limit):
    return type(value) is str and "\0" not in value and len(value) <= limit


def _digest(document):
    encoded = canonical_json(document).encode("utf-8")
    if len(encoded) > _MAX_MESSAGE_BYTES:
        raise ValueError("MCP document exceeds the size limit")
    return sha256(encoded).hexdigest()


def _schema_contract(schema):
    if type(schema) is not dict or schema.get("type") != "object":
        raise ValueError("MCP tool schema must declare a JSON object")
    pending = [schema]
    while pending:
        part = pending.pop()
        if isinstance(part, dict):
            for key, value in part.items():
                if key in ("$ref", "$dynamicRef", "$recursiveRef") and (
                    not isinstance(value, str) or not value.startswith("#")
                ):
                    raise ValueError("MCP tool schema references must stay inside the schema")
                if key == "x-mcp-header":
                    raise ValueError("MCP tool arguments must remain in the message body")
                pending.append(value)
        elif isinstance(part, list):
            pending.extend(part)


def tool_schema_digest(input_schema, output_schema=None):
    """Pin the exact advertised schemas, including whether output is structured."""
    result = _digest({"input": input_schema, "output": output_schema})
    _schema_contract(input_schema)
    if output_schema is not None:
        _schema_contract(output_schema)
    return result


def _endpoint(value):
    try:
        url = urlsplit(value)
        port = url.port
    except (TypeError, ValueError):
        raise ValueError("Invalid MCP Streamable HTTP endpoint") from None
    local = url.hostname in {"localhost", "127.0.0.1", "::1"}
    if (
        not _text(value, 2048) or not value or any(not 0x21 <= ord(ch) <= 0x7E for ch in value)
        or any(ch in value for ch in "?#\\") or port == 0 or not url.hostname or url.username is not None
        or (url.scheme != "https" and not (url.scheme == "http" and local))
    ):
        raise ValueError("MCP endpoint must use HTTPS or loopback HTTP without credentials or redirects")
    return value


def _path(value):
    if not isinstance(value, (str, Path)) or not _text(str(value), 4096):
        raise ValueError("MCP launch paths must be nonempty absolute paths")
    path = Path(value)
    if not path.is_absolute():
        raise ValueError("MCP launch paths must be absolute")
    return path


@dataclass(frozen=True)
class StdioLaunch:
    """One operator-allowed command, arguments, working directory and explicit environment."""

    command: str | Path
    args: tuple[str, ...] | list[str]
    cwd: str | Path
    env: Mapping[str, str] | None = field(default=None, repr=False)
    _target: str = field(init=False, repr=False)

    def __post_init__(self):
        command, cwd = _path(self.command), _path(self.cwd)
        target = command.resolve()
        cwd = cwd.resolve()
        if not target.is_file() or not os.access(target, os.X_OK) or not cwd.is_dir():
            raise ValueError("MCP launch requires an executable and an existing working directory")
        if (
            not isinstance(self.args, (list, tuple)) or len(self.args) > 64
            or not all(_text(arg, 4096) for arg in self.args)
        ):
            raise ValueError("Invalid MCP launch arguments")
        env = {} if self.env is None else self.env
        if not isinstance(env, Mapping) or len(env) > 64 or any(
            type(key) is not str or not _ENV_NAME.fullmatch(key) or not _text(value, 16384)
            for key, value in env.items()
        ):
            raise ValueError("Invalid explicit MCP launch environment")
        object.__setattr__(self, "command", str(command))
        object.__setattr__(self, "cwd", str(cwd))
        object.__setattr__(self, "_target", str(target))
        object.__setattr__(self, "args", tuple(self.args))
        object.__setattr__(self, "env", MappingProxyType(dict(env)))

    @property
    def digest(self):
        # Values may be rotated credentials. Publishing includes env names only.
        return _digest({
            "command": self.command, "target": self._target, "args": self.args,
            "cwd": self.cwd, "env_names": sorted(self.env),
        })

    def _parameters(self):
        from mcp import StdioServerParameters
        from mcp.client.stdio import DEFAULT_INHERITED_ENV_VARS

        if Path(self.command).resolve() != Path(self._target) or Path(self.cwd).resolve() != Path(self.cwd):
            raise RemoteError("MCP stdio launch paths changed")
        # The pinned SDK otherwise merges a small set of ambient values into env.
        environment = {name: "" for name in DEFAULT_INHERITED_ENV_VARS}
        environment.update(self.env)
        return StdioServerParameters(command=self.command, args=list(self.args), cwd=self.cwd, env=environment)


class MCPSDKRemote:
    """Use a fresh, bounded official SDK session for each registered operation."""

    def __init__(
        self, *, execute_tool, lookup_tool, execute_schema_digest, lookup_schema_digest,
        endpoint=None, token="", lookup_token=None, launch=None, timeout=5, profile=None,
    ):
        if (
            not all(isinstance(name, str) and _TOOL_NAME.fullmatch(name) for name in (execute_tool, lookup_tool))
            or execute_tool == lookup_tool
        ):
            raise ValueError("MCP execute and lookup need distinct registered tool names")
        if not all(isinstance(value, str) and _HEX_DIGEST.fullmatch(value)
                   for value in (execute_schema_digest, lookup_schema_digest)):
            raise ValueError("MCP tool schema digests must be SHA-256")
        if profile not in (None, _CONDITIONAL_PROFILE):
            raise ValueError("Unknown MCP operation profile")
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("MCP deadline must be positive")
        if not all(
            _text(value, 8192) and all(0x21 <= ord(ch) <= 0x7E for ch in value)
            for value in (token, lookup_token if lookup_token is not None else "")
        ):
            raise ValueError("Invalid MCP bearer credential")
        if (endpoint is None) == (launch is None):
            raise ValueError("Configure exactly one MCP Streamable HTTP or stdio destination")
        if launch is not None and (not isinstance(launch, StdioLaunch) or token or lookup_token is not None):
            raise ValueError("MCP stdio requires an allowed launch and uses only its explicit environment")
        self._endpoint = _endpoint(endpoint) if endpoint is not None else None
        self._launch = launch
        self._token = token
        self._lookup_token = token if lookup_token is None else lookup_token
        self._execute_tool = execute_tool
        self._lookup_tool = lookup_tool
        self._digests = {execute_tool: execute_schema_digest, lookup_tool: lookup_schema_digest}
        self._timeout = timeout
        self._profile = profile

    @property
    def separate_lookup_credentials(self):
        return bool(self._endpoint and self._token and self._lookup_token and self._token != self._lookup_token)

    @property
    def identity(self):
        destination = (
            {"type": "mcp-sdk-http", "endpoint": self._endpoint} if self._endpoint is not None
            else {"type": "mcp-sdk-stdio", "launch_digest": self._launch.digest}
        )
        if self._profile is not None:
            destination["profile"] = self._profile
        return {
            **destination,
            "execute_tool": self._execute_tool,
            "lookup_tool": self._lookup_tool,
            "execute_schema_digest": self._digests[self._execute_tool],
            "lookup_schema_digest": self._digests[self._lookup_tool],
        }

    def execute(self, operation):
        if self._profile is not None:
            raise RemoteError("Conditional MCP execution requires a signed authorization")
        return self._invoke(self._execute_tool, operation, self._token)

    def execute_authorized(self, operation, envelope):
        if self._profile != _CONDITIONAL_PROFILE or not isinstance(envelope, dict):
            raise RemoteError("Conditional MCP execution requires a registered source profile and authorization")
        return self._invoke(self._execute_tool, {"operation": operation, "authorization": envelope}, self._token)

    def lookup(self, operation):
        arguments = {"operation": operation} if self._profile is not None else operation
        return self._invoke(self._lookup_tool, arguments, self._lookup_token)

    def _invoke(self, name, arguments, token):
        if not isinstance(arguments, dict):
            raise RemoteError("MCP arguments must be a JSON object")
        try:
            _digest(arguments)
            return asyncio.run(self._call(name, arguments, token))
        except Exception as error:
            # SDK task groups can wrap our own safe errors at transport shutdown.
            while isinstance(error, BaseExceptionGroup) and len(error.exceptions) == 1:
                error = error.exceptions[0]
            if isinstance(error, RemoteError):
                raise error from None
            # Third-party error messages may echo signed arguments or tool output.
            raise RemoteError("Registered MCP call failed or exceeded its deadline") from None

    async def _call(self, name, arguments, token):
        if version("mcp") != _SDK_VERSION:
            raise RemoteError("Install the pinned official MCP SDK")
        from mcp import Client
        from mcp.client.stdio import stdio_client
        from mcp.client.streamable_http import streamable_http_client

        async with asyncio.timeout(self._timeout):
            if self._launch is not None:
                # Discard child diagnostics so the remote process cannot inject secrets into caller logs.
                with open(os.devnull, "w", encoding="utf-8") as errors:
                    async with Client(stdio_client(self._launch._parameters(), errlog=errors),
                                      read_timeout_seconds=self._timeout, cache=None) as client:
                        return await self._call_registered(client, name, arguments)

            import httpx2

            headers = {"Accept-Encoding": "identity"}
            if token:
                headers["Authorization"] = f"Bearer {token}"
            async with httpx2.AsyncClient(
                headers=headers, trust_env=False, follow_redirects=False, timeout=self._timeout,
                transport=_restricted_http_transport(httpx2, self._endpoint),
            ) as connection:
                transport = streamable_http_client(
                    self._endpoint, http_client=connection, max_sse_event_size=_MAX_WIRE_BYTES,
                )
                async with Client(transport, read_timeout_seconds=self._timeout, cache=None) as client:
                    return await self._call_registered(client, name, arguments)

    async def _call_registered(self, client, name, arguments):
        from jsonschema import Draft202012Validator
        from referencing import Registry

        tools = await self._verified_directory(client, name)
        declared = tools[name]
        input_schema, output_schema = declared.input_schema, declared.output_schema
        Draft202012Validator.check_schema(input_schema)
        Draft202012Validator(input_schema, registry=Registry()).validate(arguments)
        if output_schema is not None:
            Draft202012Validator.check_schema(output_schema)
        # The high-level SDK call may re-list and retry on schema mismatch.
        # A write uses a single SDK session call instead.
        response = await client.session.call_tool(name, arguments)
        if response.is_error:
            raise RemoteError("MCP tool reported an error")
        result = response.structured_content
        if result is None and output_schema is None:
            if len(response.content) == 1 and response.content[0].type == "text":
                result = _json_object(response.content[0].text)
        if not isinstance(result, dict):
            raise RemoteError("MCP tool must return a JSON object")
        _digest(result)
        if output_schema is not None:
            Draft202012Validator(output_schema, registry=Registry()).validate(result)
        return result

    async def _verified_directory(self, client, required):
        registered = {}
        cursors = set()
        cursor = None
        count = 0
        for _ in range(_MAX_DIRECTORY_PAGES):
            page = await client.list_tools(cursor=cursor)
            count += len(page.tools)
            if count > _MAX_DIRECTORY_TOOLS:
                raise RemoteError("MCP tool directory exceeded its size limit")
            for tool in page.tools:
                if tool.name not in self._digests:
                    continue
                if tool.name in registered:
                    raise RemoteError("MCP directory listed a registered tool more than once")
                if tool_schema_digest(tool.input_schema, tool.output_schema) != self._digests[tool.name]:
                    raise RemoteError("MCP registered tool schema changed")
                if tool.annotations is not None:
                    read_only = tool.annotations.read_only_hint
                    if read_only is not None and read_only != (tool.name == self._lookup_tool):
                        raise RemoteError("MCP tool's declared access mode contradicts its registration")
                registered[tool.name] = tool
            cursor = page.next_cursor
            if cursor is None:
                if required not in registered:
                    raise RemoteError("MCP endpoint did not list the registered tool for this request")
                return registered
            if not cursor or len(cursor) > 2048 or cursor in cursors:
                raise RemoteError("Invalid MCP tool-list cursor")
            cursors.add(cursor)
        raise RemoteError("MCP tool directory exceeded its page limit")


def _restricted_http_transport(httpx2, endpoint):
    destination = httpx2.URL(endpoint)

    class BoundedStream(httpx2.AsyncByteStream):
        def __init__(self, source):
            self.source = source

        async def __aiter__(self):
            size = 0
            async for chunk in self.source:
                size += len(chunk)
                if size > _MAX_WIRE_BYTES:
                    raise RemoteError("MCP response exceeded its wire limit")
                yield chunk

        async def aclose(self):
            await self.source.aclose()

    class RestrictedTransport(httpx2.AsyncHTTPTransport):
        async def handle_async_request(self, request):
            if request.url != destination:
                raise RemoteError("MCP request destination changed")
            response = await super().handle_async_request(request)
            if 300 <= response.status_code < 400:
                await response.aclose()
                raise RemoteError("MCP HTTP redirects are not permitted")
            if response.headers.get("content-encoding", "identity").lower() != "identity":
                await response.aclose()
                raise RemoteError("MCP compressed responses are not permitted")
            response.stream = BoundedStream(response.stream)
            return response

    return RestrictedTransport(retries=0, trust_env=False)
