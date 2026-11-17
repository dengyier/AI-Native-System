"""Trusted transactional tools. Handlers must keep all effects in the supplied transaction."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Tool:
    name: str
    version: str
    handler: object
    remote: bool = False
    source: object | None = None

    @property
    def identity(self):
        if not self.remote:
            return None
        value = getattr(self.handler, "identity", None)
        return value if self.source is None else {**value, "source_binding": self.source.identity}


class ToolRegistry:
    def __init__(self):
        self._tools = {}
        self.register("state.transition", "1", transition)

    def register(self, name, version, handler):
        if not name or not version or not callable(handler) or (name, version) in self._tools:
            raise ValueError("Tool requires a unique name/version and callable handler")
        self._tools[name, version] = Tool(name, version, handler)

    def register_remote(self, name, version, adapter, *, source=None):
        if (not name or not version or (name, version) in self._tools
                or not callable(getattr(adapter, "execute", None))
                or not callable(getattr(adapter, "lookup", None))):
            raise ValueError("Remote tool requires a unique version, execute and lookup")
        if source is not None:
            from .adapters.mcp_sdk import MCPSDKRemote
            from .p4_tools import SourceBinding

            if (not isinstance(source, SourceBinding) or not isinstance(adapter, MCPSDKRemote)
                    or adapter.identity.get("profile") != "source-write/v1" or not adapter.separate_lookup_credentials):
                raise ValueError("Conditional writes require the signed SDK protocol with separate lookup credentials")
        elif (getattr(adapter, "identity", None) or {}).get("profile") == "source-write/v1":
            raise ValueError("Conditional writes require a trusted source binding")
        self._tools[name, version] = Tool(name, version, adapter, True, source)

    def resolve(self, action):
        key = (action.get("tool", "state.transition"), action.get("tool_version", "1"))
        try:
            return self._tools[key]
        except KeyError:
            raise ValueError("Unregistered tool version") from None

    def list_tools(self):
        return [{"name": tool.name, "version": tool.version, "transactional": not tool.remote,
                 **({"kind": "write_remote", "conditional_write": True, "receipt_lookup": True,
                     "destination": tool.identity} if tool.source is not None else {})}
                for tool in self._tools.values()]


def transition(connection, task, action, ground):
    item = ground["object"]
    changed = connection.execute(
        """UPDATE objects SET state = ?, version = version + 1
           WHERE tenant = ? AND id = ? AND state = ? AND version = ?""",
        (action["to_state"], task["tenant"], item["id"], action["from_state"], item["version"]),
    )
    if changed.rowcount != 1:
        raise ValueError("Object changed during tool execution")
    return {"state": action["to_state"], "version": item["version"] + 1}


def configured_tools(configuration):
    """Register remote adapters explicitly; credential values stay in environment variables."""
    import os
    from .remote import HttpRemote, MCPRemote

    registry = ToolRegistry()
    for config in configuration["tools"]:
        kind = config["transport"]
        key_env = config.get("token_env")
        token = os.environ[key_env] if key_env else ""
        kwargs = {"token": token, "timeout": config.get("timeout", 5)}
        if config.get("idempotent") is not True:
            raise ValueError("Remote execution requires an idempotent operation/receipt contract")
        if kind == "http":
            adapter = HttpRemote(config["endpoint"], **kwargs)
        elif kind == "mcp":
            adapter = MCPRemote(config["endpoint"], config["execute_tool"], config["lookup_tool"], **kwargs)
        elif kind in ("mcp-sdk-http", "mcp-sdk-stdio"):
            adapter, source = _sdk_adapter(config, kind, kwargs, os.environ)
            registry.register_remote(config["name"], config["version"], adapter, source=source)
            continue
        else:
            raise ValueError("Unsupported remote transport")
        registry.register_remote(config["name"], config["version"], adapter)
    return registry


def _sdk_adapter(config, kind, kwargs, env):
    import json
    from pathlib import Path

    from .adapters.mcp_sdk import MCPSDKRemote, StdioLaunch
    from .registry import unique_keys

    source = None
    endpoint, launch, lookup_token = None, None, None
    if kind == "mcp-sdk-http":
        endpoint = config["endpoint"]
        if "lookup_token_env" in config:
            lookup_token = env[config["lookup_token_env"]]
    else:
        allowlist_path = env.get("AI_NATIVE_MCP_STDIO_ALLOWLIST")
        if not allowlist_path or config.get("token_env") or config.get("lookup_token_env"):
            raise ValueError("MCP stdio requires an independent launch allowlist")
        entries = json.loads(Path(allowlist_path).read_text(), object_pairs_hook=unique_keys)
        entry = entries[config["launch"]]
        if set(entry) - {"command", "args", "cwd", "env"}:
            raise ValueError("Invalid MCP stdio launch configuration")
        launch = StdioLaunch(entry["command"], entry["args"], entry["cwd"],
                             env={key: env[name] for key, name in entry.get("env", {}).items()})
    if "source" in config:
        from .adapters.owp import key_id, load_public_key
        from .p4_tools import SourceBinding

        declared = config["source"]
        if (kind != "mcp-sdk-http" or not kwargs["token"] or not lookup_token or kwargs["token"] == lookup_token
                or not isinstance(declared, dict)
                or declared.keys() != {"source", "lookup_principal", "retention_seconds", "receipt_public_keys"}
                or not isinstance(declared["receipt_public_keys"], list)):
            raise ValueError("Conditional writes require HTTP, separate lookup credentials and source receipt trust")
        keys = {}
        for path in declared["receipt_public_keys"]:
            public = load_public_key(Path(path).read_bytes())
            keys[key_id(public)] = public
        source = SourceBinding(declared["source"], declared["lookup_principal"], declared["retention_seconds"], keys)
    adapter = MCPSDKRemote(
        execute_tool=config["execute_tool"], lookup_tool=config["lookup_tool"],
        execute_schema_digest=config["execute_schema_digest"], lookup_schema_digest=config["lookup_schema_digest"],
        endpoint=endpoint, launch=launch, lookup_token=lookup_token,
        profile="source-write/v1" if source is not None else None, **kwargs,
    )
    return adapter, source
