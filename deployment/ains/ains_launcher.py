"""Start the AI Native System MCP server from the AINS command."""


def mcp_main():
    try:
        from ai_native_system.mcp_server import main
    except ModuleNotFoundError as error:
        if error.name != "mcp":
            raise
        raise SystemExit('Install MCP support with pip install "ains[mcp]".') from None
    return main()
