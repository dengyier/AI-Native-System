"""Check that the locked P0 Python dependencies work in one environment."""

import asyncio
from importlib import import_module
from importlib.metadata import version
import os
import sys
from tempfile import TemporaryDirectory


PACKAGES = {
    "alembic": "alembic.command",
    "langfuse": "langfuse",
    "langgraph": "langgraph.graph",
    "langgraph-checkpoint-postgres": "langgraph.checkpoint.postgres",
    "litellm": "litellm",
    "llama-index-core": "llama_index.core",
    "llama-index-vector-stores-postgres": "llama_index.vector_stores.postgres",
    "mcp": "mcp",
    "openworkproof": "openworkproof.signing",
    "pgvector": "pgvector.psycopg",
    "psycopg": "psycopg",
    "psycopg-pool": "psycopg_pool",
}


async def verify_openworkproof() -> None:
    from mcp import Client, StdioServerParameters

    with TemporaryDirectory() as directory:
        server = StdioServerParameters(
            command=sys.executable,
            args=["-B", "-m", "openworkproof.mcp_transport"],
            cwd=directory,
        )
        async with asyncio.timeout(20), Client(server) as client:
            tools = await client.list_tools()
            if not any(tool.name == "owp_get_schema" for tool in tools.tools):
                raise RuntimeError("The OWP server did not advertise owp_get_schema")
            response = await client.call_tool("owp_get_schema", {"object_type": "work-order"})
            data = response.structured_content or {}
            if response.is_error or data.get("ok") is not True or not data.get("schema"):
                raise RuntimeError("The OWP server did not return its work-order schema")
            print(f"OpenWorkProof MCP stdio: {client.protocol_version}, {len(tools.tools)} tools, schema OK")


def main() -> None:
    os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "true"
    os.environ["LITELLM_OFFLINE_MODE"] = "true"
    os.environ["OTEL_SDK_DISABLED"] = "true"

    for distribution, module in PACKAGES.items():
        import_module(module)
        print(f"{distribution} {version(distribution)}")

    from langgraph.graph import END, START, StateGraph

    graph = StateGraph(int)
    graph.add_node("increment", lambda value: value + 1)
    graph.add_edge(START, "increment")
    graph.add_edge("increment", END)
    if graph.compile().invoke(1) != 2:
        raise RuntimeError("LangGraph did not produce the expected local result")
    print("LangGraph in-memory graph: OK")

    asyncio.run(verify_openworkproof())


if __name__ == "__main__":
    main()
