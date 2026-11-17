"""Verify LangGraph and protected task recovery against disposable PostgreSQL."""

import argparse
from importlib.util import find_spec
import os
import subprocess
import sys
from pathlib import Path

import psycopg
from psycopg.conninfo import make_conninfo

from verify import disposable_postgres


SUITES = {
    "contract": "test_graph_contract.py",
    "adapter": "test_langgraph_adapter.py",
    "checkpoints": "test_langgraph_postgres.py",
    "workflow": "test_graph_runtime.py",
    "remote": "test_graph_remote.py",
    "signed-remote": "test_graph_signed_remote.py",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", choices=SUITES, action="append")
    selected = parser.parse_args().only or SUITES
    if find_spec("langgraph") is None or find_spec("langgraph.checkpoint.postgres") is None:
        parser.error("install the locked postgres and integrations dependencies")
    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root))
    from ai_native_system.adapters.postgres import migrate_postgres

    with disposable_postgres("ai-native-p6") as (port, password):
        dsn = make_conninfo(host="127.0.0.1", hostaddr="127.0.0.1", port=port, dbname="ai_native_p0",
                            user="p0_admin", password=password, connect_timeout=5)
        with psycopg.connect(dsn) as connection:
            connection.execute("CREATE SCHEMA IF NOT EXISTS ai_native")
            version, = connection.execute("SHOW server_version").fetchone()
        revision = migrate_postgres(dsn)
        print(f"P6 PostgreSQL {version}, migration {revision}", flush=True)
        environment = {**os.environ, "AI_NATIVE_P6_TEST_DSN": dsn,
                       "AI_NATIVE_P4_TEST_DSN": dsn, "AI_NATIVE_P4_SOURCE_TEST_DSN": dsn}
        if any(suite in selected for suite in ("checkpoints", "workflow", "remote", "signed-remote")):
            subprocess.run([sys.executable, "-B", "-m", "ai_native_system", "--postgres", "p6", "migrate-checkpoints"],
                           cwd=root, env={**environment, "AI_NATIVE_GRAPH_MIGRATION_DSN": dsn}, check=True)
        for suite in selected:
            subprocess.run(
                [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-p", SUITES[suite], "-v"],
                cwd=root, env=environment, check=True,
            )


if __name__ == "__main__":
    main()
