"""Verify P5 against disposable PostgreSQL and loopback provider/OTLP endpoints."""

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
    "backend": "test_model_backend.py",
    "accounting": "test_model_accounting.py",
    "observation": "test_observability.py",
    "workflow": "test_p5_workflow.py",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", choices=SUITES, action="append")
    selected = parser.parse_args().only or SUITES
    if any(find_spec(package) is None for package in ("litellm", "langfuse")):
        parser.error("install the locked postgres and integrations dependencies")
    root = Path(__file__).resolve().parents[2]
    with disposable_postgres("ai-native-p5") as (port, password):
        dsn = make_conninfo(host="127.0.0.1", hostaddr="127.0.0.1", port=port, dbname="ai_native_p0",
                            user="p0_admin", password=password, connect_timeout=5)
        with psycopg.connect(dsn) as connection:
            connection.execute("CREATE SCHEMA IF NOT EXISTS ai_native")
            version, = connection.execute("SHOW server_version").fetchone()
        sys.path.insert(0, str(root))
        from ai_native_system.adapters.postgres import migrate_postgres

        revision = migrate_postgres(dsn)
        print(f"P5 PostgreSQL {version}, migration {revision}", flush=True)
        for suite in selected:
            subprocess.run(
                [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-p", SUITES[suite], "-v"],
                cwd=root, env={**os.environ, "AI_NATIVE_P5_TEST_DSN": dsn}, check=True,
            )


if __name__ == "__main__":
    main()
