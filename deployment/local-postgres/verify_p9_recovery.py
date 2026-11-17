"""Rehearse an isolated PostgreSQL backup restore with authority and knowledge replay."""

import argparse
import os
import secrets
import subprocess
import sys
from pathlib import Path

import psycopg
from psycopg.conninfo import make_conninfo

from verify import disposable_postgres


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", action="append", choices=("recovery", "agent"))
    selected = parser.parse_args().only or ("recovery", "agent")
    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root))
    from ai_native_system.adapters.postgres import migrate_postgres

    prefix = "ai-native-p9-" + secrets.token_hex(4)
    with disposable_postgres(prefix) as (port, password):
        dsn = make_conninfo(host="127.0.0.1", hostaddr="127.0.0.1", port=port, dbname="ai_native_p0",
                            user="p0_admin", password=password, connect_timeout=5)
        with psycopg.connect(dsn) as connection:
            connection.execute("CREATE SCHEMA IF NOT EXISTS ai_native")
            version, extension = connection.execute(
                "SELECT current_setting('server_version'), extversion FROM pg_extension WHERE extname='vector'",
            ).fetchone()
        revision = migrate_postgres(dsn)
        container, = subprocess.check_output(["docker", "ps", "--filter", f"name={prefix}", "--filter",
                                              "label=com.docker.compose.service=postgres", "-q"], text=True).split()
        print(f"P9 local PostgreSQL {version}, pgvector {extension}, migration {revision}", flush=True)
        files = {"recovery": "test_deployment_recovery.py", "agent": "test_agent_runtime.py"}
        for suite in selected:
            subprocess.run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-p",
                            files[suite], "-v"], cwd=root,
                           env={**os.environ, "AI_NATIVE_P9_TEST_DSN": dsn, "AI_NATIVE_P9_TEST_CONTAINER": container},
                           check=True)


if __name__ == "__main__":
    main()
