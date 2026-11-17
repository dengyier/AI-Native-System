"""Verify the SDK, isolated source, delivery stores and end-to-end P4 execution."""

import argparse
import os
import secrets
import subprocess
import sys
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo

from verify import disposable_postgres


SUITES = {
    "sdk": "test_mcp_sdk_adapter.py",
    "source": "test_source_write.py",
    "delivery": "test_p4_delivery.py",
    "workflow": "test_p4_workflow.py",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", choices=SUITES, action="append")
    selected = parser.parse_args().only or SUITES
    root = Path(__file__).resolve().parents[2]
    prefix = f"ai-native-p4-{secrets.token_hex(5)}"
    with disposable_postgres(prefix) as (port, password):
        dsn = make_conninfo(host="127.0.0.1", hostaddr="127.0.0.1", port=port, dbname="ai_native_p0",
                            user="p0_admin", password=password, connect_timeout=5)
        container, = subprocess.check_output(["docker", "ps", "--filter", f"name={prefix}", "--filter",
                                              "label=com.docker.compose.service=postgres", "-q"], text=True).split()
        for suite in selected:
            name, native = "p4_" + suite, "native_" + suite
            with psycopg.connect(dsn, autocommit=True) as admin:
                for database in (name, native):
                    admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
            framework = make_conninfo(dsn, dbname=name)
            with psycopg.connect(framework) as admin:
                admin.execute("CREATE SCHEMA ai_native")
            subprocess.run(
                [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-p", SUITES[suite], "-v"],
                cwd=root, env={**os.environ, "AI_NATIVE_P4_TEST_DSN": framework, "AI_NATIVE_P4_TEST_CONTAINER": container,
                               "AI_NATIVE_P4_SOURCE_TEST_DSN": make_conninfo(dsn, dbname=native)}, check=True,
            )


if __name__ == "__main__":
    main()
