"""Run OpenWorkProof profile, ledger, evidence and runtime suites against PostgreSQL."""

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
    "profile": "test_owp_profile.py",
    "ledger": "test_owp_ledger.py",
    "evidence": "test_owp_evidence.py",
    "workflow": "test_security_entry.py",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", choices=SUITES, action="append", help="Run one or more selected suites")
    selected = parser.parse_args().only or SUITES
    root = Path(__file__).resolve().parents[2]
    prefix = f"ai-native-p3-{secrets.token_hex(5)}"
    with disposable_postgres(prefix) as (port, password):
        base = make_conninfo(host="127.0.0.1", hostaddr="127.0.0.1", port=port, dbname="ai_native_p0",
                             user="p0_admin", password=password, connect_timeout=5)
        container, = subprocess.check_output(["docker", "ps", "--filter", f"name={prefix}", "--filter",
                                              "label=com.docker.compose.service=postgres", "-q"], text=True).split()
        for name in selected:
            database = f"p3_{name}"
            with psycopg.connect(base, autocommit=True) as admin:
                admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
            dsn = make_conninfo(base, dbname=database)
            with psycopg.connect(dsn) as admin:
                admin.execute("CREATE SCHEMA ai_native")
            subprocess.run(
                [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-p", SUITES[name], "-v"],
                cwd=root, env={**os.environ, "AI_NATIVE_P3_TEST_DSN": dsn, "AI_NATIVE_P3_TEST_CONTAINER": container},
                check=True,
            )


if __name__ == "__main__":
    main()
