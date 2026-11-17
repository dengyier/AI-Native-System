"""Run the fact synchronization, authority, rules and task workflows on PostgreSQL."""

import argparse
import os
import subprocess
import sys
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo

from verify import disposable_postgres


SUITES = {
    "facts": "test_fact_store.py",
    "sync": "test_fact_sync.py",
    "rules": "test_rule_evaluation.py",
    "workflow": "test_p2b_workflow.py",
    "authoritative": "test_p9_authoritative_query.py",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", choices=SUITES, action="append", help="Run one or more selected suites")
    selected = parser.parse_args().only or SUITES
    root = Path(__file__).resolve().parents[2]
    with disposable_postgres("ai-native-p2b") as (port, password):
        base = make_conninfo(host="127.0.0.1", hostaddr="127.0.0.1", port=port, dbname="ai_native_p0",
                             user="p0_admin", password=password, connect_timeout=5)
        for name in selected:
            dbname = f"p2b_{name}"
            with psycopg.connect(base, autocommit=True) as admin:
                admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(dbname)))
            dsn = make_conninfo(base, dbname=dbname)
            with psycopg.connect(dsn) as admin:
                admin.execute("CREATE SCHEMA ai_native")
            subprocess.run(
                [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-p", SUITES[name], "-v"],
                cwd=root, env={**os.environ, "AI_NATIVE_P2B_TEST_DSN": dsn}, check=True,
            )


if __name__ == "__main__":
    main()
