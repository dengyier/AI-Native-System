"""Run the enterprise identity, resource policy, releases and workflow suites on PostgreSQL."""

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
    "identity": ("test_postgres_identity.py", "AI_NATIVE_PG_IDENTITY_TEST_DSN"),
    "policy": ("test_postgres_resource_policy.py", "AI_NATIVE_PG_POLICY_TEST_DSN"),
    "releases": ("test_postgres_releases.py", "AI_NATIVE_PG_RELEASE_TEST_DSN"),
    "workflow": ("test_p2a_workflow.py", "AI_NATIVE_P2A_TEST_DSN"),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", choices=SUITES, action="append", help="Run one or more selected suites")
    selected = dict.fromkeys(parser.parse_args().only or SUITES)
    root = Path(__file__).resolve().parents[2]
    with disposable_postgres("ai-native-p2a") as (port, password):
        base_dsn = make_conninfo(host="127.0.0.1", hostaddr="127.0.0.1", port=port, dbname="ai_native_p0",
                                 user="p0_admin", password=password, connect_timeout=5)
        for name in selected:
            filename, variable = SUITES[name]
            if not (root / "tests" / filename).is_file():
                raise FileNotFoundError(filename)
            dbname = f"p2a_{name}"
            with psycopg.connect(base_dsn, autocommit=True) as admin:
                admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(dbname)))
            dsn = make_conninfo(base_dsn, dbname=dbname)
            subprocess.run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-p", filename, "-v"],
                           cwd=root, env={**os.environ, variable: dsn}, check=True)


if __name__ == "__main__":
    main()
