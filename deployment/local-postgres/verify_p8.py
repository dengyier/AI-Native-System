"""Verify the P8 applications, SDK and console against disposable PostgreSQL."""

import argparse
import os
import subprocess
import sys
from pathlib import Path

import psycopg
from psycopg.conninfo import make_conninfo

from verify import disposable_postgres


SUITES = {"sdk": "test_client.py", "applications": "test_application_reuse.py", "console": "test_console_api.py"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", action="append", choices=SUITES)
    parser.add_argument("--browser", action="store_true", help="Require the actual Playwright browser flow")
    args = parser.parse_args()
    selected = args.only or SUITES
    if args.browser and "console" not in selected:
        parser.error("The browser uses the real PostgreSQL console suite")
    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root))
    from ai_native_system.adapters.postgres import migrate_postgres

    with disposable_postgres("ai-native-p8") as (port, password):
        dsn = make_conninfo(host="127.0.0.1", hostaddr="127.0.0.1", port=port, dbname="ai_native_p0",
                            user="p0_admin", password=password, connect_timeout=5)
        with psycopg.connect(dsn) as connection:
            connection.execute("CREATE SCHEMA IF NOT EXISTS ai_native")
            version, extension = connection.execute(
                "SELECT current_setting('server_version'), extversion FROM pg_extension WHERE extname='vector'",
            ).fetchone()
        revision = migrate_postgres(dsn)
        print(f"P8 PostgreSQL {version}, pgvector {extension}, migration {revision}", flush=True)
        environment = {**os.environ, "AI_NATIVE_P8_TEST_DSN": dsn, "AI_NATIVE_P8_BROWSER": "1" if args.browser else "0"}
        for suite in selected:
            subprocess.run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-p", SUITES[suite], "-v"],
                           cwd=root, env=environment, check=True)


if __name__ == "__main__":
    main()
