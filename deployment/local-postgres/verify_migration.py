"""Run the PostgreSQL migration tests in a disposable Compose project."""

import os
import subprocess
import sys
from pathlib import Path

from psycopg.conninfo import make_conninfo

from verify import disposable_postgres


def main():
    root = Path(__file__).resolve().parents[2]
    with disposable_postgres("ai-native-p1b") as (port, password):
        dsn = make_conninfo(host="127.0.0.1", hostaddr="127.0.0.1", port=port,
                            dbname="ai_native_p0", user="p0_admin", password=password, connect_timeout=5)
        environment = {**os.environ, "AI_NATIVE_PG_TEST_DSN": dsn}
        subprocess.run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-p", "test_migrations.py", "-v"],
                       cwd=root, env=environment, check=True)


if __name__ == "__main__":
    main()
