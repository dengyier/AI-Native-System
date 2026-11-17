"""Run the tenant isolation tests in a disposable Compose project."""

import os
import subprocess
import sys
from pathlib import Path

from psycopg.conninfo import make_conninfo

from verify import disposable_postgres


def main():
    root = Path(__file__).resolve().parents[2]
    with disposable_postgres("ai-native-p2a") as (port, password):
        dsn = make_conninfo(host="127.0.0.1", hostaddr="127.0.0.1", port=port, dbname="ai_native_p0",
                            user="p0_admin", password=password, connect_timeout=5)
        subprocess.run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-p",
                        "test_postgres_tenant_isolation.py", "-v"], cwd=root,
                       env={**os.environ, "AI_NATIVE_PG_TENANT_TEST_DSN": dsn}, check=True)


if __name__ == "__main__":
    main()
