"""Run the PostgreSQL runtime integration tests in a disposable Compose project."""

import os
import secrets
import subprocess
import sys
from pathlib import Path

from psycopg.conninfo import make_conninfo

from verify import disposable_postgres


def main():
    root = Path(__file__).resolve().parents[2]
    prefix = f"ai-native-p1b-runtime-{secrets.token_hex(5)}"
    with disposable_postgres(prefix) as (port, password):
        dsn = make_conninfo(host="127.0.0.1", hostaddr="127.0.0.1", port=port, dbname="ai_native_p0",
                            user="p0_admin", password=password, connect_timeout=5)
        container, = subprocess.check_output(["docker", "ps", "--filter", f"name={prefix}", "--filter",
                                              "label=com.docker.compose.service=postgres", "-q"], text=True).split()
        subprocess.run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-p",
                        "test_postgres_storage.py", "-v"], cwd=root,
                       env={**os.environ, "AI_NATIVE_PG_RUNTIME_TEST_DSN": dsn,
                            "AI_NATIVE_PG_RUNTIME_TEST_CONTAINER": container}, check=True)


if __name__ == "__main__":
    main()
