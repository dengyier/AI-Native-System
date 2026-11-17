"""Verify permissioned knowledge and real pgvector retrieval on disposable PostgreSQL."""

import argparse
import os
import subprocess
import sys
from importlib.util import find_spec
from pathlib import Path

import psycopg
from psycopg.conninfo import make_conninfo

from verify import disposable_postgres


SUITES = {
    "ingestion": "test_knowledge_ingest.py",
    "permissions": "test_authorized_retrieval.py",
    "vector": "test_pgvector_retrieval.py",
    "memory": "test_memory_scope.py",
    "evidence": "test_knowledge_evidence.py",
    "evaluation": "test_evaluation.py",
    "workflow": "test_p7_workflow.py",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--only", choices=SUITES, action="append")
    selected = parser.parse_args().only or SUITES
    if any(find_spec(package) is None for package in ("llama_index", "litellm", "langfuse")):
        parser.error("install the locked postgres and integrations dependencies")
    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root))
    from ai_native_system.adapters.postgres import migrate_postgres

    with disposable_postgres("ai-native-p7") as (port, password):
        dsn = make_conninfo(host="127.0.0.1", hostaddr="127.0.0.1", port=port, dbname="ai_native_p0",
                            user="p0_admin", password=password, connect_timeout=5)
        with psycopg.connect(dsn) as connection:
            connection.execute("CREATE SCHEMA IF NOT EXISTS ai_native")
            version, extension = connection.execute(
                "SELECT current_setting('server_version'), extversion FROM pg_extension WHERE extname = 'vector'",
            ).fetchone()
        revision = migrate_postgres(dsn)
        print(f"P7 PostgreSQL {version}, pgvector {extension}, migration {revision}", flush=True)
        environment = {**os.environ, "AI_NATIVE_P7_TEST_DSN": dsn}
        for suite in selected:
            if not (root / "tests" / SUITES[suite]).is_file():
                raise RuntimeError(f"Missing P7 test suite {suite}")
            subprocess.run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-p", SUITES[suite], "-v"],
                           cwd=root, env=environment, check=True)


if __name__ == "__main__":
    main()
