"""Exercise the P0 database environment in a disposable Compose project."""

import os
import secrets
import subprocess
from contextlib import contextmanager
from pathlib import Path

import psycopg
import sqlalchemy as sa
from alembic.migration import MigrationContext
from alembic.operations import Operations
from pgvector import Vector
from pgvector.psycopg import register_vector
from pgvector.sqlalchemy import VECTOR
from psycopg import sql
from psycopg.errors import InsufficientPrivilege
from psycopg_pool import ConnectionPool


def verify_database(port, admin_password):
    connection = {"host": "127.0.0.1", "hostaddr": "127.0.0.1", "port": port, "dbname": "ai_native_p0"}
    migrator_password = secrets.token_urlsafe(24)
    runtime_password = secrets.token_urlsafe(24)
    with psycopg.connect(**connection, user="p0_admin", password=admin_password, connect_timeout=5) as admin:
        server_version = admin.execute("SHOW server_version_num").fetchone()[0]
        server_description = admin.execute("SHOW server_version").fetchone()[0]
        if server_version != "180007":
            raise RuntimeError(f"Unexpected PostgreSQL version: {server_description}")
        admin.execute("CREATE EXTENSION IF NOT EXISTS vector")
        extension_version = admin.execute("SELECT extversion FROM pg_extension WHERE extname = 'vector'").fetchone()[0]
        if extension_version != "0.8.7":
            raise RuntimeError(f"Unexpected pgvector version: {extension_version}")
        for role, password in (("p0_migrator", migrator_password), ("p0_runtime", runtime_password)):
            admin.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(sql.Identifier(role), sql.Literal(password)))
        admin.execute("REVOKE ALL ON DATABASE ai_native_p0 FROM PUBLIC")
        admin.execute("GRANT CONNECT ON DATABASE ai_native_p0 TO p0_migrator, p0_runtime")
        admin.execute("CREATE SCHEMA p0_smoke AUTHORIZATION p0_migrator")

    migration_url = sa.URL.create(
        "postgresql+psycopg", username="p0_migrator", password=migrator_password,
        host=connection["host"], port=port, database=connection["dbname"],
    )
    engine = sa.create_engine(migration_url, connect_args={"hostaddr": connection["hostaddr"], "connect_timeout": 5})
    try:
        with engine.begin() as migration:
            operations = Operations(MigrationContext.configure(migration))
            operations.create_table(
                "vectors", sa.Column("id", sa.Integer, primary_key=True),
                sa.Column("embedding", VECTOR(3), nullable=False), schema="p0_smoke",
            )
            migration.exec_driver_sql("GRANT USAGE ON SCHEMA p0_smoke TO p0_runtime")
            migration.exec_driver_sql("GRANT SELECT, INSERT ON p0_smoke.vectors TO p0_runtime")
    finally:
        engine.dispose()

    with ConnectionPool(
        kwargs={**connection, "user": "p0_runtime", "password": runtime_password,
                "connect_timeout": 5, "autocommit": True},
        min_size=1, max_size=1, timeout=5, configure=register_vector, open=True,
    ) as pool:
        with pool.connection() as runtime:
            with runtime.transaction():
                runtime.execute("INSERT INTO p0_smoke.vectors VALUES (%s, %s)", (1, Vector([2, 0, 0])))
                runtime.execute("INSERT INTO p0_smoke.vectors VALUES (%s, %s)", (2, Vector([0, 1, 0])))
            with runtime.transaction(force_rollback=True):
                runtime.execute("INSERT INTO p0_smoke.vectors VALUES (%s, %s)", (3, Vector([0, 0, 0])))
            rows = runtime.execute(
                "SELECT id, embedding <-> %s AS distance FROM p0_smoke.vectors ORDER BY distance, id",
                (Vector([0, 0, 0]),),
            ).fetchall()
            if rows != [(2, 1.0), (1, 2.0)]:
                raise RuntimeError(f"Vector query or transaction rollback failed: {rows!r}")
            for statement in (
                "CREATE TABLE p0_smoke.forbidden (id integer)",
                "CREATE TABLE public.forbidden (id integer)",
                "CREATE SCHEMA forbidden",
                "ALTER TABLE p0_smoke.vectors ADD COLUMN forbidden integer",
            ):
                try:
                    runtime.execute(statement)
                except InsufficientPrivilege:
                    continue
                raise RuntimeError(f"Runtime role unexpectedly executed DDL: {statement}")

    print(f"PostgreSQL {server_description}, pgvector {extension_version}")
    print("Passed: driver connection/pool, Alembic DDL, separate roles, committed writes, rollback, vector distances")


@contextmanager
def disposable_postgres(project_prefix="ai-native-p0"):
    password = secrets.token_urlsafe(24)
    project = f"{project_prefix}-{secrets.token_hex(6)}"
    compose = ["docker", "compose", "-p", project, "-f", str(Path(__file__).with_name("compose.yaml").resolve())]
    environment = {**os.environ, "AI_NATIVE_P0_ADMIN_PASSWORD": password}
    try:
        subprocess.run([*compose, "up", "-d", "--wait", "--wait-timeout", "60"], env=environment, check=True)
        address = subprocess.check_output([*compose, "port", "postgres", "5432"], env=environment, text=True).strip()
        host, _, port = address.rpartition(":")
        if host != "127.0.0.1":
            raise RuntimeError(f"Expected a loopback port, received {address!r}")
        # Database owners applying framework migrations need vector in both the
        # initial database and new databases created for restricted-role suites.
        for database in ("ai_native_p0", "template1"):
            with psycopg.connect(host=host, hostaddr=host, port=int(port), dbname=database,
                                 user="p0_admin", password=password, connect_timeout=5) as connection:
                connection.execute("CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA public")
        yield int(port), password
    finally:
        subprocess.run([*compose, "down", "--volumes"], env=environment, check=True)


def main():
    with disposable_postgres() as (port, password):
        verify_database(port, password)


if __name__ == "__main__":
    main()
