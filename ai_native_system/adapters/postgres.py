"""Explicit PostgreSQL schema migration and offline legacy SQLite import."""

import json
import math
import sqlite3
from contextlib import closing, contextmanager
from dataclasses import dataclass
from hashlib import sha256
from importlib.resources import files
from pathlib import Path

import psycopg
from psycopg import sql

from ..contracts import LegacyOperationRef
from ..migrations import REVISIONS
from ..storage import digest as legacy_digest, encode


SCHEMA_LOCK = (184133000, 1)


class MigrationError(RuntimeError):
    """Schema or legacy snapshot cannot be applied unchanged."""


@dataclass(frozen=True)
class ImportReport:
    counts: dict[str, int]
    snapshot_digest: str
    already_present: bool


@dataclass(frozen=True)
class _Table:
    columns: tuple[str, ...]
    keys: tuple[str, ...]
    integers: tuple[str, ...] = ()
    reals: tuple[str, ...] = ()
    nullable: tuple[str, ...] = ()
    optional: bool = False


# Ordering satisfies PostgreSQL foreign keys during import.
_TABLES = {
    "principals": _Table(("tenant", "id", "roles", "active"), ("tenant", "id"), ("active",)),
    "objects": _Table(("tenant", "id", "type", "state", "version", "properties", "links"),
                      ("tenant", "id"), ("version",)),
    "knowledge": _Table(("tenant", "id", "version", "text"), ("tenant", "id"), ("version",)),
    "knowledge_history": _Table(("tenant", "id", "version", "text"), ("tenant", "id", "version"),
                                ("version",), optional=True),
    "tasks": _Table(("id", "tenant", "application", "object_id", "requester", "request_key", "definition_hash",
                     "status", "next_stage", "grounding_hash", "proposal", "approver", "approval_hash"),
                    ("id",), ("next_stage",), nullable=("grounding_hash", "proposal", "approver", "approval_hash")),
    "steps": _Table(("task_id", "stage", "agent_id", "proposal"), ("task_id", "stage"), ("stage",)),
    "events": _Table(("id", "task_id", "time", "event", "detail"), ("id",), ("id",)),
    "execution_claims": _Table(("task_id", "token", "expires"), ("task_id",), reals=("expires",), optional=True),
    "remote_operations": _Table(("operation_id", "tool_name", "tool_version", "adapter_identity", "payload",
                                 "status", "response", "attempts"),
                                ("operation_id",), ("attempts",), nullable=("response",), optional=True),
    "effects": _Table(("operation_id", "action", "object_id", "receipt"), ("operation_id",)),
}
_TASK_ORDER = _Table(("task_id", "row_id"), ("task_id",), ("row_id",))
_DESTINATION = {**_TABLES, "legacy_task_order": _TASK_ORDER}


@contextmanager
def _locked_transaction(dsn, *, shared=False):
    if type(dsn) is not str or not dsn.strip():
        raise MigrationError("An explicit PostgreSQL connection string is required")
    with psycopg.connect(dsn, connect_timeout=5) as connection:
        connection.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
        connection.execute("SET LOCAL search_path TO pg_catalog")
        connection.execute("SET LOCAL lock_timeout TO '5s'")
        connection.execute("SET LOCAL statement_timeout TO '60s'")
        if shared:
            connection.execute("SELECT pg_advisory_xact_lock_shared(%s, %s)", SCHEMA_LOCK)
        else:
            connection.execute("SELECT pg_advisory_xact_lock(%s, %s)", SCHEMA_LOCK)
        yield connection


def _revision_files():
    directory = files("ai_native_system.migrations")
    for revision in REVISIONS:
        body = directory.joinpath(f"{revision}.sql").read_bytes()
        yield revision, sha256(body).hexdigest(), body.decode("utf-8")


def _revision_state(connection, revisions):
    if connection.execute("SELECT to_regclass('ai_native.schema_migrations')").fetchone()[0] is None:
        raise MigrationError("Run migrate_postgres before using the framework schema")
    applied = dict(connection.execute("SELECT revision, checksum FROM ai_native.schema_migrations").fetchall())
    for index, (revision, checksum, _) in enumerate(revisions):
        if revision not in applied:
            if len(applied) != index:
                raise MigrationError("PostgreSQL schema has an unknown or out-of-order revision")
            return index
        if applied[revision] != checksum:
            raise MigrationError(f"Checksum mismatch in PostgreSQL revision {revision}")
    if len(applied) != len(revisions):
        raise MigrationError("PostgreSQL schema has an unknown revision")
    return len(revisions)


def migrate_postgres(dsn: str) -> str:
    """Apply ordered SQL revisions atomically using the owner of the ai_native schema."""
    revisions = tuple(_revision_files())
    with _locked_transaction(dsn) as connection:
        connection.execute("""CREATE TABLE IF NOT EXISTS ai_native.schema_migrations (
                                  revision text PRIMARY KEY,
                                  checksum text NOT NULL,
                                  applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
                              )""")
        start = _revision_state(connection, revisions)
        for revision, checksum, body in revisions[start:]:
            connection.execute(body, prepare=False)
            connection.execute("INSERT INTO ai_native.schema_migrations (revision, checksum) VALUES (%s, %s)",
                               (revision, checksum))
    return revisions[-1][0]


def require_compatible_schema(connection) -> str:
    """Identify the installed complete schema version without executing DDL."""
    revisions = tuple(_revision_files())
    if _revision_state(connection, revisions) != len(revisions):
        raise MigrationError("Run migrate_postgres before using the framework schema")
    return revisions[-1][0]


def _sorted_rows(rows, table):
    indices = tuple(table.columns.index(key) for key in table.keys)
    return sorted(rows, key=lambda row: tuple(row[index] for index in indices))


def _check_rows(name, table, rows):
    for row in rows:
        for column, value in zip(table.columns, row):
            if value is None:
                valid = column in table.nullable
            elif column in table.integers:
                valid = type(value) is int
            elif column in table.reals:
                valid = type(value) is float and math.isfinite(value)
            else:
                valid = type(value) is str and "\0" not in value
            if not valid:
                raise MigrationError(f"SQLite field {name}.{column} cannot be preserved as declared")


def _check_legacy_hashes(tables):
    tasks = {}
    for row in tables["tasks"]:
        task = dict(zip(_TABLES["tasks"].columns, row))
        tasks[task["id"]] = task
        if task["approval_hash"] is not None:
            try:
                proposal = json.loads(task["proposal"])
                matches = isinstance(proposal, dict) and legacy_digest(proposal) == task["approval_hash"]
            except (ValueError, TypeError, RecursionError):
                matches = False
            if not matches:
                raise MigrationError("Stored SQLite approval digest does not match its proposal")
    for row in tables["remote_operations"]:
        operation_id, _, _, _, encoded, _, _, _ = row
        try:
            payload = json.loads(encoded)
            reference = LegacyOperationRef.from_payload(payload)
        except (ValueError, TypeError, RecursionError) as error:
            raise MigrationError("Stored SQLite remote request digest does not match its payload") from error
        task = tasks.get(operation_id)
        if reference.operation_id != operation_id or task is None or payload.get("tenant") != task["tenant"]:
            raise MigrationError("Stored SQLite remote operation does not match its task and tenant")


def _read_sqlite(source):
    path = Path(source).resolve(strict=True)
    if not path.is_file():
        raise MigrationError("SQLite snapshot must be an existing database file")
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=5)) as connection:
        connection.execute("PRAGMA query_only = ON")
        connection.execute("BEGIN")
        if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise MigrationError("SQLite integrity check failed")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise MigrationError("SQLite snapshot contains an invalid foreign key")
        present = {name for name, in connection.execute(
            "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT GLOB 'sqlite_*'")}
        required = {name for name, table in _TABLES.items() if not table.optional}
        if not required <= present <= _TABLES.keys():
            raise MigrationError("SQLite snapshot has missing or unexpected tables")
        tables = {}
        for name, table in _TABLES.items():
            rows = []
            if name in present:
                columns = {row[1] for row in connection.execute(f'PRAGMA table_xinfo("{name}")')}
                if columns != set(table.columns):
                    raise MigrationError(f"SQLite table {name} has unexpected columns")
                rows = connection.execute(f'SELECT {", ".join(table.columns)} FROM "{name}"').fetchall()
                _check_rows(name, table, rows)
            tables[name] = _sorted_rows(rows, table)
        tables["legacy_task_order"] = _sorted_rows(
            connection.execute("SELECT id, rowid FROM tasks").fetchall(), _TASK_ORDER,
        )
    _check_legacy_hashes(tables)
    identity = {"contract": "legacy-sqlite-snapshot/1", "source_tables": sorted(present), "rows": tables}
    return tables, sha256(encode(identity).encode("utf-8")).hexdigest()


def _select_table(connection, name, table):
    query = sql.SQL("SELECT {} FROM {}").format(
        sql.SQL(", ").join(map(sql.Identifier, table.columns)), sql.Identifier("ai_native", name))
    return _sorted_rows(connection.execute(query).fetchall(), table)


def _insert_table(connection, name, table, rows):
    if rows:
        query = sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(
            sql.Identifier("ai_native", name), sql.SQL(", ").join(map(sql.Identifier, table.columns)),
            sql.SQL(", ").join(sql.Placeholder() for _ in table.columns),
        )
        with connection.cursor() as cursor:
            cursor.executemany(query, rows)


def import_sqlite(dsn: str, source: str | Path) -> ImportReport:
    """Copy one quiesced legacy snapshot into PostgreSQL without activating its runtime."""
    expected, snapshot_digest = _read_sqlite(source)
    with _locked_transaction(dsn) as connection:
        require_compatible_schema(connection)
        locked = sql.SQL(", ").join(sql.Identifier("ai_native", name) for name in (*_DESTINATION, "sqlite_imports"))
        connection.execute(sql.SQL("LOCK TABLE {} IN SHARE ROW EXCLUSIVE MODE").format(locked))
        recorded = connection.execute("SELECT snapshot_digest FROM ai_native.sqlite_imports").fetchone()
        actual = {name: _select_table(connection, name, table) for name, table in _DESTINATION.items()}
        if recorded is not None:
            if recorded[0] != snapshot_digest or actual != expected:
                raise MigrationError("PostgreSQL data diverges from the recorded SQLite snapshot")
        else:
            if any(actual.values()):
                raise MigrationError("PostgreSQL target already contains framework data")
            for name, table in _DESTINATION.items():
                _insert_table(connection, name, table, expected[name])
            for name, table in _DESTINATION.items():
                if _select_table(connection, name, table) != expected[name]:
                    raise MigrationError(f"Imported PostgreSQL table {name} differs from SQLite")
            if expected["events"]:
                next_id = max(0, expected["events"][-1][0]) + 1
                connection.execute(sql.SQL("ALTER TABLE ai_native.events ALTER COLUMN id RESTART WITH {}").format(
                    sql.Literal(next_id)))
            connection.execute("INSERT INTO ai_native.sqlite_imports (snapshot_digest) VALUES (%s)",
                               (snapshot_digest,))
    return ImportReport({name: len(expected[name]) for name in _TABLES}, snapshot_digest, recorded is not None)
