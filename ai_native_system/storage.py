import hashlib
import json
import sqlite3
from contextlib import contextmanager
from typing import Protocol, runtime_checkable

REMOTE_SCHEMA = """
CREATE TABLE IF NOT EXISTS remote_operations (
  operation_id TEXT PRIMARY KEY REFERENCES tasks(id),
  tool_name TEXT NOT NULL, tool_version TEXT NOT NULL,
  adapter_identity TEXT NOT NULL, payload TEXT NOT NULL,
  status TEXT NOT NULL, response TEXT, attempts INTEGER NOT NULL DEFAULT 0
);
"""

SCHEMA = """
CREATE TABLE IF NOT EXISTS principals (
  tenant TEXT NOT NULL, id TEXT NOT NULL, roles TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1, PRIMARY KEY (tenant, id)
);
CREATE TABLE IF NOT EXISTS objects (
  tenant TEXT NOT NULL, id TEXT NOT NULL, type TEXT NOT NULL, state TEXT NOT NULL,
  version INTEGER NOT NULL, properties TEXT NOT NULL, links TEXT NOT NULL,
  PRIMARY KEY (tenant, id)
);
CREATE TABLE IF NOT EXISTS knowledge (
  tenant TEXT NOT NULL, id TEXT NOT NULL, version INTEGER NOT NULL, text TEXT NOT NULL,
  PRIMARY KEY (tenant, id)
);
CREATE TABLE IF NOT EXISTS tasks (
  id TEXT PRIMARY KEY, tenant TEXT NOT NULL, application TEXT NOT NULL,
  object_id TEXT NOT NULL, requester TEXT NOT NULL, request_key TEXT NOT NULL,
  definition_hash TEXT NOT NULL, status TEXT NOT NULL, next_stage INTEGER NOT NULL DEFAULT 0,
  grounding_hash TEXT, proposal TEXT, approver TEXT, approval_hash TEXT,
  UNIQUE (tenant, requester, request_key)
);
CREATE TABLE IF NOT EXISTS steps (
  task_id TEXT NOT NULL REFERENCES tasks(id), stage INTEGER NOT NULL, agent_id TEXT NOT NULL,
  proposal TEXT NOT NULL, PRIMARY KEY(task_id, stage)
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY, task_id TEXT NOT NULL REFERENCES tasks(id),
  time TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  event TEXT NOT NULL, detail TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_by_task ON events(task_id, id);
CREATE TABLE IF NOT EXISTS execution_claims (
  task_id TEXT PRIMARY KEY REFERENCES tasks(id), token TEXT NOT NULL,
  expires REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS remote_operations (
  operation_id TEXT PRIMARY KEY REFERENCES tasks(id),
  tool_name TEXT NOT NULL, tool_version TEXT NOT NULL,
  adapter_identity TEXT NOT NULL, payload TEXT NOT NULL,
  status TEXT NOT NULL, response TEXT, attempts INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS effects (
  operation_id TEXT PRIMARY KEY REFERENCES tasks(id), action TEXT NOT NULL,
  object_id TEXT NOT NULL, receipt TEXT NOT NULL
);
"""


def encode(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value):
    return hashlib.sha256(encode(value).encode()).hexdigest()


@runtime_checkable
class RuntimeStore(Protocol):
    """Opt-in storage for the existing runtime's transactions and reference seed."""

    def transaction(self, *, write=False, tenant=None): ...

    def initialize(self, seed): ...


@contextmanager
def database(path, write=False, *, tenant=None):
    if isinstance(path, RuntimeStore):
        with path.transaction(write=write, tenant=tenant) as connection:
            yield connection
        return
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    try:
        with connection:
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            yield connection
    finally:
        connection.close()


def initialize(path, seed):
    if isinstance(path, RuntimeStore):
        path.initialize(seed)
        return
    with database(path, write=True) as connection:
        for statement in SCHEMA.split(";"):
            if statement.strip():
                connection.execute(statement)
        seed_rows(connection, seed)


def seed_rows(connection, seed):
    connection.executemany(
        "INSERT INTO principals (tenant, id, roles) VALUES (?, ?, ?) ON CONFLICT (tenant, id) DO NOTHING",
        ((row["tenant"], row["id"], encode(row["roles"])) for row in seed["actors"]),
    )
    connection.executemany(
        """INSERT INTO objects (tenant, id, type, state, version, properties, links)
           VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (tenant, id) DO NOTHING""",
        ((row["tenant"], row["id"], row["type"], row["state"], row["version"],
          encode(row["properties"]), encode(row["links"])) for row in seed["objects"]),
    )
    connection.executemany(
        """INSERT INTO knowledge (tenant, id, version, text)
           VALUES (?, ?, ?, ?) ON CONFLICT (tenant, id) DO NOTHING""",
        ((row["tenant"], row["id"], row["version"], row["text"]) for row in seed["knowledge"]),
    )


def row_data(row, *serialized):
    if row is None:
        return None
    result = dict(row)
    for key in serialized:
        if result[key] is not None:
            result[key] = json.loads(result[key])
    return result


def object_data(connection, tenant, object_id):
    return row_data(
        connection.execute(
            "SELECT * FROM objects WHERE tenant = ? AND id = ?", (tenant, object_id)
        ).fetchone(),
        "properties", "links",
    )


def task_row(row):
    result = row_data(row, "proposal")
    if result is not None:
        result.pop("graph_last_claim", None)
        if result.get("graph_version") is None:
            result.pop("graph_version", None)
            result.pop("graph_deadline", None)
        if result.get("knowledge_citations") is None:
            result.pop("knowledge_citations", None)
        else:
            result["knowledge_citations"] = json.loads(result["knowledge_citations"])
        if result.get("expected_object_version") is None:
            result.pop("expected_object_version", None)
    return result


def task_data(connection, tenant, task_id):
    result = task_row(connection.execute(
        "SELECT * FROM tasks WHERE tenant = ? AND id = ?", (tenant, task_id)
    ).fetchone())
    if result is None:
        raise ValueError("Task not found in this tenant")
    return result


def audit(connection, task_id, event, **detail):
    connection.execute(
        "INSERT INTO events (task_id, event, detail) VALUES (?, ?, ?)",
        (task_id, event, encode(detail)),
    )
