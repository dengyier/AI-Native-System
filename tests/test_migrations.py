import json
import os
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from uuid import uuid4

from ai_native_system.data import DataService
from ai_native_system.model import DemoModel
from ai_native_system.registry import Registry
from ai_native_system.runtime import Runtime
from ai_native_system.storage import database, digest, encode
from ai_native_system.tools import ToolRegistry


FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "conformance.json"
TEST_DSN = os.environ.get("AI_NATIVE_PG_TEST_DSN")
LEGACY_TABLES = {
    "principals": "tenant, id", "objects": "tenant, id", "knowledge": "tenant, id", "tasks": "id",
    "steps": "task_id, stage", "events": "id", "effects": "operation_id", "remote_operations": "operation_id",
    "execution_claims": "task_id", "knowledge_history": "tenant, id, version",
}


class UncertainAdapter:
    identity = {"kind": "synthetic", "endpoint": "in-process"}

    def __init__(self):
        self.calls = []

    def execute(self, request):
        self.calls.append(request)
        raise TimeoutError("synthetic response loss")

    def lookup(self, request):
        raise AssertionError("Migration cannot query a business system")


@unittest.skipUnless(TEST_DSN, "Run deployment/local-postgres/verify_migration.py for real PostgreSQL tests")
class PostgreSQLMigrationTests(unittest.TestCase):
    def setUp(self):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo

        from ai_native_system.adapters.postgres import import_sqlite, migrate_postgres

        self.connect = psycopg.connect
        self.import_sqlite = import_sqlite
        self.migrate = migrate_postgres
        suffix = uuid4().hex[:12]
        dbname, role, password = f"p1b_{suffix}", f"p1b_migrator_{suffix}", uuid4().hex
        with self.connect(TEST_DSN, autocommit=True) as admin:
            admin.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(sql.Identifier(role), sql.Literal(password)))
            self.addCleanup(self._drop, "ROLE", role)
            admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(dbname)))
            self.addCleanup(self._drop, "DATABASE", dbname)
        with self.connect(make_conninfo(TEST_DSN, dbname=dbname)) as admin:
            admin.execute(sql.SQL("CREATE SCHEMA ai_native AUTHORIZATION {}").format(sql.Identifier(role)))
        self.dsn = make_conninfo(TEST_DSN, dbname=dbname, user=role, password=password)
        self.assertEqual(self.migrate(self.dsn), "0022_knowledge_release_selection")
        directory = self.enterContext(tempfile.TemporaryDirectory())
        self.source = Path(directory) / "legacy.sqlite"
        self._populate_legacy()

    def _drop(self, kind, name):
        from psycopg import sql

        with self.connect(TEST_DSN, autocommit=True) as admin:
            admin.execute(sql.SQL("DROP {} {}").format(sql.SQL(kind), sql.Identifier(name)))

    def _populate_legacy(self):
        registry = Registry.load(FIXTURE)
        registry.actions["remote_verify"] = {**registry.actions["verify_asset"], "tool": "remote.verify", "tool_version": "1"}
        registry.applications["remote"] = {**registry.applications["single"], "id": "remote", "action": "remote_verify"}
        tools = ToolRegistry()
        self.adapter = UncertainAdapter()
        tools.register_remote("remote.verify", "1", self.adapter)
        runtime = Runtime(self.source, registry, DemoModel(), tools)
        runtime.initialize()
        with database(self.source, write=True) as connection:
            connection.execute("INSERT INTO principals (tenant, id, roles) VALUES (?, ?, ?)",
                               ("local", "fixture-author", encode(["data_admin"])))
            connection.execute("""INSERT INTO objects (tenant,id,type,state,version,properties,links)
                SELECT tenant,'remote-asset',type,state,version,properties,links FROM objects WHERE tenant='local' AND id='asset-1'""")
        data = DataService(self.source, registry)
        data.put_knowledge("local", "fixture-author", "asset-policy", "第二版证据", expected_version=1)
        for app, object_id, status in (("single", "asset-1", "completed"), ("remote", "remote-asset", "reconciling")):
            task_id = runtime.submit("local", app, object_id, "requester", f"legacy-{app}")["id"]
            self.assertEqual(runtime.advance("local", task_id)["status"], "awaiting_approval")
            self.assertEqual(runtime.decide("local", task_id, "reviewer", "approve")["status"], "ready")
            self.assertEqual(runtime.advance("local", task_id)["status"], status)
            if app == "single":
                self.completed_id = task_id
            else:
                self.unknown_id = task_id
        with database(self.source, write=True) as connection:
            connection.execute("INSERT INTO events (id,task_id,event,detail) VALUES (700,?,?,?)",
                               (self.completed_id, "localized.proof", '{ "证据" : ["甲", 0.500] }'))

    def test_real_sqlite_history_is_reproduced_and_reimport_is_idempotent(self):
        from psycopg import sql

        original_bytes = self.source.read_bytes()
        result = self.import_sqlite(self.dsn, self.source)
        self.assertFalse(result.already_present)
        self.assertEqual(result.counts["tasks"], 2)
        self.assertEqual(result.counts["effects"], 1)
        with database(self.source) as source, self.connect(self.dsn) as target:
            for table, ordering in LEGACY_TABLES.items():
                source_rows = source.execute(f"SELECT * FROM {table} ORDER BY {ordering}")
                columns = sql.SQL(", ").join(sql.Identifier(description[0]) for description in source_rows.description)
                expected = [tuple(row) for row in source_rows]
                actual = target.execute(sql.SQL("SELECT {} FROM {} ORDER BY {}").format(
                    columns, sql.Identifier("ai_native", table), sql.SQL(ordering),
                )).fetchall()
                self.assertEqual(actual, expected, table)
                self.assertEqual(result.counts[table], len(expected), table)
            self.assertEqual(target.execute("""SELECT count(*) FROM ai_native.tasks
                WHERE graph_version IS NOT NULL OR graph_deadline IS NOT NULL OR graph_last_claim IS NOT NULL
                   OR knowledge_citations IS NOT NULL
                """).fetchone()[0], 0)
            old_order = [tuple(row) for row in source.execute("SELECT id,rowid FROM tasks ORDER BY rowid")]
            self.assertEqual(target.execute("SELECT task_id,row_id FROM ai_native.legacy_task_order ORDER BY row_id").fetchall(),
                             old_order)
            approvals = target.execute("SELECT proposal, approval_hash FROM ai_native.tasks").fetchall()
            self.assertTrue(all(digest(json.loads(proposal)) == expected_hash for proposal, expected_hash in approvals))
            status, attempts, payload = target.execute(
                "SELECT status, attempts, payload FROM ai_native.remote_operations WHERE operation_id=%s", (self.unknown_id,),
            ).fetchone()
            unknown = json.loads(payload)
            self.assertEqual((status, attempts, unknown["operation_id"]), ("unknown", 1, self.unknown_id))
            self.assertEqual(unknown, self.adapter.calls[0])
        self.assertEqual(len(self.adapter.calls), 1)
        self.assertEqual(self.source.read_bytes(), original_bytes)
        repeated = self.import_sqlite(self.dsn, self.source)
        self.assertTrue(repeated.already_present)
        self.assertEqual((repeated.snapshot_digest, repeated.counts), (result.snapshot_digest, result.counts))
        with self.connect(self.dsn) as target:
            next_id, = target.execute("INSERT INTO ai_native.events (task_id,event,detail) VALUES (%s,'identity_check','{}') RETURNING id",
                                      (self.completed_id,)).fetchone()
            self.assertGreater(next_id, 700)

    def test_import_refuses_source_divergence(self):
        from ai_native_system.adapters.postgres import MigrationError

        self.import_sqlite(self.dsn, self.source)
        with database(self.source, write=True) as source:
            source.execute("UPDATE knowledge SET text='Modified after import' WHERE id='asset-policy'")
        with self.assertRaises(MigrationError):
            self.import_sqlite(self.dsn, self.source)
        with self.connect(self.dsn) as target:
            current, = target.execute("SELECT text FROM ai_native.knowledge WHERE tenant='local' AND id='asset-policy'").fetchone()
            self.assertEqual(current, "第二版证据")

    def test_import_preserves_target_writes_after_cutover(self):
        from ai_native_system.adapters.postgres import MigrationError

        self.import_sqlite(self.dsn, self.source)
        with self.connect(self.dsn) as target:
            target.execute("UPDATE ai_native.knowledge SET text='After cutover' WHERE id='asset-policy'")
        with self.assertRaises(MigrationError):
            self.import_sqlite(self.dsn, self.source)
        with self.connect(self.dsn) as target:
            current, = target.execute("SELECT text FROM ai_native.knowledge WHERE tenant='local' AND id='asset-policy'").fetchone()
            self.assertEqual(current, "After cutover")

    def test_write_failure_rolls_back_all_rows_and_retry_succeeds(self):
        from psycopg.errors import CheckViolation

        with self.connect(self.dsn) as target:
            target.execute("ALTER TABLE ai_native.events ADD CONSTRAINT fixture_fault CHECK (event <> 'localized.proof')")
        with self.assertRaises(CheckViolation):
            self.import_sqlite(self.dsn, self.source)
        with self.connect(self.dsn) as target:
            for table in (*LEGACY_TABLES, "legacy_task_order", "sqlite_imports"):
                self.assertEqual(target.execute(f"SELECT count(*) FROM ai_native.{table}").fetchone(), (0,), table)
            target.execute("ALTER TABLE ai_native.events DROP CONSTRAINT fixture_fault")
        self.assertFalse(self.import_sqlite(self.dsn, self.source).already_present)

    def test_orphaned_source_leaves_target_empty(self):
        from ai_native_system.adapters.postgres import MigrationError

        with closing(sqlite3.connect(self.source)) as source, source:
            source.execute("UPDATE events SET task_id='missing-task' WHERE id=700")
        with self.assertRaises(MigrationError):
            self.import_sqlite(self.dsn, self.source)
        with self.connect(self.dsn) as target:
            for table in ("principals", "tasks", "events", "sqlite_imports"):
                self.assertEqual(target.execute(f"SELECT count(*) FROM ai_native.{table}").fetchone(), (0,))

    def test_early_sqlite_without_optional_tables_can_be_imported(self):
        old_source = self.source.with_name("initial_release.sqlite")
        runtime = Runtime(old_source, Registry.load(FIXTURE), DemoModel())
        runtime.initialize()
        task_id = runtime.submit("local", "single", "asset-1", "requester", "early")["id"]
        runtime.advance("local", task_id)
        runtime.decide("local", task_id, "reviewer", "approve")
        self.assertEqual(runtime.advance("local", task_id)["status"], "completed")
        with database(old_source, write=True) as source:
            source.execute("DROP TABLE remote_operations")
            source.execute("DROP TABLE execution_claims")
        result = self.import_sqlite(self.dsn, old_source)
        self.assertEqual(result.counts["tasks"], 1)
        for table in ("remote_operations", "execution_claims", "knowledge_history"):
            self.assertEqual(result.counts.get(table, 0), 0)

    def test_explicit_migration_is_versioned_and_repeatable(self):
        from ai_native_system.adapters.postgres import MigrationError

        self.assertEqual(self.migrate(self.dsn), "0022_knowledge_release_selection")
        with self.connect(self.dsn) as target:
            rows = target.execute("SELECT revision,checksum FROM ai_native.schema_migrations ORDER BY revision").fetchall()
            self.assertEqual([row[0] for row in rows], [
                "0001_legacy", "0002_semantics", "0003_semantic_state", "0004_tenant_rls",
                "0005_enterprise_identity", "0006_resource_policy", "0007_release_snapshots", "0008_task_governance",
                "0009_fact_sync", "0010_owp_authorization", "0011_owp_evidence",
                "0012_p4_delivery", "0013_p4_execution", "0014_model_accounting", "0015_model_observability",
                "0016_graph_tasks",
                "0017_knowledge_vectors", "0018_knowledge_evidence", "0019_knowledge_tasks",
                "0020_application_delivery", "0021_knowledge_lexical", "0022_knowledge_release_selection",
            ])
            for _, checksum in rows:
                self.assertRegex(checksum, r"^[0-9a-f]{64}$")
            target.execute("UPDATE ai_native.schema_migrations SET checksum=repeat('0', 64)")
        with self.assertRaises(MigrationError):
            self.migrate(self.dsn)
