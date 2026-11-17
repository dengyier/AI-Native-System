import json
import os
import secrets
import subprocess
import sys
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tempfile import TemporaryDirectory

from ai_native_system.data import DataService
from ai_native_system.model import DemoModel
from ai_native_system.registry import Registry
from ai_native_system.remote import HttpRemote, RemoteError
from ai_native_system.runtime import Runtime
from ai_native_system.storage import database, object_data
from ai_native_system.tools import ToolRegistry
from remote_server import RemoteFixture


DSN = os.environ.get("AI_NATIVE_PG_RUNTIME_TEST_DSN")
CONTAINER = os.environ.get("AI_NATIVE_PG_RUNTIME_TEST_CONTAINER")
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "conformance.json"


@unittest.skipUnless(DSN, "Run deployment/local-postgres/verify_runtime.py for PostgreSQL integration tests")
class PostgresRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo

        from ai_native_system.adapters.postgres import migrate_postgres
        from ai_native_system.adapters.postgres_runtime import PostgresRuntimeStore

        cls.store_type = PostgresRuntimeStore
        migrator_password, runtime_password = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        cls.migrator_dsn = make_conninfo(DSN, user="p1b_migrator", password=migrator_password)
        cls.runtime_dsn = make_conninfo(DSN, user="p1b_runtime", password=runtime_password)
        with psycopg.connect(DSN) as conn:
            for role, password in (("p1b_migrator", migrator_password), ("p1b_runtime", runtime_password)):
                conn.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(sql.Identifier(role), sql.Literal(password)))
            conn.execute("CREATE SCHEMA ai_native AUTHORIZATION p1b_migrator")
        migrate_postgres(cls.migrator_dsn)
        cls.grant_runtime(cls.migrator_dsn)

    @staticmethod
    def grant_runtime(owner_dsn):
        import psycopg
        from psycopg import sql

        with psycopg.connect(owner_dsn) as conn:
            conn.execute("GRANT USAGE ON SCHEMA ai_native TO p1b_runtime")
            conn.execute("GRANT SELECT ON ALL TABLES IN SCHEMA ai_native TO p1b_runtime")
            conn.execute("GRANT USAGE ON ALL SEQUENCES IN SCHEMA ai_native TO p1b_runtime")
            for table in ("principals", "objects", "knowledge", "knowledge_history", "tasks", "steps",
                          "events", "execution_claims", "remote_operations", "effects"):
                conn.execute(sql.SQL("GRANT INSERT, UPDATE, DELETE ON ai_native.{} TO p1b_runtime").format(sql.Identifier(table)))

    def setUp(self):
        self.registry = Registry.load(FIXTURE)
        self.tenant = "test-" + secrets.token_hex(6)
        for section, rows in self.registry.seed.items():
            self.registry.seed[section] = [{**row, "tenant": self.tenant} for row in rows if row["tenant"] == "local"]
        self.registry.seed["actors"].append({"id": "data", "tenant": self.tenant, "roles": ["data_admin"]})
        self.store = self.enterContext(self.store_type(self.runtime_dsn, max_connections=4, timeout=5))
        self.runtime = Runtime(self.store, self.registry, DemoModel())
        self.runtime.initialize()

    def submit(self, key, *, application="single", tenant=None):
        return self.runtime.submit(tenant or self.tenant, application, "asset-1", "requester", key)["id"]

    def ready(self, task_id, tenant=None):
        tenant = tenant or self.tenant
        self.assertEqual(self.runtime.advance(tenant, task_id)["status"], "awaiting_approval")
        self.assertEqual(self.runtime.decide(tenant, task_id, "reviewer", "approve")["status"], "ready")

    def test_runtime_role_has_no_schema_ddl(self):
        import psycopg

        with self.assertRaises(psycopg.errors.InsufficientPrivilege), psycopg.connect(self.runtime_dsn) as conn:
            conn.execute("CREATE TABLE ai_native.forbidden (id bigint)")
        with self.assertRaises(psycopg.errors.InsufficientPrivilege), psycopg.connect(self.runtime_dsn) as conn:
            conn.execute("ALTER TABLE ai_native.tasks ADD COLUMN forbidden bigint")

    def test_explicit_postgres_cli_can_inspect_persisted_task(self):
        task_id = self.submit("inspect-cli")
        self.ready(task_id)
        result = subprocess.run([sys.executable, "-B", "-m", "ai_native_system", "--postgres", "--tenant", self.tenant,
                                 "inspect", task_id], cwd=FIXTURE.parents[1],
                                env={**os.environ, "AI_NATIVE_POSTGRES_DSN": self.runtime_dsn},
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["task"]["status"], "ready")

    def test_duplicate_submission_and_concurrent_execution_commit_one_effect(self):
        other_store = self.enterContext(self.store_type(self.runtime_dsn, max_connections=2, timeout=5))
        other = Runtime(other_store, self.registry, DemoModel())
        barrier = threading.Barrier(2, timeout=5)

        def submit(runtime):
            barrier.wait()
            return runtime.submit(self.tenant, "single", "asset-1", "requester", "same-request")["id"]

        with ThreadPoolExecutor(max_workers=2) as workers:
            first = workers.submit(submit, self.runtime)
            second = workers.submit(submit, other)
            task_id = first.result(timeout=10)
            self.assertEqual(second.result(timeout=10), task_id)
            self.ready(task_id)

            def advance(runtime):
                barrier.wait()
                return runtime.advance(self.tenant, task_id)["status"]

            first = workers.submit(advance, self.runtime)
            second = workers.submit(advance, other)
            self.assertEqual(first.result(timeout=10), "completed")
            self.assertEqual(second.result(timeout=10), "completed")
        self.assertEqual(len(other.inspect(self.tenant, task_id)["effects"]), 1)
        with database(other_store, tenant=self.tenant) as conn:
            self.assertEqual(object_data(conn, self.tenant, "asset-1")["version"], 2)

    def test_same_expected_object_version_accepts_only_one_write(self):
        data = DataService(self.store, self.registry)
        base = next(row for row in self.registry.seed["objects"] if row["id"] == "asset-1")
        barrier = threading.Barrier(2, timeout=5)

        def write(label):
            barrier.wait()
            try:
                return data.put_object(self.tenant, "data", {**base, "properties": {**base["properties"], "label": label}}, 1)
            except ValueError as error:
                self.assertIn("version conflict", str(error))
                return None

        with ThreadPoolExecutor(max_workers=2) as workers:
            results = list(workers.map(write, ("revision A", "revision B")))
        winner, = [result for result in results if result is not None]
        with database(self.store, tenant=self.tenant) as conn:
            self.assertEqual(object_data(conn, self.tenant, "asset-1"), winner)
        self.assertEqual(winner["version"], 2)

    def test_knowledge_history_and_casefold_search(self):
        data = DataService(self.store, self.registry)
        data.put_knowledge(self.tenant, "data", "literal", "Folge Straße 甲")
        data.put_knowledge(self.tenant, "data", "literal", "Straße 乙", 1)
        found, = data.search_knowledge(self.tenant, "data", "STRASSE")
        self.assertEqual((found["id"], found["version"], found["text"]), ("literal", 2, "Straße 乙"))
        with database(self.store, tenant=self.tenant) as conn:
            rows = conn.execute("SELECT version, text FROM knowledge_history WHERE tenant=? AND id=? ORDER BY version",
                                (self.tenant, "literal")).fetchall()
        self.assertEqual([(row[0], row[1]) for row in rows], [(1, "Folge Straße 甲"), (2, "Straße 乙")])

    def test_expired_worker_cannot_record_late_stage_after_takeover(self):
        entered, release = threading.Event(), threading.Event()

        class LateModel(DemoModel):
            def propose(self, context):
                entered.set()
                if not release.wait(10):
                    raise RuntimeError("Test did not release blocked worker")
                return super().propose(context)

        first = Runtime(self.store, self.registry, LateModel())
        second_store = self.enterContext(self.store_type(self.runtime_dsn, max_connections=2, timeout=5))
        second = Runtime(second_store, self.registry, DemoModel())
        task_id = self.submit("expired")
        with ThreadPoolExecutor(max_workers=1) as workers:
            pending = workers.submit(first.advance, self.tenant, task_id)
            try:
                self.assertTrue(entered.wait(5))
                self.assertEqual(second.advance(self.tenant, task_id)["status"], "planning")
                with database(second_store, write=True, tenant=self.tenant) as conn:
                    conn.execute("UPDATE execution_claims SET expires=? WHERE task_id=?", (0, task_id))
                self.assertEqual(second.metrics(self.tenant)["expired_execution_claims"], 1)
                self.assertEqual(second.advance(self.tenant, task_id)["status"], "awaiting_approval")
            finally:
                release.set()
            self.assertEqual(pending.result(timeout=5)["status"], "awaiting_approval")
        inspected = second.inspect(self.tenant, task_id)
        self.assertEqual(len(inspected["steps"]), 1)
        self.assertEqual([event["event"] for event in inspected["events"]].count("model.discarded"), 1)

    def test_local_transaction_rolls_back_and_retries_once(self):
        task_id = self.submit("rollback")
        self.ready(task_id)
        with self.assertRaises(TimeoutError):
            self.runtime.advance(self.tenant, task_id, simulate_timeout="before-commit")
        self.assertEqual(self.runtime.inspect(self.tenant, task_id)["effects"], [])
        with database(self.store, tenant=self.tenant) as conn:
            self.assertEqual(object_data(conn, self.tenant, "asset-1")["version"], 1)
        with self.assertRaises(TimeoutError):
            self.runtime.advance(self.tenant, task_id, simulate_timeout="after-commit")
        self.assertEqual(self.runtime.inspect(self.tenant, task_id)["task"]["status"], "completed")
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "completed")
        self.assertEqual(len(self.runtime.inspect(self.tenant, task_id)["effects"]), 1)

    def test_pool_and_tenant_lock_waits_are_bounded(self):
        import psycopg
        from psycopg_pool import PoolTimeout

        short_store = self.enterContext(self.store_type(self.runtime_dsn, max_connections=1, timeout=1))
        with database(short_store):
            with self.assertRaises(PoolTimeout), database(short_store):
                self.fail("A second connection exceeded the configured pool size")
        with database(self.store, write=True, tenant=self.tenant):
            with self.assertRaises(psycopg.errors.LockNotAvailable), database(short_store, write=True, tenant=self.tenant):
                self.fail("A second writer acquired the same tenant lock")
            with database(short_store, write=True, tenant="different-tenant") as conn:
                self.assertEqual(conn.execute("SELECT 1").fetchone()[0], 1)

    @unittest.skipUnless(CONTAINER, "Backup test requires the disposable Compose container")
    def test_backup_restore_preserves_unknown_operation_and_uses_lookup_only(self):
        import psycopg
        from psycopg.conninfo import make_conninfo

        class UncertainSource:
            identity = {"fixture": "p1b-restore"}
            executes = 0
            lookups = 0

            def execute(self, payload):
                self.executes += 1
                raise RemoteError("synthetic response lost")

            def lookup(self, payload):
                self.lookups += 1
                return {"status": "not_found", "operation_id": payload["operation_id"], "request_hash": payload["request_hash"]}

        source = UncertainSource()
        tools = ToolRegistry()
        tools.register_remote("fixture.restore", "1", source)
        self.registry.actions["verify_asset"].update(tool="fixture.restore", tool_version="1")
        self.runtime = Runtime(self.store, self.registry, DemoModel(), tools)
        task_id = self.submit("backup")
        self.ready(task_id)
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "reconciling")
        expected = self.runtime.inspect(self.tenant, task_id)
        metrics = self.runtime.metrics(self.tenant)
        self.assertEqual(metrics["reconciling_tasks"], 1)
        self.assertIsNotNone(metrics["oldest_reconciliation_at"])

        archive = subprocess.check_output(["docker", "exec", CONTAINER, "pg_dump", "-U", "p0_admin", "-d", "ai_native_p0",
                                           "--format=custom", "--schema=ai_native"], timeout=20)
        with psycopg.connect(DSN, autocommit=True) as conn:
            conn.execute("CREATE DATABASE p1b_restore")
        subprocess.run(["docker", "exec", "-i", CONTAINER, "pg_restore", "-U", "p0_admin", "-d", "p1b_restore",
                        "--single-transaction", "--exit-on-error", "--no-owner", "--no-privileges"],
                       input=archive, timeout=20, check=True)
        self.grant_runtime(make_conninfo(DSN, dbname="p1b_restore"))
        restored = self.enterContext(self.store_type(make_conninfo(self.runtime_dsn, dbname="p1b_restore")))
        runtime = Runtime(restored, self.registry, DemoModel(), tools)
        self.assertEqual(runtime.inspect(self.tenant, task_id), expected)
        self.assertEqual((source.executes, source.lookups), (1, 0))
        self.assertEqual(runtime.advance(self.tenant, task_id)["status"], "reconciling")
        self.assertEqual((source.executes, source.lookups), (1, 1))

    def test_remote_commit_and_lost_reply_reconcile_across_pools(self):
        remote_dir = Path(self.enterContext(TemporaryDirectory()))
        source = self.enterContext(RemoteFixture(remote_dir / "source.sqlite"))
        simultaneous = threading.Barrier(2, timeout=5)

        class CoordinatedLookup(HttpRemote):
            def lookup(self, payload):
                simultaneous.wait()
                return super().lookup(payload)

        tools = ToolRegistry()
        tools.register_remote("fixture.verify", "1", CoordinatedLookup(source.endpoint))
        registry = Registry.load(FIXTURE)
        registry.actions["verify_asset"].update(tool="fixture.verify", tool_version="1")
        self.runtime = Runtime(self.store, registry, DemoModel(), tools)
        self.runtime.initialize()
        task_id = self.submit("remote", tenant="local")
        self.ready(task_id, tenant="local")
        source.drop_after_commit = True
        self.assertEqual(self.runtime.advance("local", task_id)["status"], "reconciling")
        fresh_store = self.enterContext(self.store_type(self.runtime_dsn, max_connections=2, timeout=5))
        fresh_runtime = Runtime(fresh_store, registry, DemoModel(), tools)
        with ThreadPoolExecutor(max_workers=2) as workers:
            original = workers.submit(self.runtime.reconcile, "local", task_id)
            resumed = workers.submit(fresh_runtime.reconcile, "local", task_id)
            self.assertEqual(original.result(timeout=10)["status"], "completed")
            self.assertEqual(resumed.result(timeout=10)["status"], "completed")
        self.assertEqual(len(fresh_runtime.inspect("local", task_id)["effects"]), 1)
        self.assertEqual([path for path, _ in source.calls], ["/execute", "/lookup", "/lookup"])
        self.assertEqual(source.object_status(), {"state": "verified", "version": 2})

    def test_resume_migrated_sqlite_operation_after_source_committed(self):
        import psycopg
        from psycopg.conninfo import make_conninfo

        from ai_native_system.adapters.postgres import import_sqlite, migrate_postgres

        files = Path(self.enterContext(TemporaryDirectory()))
        source = self.enterContext(RemoteFixture(files / "source.sqlite"))
        tools = ToolRegistry()
        tools.register_remote("fixture.cutover", "1", HttpRemote(source.endpoint))
        registry = Registry.load(FIXTURE)
        registry.actions["verify_asset"].update(tool="fixture.cutover", tool_version="1")
        sqlite_path = files / "legacy.sqlite"
        legacy = Runtime(sqlite_path, registry, DemoModel(), tools)
        legacy.initialize()
        self.runtime = legacy
        task_id = self.submit("cutover", tenant="local")
        self.ready(task_id, tenant="local")
        source.drop_after_commit = True
        self.assertEqual(legacy.advance("local", task_id)["status"], "reconciling")
        before = legacy.inspect("local", task_id)
        self.assertEqual(source.object_status(), {"state": "verified", "version": 2})

        with psycopg.connect(DSN, autocommit=True) as conn:
            conn.execute("CREATE DATABASE p1b_cutover")
        with psycopg.connect(make_conninfo(DSN, dbname="p1b_cutover")) as conn:
            conn.execute("CREATE SCHEMA ai_native AUTHORIZATION p1b_migrator")
        cutover_owner = make_conninfo(self.migrator_dsn, dbname="p1b_cutover")
        migrate_postgres(cutover_owner)
        report = import_sqlite(cutover_owner, sqlite_path)
        self.assertEqual(report.counts["remote_operations"], 1)
        self.grant_runtime(cutover_owner)
        cutover = self.enterContext(self.store_type(make_conninfo(self.runtime_dsn, dbname="p1b_cutover")))
        runtime = Runtime(cutover, registry, DemoModel(), tools)
        self.assertEqual(runtime.inspect("local", task_id), before)
        self.assertEqual(runtime.advance("local", task_id)["status"], "completed")
        self.assertEqual(len(runtime.inspect("local", task_id)["effects"]), 1)
        [(execute, sent), (lookup, checked)] = source.calls
        self.assertEqual((execute, lookup), ("/execute", "/lookup"))
        self.assertEqual((checked["operation_id"], checked["request_hash"]), (sent["operation_id"], sent["request_hash"]))
