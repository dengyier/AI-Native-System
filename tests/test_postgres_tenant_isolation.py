import os
import secrets
import unittest


DSN = os.environ.get("AI_NATIVE_PG_TENANT_TEST_DSN")
DIRECT_TABLES = (
    "principals", "objects", "knowledge", "knowledge_history", "tasks", "ontology_releases",
    "identity_mappings", "fact_assertions", "source_events", "fact_projections", "source_cursors",
    "fact_invalidation_outbox",
)
TASK_CHILDREN = {
    "legacy_task_order": "task_id", "steps": "task_id", "events": "task_id", "execution_claims": "task_id",
    "remote_operations": "operation_id", "effects": "operation_id",
}


def bind_tenant(connection, tenant):
    connection.execute("SELECT set_config('ai_native.tenant', %s, true)", (tenant,))


@unittest.skipUnless(DSN, "Run deployment/local-postgres/verify_tenant_isolation.py for PostgreSQL RLS tests")
class PostgresTenantIsolationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo

        from ai_native_system.adapters.postgres import migrate_postgres

        cls.connect = psycopg.connect
        owner_password, runtime_password = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        cls.owner_dsn = make_conninfo(DSN, user="p2a_migrator", password=owner_password)
        cls.runtime_dsn = make_conninfo(DSN, user="p2a_runtime", password=runtime_password)
        with psycopg.connect(DSN) as admin:
            for role, password in (("p2a_migrator", owner_password), ("p2a_runtime", runtime_password)):
                admin.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(sql.Identifier(role), sql.Literal(password)))
            admin.execute("CREATE SCHEMA ai_native AUTHORIZATION p2a_migrator")
        migrate_postgres(cls.owner_dsn)
        with psycopg.connect(cls.owner_dsn) as owner:
            owner.execute("GRANT USAGE ON SCHEMA ai_native TO p2a_runtime")
            owner.execute("GRANT SELECT ON ai_native.schema_migrations TO p2a_runtime")
            owner.execute("GRANT USAGE ON ALL SEQUENCES IN SCHEMA ai_native TO p2a_runtime")
            for table in (*DIRECT_TABLES, *TASK_CHILDREN):
                owner.execute(sql.SQL("GRANT SELECT, INSERT, UPDATE, DELETE ON ai_native.{} TO p2a_runtime").format(
                    sql.Identifier(table)))
            cls.seed(owner, "alpha", 1)
            cls.seed(owner, "beta", 2)

    @staticmethod
    def seed(owner, tenant, ordinal):
        identity = f"{tenant}-task"
        statements = [
            ("INSERT INTO ai_native.principals VALUES (%s, 'actor', '[]', 1)", (tenant,)),
            ("INSERT INTO ai_native.objects VALUES (%s, 'object', 'kind', 'open', 1, '{}', '{}')", (tenant,)),
            ("INSERT INTO ai_native.knowledge VALUES (%s, 'note', 1, 'note')", (tenant,)),
            ("INSERT INTO ai_native.knowledge_history VALUES (%s, 'note', 1, 'note')", (tenant,)),
            ("""INSERT INTO ai_native.tasks (tenant, id, application, object_id, requester, request_key, definition_hash, status)
                VALUES (%s, %s, 'app', 'object', 'actor', 'key', 'old-hash', 'completed')""", (tenant, identity)),
            ("INSERT INTO ai_native.legacy_task_order VALUES (%s, %s)", (identity, ordinal)),
            ("INSERT INTO ai_native.steps VALUES (%s, 0, 'agent', '{}')", (identity,)),
            ("INSERT INTO ai_native.events (task_id, event, detail) VALUES (%s, 'event', '{}')", (identity,)),
            ("INSERT INTO ai_native.execution_claims VALUES (%s, 'token', 1)", (identity,)),
            ("""INSERT INTO ai_native.remote_operations (operation_id,tool_name,tool_version,adapter_identity,payload,status)
                VALUES (%s,'tool','1','{}','{}','unknown')""", (identity,)),
            ("INSERT INTO ai_native.effects VALUES (%s, 'action', 'object', '{}')", (identity,)),
            ("INSERT INTO ai_native.ontology_releases VALUES (%s,'domain','1',repeat('0',64),'{}')", (tenant,)),
            ("INSERT INTO ai_native.identity_mappings VALUES (%s,'source','type','key','1',now(),repeat('0',64),'{}')", (tenant,)),
            ("""INSERT INTO ai_native.fact_assertions
                    (tenant,assertion_id,revision_key,object_type,object_id,field_name,recorded_at,digest,document)
                VALUES (%s,'assertion','1','kind','object','field',now(),repeat('0',64),'{}')""", (tenant,)),
            ("INSERT INTO ai_native.fact_projections VALUES (%s,'kind','object','field','','assertion','1')", (tenant,)),
            ("INSERT INTO ai_native.source_events VALUES (%s,'source','event','epoch',now(),repeat('0',64),'{}')", (tenant,)),
            ("INSERT INTO ai_native.source_cursors VALUES (%s,'source','stream','epoch','cursor',1)", (tenant,)),
            ("INSERT INTO ai_native.fact_invalidation_outbox (tenant,event_id,digest,document) VALUES (%s,'event',repeat('0',64),'{}')",
             (tenant,)),
        ]
        for statement, parameters in statements:
            owner.execute(statement, parameters)

    def test_default_deny_and_owner_offline_access(self):
        from psycopg.errors import InsufficientPrivilege

        with self.connect(self.runtime_dsn) as runtime, self.connect(self.owner_dsn) as owner:
            self.assertIsNotNone(runtime.execute("SELECT revision FROM ai_native.schema_migrations LIMIT 1").fetchone())
            for table in (*DIRECT_TABLES, *TASK_CHILDREN):
                with self.subTest(table=table):
                    self.assertEqual(runtime.execute(f"SELECT count(*) FROM ai_native.{table}").fetchone(), (0,))
                    self.assertEqual(owner.execute(f"SELECT count(*) FROM ai_native.{table}").fetchone(), (2,))
            with self.assertRaises(InsufficientPrivilege), runtime.transaction():
                runtime.execute("INSERT INTO ai_native.knowledge VALUES ('alpha','denied',1,'text')")
            with self.assertRaises(InsufficientPrivilege), runtime.transaction():
                runtime.execute("SELECT * FROM ai_native.sqlite_imports")

    def test_tenant_scope_covers_tables_and_uses_both_update_checks(self):
        from psycopg.errors import InsufficientPrivilege

        with self.connect(self.runtime_dsn) as runtime:
            bind_tenant(runtime, "alpha")
            for table in DIRECT_TABLES:
                with self.subTest(table=table):
                    self.assertEqual(runtime.execute(f"SELECT tenant FROM ai_native.{table}").fetchall(), [("alpha",)])
            for table, column in TASK_CHILDREN.items():
                with self.subTest(table=table):
                    self.assertEqual(runtime.execute(f"SELECT {column} FROM ai_native.{table}").fetchall(), [("alpha-task",)])
            self.assertEqual(runtime.execute("UPDATE ai_native.objects SET version=2 WHERE tenant='beta'").rowcount, 0)
            self.assertEqual(runtime.execute("DELETE FROM ai_native.events WHERE task_id='beta-task'").rowcount, 0)
            for statement in (
                "INSERT INTO ai_native.knowledge VALUES ('beta','foreign-note',1,'text')",
                "UPDATE ai_native.objects SET tenant='beta', id='new-id' WHERE tenant='alpha'",
                "INSERT INTO ai_native.events (task_id,event,detail) VALUES ('beta-task','cross-tenant','{}')",
                "UPDATE ai_native.events SET task_id='beta-task' WHERE task_id='alpha-task'",
                "INSERT INTO ai_native.source_cursors VALUES ('beta','source','other','epoch','token',1)",
            ):
                with self.subTest(statement=statement), self.assertRaises(InsufficientPrivilege), runtime.transaction():
                    runtime.execute(statement)
            with runtime.transaction(force_rollback=True):
                self.assertEqual(runtime.execute("UPDATE ai_native.objects SET version=2 WHERE tenant='alpha'").rowcount, 1)
                runtime.execute("INSERT INTO ai_native.events (task_id,event,detail) VALUES ('alpha-task','allowed','{}')")

    def test_pool_reuse_after_commit_and_rollback_does_not_retain_tenant(self):
        from ai_native_system.adapters.postgres_runtime import PostgresRuntimeStore

        with PostgresRuntimeStore(self.runtime_dsn, max_connections=1, timeout=4) as store:
            with store.transaction(tenant="alpha") as connection:
                backend = connection.execute("SELECT pg_backend_pid()").fetchone()[0]
                self.assertEqual([row[0] for row in connection.execute("SELECT tenant FROM ai_native.tasks")], ["alpha"])
            with store.transaction() as connection:
                self.assertEqual(connection.execute("SELECT pg_backend_pid()").fetchone()[0], backend)
                self.assertEqual(connection.execute("SELECT tenant FROM ai_native.tasks").fetchall(), [])
            with self.assertRaisesRegex(RuntimeError, "fixture rollback"), store.transaction(tenant="beta", write=True) as connection:
                self.assertEqual(connection.execute("SELECT pg_backend_pid()").fetchone()[0], backend)
                self.assertEqual([row[0] for row in connection.execute("SELECT tenant FROM ai_native.tasks")], ["beta"])
                raise RuntimeError("fixture rollback")
            with store.transaction() as connection:
                self.assertEqual(connection.execute("SELECT pg_backend_pid()").fetchone()[0], backend)
                self.assertEqual(connection.execute("SELECT tenant FROM ai_native.tasks").fetchall(), [])

    def test_store_rejects_owner_bypass_and_truncate_roles(self):
        from ai_native_system.adapters.postgres import MigrationError
        from ai_native_system.adapters.postgres_runtime import PostgresRuntimeStore

        for dsn in (self.owner_dsn, DSN):
            with self.assertRaises(MigrationError), PostgresRuntimeStore(dsn):
                self.fail("Privileged account entered the runtime pool")
        for apply_dsn, grant, revoke in (
            (DSN, "ALTER ROLE p2a_runtime BYPASSRLS", "ALTER ROLE p2a_runtime NOBYPASSRLS"),
            (self.owner_dsn, "GRANT TRUNCATE ON ai_native.knowledge TO p2a_runtime",
             "REVOKE TRUNCATE ON ai_native.knowledge FROM p2a_runtime"),
        ):
            with self.subTest(grant=grant):
                with self.connect(apply_dsn) as connection:
                    connection.execute(grant)
                try:
                    with self.assertRaises(MigrationError), PostgresRuntimeStore(self.runtime_dsn):
                        self.fail("RLS-bypassing privilege entered the runtime pool")
                finally:
                    with self.connect(apply_dsn) as connection:
                        connection.execute(revoke)

    def test_store_rejects_truncate_reachable_only_through_set_role(self):
        from ai_native_system.adapters.postgres import MigrationError
        from ai_native_system.adapters.postgres_runtime import PostgresRuntimeStore

        with self.connect(DSN) as connection:
            connection.execute("CREATE ROLE p2a_maintenance NOLOGIN")
            connection.execute("GRANT TRUNCATE ON ai_native.knowledge TO p2a_maintenance")
            connection.execute("GRANT p2a_maintenance TO p2a_runtime WITH INHERIT FALSE, SET TRUE")
        try:
            with self.connect(self.runtime_dsn) as connection:
                self.assertEqual(connection.execute("SELECT has_table_privilege('ai_native.knowledge','TRUNCATE')").fetchone(), (False,))
            with self.assertRaises(MigrationError), PostgresRuntimeStore(self.runtime_dsn):
                self.fail("SET ROLE escalation entered the runtime pool")
        finally:
            with self.connect(DSN) as connection:
                connection.execute("REVOKE p2a_maintenance FROM p2a_runtime")
                connection.execute("REVOKE TRUNCATE ON ai_native.knowledge FROM p2a_maintenance")
                connection.execute("DROP ROLE p2a_maintenance")
