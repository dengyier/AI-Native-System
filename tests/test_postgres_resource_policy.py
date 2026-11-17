import os
import secrets
import unittest
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone


DSN = os.environ.get("AI_NATIVE_PG_POLICY_TEST_DSN")


@unittest.skipUnless(DSN, "Run deployment/local-postgres/verify_p2a.py --only policy for PostgreSQL permission tests")
class PostgresResourcePolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo

        from ai_native_system.adapters.postgres import migrate_postgres
        from ai_native_system.policy import Policy

        cls.connect = psycopg.connect
        cls.policy = Policy()
        password = secrets.token_urlsafe(24)
        cls.runtime_dsn = make_conninfo(DSN, user="p2_policy_runtime", password=password)
        with psycopg.connect(DSN) as admin:
            admin.execute("CREATE SCHEMA ai_native")
            admin.execute(sql.SQL("CREATE ROLE p2_policy_runtime LOGIN PASSWORD {}").format(sql.Literal(password)))
        migrate_postgres(DSN)
        with psycopg.connect(DSN) as admin:
            admin.execute("GRANT USAGE ON SCHEMA ai_native TO p2_policy_runtime")
            admin.execute("""GRANT SELECT ON ai_native.schema_migrations, ai_native.resource_grants,
                             ai_native.principals, ai_native.objects, ai_native.enterprise_delegations,
                             ai_native.enterprise_delegation_scopes TO p2_policy_runtime""")

    def setUp(self):
        from ai_native_system.identity import IdentityContext
        from ai_native_system.registry import Registry

        self.tenant = "test-" + secrets.token_hex(8)
        self.identity = IdentityContext(self.tenant, "reader")
        self.registry = Registry({
            "types": {
                "asset": {"states": ["open", "closed"], "fields": {"name": "string", "internal": "string"},
                          "links": {"site": "site"}},
                "site": {"states": ["open"], "fields": {"name": "string"}, "links": {}},
            },
            "applications": {},
            "actions": {"close": {"version": 1, "object_type": "asset", "from_state": "open", "to_state": "closed",
                                  "request_role": "request", "approval_role": "approve", "execute_role": "execute",
                                  "requires_properties": {"internal": "hidden"}}},
            "seed": {"actors": [], "objects": [], "knowledge": []},
        })
        with self.connect(DSN) as admin:
            admin.execute("INSERT INTO ai_native.principals (tenant,id,roles) VALUES (%s,'reader','[]')", (self.tenant,))
            for object_id, object_type, props, links in (
                ("a-hidden", "asset", '{"name":"public","internal":"hidden"}', '{"site":"site-a"}'),
                ("b-visible", "asset", '{"name":"public","internal":"hidden"}', '{"site":"site-a"}'),
                ("site-a", "site", '{"name":"location"}', '{}'),
            ):
                admin.execute("""INSERT INTO ai_native.objects (tenant,id,type,state,version,properties,links)
                                 VALUES (%s,%s,%s,'open',1,%s,%s)""",
                              (self.tenant, object_id, object_type, props, links))

    @contextmanager
    def operator(self):
        from ai_native_system.adapters.postgres_runtime import _Transaction

        with self.connect(DSN) as admin:
            admin.execute("SET LOCAL search_path TO pg_catalog, ai_native, pg_temp")
            yield _Transaction(admin)

    def grant(self, *scopes):
        with self.operator() as admin:
            for scope in scopes:
                self.assertTrue(self.policy.grant(admin, self.tenant, "reader", *scope))

    def test_exact_grants_and_runtime_role_cannot_provision(self):
        from psycopg.errors import InsufficientPrivilege
        from ai_native_system.adapters.postgres_runtime import PostgresRuntimeStore
        from ai_native_system.policy import tool_resource_id

        granted_tool = tool_resource_id("local@test", "1")
        other_tool = tool_resource_id("local", "test@1")
        resources = (("read", "object", "b-visible"), ("read", "document", "d"), ("execute", "tool", granted_tool),
                     ("read", "task", "t"), ("read", "evidence", "e"), ("read", "field", "b-visible", "name"))
        with PostgresRuntimeStore(self.runtime_dsn) as store:
            with store.transaction(tenant=self.tenant) as db:
                for scope in resources:
                    self.assertFalse(self.policy.permits(db, self.identity, *scope))
            self.grant(*resources)
            with store.transaction(tenant=self.tenant, write=True) as db:
                for scope in resources:
                    self.assertTrue(self.policy.permits(db, self.identity, *scope))
                self.assertFalse(self.policy.permits(db, self.identity, "read", "field", "b-visible", "internal"))
                self.assertFalse(self.policy.permits(db, self.identity, "read", "object", "a-hidden"))
                self.assertFalse(self.policy.permits(db, self.identity, "read", "tool", granted_tool))
                self.assertFalse(self.policy.permits(db, self.identity, "execute", "tool", other_tool))
                with self.assertRaises(InsufficientPrivilege):
                    self.policy.grant(db, self.tenant, "reader", "read", "object", "a-hidden")
            with store.transaction() as db:
                self.assertEqual(db.execute("SELECT * FROM resource_grants").fetchall(), [])
            with store.transaction(tenant="other-tenant") as db:
                self.assertFalse(self.policy.permits(db, self.identity, "read", "object", "b-visible"))
            with self.operator() as db:
                self.assertTrue(self.policy.revoke(db, self.tenant, "reader", "read", "object", "b-visible"))
            with store.transaction(tenant=self.tenant) as db:
                self.assertFalse(self.policy.permits(db, self.identity, "read", "object", "b-visible"))

    def test_query_projection_filters_counts_and_navigation(self):
        from ai_native_system.adapters.postgres_runtime import PostgresRuntimeStore
        from ai_native_system.semantic_query import SemanticQuery

        self.grant(("read", "object", "b-visible"), ("read", "field", "b-visible", "name"),
                   ("read", "edge", "b-visible", "site"), ("read", "action", "close"),
                   ("execute", "tool", "state.transition@1"))
        with PostgresRuntimeStore(self.runtime_dsn) as store:
            query = SemanticQuery(store, self.registry)
            result = query.query(self.identity, object_type="asset", limit=1, follow=["site"], discover_actions=True)
            self.assertEqual(result["objects"], [{
                "tenant": self.tenant, "id": "b-visible", "type": "asset", "properties": {"name": "public"},
                "links": {}, "related": [], "actions": ["close"],
            }])
            self.assertEqual(query.query(self.identity, object_id="a-hidden"), {"objects": []})
            self.assertEqual(query.query(self.identity, object_id="missing"), {"objects": []})
            self.assertEqual(query.query(self.identity, object_type="asset", filters={"internal": "hidden"}),
                             {"objects": []})
            with self.assertRaises(PermissionError):
                query.query(self.identity, object_type="asset", count=True)
            self.grant(("aggregate", "type", "asset"), ("read", "object", "site-a"),
                       ("read", "field", "site-a", "name"), ("read", "metadata", "b-visible", "version"))
            result = query.query(self.identity, object_type="asset", filters={"name": "public"}, limit=1,
                                 follow=["site"], count=True)
            self.assertEqual(result["visible_count"], 1)
            asset, = result["objects"]
            self.assertEqual(asset["version"], 1)
            self.assertEqual(asset["links"], {"site": "site-a"})
            self.assertEqual(asset["related"][0]["properties"], {"name": "location"})
            for field, value in (("name", 17), ("internal", "hidden"), ("unknown", "hidden")):
                self.assertEqual(query.query(self.identity, object_type="asset", filters={field: value}),
                                 {"objects": []})
            self.assertEqual(query.query(self.identity, object_type="unknown"), {"objects": []})
            unknown_link = query.query(self.identity, object_id="b-visible", follow=["unknown"])
            self.assertEqual(unknown_link["objects"][0]["related"], [])
            for params in ({"limit": 101}, {"filters": {"name": {"unexpected": 1}}},
                           {"follow": ["site"] * 4}, {"follow": [""]}, {"object_id": "b-visible", "count": 1}):
                with self.subTest(params=params), self.assertRaises(ValueError):
                    query.query(self.identity, **params)

    def test_delegation_intersects_actor_service_and_exact_scopes(self):
        from ai_native_system.adapters.postgres_runtime import PostgresRuntimeStore
        from ai_native_system.identity import IdentityContext, create_delegation, revoke_delegation
        from ai_native_system.semantic_query import SemanticQuery

        delegated = IdentityContext(self.tenant, "reader", "service", "delegation")
        now = datetime.now(timezone.utc)
        read = ("read", "object", "b-visible")
        hidden = ("read", "object", "a-hidden")
        public_field = ("read", "field", "b-visible", "name")
        with self.operator() as db:
            db.execute("INSERT INTO principals (tenant,id,roles) VALUES (?,'service','[]')", (self.tenant,))
            create_delegation(db, delegated, ((*read, None), (*hidden, None), public_field),
                              starts_at=now - timedelta(minutes=5), expires_at=now + timedelta(minutes=5))
            for grant in (read, public_field):
                self.policy.grant(db, self.tenant, "service", *grant)
        self.grant(read, hidden, ("read", "field", "b-visible", "internal"))
        with PostgresRuntimeStore(self.runtime_dsn) as store:
            query = SemanticQuery(store, self.registry)
            result = query.query(delegated, object_type="asset", limit=1, explain=True)
            self.assertEqual(result["objects"][0]["id"], "b-visible")
            self.assertEqual(result["objects"][0]["properties"], {})
            self.assertEqual(result["explanation"]["scope"], "authorized-subset")
            self.grant(public_field)
            result = query.query(delegated, object_type="asset", filters={"name": "public"})
            self.assertEqual(result["objects"][0]["properties"], {"name": "public"})
            with self.operator() as db:
                self.assertTrue(revoke_delegation(db, self.tenant, "delegation"))
            with store.transaction(tenant=self.tenant) as db:
                self.assertFalse(self.policy.permits(db, delegated, *read))
            with self.assertRaises(PermissionError):
                query.query(delegated, object_id="b-visible")


    def test_authorized_candidate_limit_is_unaffected_by_hidden_rows(self):
        from ai_native_system.adapters.postgres_runtime import PostgresRuntimeStore
        from ai_native_system.semantic_query import MAX_CANDIDATES, SemanticQuery

        self.grant(("read", "object", "b-visible"), ("aggregate", "type", "asset"))
        with self.operator() as db:
            db.execute('''INSERT INTO objects (tenant, id, type, state, version, properties, links)
                SELECT tenant, 'a-extra-' || n::text, type, state, version, properties, links
                FROM objects CROSS JOIN generate_series(1, ?) AS n WHERE tenant=? AND id='b-visible' ''',
                (MAX_CANDIDATES + 1, self.tenant))
        with PostgresRuntimeStore(self.runtime_dsn) as store:
            query = SemanticQuery(store, self.registry)
            result = query.query(self.identity, object_type="asset", count=True, limit=1)
            self.assertEqual(result["visible_count"], 1)
            self.assertEqual(result["objects"][0]["id"], "b-visible")
            with self.operator() as db:
                db.execute('''INSERT INTO resource_grants (tenant, principal, operation, kind, resource_id)
                    SELECT tenant, 'reader', 'read', 'object', id FROM objects
                    WHERE tenant=? AND id LIKE 'a-extra-%' ''', (self.tenant,))
            with self.assertRaisesRegex(ValueError, "authorized candidate limit"):
                query.query(self.identity, object_type="asset", count=True, limit=1)
            narrowed = query.query(self.identity, object_type="asset", object_id="b-visible", count=True)
            self.assertEqual(narrowed["visible_count"], 1)
