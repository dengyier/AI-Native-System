import json
from datetime import timedelta
import os
from pathlib import Path
import secrets
import shutil
from threading import Thread
import time
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

from ai_native_system.identity import (
    EnterpriseIdentity, IdentityContext, IdentityError, create_delegation, delegation_scopes, require_identity,
    revoke_delegation,
)
from test_enterprise_identity import AUDIENCE, CLIENT, ISSUER, SUBJECT, https_provider


DSN = os.environ.get("AI_NATIVE_PG_IDENTITY_TEST_DSN")
SCOPES = (("read", "object", "record-1", "public"), ("execute", "action", "tag", None))


@unittest.skipUnless(DSN, "Run the P2a PostgreSQL verifier for enterprise delegation tests")
class PostgresDelegationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo

        from ai_native_system.adapters.postgres import migrate_postgres
        from ai_native_system.adapters.postgres_runtime import PostgresRuntimeStore

        cls.connect = psycopg.connect
        roles = {role: secrets.token_urlsafe(24) for role in ("p2_identity_owner", "p2_identity_worker", "p2_identity_admin")}
        with psycopg.connect(DSN) as admin:
            for role, password in roles.items():
                admin.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(sql.Identifier(role), sql.Literal(password)))
            admin.execute("CREATE SCHEMA ai_native AUTHORIZATION p2_identity_owner")
        owner, worker, operator = [make_conninfo(DSN, user=role, password=password) for role, password in roles.items()]
        migrate_postgres(owner)

        with psycopg.connect(owner) as connection:
            connection.execute("GRANT USAGE ON SCHEMA ai_native TO p2_identity_worker, p2_identity_admin")
            connection.execute("""GRANT SELECT ON ai_native.schema_migrations, ai_native.principals,
                ai_native.enterprise_delegations, ai_native.enterprise_delegation_scopes
                TO p2_identity_worker, p2_identity_admin""")
            connection.execute("""GRANT SELECT ON ai_native.governed_tenants, ai_native.fact_rule_bindings, ai_native.owp_enforced_tenants,
                                          ai_native.p4_sequence_steps, ai_native.tasks,
                ai_native.resource_grants, ai_native.task_governance TO p2_identity_worker""")
            connection.execute("""GRANT INSERT ON ai_native.enterprise_delegations, ai_native.enterprise_delegation_scopes
                TO p2_identity_admin""")
            connection.execute("GRANT UPDATE (revoked_at) ON ai_native.enterprise_delegations TO p2_identity_admin")
            for tenant in ("alpha", "beta"):
                for principal, active in (("alice", 1), ("robot", 1), ("mallory", 1), ("disabled", 0)):
                    connection.execute("INSERT INTO ai_native.principals VALUES (%s,%s,'[]',%s)", (tenant, principal, active))
                connection.execute("INSERT INTO ai_native.governed_tenants VALUES (%s)", (tenant,))
                task = f"{tenant}-task"
                connection.execute("""INSERT INTO ai_native.tasks
                    (tenant,id,application,object_id,requester,request_key,definition_hash,status)
                    VALUES (%s,%s,'app','object','alice','key','old-hash','completed')""", (tenant, task))
                connection.execute("""INSERT INTO ai_native.resource_grants
                    (tenant,principal,operation,kind,resource_id) VALUES (%s,'alice','read','task',%s)""", (tenant, task))
        cls.worker_dsn = worker
        cls.worker = cls.enterClassContext(PostgresRuntimeStore(worker))
        cls.operator = cls.enterClassContext(PostgresRuntimeStore(operator))

    def provision(self, *, tenant="alpha", actor="alice", service="robot", start=-60, end=60):
        identity = IdentityContext(tenant, actor, service, "grant-" + secrets.token_hex(5), int(time.time()) + 60)
        with self.operator.transaction(tenant=tenant, write=True) as connection:
            now = connection.execute("SELECT clock_timestamp()").fetchone()[0]
            create_delegation(connection, identity, SCOPES,
                              starts_at=now + timedelta(seconds=start), expires_at=now + timedelta(seconds=end))
        return identity

    def test_grant_is_identity_bound_and_attenuates_exact_scope(self):
        identity = self.provision()
        with self.worker.transaction(tenant="alpha") as connection:
            require_identity(connection, identity)
            self.assertEqual(delegation_scopes(connection, identity), frozenset(SCOPES))
            for scope in SCOPES:
                require_identity(connection, identity, scope)
            for scope in (
                ("read", "object", "record-2", "public"),
                ("read", "object", "record-1", "private"),
                ("read", "object", "record-1", None),
                ("delete", "object", "record-1", "public"),
                ("read", "other-kind", "record-1", "public"),
                ("execute", "action", "tag", "unexpected-member"),
            ):
                with self.subTest(scope=scope), self.assertRaises(IdentityError):
                    require_identity(connection, identity, scope)
            for forged in (
                IdentityContext("alpha", "mallory", "robot", identity.delegation_id),
                IdentityContext("alpha", "alice", "mallory", identity.delegation_id),
                IdentityContext("beta", "alice", "robot", identity.delegation_id),
            ):
                with self.subTest(forged=forged), self.assertRaises(IdentityError):
                    require_identity(connection, forged, SCOPES[0])
            self.assertIsNone(delegation_scopes(connection, IdentityContext("alpha", "alice")))
            require_identity(connection, IdentityContext("alpha", "robot", "robot"))

    def test_revocation_disabled_principals_and_time_limits(self):
        revoked = self.provision()
        with self.worker.transaction(tenant="alpha") as connection:
            require_identity(connection, revoked, SCOPES[0])
        with self.operator.transaction(tenant="alpha", write=True) as connection:
            self.assertTrue(revoke_delegation(connection, "alpha", revoked.delegation_id))
            self.assertFalse(revoke_delegation(connection, "alpha", revoked.delegation_id))
        unavailable = (
            revoked, self.provision(start=-60, end=-10), self.provision(start=10, end=60),
            self.provision(service="disabled"), self.provision(actor="disabled"),
            IdentityContext("alpha", "alice", expires_at=int(time.time()) - 1),
        )
        for identity in unavailable:
            with self.subTest(identity=identity), self.worker.transaction(tenant="alpha") as connection:
                with self.assertRaises(IdentityError):
                    require_identity(connection, identity, SCOPES[0])
                with self.assertRaises(IdentityError):
                    delegation_scopes(connection, identity)

    def test_tenant_rls_and_worker_cannot_issue_or_revoke_grants(self):
        alpha = self.provision()
        beta = self.provision(tenant="beta")
        for tenant, expected in ((None, []), ("alpha", [alpha.delegation_id]), ("beta", [beta.delegation_id])):
            with self.subTest(tenant=tenant), self.worker.transaction(tenant=tenant) as connection:
                for table, identity_column in (("enterprise_delegations", "id"), ("enterprise_delegation_scopes", "delegation_id")):
                    selected = connection.execute(
                        f"SELECT DISTINCT {identity_column} FROM {table} WHERE {identity_column} IN (?,?)",
                        (alpha.delegation_id, beta.delegation_id),
                    )
                    self.assertEqual([row[0] for row in selected], expected)

        from psycopg.errors import InsufficientPrivilege

        with self.assertRaises(InsufficientPrivilege), self.worker.transaction(tenant="alpha", write=True) as connection:
            revoke_delegation(connection, "alpha", alpha.delegation_id)
        with self.assertRaises(InsufficientPrivilege), self.worker.transaction(tenant="alpha", write=True) as connection:
            now = connection.execute("SELECT clock_timestamp()").fetchone()[0]
            create_delegation(connection, IdentityContext("alpha", "alice", "robot", "forged"), SCOPES,
                              starts_at=now, expires_at=now + timedelta(minutes=1))
        with self.assertRaises(InsufficientPrivilege), self.operator.transaction(tenant="alpha", write=True) as connection:
            now = connection.execute("SELECT clock_timestamp()").fetchone()[0]
            create_delegation(connection, IdentityContext("beta", "alice", "robot", "cross-tenant"), SCOPES,
                              starts_at=now, expires_at=now + timedelta(minutes=1))
        with self.worker.transaction(tenant="alpha") as connection:
            require_identity(connection, alpha, SCOPES[0])

    @unittest.skipUnless(shutil.which("openssl"), "openssl is needed for the local TLS fixture")
    def test_http_bearer_identity_maps_to_one_tenant(self):
        from ai_native_system.api import make_server
        from ai_native_system.model import DemoModel
        from ai_native_system.registry import Registry
        from ai_native_system.runtime import Runtime

        registry = Registry.load(Path(__file__).resolve().parents[1] / "fixtures" / "conformance.json")
        runtime = Runtime(self.worker, registry, DemoModel())
        opener = build_opener(ProxyHandler({}))
        token = "opaque-oauth-token"
        with https_provider() as (endpoint, cert, received):
            config = {
                "issuer": ISSUER, "audience": AUDIENCE, "endpoint": endpoint + "/introspect",
                "introspection_client_id": "api", "introspection_secret_env": "TEST_IDP_SECRET",
                "bindings": [{"subject": SUBJECT, "client_id": CLIENT, "tenant": "alpha", "actor": "alice"}],
            }
            with (
                patch.dict("os.environ", {"SSL_CERT_FILE": cert}),
                make_server(runtime, {}, 0, enterprise_identity=EnterpriseIdentity.from_config(
                    config, env={"TEST_IDP_SECRET": "local-test"}
                )) as api,
            ):
                worker = Thread(target=api.serve_forever, daemon=True)
                worker.start()
                try:
                    def request(path, body=None):
                        req = Request(f"http://127.0.0.1:{api.server_port}/v1/tasks{path}",
                                      headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                                      data=json.dumps(body).encode() if body is not None else None)
                        with opener.open(req, timeout=5) as response:
                            return json.load(response)

                    self.assertEqual(request("/alpha-task"), {"id": "alpha-task", "status": "completed"})
                    forged = {"application": "app", "object_id": "object", "request_key": "a",
                              "tenant": "beta", "actor": "mallory", "delegation_id": "forged"}
                    for path, body, expected_status in (("/beta-task", None, 403), ("/missing", None, 403), ("", forged, 400)):
                        with self.assertRaises(HTTPError) as denied:
                            request(path, body)
                        denied.exception.close()
                        self.assertEqual(denied.exception.code, expected_status)
                finally:
                    api.shutdown()
                    worker.join()
            self.assertEqual([form["token"] for _, _, form in received], [[token]] * 4)


if __name__ == "__main__":
    unittest.main()
