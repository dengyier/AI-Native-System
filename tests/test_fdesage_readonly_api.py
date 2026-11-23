"""Real PostgreSQL privileges and loopback AINS API checks for historical captures."""

import json
import secrets
import time
import unittest
from threading import Thread
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

from ai_native_system.api import make_server
from ai_native_system.fdesage_readonly import import_observation, observation_registry
from ai_native_system.governance import activate
from ai_native_system.identity import EnterpriseIdentity, IdentityBinding
from ai_native_system.policy import Policy
from ai_native_system.runtime import Runtime
from p2b_support import TEST_DSN, restricted_role
from test_fdesage_readonly_capture import sample, scope


class _NoModel:
    def propose(self, _):
        raise AssertionError("Readonly observation queries must not invoke a model")


@unittest.skipUnless(TEST_DSN, "Set AI_NATIVE_P2B_TEST_DSN to an isolated PostgreSQL test database")
class ReadonlyAPITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from ai_native_system.adapters.postgres import migrate_postgres
        from ai_native_system.adapters.postgres_runtime import PostgresRuntimeStore

        migrate_postgres(TEST_DSN)
        cls.store_type = PostgresRuntimeStore
        cls.query_dsn = restricted_role(("SELECT ON ALL TABLES IN SCHEMA ai_native",))
        cls.import_dsn = restricted_role(("SELECT ON ALL TABLES IN SCHEMA ai_native", "INSERT ON ai_native.objects"))
        cls.control_dsn = restricted_role((
            "SELECT ON ALL TABLES IN SCHEMA ai_native",
            "INSERT ON ai_native.principals, ai_native.governed_tenants, ai_native.resource_grants",
            "DELETE ON ai_native.resource_grants",
            "UPDATE (active) ON ai_native.principals",
        ))

    def setUp(self):
        self.tenant = "fdesage-shadow-" + secrets.token_hex(6)
        self.control = self.enterContext(self.store_type(self.control_dsn))
        self.importer = self.enterContext(self.store_type(self.import_dsn))
        self.query_store = self.enterContext(self.store_type(self.query_dsn))
        with self.importer.transaction(tenant=self.tenant, write=True) as connection:
            self.object_id = import_observation(connection, self.tenant, sample(), scope())
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            for principal in ("reviewer", "guest"):
                connection.execute("INSERT INTO principals (tenant,id,roles,active) VALUES (?,?,?,1)",
                                   (self.tenant, principal, "[]"))
            activate(connection, self.tenant)
            policy = Policy()
            policy.grant(connection, self.tenant, "reviewer", "read", "object", self.object_id)
            for field in observation_registry().types["fdesage_captured_observation"]["fields"]:
                policy.grant(connection, self.tenant, "reviewer", "read", "field", self.object_id, field)

        self.tokens = {
            "ains-reviewer-test": {"sub": "reviewer-sub", "aud": "ains-api"},
            "ains-guest-test": {"sub": "guest-sub", "aud": "ains-api"},
            "source-credential-test": {"sub": "reviewer-sub", "aud": "fdesage-ains-readonly"},
        }

        def introspect(token):
            if token not in self.tokens:
                return {"active": False}
            return {"active": True, "iss": "https://identity.test", "token_type": "Bearer",
                    "scope": "ai-native.access", "exp": int(time.time()) + 300,
                    "client_id": "ains-client", **self.tokens[token]}

        identity = EnterpriseIdentity(
            "https://identity.test", "ains-api",
            [IdentityBinding(subject, "ains-client", self.tenant, actor)
             for subject, actor in (("reviewer-sub", "reviewer"), ("guest-sub", "guest"))], introspect,
        )
        runtime = Runtime(self.query_store, observation_registry(), _NoModel())
        self.server = make_server(runtime, {}, port=0, enterprise_identity=identity)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)
        self.origin = f"http://127.0.0.1:{self.server.server_port}"
        self.opener = build_opener(ProxyHandler({}))

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, path="/v1/query", token="ains-reviewer-test", body=None):
        if body is None:
            body = {"object_type": "fdesage_captured_observation", "object_id": self.object_id}
        request = Request(self.origin + path, method="POST", data=json.dumps(body).encode(),
                          headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
        try:
            with self.opener.open(request, timeout=5) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            with error:
                return error.code, json.load(error)

    def assert_no_work(self):
        with self.query_store.transaction(tenant=self.tenant) as connection:
            for table in ("tasks", "steps", "events", "model_calls", "remote_operations", "effects",
                          "owp_authorizations", "owp_consumptions", "source_events", "source_cursors"):
                with self.subTest(table=table):
                    self.assertEqual(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0], 0)

    def test_reviewer_reads_the_historical_capture_through_existing_http_query_with_no_work(self):
        status, result = self.request(body={"object_type": "fdesage_captured_observation",
                                          "object_id": self.object_id, "discover_actions": True})
        self.assertEqual(status, 200)
        item, = result["objects"]
        self.assertEqual(item["actions"], [])
        self.assertEqual(item["properties"]["coverage"], "selected_object")
        self.assertEqual(json.loads(item["properties"]["snapshot_json"]), sample())
        self.assert_no_work()

    def test_source_credential_is_rejected_and_ungranted_reviewer_learns_no_objects(self):
        self.assertEqual(self.request(token="source-credential-test")[0], 403)
        self.assertEqual(self.request(token="ains-guest-test"), (200, {"objects": []}))
        self.assert_no_work()

    def test_live_field_and_object_revocation_take_effect_on_the_next_query(self):
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            Policy().revoke(connection, self.tenant, "reviewer", "read", "field", self.object_id, "snapshot_json")
        status, result = self.request()
        self.assertEqual(status, 200)
        self.assertNotIn("snapshot_json", result["objects"][0]["properties"])
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            Policy().revoke(connection, self.tenant, "reviewer", "read", "object", self.object_id)
        self.assertEqual(self.request(), (200, {"objects": []}))
        self.assert_no_work()

    def test_no_executable_app_or_task_submission_or_authoritative_source_claim_is_available(self):
        task = {"application": "fdesage-readonly", "object_id": self.object_id, "request_key": "deny-write"}
        self.assertEqual(self.request(path="/v1/tasks", body=task)[0], 403)
        self.assertEqual(self.request(body={"application": "fdesage-readonly", "object_type": "fdesage_captured_observation",
                                           "object_id": self.object_id, "authoritative": {"fields": []}})[0], 403)
        self.assert_no_work()

    def test_disabled_reviewer_cannot_reuse_a_previously_valid_bearer(self):
        self.assertEqual(self.request()[0], 200)
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            connection.execute("UPDATE principals SET active=0 WHERE tenant=? AND id=?", (self.tenant, "reviewer"))
        self.assertEqual(self.request()[0], 403)
        self.assert_no_work()

    def test_database_reader_cannot_insert_and_importer_cannot_modify_existing_observations(self):
        import psycopg

        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            with self.query_store.transaction(tenant=self.tenant, write=True) as connection:
                import_observation(connection, self.tenant, sample(), scope())
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            with self.importer.transaction(tenant=self.tenant, write=True) as connection:
                connection.execute("UPDATE objects SET version=2 WHERE tenant=? AND id=?", (self.tenant, self.object_id))
        with self.importer.transaction(tenant=self.tenant, write=True) as connection:
            self.assertEqual(import_observation(connection, self.tenant, sample(), scope()), self.object_id)
        self.assert_no_work()


if __name__ == "__main__":
    unittest.main()
