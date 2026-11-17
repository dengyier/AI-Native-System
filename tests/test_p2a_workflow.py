import json
import os
import secrets
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import ExitStack
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ai_native_system.api import ApplicationAPI
from ai_native_system.governance import activate
from ai_native_system.identity import EnterpriseIdentity, IdentityBinding, IdentityContext, create_delegation, revoke_delegation
from ai_native_system.model import DemoModel, OpenAICompatibleModel
from ai_native_system.policy import Policy, tool_resource_id
from ai_native_system.registry import Registry
from ai_native_system.remote import HttpRemote
from ai_native_system.releases import ReleaseStore, ReleaseSnapshot
from ai_native_system.runtime import Runtime
from ai_native_system.storage import database
from ai_native_system.tools import ToolRegistry
from remote_server import RemoteFixture

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "conformance.json"
ADMIN_DSN = os.environ.get("AI_NATIVE_P2A_TEST_DSN")


@unittest.skipUnless(ADMIN_DSN, "Set AI_NATIVE_P2A_TEST_DSN for disposable PostgreSQL")
class P2aWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo

        from ai_native_system.adapters.postgres import migrate_postgres
        from ai_native_system.adapters.postgres_runtime import PostgresRuntimeStore

        cls.store_type = PostgresRuntimeStore
        with psycopg.connect(ADMIN_DSN) as connection:
            connection.execute("CREATE SCHEMA ai_native")
        migrate_postgres(ADMIN_DSN)
        password = secrets.token_urlsafe(24)
        cls.run_dsn = make_conninfo(ADMIN_DSN, user="workflow_runtime", password=password)
        cls.control_dsn = make_conninfo(ADMIN_DSN, user="workflow_control", password=password)
        with psycopg.connect(ADMIN_DSN) as connection:
            for role in ("workflow_runtime", "workflow_control"):
                connection.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(sql.Identifier(role),
                                                                                       sql.Literal(password)))
            connection.execute("GRANT USAGE ON SCHEMA ai_native TO workflow_runtime, workflow_control")
            connection.execute("GRANT SELECT ON ALL TABLES IN SCHEMA ai_native TO workflow_runtime, workflow_control")
            connection.execute("GRANT USAGE ON ALL SEQUENCES IN SCHEMA ai_native TO workflow_runtime")
            connection.execute("""GRANT INSERT ON ai_native.principals, ai_native.objects, ai_native.knowledge,
                ai_native.knowledge_history, ai_native.events TO workflow_runtime""")
            connection.execute("""GRANT INSERT, UPDATE ON ai_native.tasks, ai_native.steps,
                ai_native.remote_operations, ai_native.effects TO workflow_runtime""")
            connection.execute("GRANT INSERT, UPDATE, DELETE ON ai_native.execution_claims TO workflow_runtime")
            connection.execute("GRANT UPDATE (state, version) ON ai_native.objects TO workflow_runtime")
            connection.execute("GRANT INSERT, UPDATE (approver_context) ON ai_native.task_governance TO workflow_runtime")
            connection.execute("""GRANT INSERT ON ai_native.governed_tenants, ai_native.enterprise_delegations,
                ai_native.enterprise_delegation_scopes, ai_native.application_releases,
                ai_native.application_release_lifecycle, ai_native.application_release_selections TO workflow_control""")
            connection.execute("GRANT INSERT, DELETE ON ai_native.resource_grants TO workflow_control")
            connection.execute("GRANT UPDATE (revoked_at) ON ai_native.enterprise_delegations TO workflow_control")
            connection.execute("""GRANT UPDATE (status, changed_by, changed_at, migration_ref)
                                  ON ai_native.application_release_lifecycle TO workflow_control""")
            connection.execute("""GRANT UPDATE (digest, changed_by, changed_at)
                                  ON ai_native.application_release_selections TO workflow_control""")
            connection.execute("GRANT UPDATE (active) ON ai_native.principals TO workflow_control")

    def setUp(self):
        self.resources = ExitStack()
        self.addCleanup(self.resources.close)
        self.store = self.resources.enter_context(self.store_type(self.run_dsn))
        self.control = self.resources.enter_context(self.store_type(self.control_dsn))
        self.tenant = "workflow-" + secrets.token_hex(8)
        self.registry = Registry.load(FIXTURE)
        for section, rows in self.registry.seed.items():
            self.registry.seed[section] = [{**row, "tenant": self.tenant} for row in rows if row["tenant"] == "local"]
        self.registry.seed["actors"].append({"id": "service", "tenant": self.tenant, "roles": []})
        self.model = DemoModel()
        self.tools = ToolRegistry()
        self.runtime = Runtime(self.store, self.registry, self.model, self.tools)
        self.runtime.initialize()
        self.policy, self.catalog = Policy(), ReleaseStore()
        self.app, self.object_id = "single", "asset-1"
        self.snapshot = ReleaseSnapshot.capture(self.registry, self.app, self.model, self.tools)
        self.identities = {
            actor: {
                "iss": "https://issuer.example", "aud": "p2a", "sub": actor, "client_id": "p2a-client",
                "scope": "ai-native.access", "token_type": "Bearer", "active": True,
                "exp": int(time.time()) + 3600,
            } for actor in ("requester", "reviewer", "guest", "delegate")
        }
        self.identities["delegate"].update(sub="requester", act={"sub": "service"}, delegation_id="delegate")
        provider = EnterpriseIdentity("https://issuer.example", "p2a", [
            *(IdentityBinding(actor, "p2a-client", self.tenant, actor) for actor in ("requester", "reviewer", "guest")),
            IdentityBinding("requester", "p2a-client", self.tenant, "requester", "service", "service"),
        ], self.identities.get)
        self.api = ApplicationAPI(self.runtime, {}, enterprise_identity=provider)

    def grant(self, connection, principal, operation, kind, resource_id, member=None):
        self.policy.grant(connection, self.tenant, principal, operation, kind, resource_id, member)

    def provision(self, snapshot=None, *, activate_tenant=True, tools=None):
        snapshot = self.snapshot if snapshot is None else snapshot
        tools = self.tools if tools is None else tools
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.catalog.draft(connection, self.tenant, snapshot, publisher="operator")
            self.catalog.publish(connection, self.tenant, snapshot.digest, publisher="operator")
            self.catalog.select(connection, self.tenant, self.app, snapshot.digest, publisher="operator")
            self.grant(connection, "requester", "submit", "app", self.app)
            self.grant(connection, "requester", "read", "release", snapshot.digest)
            _, action, _ = snapshot.registry().definition(self.app)
            tool = tools.resolve(action)
            self.grant(connection, "worker", "execute", "action", "verify_asset")
            self.grant(connection, "worker", "execute", "tool", tool_resource_id(tool.name, tool.version))
            self.grant(connection, "worker", "write", "object", self.object_id)
            self.grant(connection, "worker", "write", "metadata", self.object_id, "state")
            for actor in ("requester", "reviewer", "worker"):
                for scope in self.read_ground_scopes():
                    self.grant(connection, actor, *scope)
            if activate_tenant:
                activate(connection, self.tenant)

    def read_ground_scopes(self):
        return (
            ("read", "object", self.object_id, None),
            ("read", "field", self.object_id, "label"),
            ("read", "field", self.object_id, "checksum_ok"),
            ("read", "metadata", self.object_id, "state"),
            ("read", "metadata", self.object_id, "version"),
            ("read", "document", "asset-policy", None),
        )

    def submit(self, key="run", token="requester"):
        payload = {"application": self.app, "object_id": self.object_id, "request_key": key}
        return self.api.dispatch("POST", "/v1/tasks", token, payload)

    def prepare(self, key="run", token="requester"):
        task = self.submit(key, token)
        self.assertEqual(task["status"], "planning")
        task_id = task["id"]
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.grant(connection, "reviewer", "read", "task", task_id)
            self.grant(connection, "reviewer", "approve", "task", task_id)
            self.grant(connection, "requester", "read", "task", task_id)
            self.grant(connection, "requester", "export", "evidence", task_id)
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "awaiting_approval")
        review = self.api.dispatch("GET", f"/v1/tasks/{task_id}", "reviewer", {})["review"]
        self.assertIn("grounding", review)
        return task_id, review["proposal_digest"]

    def approve(self, task_id, proposal_digest):
        return self.api.dispatch("POST", f"/v1/tasks/{task_id}/decision", "reviewer",
                                 {"verdict": "approve", "proposal_digest": proposal_digest})

    def test_pinning_approval_idempotency_and_rollback_do_not_replay(self):
        self.provision()
        task_id, proposal_digest = self.prepare()
        with self.assertRaises(ValueError):
            self.approve(task_id, "wrong-digest")
        self.assertEqual(self.approve(task_id, proposal_digest)["status"], "ready")
        self.assertEqual(self.approve(task_id, proposal_digest)["status"], "ready")
        current = Registry.load(FIXTURE)
        current.applications[self.app]["agents"][0]["instructions"] = "New instructions"
        replacement = ReleaseSnapshot.capture(current, self.app, self.model, self.tools)
        self.assertNotEqual(replacement.digest, self.snapshot.digest)
        self.provision(replacement)
        changed_model = OpenAICompatibleModel("http://127.0.0.1:9/v1", "another-route")
        self.runtime = Runtime(self.store, current, changed_model, self.tools,
                               release_adapters={self.snapshot.digest: (self.model, self.tools)})
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "completed")
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "completed")
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.catalog.select(connection, self.tenant, self.app, self.snapshot.digest, publisher="operator")
        self.assertEqual(self.submit()["id"], task_id)
        with self.control.transaction(tenant=self.tenant) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM effects WHERE operation_id = ?", (task_id,)).fetchone()[0], 1)
            self.assertEqual(connection.execute("SELECT release_digest FROM task_governance WHERE task_id = ?",
                                                (task_id,)).fetchone()[0], self.snapshot.digest)
        evidence = self.api.dispatch("GET", f"/v1/tasks/{task_id}/evidence", "requester", {})
        self.assertEqual(evidence["proposal_digest"], proposal_digest)
        self.assertTrue(evidence["effect_recorded"])
        self.assertNotIn("review", evidence)

    def test_live_revocation_blocks_approved_tasks(self):
        self.provision()
        first, first_proposal = self.prepare("first")
        second, second_proposal = self.prepare("second")
        for task, proposal in ((first, first_proposal), (second, second_proposal)):
            self.approve(task, proposal)
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.policy.revoke(connection, self.tenant, "reviewer", "approve", "task", first)
        self.assertEqual(self.runtime.advance(self.tenant, first)["status"], "blocked")
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.catalog.revoke(connection, self.tenant, self.snapshot.digest, publisher="operator")
        self.assertEqual(self.runtime.advance(self.tenant, second)["status"], "blocked")
        with self.assertRaises(ValueError):
            self.submit("new")
        with self.control.transaction(tenant=self.tenant) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM effects").fetchone()[0], 0)

    def test_revoked_delegate_and_legacy_task_cannot_execute(self):
        legacy = self.runtime.submit(self.tenant, self.app, self.object_id, "requester", "legacy")
        self.provision()
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.grant(connection, "requester", "read", "task", legacy["id"])
            start = datetime.now(timezone.utc)
            scopes = (*self.read_ground_scopes(), ("submit", "app", self.app, None),
                      ("read", "release", self.snapshot.digest, None))
            for scope in scopes:
                self.grant(connection, "service", *scope)
            create_delegation(connection, IdentityContext(self.tenant, "requester", "service", "delegate"),
                              scopes, starts_at=start - timedelta(seconds=2), expires_at=start + timedelta(minutes=5))
        self.assertEqual(self.api.dispatch("GET", f"/v1/tasks/{legacy['id']}", "requester", {})["status"], "planning")
        self.assertEqual(self.runtime.advance(self.tenant, legacy["id"])["status"], "blocked")
        with self.assertRaises(PermissionError):
            self.runtime.submit(self.tenant, self.app, self.object_id, "requester", "bypass")
        task_id, proposal_digest = self.prepare("delegate", "delegate")
        self.approve(task_id, proposal_digest)
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            revoke_delegation(connection, self.tenant, "delegate")
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "blocked")
        with self.assertRaises(PermissionError):
            self.submit("new-delegation", "delegate")

    def test_same_tenant_permissions_hide_task_and_field(self):
        self.provision()
        task = self.submit()
        for task_id in (task["id"], "unknown"):
            with self.assertRaises(PermissionError):
                self.api.dispatch("GET", f"/v1/tasks/{task_id}", "guest", {})
        with self.assertRaises(ValueError):
            self.api.dispatch("POST", "/v1/tasks", "requester", {"tenant": "other", "actor": "reviewer",
                              "application": self.app, "object_id": self.object_id, "request_key": "forged"})
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.grant(connection, "guest", "read", "object", self.object_id)
        result = self.api.dispatch("POST", "/v1/query", "guest", {"object_id": self.object_id})
        self.assertEqual(result["objects"][0]["properties"], {})
        self.assertNotIn("state", result["objects"][0])
        self.assertNotIn("Source fixture", json.dumps(result))
        with self.assertRaises(PermissionError):
            self.api.dispatch("POST", "/v1/query", "guest", {"application": self.app, "object_id": self.object_id})
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.grant(connection, "guest", "read", "app", self.app)
            self.grant(connection, "guest", "read", "release", self.snapshot.digest)
        self.assertEqual(self.api.dispatch("POST", "/v1/query", "guest",
                                          {"application": self.app, "object_id": self.object_id}), result)

    def test_remote_pin_and_lookup_after_revocation(self):
        directory = Path(self.resources.enter_context(tempfile.TemporaryDirectory()))
        remote_db, other_db = directory / "remote.sqlite", directory / "other.sqlite"
        remote = self.resources.enter_context(RemoteFixture(remote_db))
        other = self.resources.enter_context(RemoteFixture(other_db))
        with database(remote_db, write=True) as connection:
            connection.execute("UPDATE remote_objects SET tenant = ?", (self.tenant,))
        self.registry.actions["verify_asset"].update(tool="remote.verify", tool_version="1")
        original, different = ToolRegistry(), ToolRegistry()
        original.register_remote("remote.verify", "1", HttpRemote(remote.endpoint))
        different.register_remote("remote.verify", "1", HttpRemote(other.endpoint))
        self.runtime.tools = original
        snapshot = ReleaseSnapshot.capture(self.registry, self.app, self.model, original)
        self.provision(snapshot, tools=original)
        wrong_id, wrong_proposal = self.prepare("wrong-destination")
        run_id, proposal = self.prepare("remote-operation")
        self.approve(wrong_id, wrong_proposal)
        self.approve(run_id, proposal)
        changed_runtime = Runtime(self.store, self.registry, self.model, different)
        self.assertEqual(changed_runtime.advance(self.tenant, wrong_id)["status"], "blocked")
        self.assertEqual((remote.calls, other.calls), ([], []))

        remote.drop_after_commit = True
        self.assertEqual(self.runtime.advance(self.tenant, run_id)["status"], "reconciling")
        self.assertEqual(remote.object_status(self.tenant), {"state": "verified", "version": 2})
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.catalog.revoke(connection, self.tenant, snapshot.digest, publisher="operator")
        archive = Runtime(self.store, self.registry, OpenAICompatibleModel("http://127.0.0.1:9/v1", "changed"),
                          different, release_adapters={snapshot.digest: (None, original)})
        self.assertEqual(archive.reconcile(self.tenant, run_id)["status"], "completed")
        self.assertEqual(archive.advance(self.tenant, run_id)["status"], "completed")
        self.assertEqual([path for path, _ in remote.calls], ["/execute", "/lookup"])
        self.assertEqual(remote.calls[0][1]["release_digest"], snapshot.digest)
        self.assertEqual(other.calls, [])
        with self.control.transaction(tenant=self.tenant) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM effects").fetchone()[0], 1)

    def test_control_cli_publishes_and_activates(self):
        env = {key: value for key, value in os.environ.items() if not key.startswith("AI_NATIVE_MODEL_")}
        env["AI_NATIVE_POSTGRES_CONTROL_DSN"] = self.control_dsn

        def cli(*args):
            result = subprocess.run([sys.executable, "-B", "-m", "ai_native_system", "--postgres",
                                     "--tenant", self.tenant, *args],
                                    cwd=FIXTURE.parents[1], env=env, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)

        draft = cli("release", "draft", "single", "--actor", "operator")
        digest = draft["digest"]
        self.assertEqual(draft["status"], "draft")
        self.assertIn("classification", cli("release", "impact", digest))
        self.assertEqual(cli("release", "publish", digest, "--actor", "operator")["status"], "published")
        self.assertEqual(cli("release", "select", "single", digest, "--actor", "operator")["digest"], digest)
        self.assertTrue(cli("govern", "grant", "requester", "submit", "app", "single")["changed"])
        self.assertTrue(cli("govern", "activate")["governed"])
        self.assertTrue(cli("govern", "revoke", "requester", "submit", "app", "single")["changed"])

    def test_missing_field_grant_cannot_infer_object_state(self):
        self.provision()
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.policy.revoke(connection, self.tenant, "requester", "read", "metadata", self.object_id, "state")
        with self.assertRaises(PermissionError):
            self.submit("pending-state")
        with self.store.transaction(tenant=self.tenant, write=True) as connection:
            connection.execute("UPDATE objects SET state = ? WHERE id = ?", ("verified", self.object_id))
        with self.assertRaises(PermissionError):
            self.submit("verified-state")

    def test_pinned_task_binding_isolated_and_not_rewritable(self):
        import psycopg

        self.provision()
        task_id = self.submit()["id"]
        for tenant in (None, "other"):
            with self.store.transaction(tenant=tenant) as connection:
                self.assertIsNone(connection.execute("SELECT * FROM task_governance").fetchone())
        with self.store.transaction(tenant=self.tenant) as connection:
            self.assertEqual(connection.execute("SELECT task_id FROM task_governance").fetchone()[0], task_id)
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            with self.store.transaction(tenant=self.tenant, write=True) as connection:
                connection.execute("UPDATE task_governance SET release_digest = ?", ("wrong",))

    def test_runtime_cannot_use_operator_credentials(self):
        from ai_native_system.adapters.postgres import MigrationError

        with self.assertRaises(MigrationError):
            Runtime(self.control, self.registry, self.model, self.tools)


if __name__ == "__main__":
    unittest.main()
