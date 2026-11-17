import multiprocessing
import os
import secrets
import subprocess
import unittest
from copy import deepcopy
from hashlib import sha256
from pathlib import Path

from ai_native_system.adapters.owp import (
    AUTHORIZATION_PROFILE, key_id, load_public_key, sign_authorization, verify_authorization,
)
from ai_native_system.identity import IdentityContext
from ai_native_system.model import DemoModel
from ai_native_system.registry import Registry
from ai_native_system.releases import ReleaseSnapshot, ReleaseStore
from ai_native_system.security import AuthorizationLedger, Verdict
from ai_native_system.storage import encode
from ai_native_system.tools import ToolRegistry


TEST_DSN = os.environ.get("AI_NATIVE_P3_TEST_DSN") or os.environ.get("AI_NATIVE_PG_OWP_LEDGER_TEST_DSN")
CONTAINER = os.environ.get("AI_NATIVE_P3_TEST_CONTAINER")
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "conformance.json"


def fingerprint(label):
    return sha256(label.encode()).hexdigest()


def consume_process(dsn, scope, public_key_pem, epoch, barrier, output):
    from ai_native_system.adapters.postgres_runtime import PostgresRuntimeStore

    try:
        key = load_public_key(public_key_pem)
        ledger = AuthorizationLedger(epoch, lambda envelope: verify_authorization(envelope, {key_id(key): key}))
        with PostgresRuntimeStore(dsn) as store:
            barrier.wait(timeout=8)
            with store.transaction(tenant=scope["tenant"], write=True) as connection:
                decision = ledger.consume(connection, scope["tenant"], scope["operation_id"], scope)
        output.put((os.getpid(), decision.verdict.value, decision.reason))
    except Exception as exc:
        output.put((os.getpid(), "error", type(exc).__name__))


@unittest.skipUnless(TEST_DSN, "Use verify_p3.py for real PostgreSQL tests")
class PostgreSQLAuthorizationLedgerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo

        from ai_native_system.adapters.postgres import migrate_postgres
        from ai_native_system.adapters.postgres_runtime import PostgresRuntimeStore, _Transaction, _row_factory

        cls.store_type = PostgresRuntimeStore
        cls.transaction_type = _Transaction
        cls.row_factory = staticmethod(_row_factory)
        with psycopg.connect(TEST_DSN) as admin:
            admin.execute("CREATE SCHEMA IF NOT EXISTS ai_native")
        migrate_postgres(TEST_DSN)
        ledger_tables = """ON ai_native.owp_task_admissions, ai_native.owp_authorizations,
            ai_native.owp_consumptions, ai_native.owp_revocations, ai_native.owp_enforced_tenants"""
        grants = {
            "runtime": (
                "SELECT " + ledger_tables,
                "SELECT ON ai_native.tasks, ai_native.task_governance",
                "INSERT ON ai_native.owp_task_admissions, ai_native.owp_consumptions",
            ),
            "issuer": (
                "SELECT " + ledger_tables,
                "SELECT ON ai_native.tasks, ai_native.task_governance",
                "INSERT ON ai_native.owp_authorizations",
            ),
            "operator": (
                "SELECT " + ledger_tables,
                "INSERT ON ai_native.owp_revocations, ai_native.owp_enforced_tenants",
            ),
        }
        cls.dsns = {}
        with psycopg.connect(TEST_DSN) as admin:
            for actor, permissions in grants.items():
                role, password = f"owp_{actor}_{secrets.token_hex(5)}", secrets.token_urlsafe(24)
                identifier = sql.Identifier(role)
                admin.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(identifier, sql.Literal(password)))
                admin.execute(sql.SQL("GRANT USAGE ON SCHEMA ai_native TO {}").format(identifier))
                admin.execute(sql.SQL("GRANT SELECT ON ai_native.schema_migrations TO {}").format(identifier))
                for clause in permissions:
                    admin.execute(sql.SQL("GRANT " + clause + " TO {}").format(identifier))
                cls.dsns[actor] = make_conninfo(TEST_DSN, user=role, password=password)

    def setUp(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        self.tenant = "ledger-" + secrets.token_hex(6)
        self.epoch = "original-" + secrets.token_hex(8)
        self.private_key = Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.trusted = {key_id(self.public_key): self.public_key}
        self.ledger = AuthorizationLedger(self.epoch, lambda envelope: verify_authorization(envelope, self.trusted))
        self.runtime = self.enterContext(self.store_type(self.dsns["runtime"]))
        self.issuer = self.enterContext(self.store_type(self.dsns["issuer"]))
        self.operator = self.enterContext(self.store_type(self.dsns["operator"]))
        self.registry = Registry.load(FIXTURE)
        self.release = ReleaseSnapshot.capture(self.registry, "single", DemoModel(), ToolRegistry(),
                                               owp_profile=AUTHORIZATION_PROFILE,
                                               policy_version="test-policy-v1")

    def approved_scope(self, *, remote=False, admitted=True):
        import psycopg

        task_id = secrets.token_hex(16)
        requester = IdentityContext(self.tenant, "requester").as_document()
        approver = IdentityContext(self.tenant, "reviewer").as_document()
        approval_digest = fingerprint(f"approval:{task_id}")
        with psycopg.connect(TEST_DSN, row_factory=self.row_factory) as admin:
            admin.execute("SET LOCAL search_path TO pg_catalog, ai_native")
            admin.execute("SELECT set_config('ai_native.tenant', %s, true)", (self.tenant,))
            connection = self.transaction_type(admin)
            ReleaseStore.draft(connection, self.tenant, self.release, publisher="test-operator")
            connection.execute(
                """INSERT INTO tasks
                   (tenant,id,application,object_id,requester,request_key,definition_hash,status,approver,approval_hash)
                   VALUES (?,?,?,?,?,?,?,'ready',?,?)""",
                (self.tenant, task_id, "single", "asset-1", "requester", task_id, self.release.definition_hash,
                 "reviewer", approval_digest),
            )
            connection.execute(
                """INSERT INTO task_governance (tenant,task_id,release_digest,requester_context,approver_context)
                   VALUES (?,?,?,?,?)""",
                (self.tenant, task_id, self.release.digest, encode(requester), encode(approver)),
            )
        if admitted:
            with self.runtime.transaction(tenant=self.tenant, write=True) as connection:
                self.assertTrue(self.ledger.admit(connection, self.tenant, task_id))
        return {
            "tenant": self.tenant, "task_id": task_id, "operation_id": task_id, "action_instance_id": task_id,
            "release_digest": self.release.digest, "ontology_digest": self.release.ontology().digest,
            "policy_version": "test-policy-v1", "rule_versions": {"verify_asset": 1},
            "rule_proof_digest": fingerprint("proof"), "fact_read_set_digest": fingerprint("read-set"),
            "requester": requester, "approver": approver, "executor": "worker", "approval_digest": approval_digest,
            "action": "verify_asset", "action_version": 1, "action_kind": "write_remote" if remote else "write_local",
            "targets": [{"type": "asset", "id": "asset-1"}],
            "reads": [{"kind": "object", "resource_id": "asset-1", "member": None}],
            "writes": [{"kind": "metadata", "resource_id": "asset-1", "member": "state"}],
            "parameters_digest": fingerprint(f"payload:{task_id}"),
            "tool": {"name": "state.transition", "version": "1",
                     "destination_digest": fingerprint("destination") if remote else None},
        }

    def signed(self, scope, *, nonce=None, starts=-1, ends=120, epoch=None, signing_key=None):
        with self.issuer.transaction(tenant=self.tenant) as connection:
            now = int(connection.database_time())
        return sign_authorization({
            "profile": AUTHORIZATION_PROFILE, "nonce": nonce or secrets.token_hex(20),
            "epoch": epoch or self.epoch, "issued_at": now + starts, "expires_at": now + ends,
            "scope": scope,
        }, self.private_key if signing_key is None else signing_key)

    def issue(self, scope, envelope):
        with self.issuer.transaction(tenant=self.tenant, write=True) as connection:
            return self.ledger.issue(connection, envelope, scope)

    def check(self, scope):
        with self.runtime.transaction(tenant=self.tenant) as connection:
            return self.ledger.check(connection, self.tenant, scope["operation_id"], scope)

    def consume(self, scope, *, remote=False, request_digest=None):
        with self.runtime.transaction(tenant=self.tenant, write=True) as connection:
            return self.ledger.consume(connection, self.tenant, scope["operation_id"], scope,
                                       remote=remote, request_digest=request_digest)

    def test_scope_and_approval_validation_then_single_use(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        scope = self.approved_scope()
        envelope = self.signed(scope)
        self.assertEqual(self.check(scope).verdict, Verdict.MANUAL)
        self.assertEqual(self.issue(scope, self.signed(scope, signing_key=Ed25519PrivateKey.generate())).verdict, Verdict.DENY)
        forged = deepcopy(scope)
        forged["approval_digest"] = fingerprint("different actual approval")
        self.assertEqual(self.issue(forged, self.signed(forged)).reason, "approval_binding_changed")
        self.assertTrue(self.issue(scope, envelope).allowed)
        self.assertTrue(self.issue(scope, envelope).allowed)
        for field, replacement in (
            ("parameters_digest", fingerprint("replaced-parameters")),
            ("rule_proof_digest", fingerprint("new-proof")),
            ("fact_read_set_digest", fingerprint("new-read-set")),
            ("targets", [{"type": "asset", "id": "asset-substitute"}]),
            ("reads", [{"kind": "object", "resource_id": "other", "member": None}]),
        ):
            tampered = {**scope, field: replacement}
            self.assertEqual(self.check(tampered).reason, "scope_changed")
        self.assertEqual(self.consume(scope, request_digest=fingerprint("not-bound")).reason, "request_digest_changed")
        self.assertEqual(self.consume(scope, remote=True).reason, "dispatch_mode_changed")
        self.assertTrue(self.consume(scope).allowed)
        self.assertEqual(self.consume(scope).reason, "nonce_already_consumed")

    def test_expiry_revocation_and_key_removal_block_new_dispatch(self):
        scope = self.approved_scope()
        for start, end in ((-10, -5), (10, 15)):
            self.assertEqual(self.issue(scope, self.signed(scope, starts=start, ends=end)).reason,
                             "authorization_outside_validity")
        self.assertTrue(self.issue(scope, self.signed(scope)).allowed)
        self.assertTrue(self.check(scope).allowed)
        original_keys = dict(self.trusted)
        self.trusted.clear()
        self.assertEqual(self.check(scope).reason, "invalid_authorization")
        self.trusted.update(original_keys)
        with self.operator.transaction(tenant=self.tenant, write=True) as connection:
            self.assertTrue(self.ledger.revoke(connection, self.tenant, scope["operation_id"],
                                               actor="operator", reason="Authority withdrawn"))
            self.assertFalse(self.ledger.revoke(connection, self.tenant, scope["operation_id"],
                                                actor="operator", reason="duplicate"))
        self.assertEqual(self.consume(scope).reason, "authorization_revoked")

    def test_nonce_cannot_be_registered_for_second_operation(self):
        scoped, different = self.approved_scope(), self.approved_scope()
        nonce = secrets.token_hex(24)
        self.assertTrue(self.issue(scoped, self.signed(scoped, nonce=nonce)).allowed)
        self.assertEqual(self.issue(different, self.signed(different, nonce=nonce)).reason,
                         "operation_or_nonce_already_registered")
        self.assertEqual(self.check(different).verdict, Verdict.MANUAL)

    def test_remote_unknown_allows_bound_lookup_only_across_epoch(self):
        scope = self.approved_scope(remote=True)
        before_admit = self.approved_scope(admitted=False)
        envelope = self.signed(scope)
        operation = scope["operation_id"]
        request = scope["parameters_digest"]
        self.assertTrue(self.issue(scope, envelope).allowed)
        self.assertTrue(self.consume(scope, remote=True, request_digest=request).allowed)
        self.assertEqual(self.consume(scope, remote=True).reason, "lookup_only")
        with self.operator.transaction(tenant=self.tenant, write=True) as connection:
            self.ledger.revoke(connection, self.tenant, operation, actor="operator", reason="Disabled since dispatch")
        after_restore = AuthorizationLedger("restored-" + secrets.token_hex(8),
                                            lambda auth: verify_authorization(auth, self.trusted))
        revived = self.signed(before_admit, epoch=after_restore.epoch)
        with self.issuer.transaction(tenant=self.tenant, write=True) as connection:
            self.assertEqual(after_restore.issue(connection, revived, before_admit).reason, "restore_epoch_changed")
        with self.runtime.transaction(tenant=self.tenant, write=True) as connection:
            self.assertFalse(after_restore.eligible(connection, self.tenant, scope["task_id"]))
            self.assertFalse(after_restore.admit(connection, self.tenant, scope["task_id"]))
            decision = after_restore.consume(connection, self.tenant, operation, scope, remote=True, request_digest=request)
            self.assertEqual(decision.reason, "restore_epoch_changed")
            self.assertTrue(after_restore.recover(connection, self.tenant, operation, request).allowed)
            self.assertFalse(after_restore.recover(connection, self.tenant, operation, fingerprint("different")).allowed)
            self.assertEqual(after_restore.authorization_digest(connection, self.tenant, operation), envelope["digest"])

    @unittest.skipUnless(CONTAINER, "Snapshot restore requires the disposable Compose container")
    def test_actual_backup_before_dispatch_and_revocation_cannot_reenable_authority(self):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import conninfo_to_dict, make_conninfo

        scope = self.approved_scope(remote=True)
        op_id, request_digest = scope["operation_id"], scope["parameters_digest"]
        envelope = self.signed(scope)
        self.assertTrue(self.issue(scope, envelope).allowed)
        source = conninfo_to_dict(TEST_DSN)
        archive = subprocess.check_output(
            ["docker", "exec", CONTAINER, "pg_dump", "-U", source["user"], "-d", source["dbname"],
             "--format=custom", "--schema=ai_native"], timeout=25,
        )
        self.assertTrue(self.consume(scope, remote=True, request_digest=request_digest).allowed)
        with self.operator.transaction(tenant=self.tenant, write=True) as connection:
            self.assertTrue(self.ledger.revoke(connection, self.tenant, op_id,
                                               actor="operator", reason="Withdrawn after backup"))

        restored_db = "p3_restore_" + secrets.token_hex(6)
        with psycopg.connect(TEST_DSN, autocommit=True) as admin:
            admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(restored_db)))
        try:
            subprocess.run(
                ["docker", "exec", "-i", CONTAINER, "pg_restore", "-U", source["user"], "-d", restored_db,
                 "--single-transaction", "--exit-on-error", "--no-owner"], input=archive, timeout=25, check=True,
            )
            restored_ledger = AuthorizationLedger("restored-" + secrets.token_hex(8),
                                                  lambda auth: verify_authorization(auth, self.trusted))
            with self.store_type(make_conninfo(self.dsns["runtime"], dbname=restored_db)) as restored:
                with restored.transaction(tenant=self.tenant, write=True) as connection:
                    self.assertIsNone(self.ledger.authorization_digest(connection, self.tenant, op_id))
                    self.assertTrue(self.ledger.check(connection, self.tenant, op_id, scope).allowed)
                    decision = restored_ledger.consume(connection, self.tenant, op_id, scope, remote=True,
                                                       request_digest=request_digest)
                    self.assertEqual(decision.reason, "restore_epoch_changed")
                    self.assertFalse(restored_ledger.recover(connection, self.tenant, op_id, request_digest).allowed)
                with restored.transaction(tenant=self.tenant) as connection:
                    self.assertEqual(connection.execute("SELECT count(*) FROM owp_consumptions").fetchone()[0], 0)
        finally:
            with psycopg.connect(TEST_DSN, autocommit=True) as admin:
                admin.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(restored_db)))

    def test_rls_and_distinct_operator_issuer_runtime_roles(self):
        import psycopg

        scope = self.approved_scope()
        self.assertTrue(self.issue(scope, self.signed(scope)).allowed)
        for tenant in (None, "another-" + self.tenant):
            with self.runtime.transaction(tenant=tenant) as connection:
                self.assertIsNone(connection.execute("SELECT operation_id FROM owp_authorizations").fetchone())
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            with self.runtime.transaction(tenant=self.tenant, write=True) as connection:
                self.ledger.revoke(connection, self.tenant, scope["operation_id"], actor="runtime", reason="Forbidden")
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            with self.issuer.transaction(tenant=self.tenant, write=True) as connection:
                self.ledger.consume(connection, self.tenant, scope["operation_id"], scope)
        with self.assertRaises(psycopg.errors.CheckViolation):
            with psycopg.connect(TEST_DSN) as owner:
                owner.execute("UPDATE ai_native.owp_authorizations SET nonce = 'reset' WHERE tenant = %s", (self.tenant,))

    def test_separate_processes_race_and_only_one_consumes_the_nonce(self):
        from cryptography.hazmat.primitives import serialization

        scope = self.approved_scope()
        self.assertTrue(self.issue(scope, self.signed(scope)).allowed)
        key_pem = self.public_key.public_bytes(serialization.Encoding.PEM,
                                               serialization.PublicFormat.SubjectPublicKeyInfo)
        spawn = multiprocessing.get_context("spawn")
        output = spawn.Queue()
        barrier = spawn.Barrier(2)
        children = [
            spawn.Process(target=consume_process, args=(self.dsns["runtime"], scope, key_pem, self.epoch, barrier, output))
            for _ in range(2)
        ]
        try:
            for process in children:
                process.start()
            results = [output.get(timeout=12) for _ in children]
        finally:
            for process in children:
                if process.pid is not None:
                    process.join(3)
                    if process.is_alive():
                        process.terminate()
                        process.join(3)
            output.close()
            output.join_thread()
        self.assertEqual(len({pid for pid, _, _ in results}), 2)
        self.assertCountEqual([(verdict, reason) for _, verdict, reason in results],
                              [("allow", "authorized"), ("deny", "nonce_already_consumed")])
