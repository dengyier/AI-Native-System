import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from ai_native_system.adapters.owp import key_id, sign_authorization, verify_authorization
from ai_native_system.evidence import deliver_effect, pending_effects, sign_effect, verify_effect
from ai_native_system.owp_gate import PROFILE, enforce
from ai_native_system.releases import ReleaseSnapshot, ReleaseStore
from ai_native_system.runtime import Runtime
from ai_native_system.security import AuthorizationLedger
from p2b_support import restricted_role
from test_p2b_workflow import FactWorkflowFixture


TEST_DSN = os.environ.get("AI_NATIVE_P3_TEST_DSN")


class SecureWorkflowFixture(FactWorkflowFixture):
    test_dsn = TEST_DSN
    owp_profile = PROFILE
    runtime_grants = (
        "INSERT ON ai_native.owp_task_admissions, ai_native.owp_consumptions, ai_native.owp_effect_evidence",
    )
    control_grants = (
        "INSERT ON ai_native.owp_revocations, ai_native.owp_enforced_tenants",
        "DELETE ON ai_native.resource_grants",
    )
    issuer_grants = (
        "SELECT ON ALL TABLES IN SCHEMA ai_native",
        "INSERT ON ai_native.owp_authorizations",
    )

    def make_model(self):
        from ai_native_system.gateway import ModelGateway
        from ai_native_system.model import DemoModel

        gateway = ModelGateway(default="default", max_context_bytes=65536)
        gateway.register("default", DemoModel())
        return gateway

    def make_ledgers(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        self.private_key = Ed25519PrivateKey.generate()
        public = self.private_key.public_key()
        self.trusted_keys = {key_id(public): public}
        self.ledger = self.ledger_at("deployment-1")
        return {self.tenant: self.ledger}

    def ledger_at(self, epoch):
        return AuthorizationLedger(epoch, lambda envelope: verify_authorization(envelope, self.trusted_keys))

    def signing_request(self, task_id):
        with self.store.transaction(tenant=self.tenant) as connection:
            return self.runtime.authorization_request(connection, self.tenant, task_id)

    def sign(self, request):
        now = int(time.time())
        return sign_authorization({**request, "nonce": uuid4().hex, "issued_at": now - 1, "expires_at": now + 120},
                                  self.private_key)

    def register(self, task_id, envelope):
        issuer = self.enterContext(self.store_type(self.issuer_dsn))
        with issuer.transaction(tenant=self.tenant, write=True) as connection:
            current = self.runtime.authorization_request(connection, self.tenant, task_id)
            return self.ledger.issue(connection, envelope, current["scope"])

    def authorize(self, task_id):
        envelope = self.sign(self.signing_request(task_id))
        self.assertTrue(self.register(task_id, envelope).allowed)
        return envelope

    def restarted(self, epoch):
        return Runtime(self.store, self.registry, self.runtime.model, self.runtime.tools,
                       owp_ledgers={self.tenant: self.ledger_at(epoch)})

    def counts(self):
        with self.store.transaction(tenant=self.tenant) as connection:
            return tuple(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                         for table in ("effects", "owp_consumptions", "owp_effect_evidence"))


@unittest.skipUnless(TEST_DSN, "Use verify_p3.py for real PostgreSQL tests")
class LocalSecurityTests(SecureWorkflowFixture, unittest.TestCase):
    tool_remote = False

    def test_signed_approval_tool_and_evidence_survive_restarts_without_replay(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        with patch.object(self.runtime.model, "propose", wraps=self.runtime.model.propose) as propose:
            task_id = self.approved()
        context = propose.call_args.args[0]
        self.assertNotIn("_owp_rule", context)
        self.assertNotIn("_fact_fingerprint", context)
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["authorization"]["verdict"], "manual")
        envelope = self.authorize(task_id)
        with self.assertRaises(TimeoutError):
            self.runtime.advance(self.tenant, task_id, "before-commit")
        self.assertEqual(self.counts(), (0, 0, 0))
        fresh = self.restarted("deployment-1")
        with ThreadPoolExecutor(max_workers=2) as worker:
            futures = [worker.submit(fresh.advance, self.tenant, task_id) for _ in range(2)]
            self.assertEqual([future.result()["status"] for future in futures], ["completed", "completed"])
        self.assertEqual(self.counts(), (1, 1, 1))
        response = fresh.inspect(self.tenant, task_id, identity=self.identity["requester"], evidence=True)
        self.assertEqual(response["owp_evidence"], "pending")

        evidence_dsn = restricted_role((
            "SELECT ON ai_native.owp_effect_evidence",
            "UPDATE (signed_document, delivered_at, attempts, last_error) ON ai_native.owp_effect_evidence",
        ), self.test_dsn)
        evidence_store = self.enterContext(self.store_type(evidence_dsn))
        attest_key = Ed25519PrivateKey.generate()
        public_key = attest_key.public_key()
        evidence_trust = {key_id(public_key): public_key}

        def unavailable(_body):
            raise OSError("test signer unavailable")

        self.assertEqual(deliver_effect(evidence_store, self.tenant, task_id, unavailable, evidence_trust)["status"],
                         "pending")
        self.assertEqual(len(pending_effects(evidence_store, self.tenant)), 1)
        result = deliver_effect(evidence_store, self.tenant, task_id, lambda body: sign_effect(body, attest_key),
                                evidence_trust)
        proof = verify_effect(result["proof"], evidence_trust)
        self.assertEqual(proof["authorization_digest"], envelope["digest"])
        self.assertEqual(proof["observation"], "local_transaction")
        self.assertEqual(pending_effects(evidence_store, self.tenant), ())
        self.assertEqual(self.counts(), (1, 1, 1))

    def test_owp_release_publish_requires_a_fact_rule(self):
        snapshot = ReleaseSnapshot.capture(
            self.registry, "single", self.runtime.model, self.runtime.tools,
            owp_profile=PROFILE, policy_version="next-policy",
        )
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            ReleaseStore.draft(connection, self.tenant, snapshot, publisher="operator")
            with self.assertRaisesRegex(ValueError, "requires a bound fact rule"):
                ReleaseStore.publish(connection, self.tenant, snapshot.digest, publisher="operator")

    def test_old_epoch_planner_cannot_send_model_context(self):
        task_id = self.runtime.submit(self.tenant, "single", self.object.object_id, "requester", "stale-planner",
                                      identity=self.identity["requester"])["id"]
        restarted = self.restarted("deployment-2")
        with patch.object(restarted.model, "propose", wraps=restarted.model.propose) as propose:
            self.assertEqual(restarted.advance(self.tenant, task_id)["status"], "blocked")
        propose.assert_not_called()
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_valid_signature_on_changed_scope_does_not_authorize(self):
        task_id = self.approved()
        request = self.signing_request(task_id)
        wrong = deepcopy(request)
        wrong["scope"]["parameters_digest"] = "0" * 64
        decision = self.register(task_id, self.sign(wrong))
        self.assertEqual((decision.verdict, decision.reason), ("deny", "scope_changed"))
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["authorization"]["verdict"], "manual")
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_revocation_while_ready_prevents_effect(self):
        task_id = self.approved()
        self.authorize(task_id)
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.assertTrue(self.ledger.revoke(connection, self.tenant, task_id, actor="operator", reason="Cancelled"))
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "blocked")
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_changed_read_set_prevents_effect_even_when_rule_is_still_true(self):
        task_id = self.approved()
        self.authorize(task_id)
        self.deliver("quality", self.quality(True))
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "blocked")
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_lost_resource_permission_prevents_effect(self):
        from ai_native_system.policy import Policy

        task_id = self.approved()
        self.authorize(task_id)
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            Policy().revoke(connection, self.tenant, "reviewer", "read", "field", self.object.object_id, "checksum_ok")
        with self.assertRaises(PermissionError):
            self.signing_request(task_id)
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "blocked")
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_rule_only_field_requires_resource_permission(self):
        from ai_native_system.fact_contracts import FactField, FieldAuthority
        from ai_native_system.fact_gate import bind_rule
        from ai_native_system.ontology import OntologyRelease

        ontology = self.registry.ontology(namespace="p3-field-scope").to_document()
        ontology["types"]["asset"]["properties"]["risk_score"] = {"type": "integer", "required": False}
        ontology["rules"]["verify_asset"]["conditions"].append({"property": "risk_score", "operator": "eq", "value": 5})
        snapshot = ReleaseSnapshot.capture(
            self.registry, "single", self.runtime.model, self.runtime.tools,
            ontology=OntologyRelease.from_document(ontology), owp_profile=PROFILE,
        )
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            field = FactField(self.object, "risk_score")
            self.facts.set_authority(connection, FieldAuthority(field, ("quality",), 1),
                                     actor="operator", reason="Declared rule input")
            ReleaseStore.draft(connection, self.tenant, snapshot, publisher="operator")
            bind_rule(connection, self.tenant, snapshot.digest, "verify_asset", actor="operator")
            ReleaseStore.publish(connection, self.tenant, snapshot.digest, publisher="operator", migration_ref="P3 rule")
            ReleaseStore.select(connection, self.tenant, "single", snapshot.digest, publisher="operator")
            self.grant(connection, "requester", "read", "release", snapshot.digest)
        payload = self.quality(True)
        payload["properties"]["risk_score"] = 5
        self.deliver("quality", payload)
        with patch.object(self.runtime.model, "propose", wraps=self.runtime.model.propose) as propose:
            with self.assertRaises(PermissionError):
                self.runtime.submit(self.tenant, "single", self.object.object_id, "requester", "scoped",
                                    identity=self.identity["requester"])
        propose.assert_not_called()
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            for actor in ("requester", "worker", "reviewer"):
                self.grant(connection, actor, "read", "field", self.object.object_id, "risk_score")
        task_id = self.approved("permitted")
        request = self.signing_request(task_id)
        self.assertIn({"kind": "field", "resource_id": self.object.object_id, "member": "risk_score"},
                      request["scope"]["reads"])
        self.authorize(task_id)
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "completed")
        self.assertEqual(self.counts(), (1, 1, 1))

    def test_distinct_cli_request_sign_register_executes_on_normal_entry(self):
        from cryptography.hazmat.primitives import serialization

        task_id = self.approved()
        directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        private_file, public_file, config_file = (directory / name for name in ("authority.pem", "public.pem", "trust.json"))
        private_file.write_bytes(self.private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
        ))
        public_file.write_bytes(self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
        config_file.write_text(json.dumps({self.tenant: {"epoch": self.ledger.epoch, "public_keys": [str(public_file)]}}))
        env = {name: value for name, value in os.environ.items() if not name.startswith("AI_NATIVE_MODEL_")}
        env.update(AI_NATIVE_OWP_TRUST=str(config_file), AI_NATIVE_POSTGRES_DSN=self.runtime_dsn,
                   AI_NATIVE_OWP_ISSUER_DSN=self.issuer_dsn)

        def cli(*args, environment=env):
            result = subprocess.run([sys.executable, "-B", "-m", "ai_native_system", "--postgres",
                                     "--tenant", self.tenant, *args], cwd=Path(__file__).resolve().parents[1],
                                    env=environment, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)

        request_file = directory / "request.json"
        request_file.write_text(json.dumps(cli("owp", "request", task_id)))
        independent = {name: value for name, value in env.items() if not name.endswith("_DSN")}
        signed_file = directory / "authorization.json"
        signed_file.write_text(json.dumps(cli("owp", "sign", str(request_file), "--key-file", str(private_file),
                                              environment=independent)))
        self.assertEqual(cli("owp", "register", str(signed_file))["verdict"], "allow")
        self.assertEqual(cli("advance", task_id)["status"], "completed")
        self.assertEqual(self.counts(), (1, 1, 1))

    def test_read_only_endpoint_cannot_start_a_worker(self):
        from psycopg.conninfo import make_conninfo
        from psycopg_pool import PoolTimeout

        dsn = make_conninfo(self.runtime_dsn, options="-c default_transaction_read_only=on")
        with self.assertRaises(PoolTimeout), self.store_type(dsn, timeout=0.5):
            self.fail("An authorization runtime cannot use read-only connections")

    def test_legacy_release_cannot_bypass_enforced_tenant(self):
        old = ReleaseSnapshot.capture(self.registry, "single", self.runtime.model, self.runtime.tools)
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            ReleaseStore.draft(connection, self.tenant, old, publisher="operator")
            ReleaseStore.publish(connection, self.tenant, old.digest, publisher="operator")
            self.grant(connection, "requester", "read", "release", old.digest)
            enforce(connection, self.tenant)
        old_worker = Runtime(self.store, self.registry, self.runtime.model, self.runtime.tools)
        with self.assertRaises(PermissionError):
            old_worker.submit(self.tenant, "single", self.object.object_id, "requester", "old-release",
                              identity=self.identity["requester"], release_digest=old.digest)
        self.assertEqual(self.counts(), (0, 0, 0))


@unittest.skipUnless(TEST_DSN, "Use verify_p3.py for real PostgreSQL tests")
class RemoteSecurityTests(SecureWorkflowFixture, unittest.TestCase):
    def test_lost_reply_can_recover_with_prior_scope_after_revocation_and_epoch_change(self):
        task_id = self.approved()
        self.authorize(task_id)
        self.remote.drop_after_commit = True
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "reconciling")
        self.assertEqual(self.counts(), (0, 1, 0))
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.assertTrue(self.ledger.revoke(connection, self.tenant, task_id, actor="operator", reason="Recalled"))
        restarted = self.restarted("deployment-2")
        self.assertEqual(restarted.reconcile(self.tenant, task_id)["status"], "completed")
        self.assertEqual(self.counts(), (1, 1, 1))
        self.assertEqual([path for path, _ in self.remote.calls], ["/execute", "/lookup"])

    def test_unknown_after_dispatch_does_not_replay_even_if_provider_reports_absent(self):
        task_id = self.approved()
        self.authorize(task_id)
        self.remote.drop_before_commit = True
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "reconciling")
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.grant(connection, "requester", "retry", "task", task_id)
            self.grant(connection, "requester", "reconcile", "task", task_id)
            self.grant(connection, "requester", "advance", "task", task_id)
        task = self.runtime.retry_remote(self.tenant, task_id, "requester", identity=self.identity["requester"])
        self.assertEqual(task["authorization"], {"verdict": "manual", "reason": "lookup_only"})
        self.assertEqual(self.counts(), (0, 1, 0))
        self.assertEqual([path for path, _ in self.remote.calls], ["/execute", "/lookup"])

    def test_changed_historical_payload_cannot_project_an_old_signed_receipt(self):
        from ai_native_system.remote_execution import operation, record_response
        from ai_native_system.storage import encode

        task_id = self.approved()
        self.authorize(task_id)
        self.remote.drop_after_commit = True
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "reconciling")
        response, = self.remote.operation_states()
        with self.store.transaction(tenant=self.tenant, write=True) as connection:
            prior = operation(connection, task_id)
            forged = {**prior["payload"], "object_id": "asset-stale"}
            connection.execute("UPDATE remote_operations SET payload = ? WHERE operation_id = ?",
                               (encode(forged), task_id))
        with self.assertRaisesRegex(ValueError, "does not match"):
            self.runtime.reconcile(self.tenant, task_id)
        with self.assertRaisesRegex(ValueError, "does not match"):
            record_response(self.runtime, self.tenant, task_id, response, "lookup")
        self.assertEqual([path for path, _ in self.remote.calls], ["/execute"])
        self.assertEqual(self.counts(), (0, 1, 0))

    def test_prepared_operation_from_old_epoch_remains_manual_without_dispatch(self):
        task_id = self.approved()
        self.authorize(task_id)
        task, wrote = self.runtime._execute(self.tenant, task_id, None)
        self.assertEqual((task["status"], wrote), ("reconciling", False))
        result = self.restarted("deployment-2").advance(self.tenant, task_id)
        self.assertEqual(result["authorization"], {"verdict": "manual", "reason": "restore_epoch_changed"})
        self.assertEqual(self.remote.calls, [])
        self.assertEqual(self.counts(), (0, 0, 0))
