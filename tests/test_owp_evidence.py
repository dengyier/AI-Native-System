import importlib.util
import json
import os
import secrets
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

from ai_native_system.evidence import (
    deliver_effect, enqueue_effect, evidence_status, pending_effects, sign_effect, verify_effect,
)
from ai_native_system.storage import digest, encode


OWP_AVAILABLE = importlib.util.find_spec("openworkproof") is not None
TEST_DSN = os.environ.get("AI_NATIVE_P3_TEST_DSN")
AUTH_DIGEST = "9" * 64
RESULT = {"state": "verified", "version": 2, "private_detail": "only in the stored tool receipt"}


@unittest.skipUnless(OWP_AVAILABLE, "Install locked OpenWorkProof integration dependency")
class EffectEvidenceProfileTests(unittest.TestCase):
    def setUp(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from ai_native_system.adapters.owp import key_id

        self.key = Ed25519PrivateKey.generate()
        self.trust = {key_id(self.key.public_key()): self.key.public_key()}
        other_key = Ed25519PrivateKey.generate().public_key()
        self.other_trust = {key_id(other_key): other_key}
        self.body = {
            "profile": "ai-native-action/effect-evidence/v0.1", "tenant": "test",
            "task_id": "task-1", "operation_id": "operation-1",
            "authorization_digest": AUTH_DIGEST, "result_digest": digest(RESULT),
            "observation": "remote_receipt_observed", "recorded_at": "2026-11-17T09:00:00.000000Z",
        }

    def test_tampering_and_wrong_attestation_trust_fail(self):
        envelope = sign_effect(self.body, self.key)
        self.assertEqual(verify_effect(envelope, self.trust), self.body)
        for field in ("task_id", "operation_id", "authorization_digest", "result_digest", "observation"):
            tampered = {**envelope, "payload": {**self.body, field: "changed"}}
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify_effect(tampered, self.trust)
        with self.assertRaises(ValueError):
            verify_effect(envelope, self.other_trust)

    def test_effect_signature_cannot_transfer_across_domains(self):
        from openworkproof.signing import sign_payload, verify_payload

        from ai_native_system.adapters.owp import sign_profile

        envelope = sign_effect(self.body, self.key)
        stock = sign_payload("action-receipt", self.body, self.key, version="0.1")
        self.assertFalse(verify_payload("action-receipt", envelope, self.key.public_key(), version="0.1"))
        with self.assertRaises(ValueError):
            verify_effect(stock, self.trust)
        wrong_domain = sign_profile(self.body, self.key, domain=b"ai-native-action/authorization/v0.1\x00",
                                    substrate="action-receipt")
        with self.assertRaises(ValueError):
            verify_effect(wrong_domain, self.trust)

    def test_profile_does_not_allow_extra_fields_or_noncanonical_times(self):
        from jsonschema import Draft202012Validator

        schema_file = Path(__file__).resolve().parents[1] / "schemas/ai-native-action-v0.1/effect-evidence.json"
        schema = json.loads(schema_file.read_text())
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)
        validator.validate(sign_effect(self.body, self.key))
        with self.assertRaises(ValueError):
            sign_effect({**self.body, "tool_result": RESULT}, self.key)
        with self.assertRaises(ValueError):
            sign_effect({**self.body, "recorded_at": "2026-11-17T09:00:00+00:00"}, self.key)


@unittest.skipUnless(TEST_DSN and OWP_AVAILABLE, "Run the OpenWorkProof PostgreSQL verification runner")
class PostgresEffectEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo

        from ai_native_system.adapters.postgres import migrate_postgres
        from ai_native_system.adapters.postgres_runtime import PostgresRuntimeStore

        migrate_postgres(TEST_DSN)
        suffix = secrets.token_hex(6)
        producer, attester = f"evidence_producer_{suffix}", f"evidence_attester_{suffix}"
        password = secrets.token_urlsafe(24)
        with psycopg.connect(TEST_DSN) as admin:
            for role in (producer, attester):
                name = sql.Identifier(role)
                admin.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(name, sql.Literal(password)))
                admin.execute(sql.SQL("GRANT USAGE ON SCHEMA ai_native TO {}").format(name))
                admin.execute(sql.SQL("""
                    GRANT SELECT ON ai_native.schema_migrations, ai_native.owp_effect_evidence TO {}
                """).format(name))
            admin.execute(sql.SQL("""
                GRANT SELECT ON ai_native.tasks, ai_native.effects TO {};
                GRANT INSERT ON ai_native.tasks, ai_native.effects, ai_native.owp_effect_evidence TO {}
            """).format(sql.Identifier(producer), sql.Identifier(producer)))
            admin.execute(sql.SQL("""
                GRANT UPDATE (attempts, last_error, signed_document, delivered_at)
                  ON ai_native.owp_effect_evidence TO {}
            """).format(sql.Identifier(attester)))
        cls.producer = cls.enterClassContext(PostgresRuntimeStore(make_conninfo(TEST_DSN, user=producer, password=password)))
        cls.attester = cls.enterClassContext(PostgresRuntimeStore(make_conninfo(TEST_DSN, user=attester, password=password)))

    def setUp(self):
        import psycopg
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from ai_native_system.adapters.owp import key_id

        self.tenant = "evidence-" + secrets.token_hex(6)
        self.operation_id = "operation-" + secrets.token_hex(6)
        self.key = Ed25519PrivateKey.generate()
        self.trust = {key_id(self.key.public_key()): self.key.public_key()}
        with self.producer.transaction(tenant=self.tenant, write=True) as connection:
            connection.execute(
                """INSERT INTO tasks (id, tenant, application, object_id, requester, request_key, definition_hash, status)
                   VALUES (?, ?, 'single', 'resource', 'operator', 'request', 'definition', 'ready')""",
                (self.operation_id, self.tenant),
            )
        with psycopg.connect(TEST_DSN) as admin:
            admin.execute("INSERT INTO ai_native.owp_task_admissions (tenant, task_id, epoch) VALUES (%s, %s, 'live')",
                          (self.tenant, self.operation_id))
            admin.execute(
                """INSERT INTO ai_native.owp_authorizations
                   (tenant, operation_id, task_id, epoch, nonce, authorization_digest, request_digest,
                    issued_at, expires_at, envelope)
                   VALUES (%s, %s, %s, 'live', 'evidence-test-nonce', %s, %s, 100, 500, '{}')""",
                (self.tenant, self.operation_id, self.operation_id, AUTH_DIGEST, "f" * 64),
            )
            admin.execute(
                """INSERT INTO ai_native.owp_consumptions
                   (tenant, operation_id, nonce, authorization_digest, request_digest, remote)
                   VALUES (%s, %s, 'evidence-test-nonce', %s, %s, false)""",
                (self.tenant, self.operation_id, AUTH_DIGEST, "f" * 64),
            )

    def _insert_effect(self, connection):
        connection.execute(
            "INSERT INTO effects VALUES (?, 'verify_asset', 'resource', ?)",
            (self.operation_id, encode(RESULT)),
        )

    def _enqueue(self, connection, result=RESULT, authorization_digest=AUTH_DIGEST):
        return enqueue_effect(
            connection, tenant=self.tenant, task_id=self.operation_id, operation_id=self.operation_id,
            authorization_digest=authorization_digest, result=result, observation="local_transaction",
        )

    def _record(self):
        with self.producer.transaction(tenant=self.tenant, write=True) as connection:
            self._insert_effect(connection)
            return self._enqueue(connection)

    def _stored(self):
        with self.attester.transaction(tenant=self.tenant) as connection:
            return connection.execute(
                "SELECT attempts, last_error, signed_document FROM owp_effect_evidence WHERE operation_id = ?",
                (self.operation_id,),
            ).fetchone()

    def _deliver(self, signer):
        return deliver_effect(self.attester, self.tenant, self.operation_id, signer, self.trust)

    def _sign(self, body):
        return sign_effect(body, self.key)

    def test_effect_queue_is_atomic_and_cannot_bind_changed_facts(self):
        import psycopg

        with self.assertRaises(psycopg.errors.ForeignKeyViolation):
            with self.producer.transaction(tenant=self.tenant, write=True) as connection:
                self._insert_effect(connection)
                self._enqueue(connection, authorization_digest="a" * 64)
        with self.assertRaisesRegex(ValueError, "does not match"):
            with self.producer.transaction(tenant=self.tenant, write=True) as connection:
                self._insert_effect(connection)
                self._enqueue(connection, {"state": "forged"})
        with self.assertRaisesRegex(RuntimeError, "abort effect"):
            with self.producer.transaction(tenant=self.tenant, write=True) as connection:
                self._insert_effect(connection)
                self._enqueue(connection)
                raise RuntimeError("abort effect")
        with self.producer.transaction(tenant=self.tenant) as connection:
            self.assertIsNone(evidence_status(connection, self.tenant, self.operation_id))
            self.assertEqual(connection.execute("SELECT count(*) FROM effects").fetchone()[0], 0)
        body = self._record()
        self.assertEqual(body["result_digest"], digest(RESULT))
        with self.producer.transaction(tenant=self.tenant, write=True) as connection:
            self.assertEqual(self._enqueue(connection), body)
            with self.assertRaisesRegex(ValueError, "already bound"):
                self._enqueue(connection, authorization_digest="a" * 64)
        with self.attester.transaction(tenant="foreign") as connection:
            self.assertIsNone(evidence_status(connection, self.tenant, self.operation_id))

    def test_signer_failure_resumes_without_replaying_effect(self):
        original = self._record()

        def unavailable(_):
            raise TimeoutError("private signing service details")

        self.assertEqual(self._deliver(unavailable), {"status": "pending"})
        self.assertEqual(tuple(self._stored()), (1, "signer_unavailable", None))
        self.assertEqual(pending_effects(self.attester, self.tenant), (
            {"operation_id": self.operation_id, "attempts": 1, "last_error": "signer_unavailable"},
        ))
        proof = self._deliver(self._sign)
        self.assertEqual(proof["status"], "delivered")
        self.assertEqual(verify_effect(proof["proof"], self.trust), original)
        self.assertNotIn(RESULT["private_detail"], json.dumps(proof))
        self.assertEqual(self._deliver(self._sign), proof)
        self.assertEqual(self._stored()[0], 2)
        self.assertEqual(pending_effects(self.attester, self.tenant), ())
        with self.producer.transaction(tenant=self.tenant) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM effects").fetchone()[0], 1)

    def test_signer_must_return_the_exact_queued_facts(self):
        self._record()
        result = self._deliver(lambda body: self._sign({**body, "authorization_digest": "b" * 64}))
        self.assertEqual(result, {"status": "pending"})
        self.assertEqual(tuple(self._stored()), (1, "invalid_proof", None))
        self.assertEqual(self._deliver(self._sign)["status"], "delivered")

    def test_concurrent_signers_register_one_proof(self):
        self._record()
        barrier = Barrier(2)

        def concurrent_signer(body):
            barrier.wait(timeout=4)
            return self._sign(body)

        with ThreadPoolExecutor(max_workers=2) as workers:
            one, two = [workers.submit(self._deliver, concurrent_signer) for _ in range(2)]
            self.assertEqual(one.result(timeout=8), two.result(timeout=8))
        self.assertEqual(self._stored()[0], 1)
        self.assertEqual(verify_effect(json.loads(self._stored()[2]), self.trust)["operation_id"], self.operation_id)

    def test_roles_cannot_change_the_fact_or_already_delivered_proof(self):
        import psycopg

        self._record()
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            with self.producer.transaction(tenant=self.tenant, write=True) as connection:
                connection.execute("UPDATE owp_effect_evidence SET attempts = 1")
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            with self.attester.transaction(tenant=self.tenant, write=True) as connection:
                connection.execute("UPDATE owp_effect_evidence SET authorization_digest = ?", ("b" * 64,))
        proof = self._deliver(self._sign)
        with self.assertRaises(psycopg.errors.CheckViolation):
            with self.attester.transaction(tenant=self.tenant, write=True) as connection:
                connection.execute("UPDATE owp_effect_evidence SET attempts = attempts + 1")
        self.assertEqual(self._deliver(self._sign), proof)
