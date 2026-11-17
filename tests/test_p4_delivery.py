import importlib.util
import os
import secrets
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from ai_native_system.delivery import (
    ProofStore, ProofUnavailable, claim_delivery, deliver_attestation, delivery_status,
    enqueue_delivery, finish_delivery, has_delivery_lease, publish_proof, read_proof,
    repair_proof, run_delivery_batch,
)
from ai_native_system.storage import encode

from p2b_support import restricted_role


TEST_DSN = os.environ.get("AI_NATIVE_P4_TEST_DSN")
OWP_AVAILABLE = importlib.util.find_spec("openworkproof") is not None


class ProofFilesTests(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(TemporaryDirectory()))
        self.archive = ProofStore(self.directory / "proofs")

    def test_content_addresses_and_verified_separate_namespaces(self):
        raw = b'{"private":"value"}'
        fingerprint = sha256(raw).hexdigest()
        self.assertEqual(self.archive.put("tenant", "raw", raw), fingerprint)
        self.assertEqual(self.archive.put("tenant", "raw", raw), fingerprint)
        self.assertEqual(self.archive.read("tenant", "raw", fingerprint), raw)
        for tenant, view in (("tenant", "redacted"), ("other", "raw")):
            with self.assertRaises(ProofUnavailable):
                self.archive.read(tenant, view, fingerprint)
        with self.assertRaises(ValueError):
            self.archive.read("tenant", "raw", "../../escape")
        with self.assertRaises(ValueError):
            self.archive.read("tenant", "../raw", fingerprint)

    def test_refuses_symlink_directories_and_repairs_leaf_without_following_it(self):
        root = self.archive.root
        tenant = root / sha256(b"tenant").hexdigest()
        tenant.mkdir()
        external = self.directory / "external"
        external.mkdir()
        outside = external / "outside"
        outside.write_bytes(b"do not touch")
        (tenant / "raw").symlink_to(external, target_is_directory=True)
        with self.assertRaises(ProofUnavailable):
            self.archive.put("tenant", "raw", b"proof", repair=True)
        (tenant / "raw").unlink()
        (tenant / "raw").mkdir()
        content = b"proof"
        digest = sha256(content).hexdigest()
        candidate = tenant / "raw" / f"{digest}.json"
        candidate.symlink_to(outside)
        with self.assertRaises(ProofUnavailable):
            self.archive.read("tenant", "raw", digest)
        with self.assertRaises(ProofUnavailable):
            self.archive.put("tenant", "raw", content)
        self.archive.put("tenant", "raw", content, repair=True)
        self.assertFalse(candidate.is_symlink())
        self.assertEqual(candidate.read_bytes(), content)
        self.assertEqual(outside.read_bytes(), b"do not touch")


@unittest.skipUnless(TEST_DSN, "Run the P4 PostgreSQL verification runner")
class PostgresDeliveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from ai_native_system.adapters.postgres import migrate_postgres
        from ai_native_system.adapters.postgres_runtime import PostgresRuntimeStore

        migrate_postgres(TEST_DSN)
        producer = restricted_role((
            "SELECT, INSERT ON ai_native.tasks, ai_native.effects, ai_native.owp_effect_evidence",
            "SELECT, INSERT ON ai_native.p4_delivery_jobs, ai_native.p4_proof_records",
        ), TEST_DSN)
        worker = restricted_role((
            "SELECT ON ai_native.p4_delivery_jobs",
            "SELECT, INSERT ON ai_native.p4_proof_records",
            "UPDATE (status, attempts, next_attempt_at, last_claimed_at, lease_token, lease_expires_at, "
            "lease_manual, last_error) ON ai_native.p4_delivery_jobs",
        ), TEST_DSN)
        attester = restricted_role((
            "SELECT ON ai_native.owp_effect_evidence",
            "UPDATE (attempts, last_error, signed_document, delivered_at) ON ai_native.owp_effect_evidence",
        ), TEST_DSN)
        reader = restricted_role((
            "SELECT (tenant, operation_id, kind, redacted_digest) ON ai_native.p4_proof_records",
        ), TEST_DSN)
        cls.producer = cls.enterClassContext(PostgresRuntimeStore(producer))
        cls.worker = cls.enterClassContext(PostgresRuntimeStore(worker))
        cls.attester = cls.enterClassContext(PostgresRuntimeStore(attester))
        cls.reader = cls.enterClassContext(PostgresRuntimeStore(reader))

    def setUp(self):
        self.tenant = "p4-delivery-" + secrets.token_hex(6)
        self.task = "delivery-task-" + secrets.token_hex(6)
        self.archive = ProofStore(self.enterContext(TemporaryDirectory()))
        with self.producer.transaction(tenant=self.tenant, write=True) as connection:
            connection.execute(
                """INSERT INTO tasks (id, tenant, application, object_id, requester, request_key, definition_hash, status)
                   VALUES (?, ?, 'single', 'resource', 'operator', 'request', 'definition', 'ready')""",
                (self.task, self.tenant),
            )

    def enqueue(self, operation, *, kind="reconcile", scope="scope-a", max_attempts=8):
        with self.producer.transaction(tenant=self.tenant, write=True) as connection:
            return enqueue_delivery(connection, tenant=self.tenant, task_id=self.task, operation_id=operation,
                                    kind=kind, scope=scope, max_attempts=max_attempts)

    def status(self, operation, kind="reconcile"):
        with self.worker.transaction(tenant=self.tenant) as connection:
            return delivery_status(connection, self.tenant, operation, kind)

    def retime(self, operation, *, lease_expired=False):
        field = "lease_expires_at" if lease_expired else "next_attempt_at"
        with self.worker.transaction(tenant=self.tenant, write=True) as connection:
            connection.execute(
                f"UPDATE p4_delivery_jobs SET {field} = clock_timestamp() - interval '1 hour' WHERE operation_id = ?",
                (operation,),
            )

    def test_enqueue_is_atomic_and_unique_with_tenant_scope(self):
        with self.assertRaisesRegex(RuntimeError, "commit failure"):
            with self.producer.transaction(tenant=self.tenant, write=True) as connection:
                enqueue_delivery(connection, tenant=self.tenant, task_id=self.task, operation_id="roundtrip",
                                 kind="reconcile", scope="scope-a")
                raise RuntimeError("commit failure")
        self.assertIsNone(self.status("roundtrip"))
        self.assertTrue(self.enqueue("roundtrip"))
        self.assertFalse(self.enqueue("roundtrip"))
        with self.assertRaisesRegex(ValueError, "different work"):
            self.enqueue("roundtrip", scope="scope-b")
        self.assertTrue(self.enqueue("roundtrip", kind="evidence"))
        with self.worker.transaction(tenant="foreign") as connection:
            self.assertIsNone(delivery_status(connection, self.tenant, "roundtrip", "reconcile"))

    def test_worker_limits_scope_tenant_and_spacing(self):
        for operation, scope in (("a", "same-tool"), ("b", "same-tool"), ("c", "different-tool")):
            self.enqueue(operation, scope=scope)
        with ThreadPoolExecutor(max_workers=5) as threads:
            futures = [threads.submit(claim_delivery, self.worker, self.tenant, "reconcile", active_limit=2)
                       for _ in range(5)]
            leases = [item for future in futures if (item := future.result())]
        self.assertEqual(len(leases), 2)
        self.assertEqual({lease.scope for lease in leases}, {"same-tool", "different-tool"})
        for lease in leases:
            self.assertEqual(finish_delivery(self.worker, lease, "done"), "completed")
        self.assertIsNone(claim_delivery(self.worker, self.tenant, "reconcile", scope_interval_seconds=60))
        self.assertIsNotNone(claim_delivery(self.worker, self.tenant, "reconcile", scope_interval_seconds=0))

    def test_backoff_exhaustion_and_unaffected_destination_progress(self):
        self.enqueue("unavailable", scope="offline-tool", max_attempts=2)
        self.enqueue("available", scope="working-tool")
        calls = []

        def handler(lease):
            calls.append(lease.operation_id)
            if lease.operation_id == "unavailable":
                raise OSError("secret transport details")
            return "done"

        self.assertEqual(run_delivery_batch(self.worker, self.tenant, "reconcile", handler, limit=2), [
            {"operation_id": "unavailable", "status": "queued"},
            {"operation_id": "available", "status": "completed"},
        ])
        self.assertEqual(self.status("unavailable")["last_error"], "transient")
        self.assertIsNone(claim_delivery(self.worker, self.tenant, "reconcile", scope_interval_seconds=0))
        self.retime("unavailable")
        self.assertEqual(run_delivery_batch(self.worker, self.tenant, "reconcile", handler, limit=2,
                                            scope_interval_seconds=0), [
            {"operation_id": "unavailable", "status": "manual"},
        ])
        self.assertEqual(calls, ["unavailable", "available", "unavailable"])
        self.assertEqual(self.status("unavailable")["last_error"], "retry_limit")
        self.assertIsNone(claim_delivery(self.worker, self.tenant, "reconcile", scope_interval_seconds=0))

    def test_after_a_crash_old_lease_cannot_finish_or_call_lookup(self):
        self.enqueue("interrupted", max_attempts=2)
        old = claim_delivery(self.worker, self.tenant, "reconcile")
        with self.worker.transaction(tenant=self.tenant) as connection:
            self.assertTrue(has_delivery_lease(connection, old, self.tenant, self.task, "interrupted", "reconcile"))
            self.assertFalse(has_delivery_lease(connection, old, self.tenant, self.task, "other", "reconcile"))
            self.assertFalse(has_delivery_lease(connection, replace(old, token="fake"), self.tenant, self.task,
                                                "interrupted", "reconcile"))
        self.retime("interrupted", lease_expired=True)
        self.assertIsNone(finish_delivery(self.worker, old, "done"))
        resumed = claim_delivery(self.worker, self.tenant, "reconcile", scope_interval_seconds=0)
        self.assertNotEqual(old.token, resumed.token)
        self.assertEqual(resumed.attempts, 2)
        self.assertIsNone(finish_delivery(self.worker, old, "done"))
        self.retime("interrupted", lease_expired=True)
        self.assertIsNone(claim_delivery(self.worker, self.tenant, "reconcile", scope_interval_seconds=0))
        self.assertEqual(self.status("interrupted")["status"], "manual")

    def test_named_manual_lease_can_query_without_replenishing_auto_attempts(self):
        self.enqueue("review", max_attempts=1)
        self.assertIsNone(claim_delivery(self.worker, self.tenant, "reconcile", manual_operation_id="review"))
        automatic = claim_delivery(self.worker, self.tenant, "reconcile")
        self.assertEqual(finish_delivery(self.worker, automatic, "retry"), "manual")
        manual = claim_delivery(self.worker, self.tenant, "reconcile", manual_operation_id="review",
                                scope_interval_seconds=0)
        self.assertTrue(manual.manual)
        self.assertEqual(manual.attempts, automatic.attempts)
        with self.worker.transaction(tenant=self.tenant) as connection:
            self.assertTrue(has_delivery_lease(connection, manual, self.tenant, self.task, "review", "reconcile"))
        self.assertEqual(finish_delivery(self.worker, manual, "retry"), "manual")
        self.assertIsNone(claim_delivery(self.worker, self.tenant, "reconcile", scope_interval_seconds=0))
        operator = claim_delivery(self.worker, self.tenant, "reconcile", manual_operation_id="review",
                                  scope_interval_seconds=0)
        self.assertEqual(finish_delivery(self.worker, operator, "done"), "completed")
        self.assertEqual(self.status("review")["attempts"], 1)

    def publish(self, raw, redacted, store=None):
        return publish_proof(store or self.worker, self.archive, tenant=self.tenant, task_id=self.task,
                             operation_id="source-operation", kind="source_receipt", raw=raw, redacted=redacted)

    def test_archive_reference_read_access_and_restore_from_database(self):
        import psycopg

        raw = {"payload": {"credit": 8}, "signature": "fake test bytes"}
        redacted = {"status": "succeeded", "operation_id": "source-operation"}
        refs = self.publish(raw, redacted)
        self.assertEqual(self.publish(raw, redacted), refs)
        self.assertEqual(read_proof(self.reader, self.archive, self.tenant, "source-operation", "source_receipt"),
                         redacted)
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            read_proof(self.reader, self.archive, self.tenant, "source-operation", "source_receipt", view="raw")
        with self.assertRaises(LookupError):
            read_proof(self.reader, self.archive, "foreign", "source-operation", "source_receipt")
        self.assertEqual(read_proof(self.worker, self.archive, self.tenant, "source-operation", "source_receipt",
                                    view="raw"), raw)
        raw_file, = self.archive.root.glob(f"*/raw/{refs['raw_digest']}.json")
        for simulate_failure in (raw_file.unlink, lambda: raw_file.write_bytes(b"corrupt")):
            simulate_failure()
            with self.assertRaises(ProofUnavailable):
                read_proof(self.worker, self.archive, self.tenant, "source-operation", "source_receipt", view="raw")
            self.assertEqual(repair_proof(self.worker, self.archive, self.tenant, "source-operation", "source_receipt",
                                          view="raw"), refs["raw_digest"])
            self.assertEqual(raw_file.read_bytes(), encode(raw).encode("utf-8"))
        with self.assertRaisesRegex(ValueError, "already points"):
            self.publish({"different": True}, redacted)

    def test_files_can_be_reused_after_database_registration_rolls_back(self):
        underlying = self.worker

        class InterruptCommit:
            @contextmanager
            def transaction(self, *, tenant, write=False):
                with underlying.transaction(tenant=tenant, write=write) as connection:
                    yield connection
                    raise RuntimeError("registration rollback")

        raw, redacted = {"signature": "fixture"}, {"status": "complete"}
        with self.assertRaisesRegex(RuntimeError, "registration rollback"):
            self.publish(raw, redacted, store=InterruptCommit())
        expected_files = list(self.archive.root.glob("*/*/*.json"))
        self.assertEqual(len(expected_files), 2)
        with self.assertRaises(LookupError):
            read_proof(self.reader, self.archive, self.tenant, "source-operation", "source_receipt")
        self.publish(raw, redacted)
        self.assertEqual(set(self.archive.root.glob("*/*/*.json")), set(expected_files))

    def test_disk_failure_leaves_only_orphan_raw_bytes_and_no_reference(self):
        raw, redacted = {"signature": "fixture"}, {"status": "complete"}
        available = self.archive.put

        def fail_redacted(tenant, view, document, **kwargs):
            if view == "redacted":
                raise OSError("simulated storage outage")
            return available(tenant, view, document, **kwargs)

        with patch.object(self.archive, "put", side_effect=fail_redacted):
            with self.assertRaisesRegex(OSError, "storage outage"):
                self.publish(raw, redacted)
        self.assertEqual(len(list(self.archive.root.glob("*/*/*.json"))), 1)
        with self.assertRaises(LookupError):
            read_proof(self.reader, self.archive, self.tenant, "source-operation", "source_receipt")
        self.publish(raw, redacted)
        self.assertEqual(len(list(self.archive.root.glob("*/*/*.json"))), 2)

    @unittest.skipUnless(OWP_AVAILABLE, "Requires pinned OpenWorkProof")
    def test_attestation_work_survives_signer_and_file_failure_without_second_effect(self):
        import psycopg
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from ai_native_system.adapters.owp import key_id
        from ai_native_system.evidence import enqueue_effect, sign_effect, verify_effect

        with psycopg.connect(TEST_DSN) as admin:
            admin.execute("INSERT INTO ai_native.owp_task_admissions(tenant, task_id, epoch) VALUES (%s, %s, 'epoch')",
                          (self.tenant, self.task))
            admin.execute(
                """INSERT INTO ai_native.owp_authorizations
                   (tenant, operation_id, task_id, epoch, nonce, authorization_digest, request_digest,
                    issued_at, expires_at, envelope) VALUES (%s, %s, %s, 'epoch', 'fixture', %s, %s, 10, 20, '{}')""",
                (self.tenant, self.task, self.task, "a" * 64, "b" * 64),
            )
            admin.execute(
                """INSERT INTO ai_native.owp_consumptions
                   (tenant, operation_id, nonce, authorization_digest, request_digest, remote)
                   VALUES (%s, %s, 'fixture', %s, %s, false)""", (self.tenant, self.task, "a" * 64, "b" * 64),
            )
        effect = {"state": "verified", "private": "keep outside proof"}
        with self.producer.transaction(tenant=self.tenant, write=True) as connection:
            connection.execute("INSERT INTO effects VALUES (?, 'verify_asset', 'resource', ?)",
                               (self.task, encode(effect)))
            enqueue_effect(connection, tenant=self.tenant, task_id=self.task, operation_id=self.task,
                           authorization_digest="a" * 64, result=effect, observation="local_transaction")
        self.enqueue(self.task, kind="evidence")
        private = Ed25519PrivateKey.generate()
        public = private.public_key()
        keys = {key_id(public): public}

        def unavailable(_body):
            raise OSError("temporary signer unavailability")

        def sign(body):
            return sign_effect(body, private)

        def work(lease, signer):
            return deliver_attestation(self.attester, self.archive, self.tenant, self.task, lease.operation_id,
                                       signer, keys, archive_store=self.worker)

        self.assertEqual(run_delivery_batch(self.worker, self.tenant, "evidence",
                                            lambda lease: work(lease, unavailable))[0]["status"], "queued")
        self.retime(self.task)
        self.assertEqual(run_delivery_batch(self.worker, self.tenant, "evidence", lambda lease: work(lease, sign),
                                            scope_interval_seconds=0)[0]["status"], "completed")
        proof, = self.archive.root.glob("*/raw/*.json")
        proof.unlink()
        self.assertEqual(deliver_attestation(self.attester, self.archive, self.tenant, self.task, self.task,
                                             unavailable, keys, archive_store=self.worker), "done")
        raw = read_proof(self.worker, self.archive, self.tenant, self.task, "runtime_attestation", view="raw")
        self.assertEqual(verify_effect(raw, keys)["operation_id"], self.task)
        redacted = read_proof(self.reader, self.archive, self.tenant, self.task, "runtime_attestation")
        self.assertNotIn("signature", redacted)
        self.assertNotIn(effect["private"], encode(redacted))
        with self.producer.transaction(tenant=self.tenant) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM effects").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
