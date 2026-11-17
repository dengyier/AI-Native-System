import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from functools import partial
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from ai_native_system.action_sequence import create_sequence, link_compensation, sequence_status
from ai_native_system.adapters.owp import key_id
from ai_native_system.delivery import ProofStore, claim_delivery, delivery_status, read_proof, repair_proof, run_delivery_batch
from ai_native_system.p4_execution import evidence_job, reconcile_job
from ai_native_system.source_receipt import verify_source_receipt
from ai_native_system.storage import digest
from ai_native_system.tools import configured_tools
from p2b_support import restricted_role
from test_security_entry import SecureWorkflowFixture


FRAMEWORK_DSN = os.environ.get("AI_NATIVE_P4_TEST_DSN")
SOURCE_DSN = os.environ.get("AI_NATIVE_P4_SOURCE_TEST_DSN")
CONTAINER = os.environ.get("AI_NATIVE_P4_TEST_CONTAINER")
ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(FRAMEWORK_DSN and SOURCE_DSN, "Use verify_p4.py for P4 workflow tests")
class P4WorkflowTests(SecureWorkflowFixture, unittest.TestCase):
    test_dsn = FRAMEWORK_DSN
    checksum_source = "inventory"
    runtime_grants = SecureWorkflowFixture.runtime_grants + (
        "INSERT ON ai_native.p4_delivery_jobs",
        "UPDATE (expected_source_version) ON ai_native.fact_feedback_expectations",
    )
    control_grants = SecureWorkflowFixture.control_grants + (
        "INSERT ON ai_native.p4_sequences, ai_native.p4_sequence_steps, ai_native.p4_compensations",
    )

    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo

        from ai_native_system.source_write import initialize_source

        super().setUpClass()
        initialize_source(SOURCE_DSN)
        with psycopg.connect(SOURCE_DSN) as admin:
            suffix = uuid4().hex[:10]
            writer, reader = "source_write_" + suffix, "source_lookup_" + suffix
            password = uuid4().hex
            for role in (writer, reader):
                admin.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(sql.Identifier(role), sql.Literal(password)))
                admin.execute(sql.SQL("GRANT USAGE ON SCHEMA p4_source TO {}").format(sql.Identifier(role)))
                admin.execute(sql.SQL("GRANT SELECT ON p4_source.receipts TO {}").format(sql.Identifier(role)))
            admin.execute(sql.SQL("GRANT SELECT, UPDATE ON p4_source.objects TO {}").format(sql.Identifier(writer)))
            admin.execute(sql.SQL("GRANT INSERT ON p4_source.receipts TO {}").format(sql.Identifier(writer)))
        cls.source_writer = make_conninfo(SOURCE_DSN, user=writer, password=password)
        cls.source_reader = make_conninfo(SOURCE_DSN, user=reader, password=password)
        cls.delivery_dsn = restricted_role((
            "SELECT ON ai_native.p4_delivery_jobs, ai_native.p4_proof_records",
            "INSERT ON ai_native.p4_proof_records",
            """UPDATE (status, attempts, next_attempt_at, last_claimed_at, lease_token,
                       lease_expires_at, last_error, lease_manual) ON ai_native.p4_delivery_jobs""",
        ), FRAMEWORK_DSN)
        cls.attester_dsn = restricted_role((
            "SELECT ON ai_native.owp_effect_evidence",
            "UPDATE (signed_document, delivered_at, attempts, last_error) ON ai_native.owp_effect_evidence",
        ), FRAMEWORK_DSN)

    @staticmethod
    def inventory(state):
        return {"state": state, "properties": {"label": "Inventory", "checksum_ok": True}, "relations": []}

    def make_tools(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from ai_native_system.source_write import seed_source_object
        from p4_source_server import EXECUTE_TOOL, LOOKUP_TOOL, tool_schema_pins

        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        source_key = Ed25519PrivateKey.generate()
        public = source_key.public_key()
        self.source_keys = {key_id(public): public}
        source_public = self.directory / "source-public.pem"
        source_public.write_bytes(public.public_bytes(serialization.Encoding.PEM,
                                                      serialization.PublicFormat.SubjectPublicKeyInfo))
        key_path = self.directory / "source.pem"
        key_path.write_bytes(source_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                      serialization.NoEncryption()))
        authority = self.directory / "authority.pem"
        authority.write_bytes(self.private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
        with socket.socket() as stream:
            stream.bind(("127.0.0.1", 0))
            self.port = stream.getsockname()[1]
        pins = tool_schema_pins()
        execute_token, lookup_token = uuid4().hex, uuid4().hex
        self.registry.actions["verify_asset"].update(tool="source.verify", tool_version="1")
        config = {"tools": [{
            "name": "source.verify", "version": "1", "transport": "mcp-sdk-http",
            "endpoint": f"http://127.0.0.1:{self.port}/mcp", "execute_tool": EXECUTE_TOOL,
            "lookup_tool": LOOKUP_TOOL, "execute_schema_digest": pins[EXECUTE_TOOL],
            "lookup_schema_digest": pins[LOOKUP_TOOL], "token_env": "P4_FIXTURE_EXECUTE_TOKEN",
            "lookup_token_env": "P4_FIXTURE_LOOKUP_TOKEN", "idempotent": True,
            "source": {"source": "inventory", "lookup_principal": "source-lookup", "retention_seconds": 1,
                       "receipt_public_keys": [str(source_public)]},
        }]}
        with patch.dict(os.environ, P4_FIXTURE_EXECUTE_TOKEN=execute_token, P4_FIXTURE_LOOKUP_TOKEN=lookup_token):
            tools = configured_tools(config)
        tool = tools.resolve(self.registry.actions["verify_asset"])
        self.binding = tool.source
        self.source_config = self.directory / "source.json"
        self.source_config.write_text(json.dumps({
            "tenant": self.tenant, "source": "inventory", "dsn": self.source_writer,
            "lookup_dsn": self.source_reader, "destination_digest": digest(tool.identity),
            "port": self.port, "epoch": self.ledger.epoch, "retention_seconds": self.binding.retention_seconds,
            "authority_public_keys": [str(authority)], "signing_key": str(key_path),
            "execute_token": execute_token, "lookup_token": lookup_token,
            "actions": {"verify_asset": {"version": 1, "object_type": "asset", "from_state": "pending",
                                         "to_state": "verified", "max_targets": 1}},
            **{name + "_file": str(self.directory / name) for name in
               ("drop_after_commit", "fail_lookup", "tamper_lookup")},
        }))
        seed_source_object(SOURCE_DSN, self.tenant, record_type="record", record_id="inventory-ref",
                           object_type="asset", object_id="asset-1", state="pending", version="v1")
        self.start_source()
        return tools

    def start_source(self):
        process = subprocess.Popen(
            [sys.executable, "-B", str(ROOT / "tests/p4_source_server.py")], cwd=ROOT,
            env={**os.environ, "AI_NATIVE_P4_SOURCE_CONFIG": str(self.source_config)},
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        self.source_process = process
        self.addCleanup(self.stop_source, process)
        deadline = time.monotonic() + 7
        while time.monotonic() < deadline and process.poll() is None:
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.03)
        self.fail(f"Independent source MCP server did not start (exit {process.poll()})")

    @staticmethod
    def stop_source(process):
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)

    def setUp(self):
        super().setUp()
        self.delivery = self.enterContext(self.store_type(self.delivery_dsn))
        self.attester = self.enterContext(self.store_type(self.attester_dsn))

    def native(self):
        import psycopg

        with psycopg.connect(SOURCE_DSN) as connection:
            item = connection.execute("SELECT state, version FROM p4_source.objects WHERE tenant=%s AND object_id='asset-1'",
                                      (self.tenant,)).fetchone()
            count = connection.execute("SELECT count(*) FROM p4_source.receipts WHERE tenant=%s", (self.tenant,)).fetchone()[0]
        return item, count

    def perturb_native(self, version):
        import psycopg

        with psycopg.connect(SOURCE_DSN) as connection:
            connection.execute("UPDATE p4_source.objects SET version=%s::jsonb WHERE tenant=%s AND object_id='asset-1'",
                               (json.dumps(version), self.tenant))

    def due(self, operation_id, kind, *, last_attempt=False):
        import psycopg

        with psycopg.connect(FRAMEWORK_DSN) as connection:
            connection.execute("""UPDATE ai_native.p4_delivery_jobs SET next_attempt_at=clock_timestamp(),
                last_claimed_at=NULL, max_attempts=CASE WHEN %s THEN attempts+1 ELSE max_attempts END
                WHERE tenant=%s AND operation_id=%s AND kind=%s""", (last_attempt, self.tenant, operation_id, kind))

    def queue_status(self, task_id, kind):
        with self.delivery.transaction(tenant=self.tenant) as connection:
            return delivery_status(connection, self.tenant, task_id, kind)

    def stored(self, task_id):
        from ai_native_system.remote_execution import operation

        with self.store.transaction(tenant=self.tenant) as connection:
            return operation(connection, task_id)

    def process_reconciliation(self):
        return run_delivery_batch(self.delivery, self.tenant, "reconcile", partial(reconcile_job, self.runtime), limit=1)

    def test_conditional_stale_source_never_changes_effect(self):
        task_id = self.approved()
        authorization = self.authorize(task_id)
        self.perturb_native("native-changed-after-local-approval")
        task = self.runtime.advance(self.tenant, task_id)
        self.assertEqual(task["status"], "failed")
        self.assertEqual(self.native(), (("pending", "native-changed-after-local-approval"), 1))
        self.assertEqual(self.counts(), (0, 1, 0))
        op = self.stored(task_id)
        proof = verify_source_receipt(op["response"], self.source_keys, operation=op["payload"],
                                      authorization_digest=authorization["digest"])
        self.assertEqual(proof["reason"], "condition_mismatch")

    def test_two_source_to_signed_receipt_and_evidence_after_real_server_crash(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        from ai_native_system.evidence import sign_effect, verify_effect

        task_id = self.approved()
        signed_gate = self.authorize(task_id)
        (self.directory / "drop_after_commit").touch()
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "reconciling")
        self.source_process.wait(timeout=5)
        (state, version), count = self.native()
        self.assertEqual((state, count), ("verified", 1))
        self.assertNotEqual(version, "v1")
        self.assertEqual(self.runtime.reconcile(self.tenant, task_id)["authorization"]["reason"], "reconciliation_queued")
        self.assertEqual(self.counts(), (0, 1, 0))
        self.start_source()

        (self.directory / "fail_lookup").touch()
        self.assertEqual(self.process_reconciliation()[0]["status"], "queued")
        self.due(task_id, "reconcile")
        (self.directory / "tamper_lookup").touch()
        self.assertEqual(self.process_reconciliation()[0]["status"], "queued")
        self.assertEqual(self.counts(), (0, 1, 0))
        self.due(task_id, "reconcile")
        self.assertEqual(self.process_reconciliation()[0]["status"], "completed")
        self.assertEqual(self.counts(), (1, 1, 1))
        op = self.stored(task_id)
        proof = verify_source_receipt(op["response"], self.source_keys, operation=op["payload"],
                                      authorization_digest=signed_gate["digest"])
        self.assertEqual(proof["result"]["objects"][0]["version"], version)

        # The second source contributed its own assertions; source write guards
        # use inventory only, because that source can lock every rule dependency.
        from ai_native_system.fact_contracts import FactField
        with self.store.transaction(tenant=self.tenant) as connection:
            history = self.facts.history(connection, FactField(self.object, "checksum_ok"))
        self.assertEqual({row["source"]["source"] for row in history}, {"quality", "inventory"})

        from dataclasses import replace
        event = self.event("inventory", 2, self.inventory("verified"), task_id)
        event = replace(event, version=replace(event.version, token=version))
        self.assertEqual(self.sync["inventory"].apply(event, position=2, predecessor=self.cursor("inventory", 1)).status,
                         "applied")
        self.assertEqual(self.feedback(task_id), ("matched", True))

        archive = ProofStore(self.directory / "proofs")
        signing_key = Ed25519PrivateKey.generate()
        public = signing_key.public_key()
        trust = {key_id(public): public}

        def unavailable(_body):
            raise OSError("Independent attester offline")

        def deliver(signer):
            handler = partial(evidence_job, self.runtime, self.delivery, archive, signer=signer, keys=trust,
                              attester_store=self.attester)
            return run_delivery_batch(self.delivery, self.tenant, "evidence", handler, limit=1)[0]["status"]

        self.assertEqual(deliver(unavailable), "queued")
        self.assertEqual(self.counts(), (1, 1, 1))
        raw = read_proof(self.delivery, archive, self.tenant, task_id, "source_receipt", view="raw")
        self.assertEqual(raw, op["response"])
        self.assertNotIn("signature", read_proof(self.delivery, archive, self.tenant, task_id, "source_receipt"))
        self.due(task_id, "evidence")
        self.assertEqual(deliver(partial(sign_effect, private_key=signing_key)), "completed")
        attested = read_proof(self.delivery, archive, self.tenant, task_id, "runtime_attestation", view="raw")
        self.assertEqual(verify_effect(attested, trust)["authorization_digest"], signed_gate["digest"])
        shutil.rmtree(self.directory / "proofs")
        archive = ProofStore(self.directory / "proofs")
        repair_proof(self.delivery, archive, self.tenant, task_id, "source_receipt", view="raw")
        self.assertEqual(read_proof(self.delivery, archive, self.tenant, task_id, "source_receipt", view="raw"), raw)
        self.assertEqual(self.native(), (("verified", version), 1))
        different = self.event("inventory", 3, self.inventory("verified"), task_id)
        self.assertEqual(self.sync["inventory"].apply(different, position=3, predecessor=self.cursor("inventory", 2)).status,
                         "applied")
        self.assertEqual(self.feedback(task_id), ("conflict", True))
        self.assertEqual(self.counts(), (1, 1, 1))

    def test_partial_sequence_retains_first_effect_and_compensation_is_unexecuted(self):
        first, second = self.approved("first"), self.approved("second")
        for task_id in (first, second):
            self.authorize(task_id)
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            sequence = create_sequence(connection, self.tenant, [first, second])
        waiting = self.runtime.advance(self.tenant, second)
        self.assertEqual(waiting["authorization"]["reason"], "prior_action_incomplete")
        self.assertEqual(self.runtime.advance(self.tenant, first)["status"], "completed")
        self.assertEqual(self.runtime.advance(self.tenant, second)["status"], "blocked")
        with self.control.transaction(tenant=self.tenant) as connection:
            summary = sequence_status(connection, self.tenant, sequence)
        self.assertEqual(summary["status"], "partial")
        self.assertEqual([step["effect_recorded"] for step in summary["steps"]], [True, False])
        compensation = self.runtime.submit(self.tenant, "single", self.object.object_id, "requester", "compensation",
                                           identity=self.identity["requester"])["id"]
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            link_compensation(connection, self.tenant, first, compensation)
        self.assertEqual(self.counts(), (1, 1, 1))

    def test_cross_source_dependencies_require_manual_decision(self):
        from ai_native_system.fact_contracts import FactField, FieldAuthority
        from ai_native_system.fact_gate import bind_rule
        from ai_native_system.releases import ReleaseSnapshot, ReleaseStore

        alternate = ReleaseSnapshot.capture(self.registry, "single", self.runtime.model, self.runtime.tools,
                                           owp_profile=self.owp_profile, policy_version="another-policy")
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            ReleaseStore.draft(connection, self.tenant, alternate, publisher="operator")
            with self.assertRaisesRegex(ValueError, "conditional write authority"):
                bind_rule(connection, self.tenant, alternate.digest, "verify_asset", actor="operator",
                          feedback_source="quality", feedback_stream="main")
            self.facts.set_authority(connection, FieldAuthority(FactField(self.object, "checksum_ok"), ("quality",), 2),
                                     expected=1, actor="operator", reason="Independent authority")
        task_id = self.approved()
        with self.assertRaises(PermissionError):
            self.signing_request(task_id)
        decision = self.runtime.advance(self.tenant, task_id)
        self.assertEqual(decision["authorization"], {"verdict": "manual", "reason": "source_guards_unavailable"})
        self.assertEqual(self.native(), (("pending", "v1"), 0))
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_hidden_and_changed_relationship_members_cannot_authorize(self):
        from datetime import timedelta

        from ai_native_system.fact_contracts import (
            Coverage, FactField, FieldAuthority, IdentityMapping, ObjectIdentity, SnapshotBoundary, SourceEvent,
            SourceIdentity, SourceVersion,
        )
        from ai_native_system.fact_gate import bind_rule
        from ai_native_system.ontology import OntologyRelease
        from ai_native_system.releases import ReleaseSnapshot, ReleaseStore
        from ai_native_system.source_write import seed_source_object

        target = ObjectIdentity(self.tenant, "asset", "asset-stale")
        native = SourceIdentity(self.tenant, "inventory", "record", "guard-ref")
        seed_source_object(SOURCE_DSN, self.tenant, record_type="record", record_id="guard-ref",
                           object_type="asset", object_id=target.object_id, state="verified", version="guard-v1")
        definition = self.registry.ontology(namespace="p4-guarded-asset").to_document()
        definition["relations"]["asset.guard"] = {
            "source_type": "asset", "target_type": "asset", "direction": "directed",
            "targets_per_source": {"min": 0, "max": None}, "sources_per_target": {"min": 0, "max": None},
        }
        definition["rules"]["verify_asset"]["conditions"].append(
            {"relation": "asset.guard", "target_state": "verified", "quantifier": "all"},
        )
        snapshot = ReleaseSnapshot.capture(
            self.registry, "single", self.runtime.model, self.runtime.tools,
            ontology=OntologyRelease.from_document(definition), owp_profile=self.owp_profile,
        )
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.facts.bind_mapping(connection, IdentityMapping(native, target, 1, self.now()),
                                    actor="operator", reason="Explicit relationship target")
            for field in (FactField(target, "$exists"), FactField(target, "$state"), FactField(self.object, "asset.guard")):
                self.facts.set_authority(connection, FieldAuthority(field, ("inventory",), 1),
                                         actor="operator", reason="Source-owned relationship")
            ReleaseStore.draft(connection, self.tenant, snapshot, publisher="operator")
            bind_rule(connection, self.tenant, snapshot.digest, "verify_asset", actor="operator",
                      feedback_source="inventory", feedback_stream="main")
            ReleaseStore.publish(connection, self.tenant, snapshot.digest, publisher="operator", migration_ref="linked guards")
            ReleaseStore.select(connection, self.tenant, "single", snapshot.digest, publisher="operator")
            self.grant(connection, "requester", "read", "release", snapshot.digest)
            for actor in ("requester", "reviewer", "worker"):
                self.grant(connection, actor, "read", "edge", self.object.object_id, "asset.guard")

        payload = self.inventory("pending")
        payload["relations"] = [{"type": "asset.guard", "id": "guard-edge", "target_type": "asset",
                                 "target_id": target.object_id, "properties": {}}]
        cutoff = self.now()
        guard_event = SourceEvent("first-guard", native, "upsert", cutoff,
                                  {"properties": {}, "state": "verified", "relations": []},
                                  SourceVersion(native, "e1", "guard-v1", 1), occurred_at=cutoff)
        parent_event = self.event("inventory", 2, payload)
        boundary = SnapshotBoundary(self.tenant, "inventory", "relations-snapshot", "e1", cutoff - timedelta(seconds=1),
                                    self.now(), Coverage.COMPLETE, self.cursor("inventory", 2))
        self.assertEqual(self.sync["inventory"].snapshot(boundary, [parent_event, guard_event], position=2,
                                                        predecessor=self.cursor("inventory", 1)).status, "applied")
        self.perturb_native("v2")
        with self.assertRaises(PermissionError):
            self.runtime.submit(self.tenant, "single", self.object.object_id, "requester", "hidden",
                                identity=self.identity["requester"])
        self.assertEqual(self.native(), (("pending", "v2"), 0))
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            for actor in ("requester", "reviewer", "worker"):
                self.grant(connection, actor, "read", "object", target.object_id)
                self.grant(connection, actor, "read", "metadata", target.object_id, "state")

        first, second = self.approved("native-guard"), self.approved("changed-collection")
        for task_id in (first, second):
            self.authorize(task_id)
        from ai_native_system.remote_execution import operation
        task, wrote = self.runtime._execute(self.tenant, first, None)
        self.assertEqual((task["status"], wrote), ("reconciling", False))
        with self.store.transaction(tenant=self.tenant) as connection:
            prepared = operation(connection, first)["payload"]
        self.assertEqual(prepared["source_conditions"]["guards"],
                         [{"type": "record", "id": "guard-ref", "expected_version": "guard-v1"}])
        import psycopg
        with psycopg.connect(SOURCE_DSN) as connection:
            connection.execute("UPDATE p4_source.objects SET version=%s::jsonb WHERE tenant=%s AND record_id='guard-ref'",
                               (json.dumps("guard-v2"), self.tenant))
        self.assertEqual(self.runtime.advance(self.tenant, first)["status"], "failed")
        self.assertEqual(self.native(), (("pending", "v2"), 1))
        removed = self.event("inventory", 3, self.inventory("pending"))
        self.assertEqual(self.sync["inventory"].apply(removed, position=3, predecessor=self.cursor("inventory", 2)).status,
                         "applied")
        self.assertEqual(self.runtime.advance(self.tenant, second)["status"], "blocked")
        self.assertEqual(self.native(), (("pending", "v2"), 1))
        self.assertEqual(self.counts(), (0, 1, 0))

    def test_signed_not_found_and_manual_recovery_never_resend(self):
        from ai_native_system.delivery import finish_delivery

        task_id = self.approved()
        self.authorize(task_id)
        self.stop_source(self.source_process)
        started = time.monotonic()
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "reconciling")
        self.start_source()
        time.sleep(max(started + self.binding.retention_seconds - time.monotonic(), 0))
        self.due(task_id, "reconcile", last_attempt=True)
        self.assertEqual(self.process_reconciliation()[0]["status"], "manual")
        self.assertEqual(self.stored(task_id)["status"], "not_found")
        self.assertEqual(self.native(), (("pending", "v1"), 0))
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            for operation in ("retry", "reconcile", "advance"):
                self.grant(connection, "requester", operation, "task", task_id)
        decision = self.runtime.retry_remote(self.tenant, task_id, "requester", identity=self.identity["requester"])
        self.assertEqual(decision["authorization"]["reason"], "lookup_only")
        self.due(task_id, "reconcile")
        manual = claim_delivery(self.delivery, self.tenant, "reconcile", manual_operation_id=task_id)
        self.assertEqual(reconcile_job(self.runtime, manual), "retry")
        self.assertEqual(finish_delivery(self.delivery, manual, "manual"), "manual")
        self.assertEqual(self.queue_status(task_id, "reconcile")["attempts"], 1)
        self.assertEqual(self.counts(), (0, 1, 0))


    @unittest.skipUnless(CONTAINER, "Actual database restore requires the P4 Compose runner")
    def test_restored_pre_dispatch_database_cannot_replay_real_source_effect(self):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import conninfo_to_dict, make_conninfo

        from ai_native_system.runtime import Runtime

        task_id = self.approved()
        self.authorize(task_id)
        task, wrote = self.runtime._execute(self.tenant, task_id, None)
        self.assertEqual((task["status"], wrote), ("reconciling", False))
        config = conninfo_to_dict(FRAMEWORK_DSN)
        archive = subprocess.check_output(
            ["docker", "exec", CONTAINER, "pg_dump", "-U", config["user"], "-d", config["dbname"],
             "--format=custom", "--schema=ai_native"], timeout=25,
        )
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "completed")
        (state, version), count = self.native()
        self.assertEqual((state, count), ("verified", 1))
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.assertTrue(self.ledger.revoke(connection, self.tenant, task_id, actor="operator", reason="Recovery"))

        restored_db = "p4_restore_" + uuid4().hex[:12]
        with psycopg.connect(FRAMEWORK_DSN, autocommit=True) as connection:
            connection.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(restored_db)))
        try:
            subprocess.run(
                ["docker", "exec", "-i", CONTAINER, "pg_restore", "-U", config["user"], "-d", restored_db,
                 "--single-transaction", "--exit-on-error", "--no-owner"], input=archive, timeout=25, check=True,
            )
            with self.store_type(make_conninfo(self.runtime_dsn, dbname=restored_db)) as restored:
                runtime = Runtime(restored, self.registry, self.runtime.model, self.runtime.tools,
                                  owp_ledgers={self.tenant: self.ledger_at("restored-epoch")})
                task = runtime.advance(self.tenant, task_id)
                self.assertEqual(task["authorization"]["reason"], "restore_epoch_changed")
                with restored.transaction(tenant=self.tenant) as connection:
                    self.assertEqual(connection.execute("SELECT count(*) FROM owp_consumptions").fetchone()[0], 0)
            self.assertEqual(self.native(), (("verified", version), 1))
        finally:
            with psycopg.connect(FRAMEWORK_DSN, autocommit=True) as connection:
                connection.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(restored_db)))
