import os
import secrets
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from importlib.util import find_spec
from unittest.mock import patch

from ai_native_system.adapters.owp import AUTHORIZATION_PROFILE, key_id, sign_authorization
from ai_native_system.identity import IdentityContext
from ai_native_system.source_receipt import (
    SOURCE_RECEIPT_PROFILE,
    sign_source_receipt,
    verify_source_receipt,
)
from ai_native_system.source_write import SourceAction, SourceWrite, initialize_source, seed_source_object
from ai_native_system.storage import digest, encode


TEST_DSN = os.environ.get("AI_NATIVE_P4_SOURCE_TEST_DSN") or os.environ.get("AI_NATIVE_P4_TEST_DSN")
DESTINATION = "1" * 64
RELEASE = "2" * 64


def make_operation(tenant, *, two_targets=True):
    targets = [
        {"type": "asset", "id": "record-a", "record_type": "native-asset", "record_id": "A",
         "expected_version": "rev:A:first", "from_state": "pending", "to_state": "verified"},
    ]
    if two_targets:
        targets.append(
            {"type": "asset", "id": "record-b", "record_type": "native-asset", "record_id": "B",
             "expected_version": "rev:B:first", "from_state": "pending", "to_state": "verified"}
        )
    operation = {
        "tenant": tenant, "operation_id": "operation-1", "action_instance_id": "operation-1:action",
        "action": "verify", "object_id": "record-a", "expected_version": 4,
        "from_state": "pending", "to_state": "verified", "requester": "operator", "approver": "reviewer",
        "executor": "bridge-worker", "release_digest": RELEASE,
        "source_conditions": {"source": "inventory", "targets": targets,
                              "guards": [{"type": "native-record", "id": "G", "expected_version": "g:first"}]},
    }
    operation["request_hash"] = digest(operation)
    return operation


@unittest.skipUnless(find_spec("openworkproof"), "Install the pinned OpenWorkProof extra")
class SourceReceiptTests(unittest.TestCase):
    def test_receipt_cannot_change_authorized_targets_or_authorization(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        signer = Ed25519PrivateKey.generate()
        keys = {key_id(signer.public_key()): signer.public_key()}
        operation = make_operation("sample", two_targets=False)
        body = {
            "profile": SOURCE_RECEIPT_PROFILE, "source": "inventory", "tenant": "sample",
            "operation_id": operation["operation_id"], "request_hash": operation["request_hash"],
            "authorization_digest": "3" * 64, "status": "succeeded", "recorded_at": 30, "retain_until": 90,
            "result": {"objects": [{"type": "asset", "id": "record-a", "previous_version": "rev:A:first",
                                    "version": "rev:A:next", "state": "verified"}]}, "reason": None,
        }
        proof = sign_source_receipt(body, signer)
        self.assertEqual(verify_source_receipt(proof, keys, operation=operation, authorization_digest="3" * 64), body)
        with self.assertRaises(ValueError):
            verify_source_receipt(proof, keys, operation=operation, authorization_digest="0" * 64)
        with self.assertRaises(ValueError):
            verify_source_receipt(proof, keys, operation=operation, source="another-source")
        with self.assertRaises(ValueError):
            verify_source_receipt(proof, {}, operation=operation)
        tampered = deepcopy(proof)
        tampered["payload"]["result"]["objects"][0]["id"] = "other"
        with self.assertRaises(ValueError):
            verify_source_receipt(tampered, keys, operation=operation)
        changed = sign_source_receipt(tampered["payload"], signer)
        with self.assertRaises(ValueError):
            verify_source_receipt(changed, keys, operation=operation)


@unittest.skipUnless(TEST_DSN, "Use the P4 verifier for independent source PostgreSQL tests")
class PostgresSourceWriteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo

        initialize_source(TEST_DSN)
        cls.roles = {}
        with psycopg.connect(TEST_DSN) as admin:
            for name, grants in {
                "execute": ("SELECT ON p4_source.objects, p4_source.receipts",
                            "UPDATE (state, version) ON p4_source.objects", "INSERT ON p4_source.receipts"),
                "lookup": ("SELECT ON p4_source.receipts",),
            }.items():
                role = f"p4_source_{name}_{secrets.token_hex(4)}"
                password = secrets.token_urlsafe(24)
                identifier = sql.Identifier(role)
                admin.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(identifier, sql.Literal(password)))
                admin.execute(sql.SQL("GRANT USAGE ON SCHEMA p4_source TO {}").format(identifier))
                for clause in grants:
                    admin.execute(sql.SQL("GRANT " + clause + " TO {}").format(identifier))
                cls.roles[name] = make_conninfo(TEST_DSN, user=role, password=password)

    def setUp(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        self.tenant = f"p4-source-{secrets.token_hex(6)}"
        self.authority, self.source_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        authority_pub, source_pub = self.authority.public_key(), self.source_key.public_key()
        self.keys = {key_id(source_pub): source_pub}
        self.source = SourceWrite(
            self.roles["execute"], tenant=self.tenant, source="inventory", destination_digest=DESTINATION,
            actions={"verify": SourceAction(1, "asset", "pending", "verified", max_targets=2)},
            authority_keys={key_id(authority_pub): authority_pub}, signing_key=self.source_key,
            epoch="external-epoch-1", lookup_dsn=self.roles["lookup"], retention_seconds=600,
        )
        for native, native_type, identifier, object_type, version in (
            ("A", "native-asset", "record-a", "asset", "rev:A:first"),
            ("B", "native-asset", "record-b", "asset", "rev:B:first"),
            ("G", "native-record", "guard", "related", "g:first"),
        ):
            seed_source_object(TEST_DSN, self.tenant, record_type=native_type, record_id=native,
                               object_type=object_type, object_id=identifier, state="pending", version=version)

    def authorization(self, operation, *, now=None, epoch="external-epoch-1", nonce=None, want_guard=True):
        now = int(time.time()) if now is None else now
        targets = [{k: t[k] for k in ("type", "id")} for t in operation["source_conditions"]["targets"]]
        reads = [{"kind": "object", "resource_id": target["id"], "member": None} for target in targets]
        if want_guard:
            reads.append({"kind": "object", "resource_id": "guard", "member": None})
        writes = [
            {"kind": kind, "resource_id": target["id"], "member": member}
            for target in targets
            for kind, member in (("object", None), ("metadata", "state"), ("metadata", "version"))
        ]
        scope = {k: operation[k] for k in ("tenant", "operation_id", "action_instance_id", "action", "executor",
                                           "release_digest")}
        claims = {
            "profile": AUTHORIZATION_PROFILE, "nonce": nonce or secrets.token_hex(12),
            "epoch": epoch, "issued_at": now - 1, "expires_at": now + 30,
            "scope": {
                **scope, "task_id": operation["operation_id"], "ontology_digest": "3" * 64,
                "policy_version": 1, "rule_versions": {"verify": 1}, "rule_proof_digest": "4" * 64,
                "fact_read_set_digest": "5" * 64, "approval_digest": "6" * 64,
                "requester": IdentityContext(operation["tenant"], operation["requester"]).as_document(),
                "approver": IdentityContext(operation["tenant"], operation["approver"]).as_document(),
                "action_version": 1, "action_kind": "write_remote", "targets": targets, "reads": reads,
                "writes": writes, "parameters_digest": operation["request_hash"],
                "tool": {"name": "inventory.verify", "version": "1", "destination_digest": DESTINATION},
            },
        }
        return sign_authorization(claims, self.authority)

    def state(self):
        import psycopg

        with psycopg.connect(TEST_DSN) as admin:
            return dict(admin.execute(
                "SELECT record_id,state FROM p4_source.objects WHERE tenant=%s ORDER BY record_id", (self.tenant,),
            ).fetchall())

    def change_guard(self, version):
        import psycopg

        with psycopg.connect(TEST_DSN) as admin:
            admin.execute("UPDATE p4_source.objects SET version=%s::jsonb WHERE tenant=%s AND record_id='G'",
                          (encode(version), self.tenant))

    def test_guard_changed_after_authorization_rejects_without_partial_write(self):
        operation = make_operation(self.tenant)
        grant = self.authorization(operation)
        self.change_guard("g:next")
        response = self.source.execute(operation, grant, principal="execute")
        proof = verify_source_receipt(response, self.keys, operation=operation, authorization_digest=grant["digest"])
        self.assertEqual(proof["status"], "rejected")
        self.assertEqual(self.state(), {"A": "pending", "B": "pending", "G": "pending"})
        self.change_guard("g:first")
        self.assertEqual(self.source.execute(operation, grant, principal="execute"), response)
        self.assertEqual(self.source.lookup(operation, principal="lookup"), response)
        self.assertEqual(self.state(), {"A": "pending", "B": "pending", "G": "pending"})

    def test_concurrent_exact_retry_returns_original_proof_and_two_targets_once(self):
        operation = make_operation(self.tenant)
        grant = self.authorization(operation)
        with ThreadPoolExecutor(max_workers=3) as workers:
            outcomes = list(workers.map(lambda _: self.source.execute(operation, grant, principal="execute"), range(3)))
        self.assertEqual(outcomes[1:], [outcomes[0]] * 2)
        proof = verify_source_receipt(outcomes[0], self.keys, operation=operation, authorization_digest=grant["digest"])
        self.assertEqual(proof["status"], "succeeded")
        self.assertEqual(proof["retain_until"] - proof["recorded_at"], 600)
        self.assertEqual(self.state(), {"A": "verified", "B": "verified", "G": "pending"})
        self.assertEqual(len(proof["result"]["objects"]), 2)
        self.assertTrue(all(isinstance(row["version"], str) and row["version"] != row["previous_version"]
                            for row in proof["result"]["objects"]))
        changed = deepcopy(operation)
        changed["expected_version"] = 8
        changed["request_hash"] = digest({k: v for k, v in changed.items() if k != "request_hash"})
        with self.assertRaises(PermissionError):
            self.source.execute(changed, self.authorization(changed), principal="execute")
        with self.assertRaises(PermissionError):
            self.source.lookup(changed, principal="lookup")

    def test_wrong_scope_epoch_and_expired_grant_cannot_write(self):
        operation = make_operation(self.tenant)
        for grant in (
            self.authorization(operation, want_guard=False),
            self.authorization(operation, epoch="stale-epoch"),
            self.authorization(operation, now=int(time.time()) - 120),
        ):
            with self.subTest(nonce=grant["payload"]["nonce"]), self.assertRaises(PermissionError):
                self.source.execute(operation, grant, principal="execute")
        self.assertEqual(self.state(), {"A": "pending", "B": "pending", "G": "pending"})

    def test_lookup_is_separate_and_signed_absence_contains_no_effect(self):
        operation = make_operation(self.tenant)
        with self.assertRaises(PermissionError):
            self.source.execute(operation, self.authorization(operation), principal="lookup")
        with self.assertRaises(PermissionError):
            self.source.lookup(operation, principal="execute")
        response = self.source.lookup(operation, principal="lookup")
        proof = verify_source_receipt(response, self.keys, operation=operation)
        self.assertEqual(proof["status"], "not_found")
        self.assertIsNone(proof["authorization_digest"])
        self.assertIsNone(proof["retain_until"])

    def test_signer_failure_rolls_back_source_effect_and_allows_exact_request(self):
        operation = make_operation(self.tenant)
        grant = self.authorization(operation)
        with patch("ai_native_system.source_write.sign_source_receipt", side_effect=OSError("test signer unavailable")):
            with self.assertRaises(OSError):
                self.source.execute(operation, grant, principal="execute")
        self.assertEqual(self.state(), {"A": "pending", "B": "pending", "G": "pending"})
        proof = self.source.execute(operation, grant, principal="execute")
        self.assertEqual(verify_source_receipt(proof, self.keys, operation=operation)["status"], "succeeded")

    def test_source_state_cannot_change_at_the_same_native_version(self):
        import psycopg

        with self.assertRaises(psycopg.errors.CheckViolation), psycopg.connect(TEST_DSN) as admin:
            admin.execute("UPDATE p4_source.objects SET state='changed' WHERE tenant=%s AND record_id='G'",
                          (self.tenant,))
        self.assertEqual(self.state()["G"], "pending")

    def test_native_mapping_cannot_redirect_canonical_target(self):
        operation = make_operation(self.tenant, two_targets=False)
        target = operation["source_conditions"]["targets"][0]
        target.update(record_id="B", expected_version="rev:B:first")
        operation["request_hash"] = digest({k: v for k, v in operation.items() if k != "request_hash"})
        response = self.source.execute(operation, self.authorization(operation), principal="execute")
        self.assertEqual(verify_source_receipt(response, self.keys, operation=operation)["status"], "rejected")
        self.assertEqual(self.state(), {"A": "pending", "B": "pending", "G": "pending"})
