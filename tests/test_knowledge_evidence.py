"""Exercise document evidence, candidate review, and P2b invalidation."""

import time
import unittest
from datetime import timedelta

from ai_native_system.fact_contracts import EvidenceRevocation, FactField
from ai_native_system.knowledge_evidence import document_revoked, process_invalidations, record_document_revocation
from ai_native_system.policy import Policy

from test_memory_scope import DSN, MemoryEvidenceFixture


@unittest.skipUnless(DSN, "Use the PostgreSQL P7 verifier for evidence tests")
class KnowledgeEvidenceTests(MemoryEvidenceFixture, unittest.TestCase):
    def test_candidate_review_never_writes_authoritative_fact(self):
        candidate = self.propose()
        self.assertEqual((candidate["state"], candidate["value"]), ("candidate", False))
        self.assertEqual(self.propose(), candidate)
        with self.assertRaises(PermissionError):
            self.evidence.fact_evidence(self.actor, candidate["id"])
        with self.assertRaises(PermissionError):
            self.evidence.review(self.actor, candidate["id"], "supported")
        review = self.evidence.review(self.reviewer, candidate["id"], "supported")
        self.assertEqual(review["state"], "supported")
        self.assertEqual(self.evidence.review(self.reviewer, candidate["id"], "supported"), review)
        with self.assertRaisesRegex(ValueError, "already recorded"):
            self.evidence.review(self.reviewer, candidate["id"], "rejected")
        refs = self.evidence.fact_evidence(self.reviewer, candidate["id"])
        self.assertEqual({r.evidence_id for r in refs}, {self.reference.document_id, self.reference.chunk_id})
        self.assertTrue(all(r.revision == self.reference.document_version for r in refs))
        with self.store.transaction(tenant=self.tenant) as connection:
            observed = self.facts.read_fact(connection, FactField(self.object, "checksum_ok"),
                                            as_of=self.now(), known_at=self.now())
        self.assertIs(observed.value, True)

    def test_index_revocation_hides_cached_candidates_and_memories(self):
        candidate = self.propose()
        entry = self.memory.remember(self.actor, "cross_task", "private", self.reference, ttl_seconds=60)
        self.assertEqual(self.evidence.get(self.actor, candidate["id"]), candidate)
        self.assertEqual(self.memory.recall(self.actor, "cross_task", "private"), [entry])
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.assertTrue(Policy().revoke(connection, self.tenant, self.actor.actor, "read", "knowledge-index",
                                            self.reference.index_version))
        with self.assertRaises(PermissionError):
            self.evidence.get(self.actor, candidate["id"])
        self.assertEqual(self.memory.recall(self.actor, "cross_task", "private"), [])
        self.assertEqual(self.evidence.review(self.reviewer, candidate["id"], "supported")["state"], "supported")

    def test_outbox_delay_redacts_and_deletes_without_reopening_old_evidence(self):
        candidate = self.propose()
        self.memory.remember(self.actor, "cross_task", "private", self.reference, ttl_seconds=60)
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.assertTrue(record_document_revocation(connection, self.tenant, self.reference.document_id,
                                                       self.reference.document_version, reason="source withdrawn"))
            self.assertFalse(record_document_revocation(connection, self.tenant, self.reference.document_id,
                                                        self.reference.document_version, reason="replayed"))
        with self.store.transaction(tenant=self.tenant) as connection:
            self.assertTrue(document_revoked(connection, self.tenant, self.reference.document_id,
                                             self.reference.document_version))
            self.assertEqual(connection.execute("SELECT count(*) FROM knowledge_memories").fetchone()[0], 1)
        self.assertEqual(self.memory.recall(self.actor, "cross_task", "private"), [])
        with self.assertRaises(PermissionError):
            self.evidence.get(self.actor, candidate["id"])
        counts = process_invalidations(self.store, self.tenant)
        self.assertEqual((counts["memories"], counts["candidates"]), (1, 1))
        self.assertEqual(process_invalidations(self.store, self.tenant), {"events": 0, "candidates": 0, "memories": 0})
        with self.store.transaction(tenant=self.tenant) as connection:
            saved = connection.execute("SELECT value,invalidated_at FROM knowledge_candidates WHERE id=?",
                                       (candidate["id"],)).fetchone()
        self.assertIsNone(saved["value"])
        self.assertIsNotNone(saved["invalidated_at"])

    def test_current_fact_input_and_document_acl_are_rechecked(self):
        candidate = self.propose()
        entry = self.memory.remember(self.actor, "cross_task", "private", self.reference, ttl_seconds=60)
        with self.assertRaises(PermissionError):
            self.memory.remember(self.actor, "cross_task", "private", self.reference, ttl_seconds=60,
                                 candidate_id=candidate["id"])
        self.evidence.review(self.reviewer, candidate["id"], "supported")
        linked = self.memory.remember(self.actor, "cross_task", "private", self.reference, ttl_seconds=60,
                                      candidate_id=candidate["id"])
        self.assertEqual(self.memory.recall(self.actor, "cross_task", "private"), [linked, entry])
        self.deliver("quality", self.quality(False))
        self.assertEqual(self.memory.recall(self.actor, "cross_task", "private"), [entry])
        with self.assertRaises(PermissionError):
            self.evidence.review(self.reviewer, candidate["id"], "supported")
        counts = process_invalidations(self.store, self.tenant)
        self.assertEqual((counts["candidates"], counts["memories"]), (1, 1))
        self.assertEqual(self.memory.recall(self.actor, "cross_task", "private"), [entry])
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.assertTrue(Policy().revoke(connection, self.tenant, "requester", "read", "document", "asset-policy"))
        self.assertEqual(self.memory.recall(self.actor, "cross_task", "private"), [])
        self.assertTrue(self.memory.forget(self.actor, "cross_task", "private", entry["id"]))

    def test_p2b_chunk_revocation_takes_effect_only_at_declared_time(self):
        candidate = self.propose()
        entry = self.memory.remember(self.actor, "cross_task", "private", self.reference, ttl_seconds=60)
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.grant(connection, "reviewer", "revoke", "evidence", self.reference.chunk_id)
            event = EvidenceRevocation("explicit-chunk-revocation", self.tenant, self.reference.chunk_id,
                                       self.reference.document_version, self.now() + timedelta(seconds=1), "Corrections")
            self.facts.revoke_evidence(connection, event, self.reviewer)
        self.assertEqual(self.memory.recall(self.actor, "cross_task", "private"), [entry])
        self.assertEqual(process_invalidations(self.store, self.tenant)["memories"], 0)
        deadline = time.monotonic() + 4
        while self.memory.recall(self.actor, "cross_task", "private"):
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.05)
        with self.assertRaises(PermissionError):
            self.evidence.get(self.actor, candidate["id"])
        with self.store.transaction(tenant=self.tenant) as connection:
            self.assertFalse(document_revoked(connection, self.tenant, self.reference.document_id,
                                              self.reference.document_version))
        result = process_invalidations(self.store, self.tenant)
        self.assertEqual((result["events"], result["candidates"], result["memories"]), (1, 1, 1))

    def test_rule_target_has_declared_type_and_permission(self):
        arguments = {"release_digest": self.release, "kind": "rule", "object_id": self.object.object_id,
                     "name": "verify_asset"}
        with self.assertRaises(PermissionError):
            self.evidence.propose(self.actor, self.reference, value=False, **arguments)
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.grant(connection, "requester", "read", "rule", "verify_asset")
        with self.assertRaises(ValueError):
            self.evidence.propose(self.actor, self.reference, value="false", **arguments)
        candidate = self.evidence.propose(self.actor, self.reference, value=False, **arguments)
        self.assertEqual((candidate["state"], candidate["target_kind"], candidate["target_name"]),
                         ("candidate", "rule", "verify_asset"))

    def test_relation_link_pins_both_object_versions(self):
        arguments = {"release_digest": self.release, "kind": "relation", "object_id": "artifact-1",
                     "name": "artifact.source", "value": "asset-stale"}
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.grant(connection, "requester", "read", "object", "artifact-1")
            self.grant(connection, "requester", "read", "edge", "artifact-1", "artifact.source")
        with self.assertRaises(PermissionError):
            self.evidence.propose(self.actor, self.reference, **arguments)
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.grant(connection, "requester", "read", "object", "asset-stale")
        candidate = self.evidence.propose(self.actor, self.reference, **arguments)
        self.assertEqual((candidate["object_version"], candidate["related_object_id"], candidate["related_object_version"]),
                         (1, "asset-stale", 2))
        with self.store.transaction(tenant=self.tenant, write=True) as connection:
            connection.execute("UPDATE objects SET version=3 WHERE tenant=? AND id='asset-stale'", (self.tenant,))
        with self.assertRaises(PermissionError):
            self.evidence.get(self.actor, candidate["id"])
