"""Exercise P7 reference memory, candidate review, and revocation on PostgreSQL."""

import os
import time
import unittest
from dataclasses import replace
from datetime import timedelta
from hashlib import sha256

from ai_native_system.identity import IdentityContext, create_delegation, revoke_delegation
from ai_native_system.knowledge import Citation
from ai_native_system.knowledge_evidence import EvidenceStore, process_invalidations
from ai_native_system.memory import MemoryStore
from ai_native_system.policy import Policy
from ai_native_system.storage import digest

from p2b_support import restricted_role
from test_p2b_workflow import FactWorkflowFixture


DSN = os.environ.get("AI_NATIVE_P7_TEST_DSN")


class MemoryEvidenceFixture(FactWorkflowFixture):
    test_dsn = DSN
    tool_remote = False
    runtime_grants = (
        "INSERT, DELETE ON ai_native.knowledge_memories",
        "INSERT ON ai_native.knowledge_candidates, ai_native.knowledge_invalidation_receipts",
        "UPDATE (verdict,reviewed_by,reviewed_at,invalidated_at,value) ON ai_native.knowledge_candidates",
    )
    control_grants = (
        "INSERT ON ai_native.enterprise_delegations, ai_native.enterprise_delegation_scopes",
        "UPDATE (revoked_at) ON ai_native.enterprise_delegations",
        "DELETE ON ai_native.resource_grants",
    )

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.indexer_dsn = restricted_role((
            "SELECT ON ai_native.knowledge, ai_native.knowledge_sources, ai_native.knowledge_vector_spaces,"
            " ai_native.knowledge_vector_documents, ai_native.knowledge_vector_chunks",
            "INSERT ON ai_native.knowledge_sources, ai_native.knowledge_vector_spaces,"
            " ai_native.knowledge_vector_documents, ai_native.knowledge_vector_chunks",
        ), DSN)

    def setUp(self):
        super().setUp()
        self.actor = self.identity["requester"]
        self.reviewer = self.identity["reviewer"]
        self.memory = MemoryStore(self.store)
        self.evidence = EvidenceStore(self.store)
        self.task = self.runtime.submit(self.tenant, "single", self.object.object_id, "requester", "memory", identity=self.actor)
        self.reference = self.seed_fragment()
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            for actor in ("requester", "reviewer", "worker"):
                self.grant(connection, actor, "read", "knowledge-index", self.reference.index_version)
                for operation in ("read", "remember", "forget"):
                    self.grant(connection, actor, operation, "memory_scope", "private")
            for operation in ("read", "remember", "forget"):
                self.grant(connection, "requester", operation, "task", self.task["id"])
            self.grant(connection, "requester", "propose", "evidence", "asset-policy")
            self.grant(connection, "requester", "review", "evidence", "asset-policy")
            self.grant(connection, "reviewer", "review", "evidence", "asset-policy")
            self.grant(connection, "reviewer", "read", "release", self.release)

    def seed_fragment(self):
        indexer = self.enterContext(self.store_type(self.indexer_dsn))
        with indexer.transaction(tenant=self.tenant, write=True) as connection:
            row = connection.execute("SELECT version,text FROM knowledge WHERE tenant=? AND id='asset-policy'",
                                     (self.tenant,)).fetchone()
            version, text = row["version"], row["text"]
            h = sha256(text.encode("utf-8")).hexdigest()
            chunk = digest(("test-chunk", self.tenant, h))
            connection.execute("""INSERT INTO knowledge_sources (tenant,document_id,source_id,format,status,last_version)
                VALUES (?,'asset-policy','fixture-source','text','active',?)""", (self.tenant, version))
            connection.execute("""INSERT INTO knowledge_vector_spaces
                (tenant,index_id,route,provider,model,model_version,preprocessing_version,dimensions,binding_digest,
                 metric,parser_version,chunk_bytes,state)
                VALUES (?,'index-test','route','openai','embed','v1','p1',2,?,'cosine','fixture-parser',128,'active')""",
                (self.tenant, digest(("test-binding",))))
            connection.execute("""INSERT INTO knowledge_vector_documents
                (tenant,index_id,document_id,document_version,dimensions,content_digest,chunk_count,state,base_version,
                 base_digest,write_current)
                VALUES (?,'index-test','asset-policy',?,2,?,1,'published',?,?,false)""",
                (self.tenant, version, h, version, h))
            connection.execute("""INSERT INTO knowledge_vector_chunks
                (tenant,index_id,document_id,document_version,dimensions,chunk_id,ordinal,start_char,end_char,
                 start_byte,end_byte,text,content_digest,embedding)
                VALUES (?,'index-test','asset-policy',?,2,?,0,0,?,0,?,?,?,'[1,0]'::public.vector)""",
                (self.tenant, version, chunk, len(text), len(text.encode("utf-8")), text, h))
        return Citation("asset-policy", version, chunk, "index-test", "fixture-source", 0, len(text), 0,
                        len(text.encode("utf-8")), h)

    def propose(self):
        return self.evidence.propose(self.actor, self.reference, release_digest=self.release, kind="field",
                                     object_id=self.object.object_id, name="checksum_ok", value=False)

@unittest.skipUnless(DSN, "Use the PostgreSQL P7 verifier for memory tests")
class KnowledgeMemoryTests(MemoryEvidenceFixture, unittest.TestCase):
    def test_recall_is_private_by_actor_and_exact_delegation(self):
        first = self.memory.remember(self.actor, "cross_task", "private", self.reference, ttl_seconds=60)
        self.assertEqual(self.memory.remember(self.actor, "cross_task", "private", self.reference, ttl_seconds=200), first)
        self.assertEqual(self.memory.recall(self.reviewer, "cross_task", "private"), [])
        self.assertFalse(self.memory.forget(self.reviewer, "cross_task", "private", first["id"]))
        with self.assertRaises(PermissionError):
            self.memory.recall(self.actor, "cross_task", "unprovisioned")
        delegated = IdentityContext(self.tenant, "requester", "worker", "memory-delegation")
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            create_delegation(connection, delegated, (
                ("read", "memory_scope", "private", None), ("remember", "memory_scope", "private", None),
                ("read", "document", "asset-policy", None),
                ("read", "knowledge-index", self.reference.index_version, None),
            ), starts_at=self.now() - timedelta(seconds=1), expires_at=self.now() + timedelta(minutes=1))
        self.assertEqual(self.memory.recall(delegated, "cross_task", "private"), [])
        delegated_entry = self.memory.remember(delegated, "cross_task", "private", self.reference, ttl_seconds=20)
        self.assertNotEqual(first["id"], delegated_entry["id"])
        self.assertEqual(self.memory.recall(self.actor, "cross_task", "private"), [first])
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.assertTrue(Policy().revoke(connection, self.tenant, "worker", "read", "document", "asset-policy"))
        self.assertEqual(self.memory.recall(delegated, "cross_task", "private"), [])
        self.assertEqual(self.memory.recall(self.actor, "cross_task", "private"), [first])
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.assertTrue(revoke_delegation(connection, self.tenant, delegated.delegation_id))
        with self.assertRaises(PermissionError):
            self.memory.recall(delegated, "cross_task", "private")

    def test_task_scope_expiry_delete_and_rls(self):
        task_id = self.task["id"]
        entry = self.memory.remember(self.actor, "task", task_id, self.reference, ttl_seconds=1)
        self.assertEqual(self.memory.recall(self.actor, "task", task_id), [entry])
        self.assertEqual(self.memory.recall(self.actor, "cross_task", "private"), [])
        with self.store.transaction() as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM knowledge_memories").fetchone()[0], 0)
        with self.assertRaises(PermissionError):
            self.memory.recall(self.reviewer, "task", task_id)
        with self.assertRaises(ValueError):
            self.memory.remember(self.actor, "task", task_id, self.reference, ttl_seconds=86401)
        with self.assertRaises(PermissionError):
            self.memory.remember(self.actor, "task", task_id, replace(self.reference, end_byte=self.reference.end_byte + 1),
                                 ttl_seconds=10)
        limit = time.monotonic() + 3
        while self.memory.recall(self.actor, "task", task_id):
            self.assertLess(time.monotonic(), limit)
            time.sleep(0.05)
        self.assertEqual(process_invalidations(self.store, self.tenant)["memories"], 1)
        renewed = self.memory.remember(self.actor, "task", task_id, self.reference, ttl_seconds=60)
        self.assertTrue(self.memory.forget(self.actor, "task", task_id, renewed["id"]))
        self.assertFalse(self.memory.forget(self.actor, "task", task_id, renewed["id"]))
