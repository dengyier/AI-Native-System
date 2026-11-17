"""An authorized vector citation through the normal approval and OWP entry points."""

import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from ai_native_system.evaluation import record_evaluation
from ai_native_system.fact_gate import bind_rule
from ai_native_system.knowledge import KnowledgeRetrieval, build_hnsw
from ai_native_system.knowledge_evidence import record_document_revocation
from ai_native_system.knowledge_ingest import KnowledgeIngestion
from ai_native_system.memory import MemoryStore
from ai_native_system.model_accounting import ModelAccounting, ModelLimits
from ai_native_system.model_service import EmbeddingService
from ai_native_system.policy import Policy
from ai_native_system.releases import AUTHORIZED_FRAGMENTS, ReleaseSnapshot, ReleaseStore

from p2b_support import restricted_role
from test_model import model_server
from test_model_backend import embedding_response
from test_security_entry import SecureWorkflowFixture


DSN = os.environ.get("AI_NATIVE_P7_TEST_DSN")
MODEL_GRANTS = (
    "INSERT ON ai_native.model_calls, ai_native.model_attempts, ai_native.model_trace_outbox",
    "UPDATE (outcome, input_tokens, output_tokens, actual_provider, actual_model, finished_at) ON ai_native.model_attempts",
)


@unittest.skipUnless(DSN, "Use verify_p7.py with real PostgreSQL and pgvector")
class KnowledgeWorkflowTests(SecureWorkflowFixture, unittest.TestCase):
    test_dsn = DSN
    tool_remote = False
    runtime_grants = SecureWorkflowFixture.runtime_grants + MODEL_GRANTS + (
        "INSERT, UPDATE, DELETE ON ai_native.knowledge_memories",
    )

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.knowledge_dsn = restricted_role((
            "SELECT ON ALL TABLES IN SCHEMA ai_native",
            "INSERT, UPDATE, DELETE ON ai_native.knowledge, ai_native.knowledge_history, ai_native.knowledge_sources, "
            "ai_native.knowledge_vector_spaces, ai_native.knowledge_vector_documents, ai_native.knowledge_vector_chunks",
            "INSERT ON ai_native.fact_invalidation_outbox, ai_native.knowledge_evaluations",
            *MODEL_GRANTS,
        ), DSN)

    def setUp(self):
        super().setUp()
        self.legacy_release = self.release
        snapshot = ReleaseSnapshot.capture(self.registry, "single", self.runtime.model, self.runtime.tools,
                                           owp_profile=self.owp_profile, knowledge_strategy=AUTHORIZED_FRAGMENTS)
        self.release = snapshot.digest
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            ReleaseStore.draft(connection, self.tenant, snapshot, publisher="operator")
            bind_rule(connection, self.tenant, self.release, "verify_asset", actor="operator")
            ReleaseStore.publish(connection, self.tenant, self.release, publisher="operator",
                                 migration_ref="P7 explicit citation release")
            ReleaseStore.select(connection, self.tenant, "single", self.release, publisher="operator")
            self.grant(connection, "requester", "read", "release", self.release)
        self.writer = self.enterContext(self.store_type(self.knowledge_dsn))
        url, self.requests = self.enterContext(model_server(result=embedding_response(vectors=((0.4, 0.6),))))
        self.enterContext(patch.dict(os.environ, {"P7_LOOPBACK_KEY": "development-fixture"}))
        tariffs = {"price_version": "test-price-v1", "input_nanos": 2, "output_nanos": 0, "max_input_tokens": 100}
        self.config = {
            "allow_providers": ["openai"], "default": "default", "routes": {"default": {"adapter": "demo"}},
            "max_context_bytes": 4096,
            "limits": {"max_active": 2, "max_attempts": 2, "max_tokens": 10000, "max_cost_nanos": 100000,
                       "deadline_seconds": 20},
            "embeddings": {"vectors": {"base_url": url, "model": "embedding-v1", "provider": "openai",
                                      "api_key_env": "P7_LOOPBACK_KEY", "dimensions": 2, "version": "vectors-v1",
                                      "accounting": tariffs, "scopes": ["tenant"]}},
        }
        limits = ModelLimits(**self.config["limits"])
        self.ingestion = KnowledgeIngestion(self.writer, EmbeddingService(self.writer, self.config, limits))
        self.retrieval = KnowledgeRetrieval(self.store, EmbeddingService(self.store, self.config, limits))
        self.reader = self.identity["requester"]
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            for actor in ("requester", "reviewer", "worker"):
                self.grant(connection, actor, "read", "knowledge-index", "v1")
            for scope in (("write", "knowledge-index", "v1", None), ("publish", "knowledge-index", "v1", None),
                          ("embed", "model", "vectors", "tenant"),
                          ("write", "document", "asset-policy", None), ("withdraw", "document", "asset-policy", None),
                          ("evaluate", "release", self.release, None), ("read", "memory_scope", "team", None),
                          ("remember", "memory_scope", "team", None)):
                self.grant(connection, "requester", *scope)
        self.ingestion.create_space(self.reader, "v1", "vectors")
        self.ingestion.rebuild(self.reader, "v1", "asset-policy")
        self.ingestion.activate_space(self.reader, "v1")

    def cite(self):
        hits = self.retrieval.search(self.reader, "查验登记条件", limit=1).hits
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].citation.document_id, "asset-policy")
        return hits[0].citation

    def approved_citation(self, citation, key):
        task = self.runtime.submit(self.tenant, "single", "asset-1", "requester", key, identity=self.reader,
                                   knowledge_citations=[citation.to_document()])
        task_id = task["id"]
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.grant(connection, "reviewer", "read", "task", task_id)
            self.grant(connection, "reviewer", "approve", "task", task_id)
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "awaiting_approval")
        review = self.runtime.inspect(self.tenant, task_id, identity=self.identity["reviewer"])["review"]
        self.assertEqual(review["proposal"]["evidence_ids"], [citation.id])
        self.assertEqual(review["grounding"]["knowledge"][0]["id"], citation.id)
        verdict = self.runtime.decide(self.tenant, task_id, "reviewer", "approve", identity=self.identity["reviewer"],
                                      proposal_digest=review["proposal_digest"])
        self.assertEqual(verdict["status"], "ready")
        return task_id

    def test_retrieve_cite_approve_execute_once_and_record_evaluation_against_the_release(self):
        started = time.monotonic()
        citation = self.cite()
        task_id = self.approved_citation(citation, "indexed-evidence")
        self.authorize(task_id)
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "completed")
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "completed")
        self.assertEqual(self.counts(), (1, 1, 1))
        self.assertEqual([request[0] for request in self.requests], ["/v1/embeddings"] * 2)
        usage = ModelAccounting(self.store).usage(self.tenant)["totals"]["known_cost_nanos"]
        dataset = [{"id": "workflow", "relevant": [citation.id], "forbidden": ["private"],
                    "supports_action": [citation.id], "action": "verify_asset", "effects": 1, "block": [], "limits": {}}]
        observations = [{"id": "workflow", "retrieved": [citation.id], "citations": [citation.id], "action": "verify_asset",
                         "effects": self.counts()[0], "blocked": [], "cost_nanos": usage,
                         "latency_ms": round((time.monotonic() - started) * 1000)}]
        report = record_evaluation(self.writer, self.reader, self.release, dataset, observations)
        self.assertTrue(report["passed"])
        self.assertEqual(report["release_digest"], self.release)
        self.assertEqual(report, record_evaluation(self.writer, self.reader, self.release, dataset, observations))

    def test_revocation_fences_search_memory_and_approved_action_before_the_consumer(self):
        citation = self.cite()
        memory = MemoryStore(self.store)
        memory.remember(self.reader, "cross_task", "team", citation, ttl_seconds=300)
        task_id = self.approved_citation(citation, "to-revoke")
        self.authorize(task_id)
        self.assertEqual(len(memory.recall(self.reader, "cross_task", "team")), 1)
        with self.writer.transaction(tenant=self.tenant, write=True) as connection:
            self.assertTrue(record_document_revocation(connection, self.tenant, "asset-policy",
                                                       citation.document_version, reason="Withdrawn evidence"))
        self.assertEqual(self.retrieval.search(self.reader, "查验", limit=1).hits, ())
        self.assertEqual(memory.recall(self.reader, "cross_task", "team"), [])
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "blocked")
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_cited_action_rechecks_index_access_for_the_executor(self):
        citation = self.cite()
        task_id = self.approved_citation(citation, "executor-index-revoked")
        self.authorize(task_id)
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.assertTrue(Policy().revoke(connection, self.tenant, "worker", "read", "knowledge-index",
                                            citation.index_version))
        self.assertEqual(self.cite(), citation)
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "blocked")
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_cli_hnsw_and_hybrid_use_the_same_authorized_citation(self):
        build_hnsw(DSN, self.tenant, "v1")
        with TemporaryDirectory() as directory:
            config = Path(directory) / "models.json"
            config.write_text(json.dumps(self.config), encoding="utf-8")
            for method in ("hnsw", "hybrid"):
                with self.subTest(method=method):
                    output = subprocess.check_output((sys.executable, "-B", "-m", "ai_native_system", "--postgres",
                        "--tenant", self.tenant, "--models", str(config), "p7", "search", "查验", "--limit", "1",
                        "--method", method, "--actor", "requester"),
                        env={**os.environ, "AI_NATIVE_POSTGRES_DSN": self.runtime_dsn}, text=True)
                    result = json.loads(output)
                    self.assertEqual(result["requested_method"], method)
                    self.assertEqual(result["hits"][0]["citation"]["document_id"], "asset-policy")
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            Policy().revoke(connection, self.tenant, "requester", "read", "document", "asset-policy")
        self.assertEqual(self.retrieval.search(self.reader, "查验", limit=2, method="hnsw").hits, ())
        self.assertEqual(self.retrieval.search(self.reader, "查验", limit=2, method="hybrid").hits, ())

    def test_release_gates_optional_citations_and_legacy_lookup_rechecks_revocations(self):
        citation = self.cite()
        with self.assertRaisesRegex(ValueError, "selected release strategy"):
            self.runtime.submit(self.tenant, "single", "asset-1", "requester", "new-missing-citation",
                                identity=self.reader)
        with self.assertRaisesRegex(ValueError, "selected release strategy"):
            self.runtime.submit(self.tenant, "single", "asset-1", "requester", "legacy-extra-citation",
                                identity=self.reader, release_digest=self.legacy_release,
                                knowledge_citations=[citation.to_document()])
        legacy = self.runtime.submit(self.tenant, "single", "asset-1", "requester", "legacy-approved",
                                     identity=self.reader, release_digest=self.legacy_release)
        with self.writer.transaction(tenant=self.tenant, write=True) as connection:
            record_document_revocation(connection, self.tenant, "asset-policy", citation.document_version,
                                       reason="Withdrawn whole document")
        self.assertEqual(self.runtime.advance(self.tenant, legacy["id"])["status"], "blocked")
