"""Verify exact, HNSW and Chinese hybrid search on authorized pgvector corpora."""

import json
import math
import unittest
from time import monotonic
from unittest.mock import patch

from ai_native_system import knowledge
from ai_native_system.policy import Policy

import test_authorized_retrieval as retrieval


@unittest.skipUnless(retrieval.DSN, "Use verify_p7.py for PostgreSQL and pgvector retrieval")
class PgvectorRetrievalTests(retrieval.RetrievalFixture, unittest.TestCase):
    def test_chinese_keyword_promotes_a_weaker_vector_match(self):
        self.seed_documents(self.tenant, [
            ("semantic", "款项划转需要逐级核验。", [1, 0]),
            ("keyword", "大额付款必须事先审批。", [0, 1]),
            ("unrelated", "办公场所安全检查。", [-1, 0]),
        ])
        self.grant_docs(self.tenant, "reader", "semantic", "keyword", "unrelated")

        query = "大额付款"
        exact = self.retrieval.search(self.actor, query, method="exact", limit=2)
        hybrid = self.retrieval.search(self.actor, query, method="hybrid", limit=2)

        self.assertEqual([hit.citation.document_id for hit in exact.hits], ["semantic", "keyword"])
        self.assertEqual([hit.citation.document_id for hit in hybrid.hits], ["keyword", "semantic"])
        self.assertEqual(hybrid.hits[0].citation, exact.hits[1].citation)

    def test_clause_number_uses_the_complete_identifier(self):
        self.seed_documents(self.tenant, [
            ("twenty", "第20条 费用审批规范。", [1, 0]),
            ("subclause", "第2条之1 费用审批规范。", [0.9, 0.1]),
            ("two", "第二条 费用审批规范。", [0, 1]),
        ])
        self.grant_docs(self.tenant, "reader", "twenty", "subclause", "two")

        hit, = self.retrieval.search(self.actor, "第２条", method="hybrid").hits
        self.assertEqual(hit.citation.document_id, "two")
        hit, = self.retrieval.search(self.actor, "第二条之一", method="hybrid").hits
        self.assertEqual(hit.citation.document_id, "subclause")
        self.assertEqual(self.retrieval.search(self.actor, "第3条", method="hybrid").hits, ())

    def test_quoted_chinese_phrase_requires_contiguous_text(self):
        self.seed_documents(self.tenant, [
            ("near", "按要求留存所有审批记录。", [1, 0]),
            ("exact", "系统应留存审批记录至少一年。", [0, 1]),
        ])
        self.grant_docs(self.tenant, "reader", "near", "exact")

        hit, = self.retrieval.search(self.actor, "“留存审批记录”", method="hybrid").hits
        self.assertEqual(hit.citation.document_id, "exact")
        self.assertEqual(self.retrieval.search(self.actor, '"留存采购记录"', method="hybrid").hits, ())

    def test_hybrid_respects_index_and_document_permissions(self):
        self.seed_documents(self.tenant, [
            ("visible", "保密资料保管要求。", [0, 1]),
            ("lexical-private", "保密资料保管要求。", [0, 1]),
            ("vector-private", "内部文件管理。", [1, 0]),
            ("out-of-scope", "保密资料保管要求。", [1, 0]),
        ])
        self.seed_documents(self.other, [("other-tenant", "保密资料保管要求。", [1, 0])])
        self.grant_docs(self.other, "reader", "other-tenant")
        self.grant_docs(self.tenant, "reader", "visible", "out-of-scope")
        scope = ["visible", "lexical-private", "vector-private", "other-tenant"]

        result = self.retrieval.search(self.actor, "保密资料", method="hybrid",
                                       index_version=retrieval.INDEX, document_ids=scope)
        hit, = result.hits
        self.assertEqual(hit.citation.document_id, "visible")
        self.assertEqual(hit.citation.source_id, self.tenant + "/visible")

        rank = knowledge._hybrid_hits

        def revoke_after_ranking(*args):
            ranked = rank(*args)
            self.assertEqual([candidate.id for candidate in ranked[0]], [hit.id])
            with self.control.transaction(tenant=self.tenant, write=True) as connection:
                Policy().revoke(connection, self.tenant, "reader", "read", "document", "visible")
            return ranked

        with patch.object(knowledge, "_hybrid_hits", side_effect=revoke_after_ranking):
            result = self.retrieval.search(self.actor, "保密资料", method="hybrid", document_ids=scope)
        self.assertEqual(result.hits, ())

        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            Policy().revoke(connection, self.tenant, "reader", "read", "knowledge-index", retrieval.INDEX)
        calls = len(self.calls)
        with self.assertRaises(PermissionError):
            self.retrieval.search(self.actor, "保密资料", method="hybrid", index_version=retrieval.INDEX)
        self.assertEqual(len(self.calls), calls)

    def test_hybrid_fusion_deduplicates_matches_and_orders_ties_consistently(self):
        self.seed_documents(self.tenant, [
            ("b", "检修窗口时间。", [1, 0]),
            ("a", "检修窗口时间。", [1, 0]),
        ])
        self.grant_docs(self.tenant, "reader", "a", "b")

        first = self.retrieval.search(self.actor, "检修窗口", method="hybrid")
        second = self.retrieval.search(self.actor, "检修窗口", method="hybrid")
        self.assertEqual(len(first.hits), 2)
        self.assertEqual({hit.citation.document_id for hit in first.hits}, {"a", "b"})
        self.assertEqual([hit.id for hit in first.hits], [hit.id for hit in second.hits])

    def test_hybrid_reports_vector_budget_degradation_and_keeps_lexical_evidence(self):
        self.seed_documents(self.tenant, [
            ("vector", "登录访问规范。", [1, 0]),
            ("keyword", "数据备份间隔为一天。", [0, 1]),
        ])
        self.grant_docs(self.tenant, "reader", "vector", "keyword")

        with patch("ai_native_system.knowledge._MAX_EXACT_CANDIDATES", 1):
            result = self.retrieval.search(self.actor, "数据备份", method="hybrid")

        self.assertEqual((result.requested_method, result.method, result.fallback),
                         ("hybrid", "lexical", "exact_candidate_limit"))
        hit, = result.hits
        self.assertEqual(hit.citation.document_id, "keyword")

    def measure_vector_update(self, document_ids):
        import psycopg

        with psycopg.connect(retrieval.DSN) as connection:
            started = monotonic()
            updated = connection.execute("""UPDATE ai_native.knowledge_vector_chunks
                SET embedding='[0.54,0.84]'::public.vector WHERE tenant=%s AND index_id=%s AND document_id=ANY(%s)""",
                (self.tenant, retrieval.INDEX, document_ids),
            ).rowcount
            connection.commit()
            elapsed = round((monotonic() - started) * 1000, 3)
        self.assertEqual(updated, len(document_ids))
        return elapsed

    def test_exact_hnsw_recall_and_highly_selective_acl_fallback(self):
        def vector(radians):
            return [math.cos(radians), math.sin(radians)]

        near = [(f"near-{index:04d}", f"Neighbor {index}", vector(0.002 + index / 10_000))
                for index in range(1600)]
        far = [(f"far-{index:04d}", f"Authorized alternate {index}", vector(1.5 + index / 100))
               for index in range(8)]
        self.seed_documents(self.tenant, near + far)
        self.grant_docs(self.tenant, "reader", *(document_id for document_id, _, _ in near[:60] + far))
        without_index = self.measure_vector_update([record[0] for record in near[900:932]])
        index = knowledge.build_hnsw(retrieval.DSN, self.tenant, retrieval.INDEX)
        with_index = self.measure_vector_update([record[0] for record in near[1000:1032]])
        self.assertGreater(index["bytes"], 0)
        metrics = self.retrieval.compare(self.actor, "near", limit=12)
        print("P7 benchmark " + json.dumps({**metrics, "hnsw_build_ms": index["elapsed_ms"], "updated_vectors": 32,
            "write_without_hnsw_ms": without_index, "write_with_hnsw_ms": with_index}), flush=True)
        self.assertEqual((metrics["exact_count"], metrics["hnsw_count"]), (12, 12))
        self.assertGreaterEqual(metrics["recall_at_k"], 0.9)
        self.assertTrue(metrics["used_hnsw_index"])
        self.assertGreaterEqual(metrics["hnsw_index_bytes"], index["bytes"])

        far_ids = [document_id for document_id, _, _ in far]
        filtered = self.retrieval.search(self.actor, "near", method="hnsw", limit=4, document_ids=far_ids)
        reference = self.retrieval.search(self.actor, "near", method="exact", limit=4, document_ids=far_ids)
        hybrid = self.retrieval.search(self.actor, "near", method="hybrid", limit=4, document_ids=far_ids)
        self.assertEqual([hit.id for hit in filtered.hits], [hit.id for hit in reference.hits])
        self.assertEqual((filtered.method, filtered.fallback), ("exact", "filtered_candidates"))
        self.assertEqual([hit.citation.document_id for hit in filtered.hits], far_ids[:4])
        self.assertEqual([hit.id for hit in hybrid.hits], [hit.id for hit in reference.hits])
        self.assertEqual((hybrid.method, hybrid.fallback), ("hybrid", "filtered_candidates"))
