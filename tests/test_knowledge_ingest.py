"""Exercise LlamaIndex citation offsets and restartable PG document publication."""

import json
import os
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.util import find_spec
from threading import Event, Thread
from unittest.mock import patch
from uuid import uuid4

from ai_native_system.adapters.litellm import EmbeddingResult
from ai_native_system.adapters.llamaindex import split_document, text_digest
from ai_native_system.identity import IdentityContext
from ai_native_system.knowledge_ingest import KnowledgeIngestion, KnowledgeIngestionError

from p2b_support import restricted_role


DSN = os.environ.get("AI_NATIVE_P7_TEST_DSN")


@unittest.skipUnless(find_spec("llama_index"), "Install locked LlamaIndex integration")
class ParserTests(unittest.TestCase):
    def test_original_offsets_with_crlf_tabs_repeated_headings_and_utf8(self):
        samples = ("  # 标题\n重复段落 😀\n# 标题\n重复段落 😀\n", "#\t标题\r\n\r\n原文🏳️‍🌈\r\n", "段落一。段落一。第二段。 " * 8)
        for source in samples:
            for file_format in ("markdown", "text"):
                with self.subTest(source=source, file_format=file_format):
                    chunks = split_document(source, file_format, 16)
                    raw = source.encode("utf-8")
                    self.assertEqual("".join("".join(chunk.text.split()) for chunk in chunks), "".join(source.split()))
                    self.assertEqual(split_document(source, file_format, 16), chunks)
                    for ordinal, chunk in enumerate(chunks):
                        self.assertEqual((chunk.ordinal, chunk.content_digest), (ordinal, text_digest(chunk.text)))
                        self.assertEqual(source[chunk.start_char:chunk.end_char], chunk.text)
                        self.assertEqual(raw[chunk.start_byte:chunk.end_byte].decode("utf-8"), chunk.text)
                        self.assertLessEqual(chunk.end_byte - chunk.start_byte, 16)


class ControlledEmbedding:
    """Deterministic failure injection with the same on-admission callback as P5."""

    max_input_bytes = 32

    def __init__(self, store):
        self.store = store
        self.calls = []
        self.before_admission = None
        self.fail = False
        self.base_url = "https://controlled.invalid/v1"

    def describe(self, route):
        dimensions = 3 if route == "second" else 2
        return {"provider": "fixture", "model": route + "-request", "response_model": route + "-reply",
                "base_url": self.base_url, "version": "test-v1", "dimensions": dimensions,
                "preprocessing_version": "raw-text-v1"}

    def embed(self, tenant, route, texts, *, scope, purpose, identity, authorize):
        if self.before_admission is not None:
            self.before_admission()
        with self.store.transaction(write=True, tenant=tenant) as connection:
            authorize(connection)
        self.calls.append((route, tuple(texts)))
        if self.fail:
            raise TimeoutError("simulated provider timeout")
        space = self.describe(route)
        vectors = tuple(tuple([1.0, float(len(item))] + [0.5] * (space["dimensions"] - 2)) for item in texts)
        return EmbeddingResult(vectors, 1, 0, space["provider"], space["response_model"], space["version"],
                               space["preprocessing_version"], space["dimensions"])


@unittest.skipUnless(DSN, "Use verify_p7.py for real PostgreSQL ingestion tests")
class KnowledgeIngestionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from ai_native_system.adapters.postgres_runtime import PostgresRuntimeStore

        role = restricted_role((
            "SELECT ON ai_native.governed_tenants, ai_native.principals, ai_native.enterprise_delegations, "
            "ai_native.enterprise_delegation_scopes, ai_native.resource_grants, ai_native.fact_invalidation_outbox",
            "INSERT ON ai_native.fact_invalidation_outbox, ai_native.principals",
            "SELECT, INSERT, UPDATE, DELETE ON ai_native.knowledge, ai_native.knowledge_history, "
            "ai_native.knowledge_sources, ai_native.knowledge_vector_spaces, "
            "ai_native.knowledge_vector_documents, ai_native.knowledge_vector_chunks",
            "SELECT, INSERT ON ai_native.model_calls, ai_native.model_attempts, ai_native.model_trace_outbox",
            "UPDATE (outcome, input_tokens, output_tokens, actual_provider, actual_model, finished_at) ON ai_native.model_attempts",
        ), DSN)
        cls.store = cls.enterClassContext(PostgresRuntimeStore(role))

    def setUp(self):
        import psycopg

        self.tenant = "p7-ingestion-" + uuid4().hex
        self.identity = IdentityContext(self.tenant, "author")
        with psycopg.connect(DSN) as admin:
            admin.execute("INSERT INTO ai_native.principals (tenant,id,roles) VALUES (%s,'author','[]')", (self.tenant,))
            admin.execute("INSERT INTO ai_native.governed_tenants VALUES (%s)", (self.tenant,))
            with admin.cursor() as cursor:
                cursor.executemany("""INSERT INTO ai_native.resource_grants (tenant,principal,operation,kind,resource_id,member)
                    VALUES (%s,'author',%s,%s,%s,'')""",
                    [(self.tenant, verb, "document", "doc") for verb in ("write", "read", "withdraw", "delete")]
                    + [(self.tenant, verb, "knowledge-index", index) for verb in ("write", "publish")
                       for index in ("first", "second")])
        self.embedding = ControlledEmbedding(self.store)
        self.ingestion = KnowledgeIngestion(self.store, self.embedding)
        self.ingestion.create_space(self.identity, "first", "first", chunk_bytes=16)

    def current(self):
        with self.store.transaction(tenant=self.tenant) as tx:
            row = tx.execute("SELECT version, text FROM knowledge WHERE id='doc'").fetchone()
            return None if row is None else tuple(row)

    def test_atomic_update_and_bounded_restart_do_not_repeat_committed_batches(self):
        original = "初版文档。"
        self.assertEqual(self.ingestion.ingest(self.identity, "first", "doc", "source", original)["state"], "published")
        self.ingestion.activate_space(self.identity, "first")
        updated = "文档甲乙丙丁戊己庚辛壬癸，二十个字组成不同片段用于检查连续恢复。"
        partial = self.ingestion.ingest(self.identity, "first", "doc", "source", updated,
                                        expected_version=1, max_batches=1)
        self.assertEqual(partial["state"], "staged")
        self.assertGreater(partial["embedded"], 0)
        self.assertEqual(self.current(), (1, original))
        sent_before = self.embedding.calls[-1][1]
        self.embedding.fail = True
        with self.assertRaises(TimeoutError):
            self.ingestion.resume(self.identity, "first", "doc", 2)
        self.assertEqual(self.current(), (1, original))
        self.embedding.fail = False
        after_failure = len(self.embedding.calls)
        restarted = KnowledgeIngestion(self.store, self.embedding)
        report = restarted.resume(self.identity, "first", "doc", 2)
        self.assertEqual(report["state"], "published")
        self.assertEqual(self.current(), (2, updated))
        self.assertFalse(set(sent_before).intersection(part for _, group in self.embedding.calls[after_failure:] for part in group))
        after_publish = len(self.embedding.calls)
        self.assertEqual(restarted.ingest(self.identity, "first", "doc", "source", updated, expected_version=1), report)
        self.assertEqual(len(self.embedding.calls), after_publish)

    def test_rebuild_cutover_requires_complete_matching_space_and_preserves_old_version(self):
        self.ingestion.ingest(self.identity, "first", "doc", "source", "甲 的定义与参考资料")
        self.ingestion.activate_space(self.identity, "first")
        self.ingestion.create_space(self.identity, "second", "second", chunk_bytes=16)
        with self.assertRaisesRegex(KnowledgeIngestionError, "missing a current managed document"):
            self.ingestion.activate_space(self.identity, "second")
        self.embedding.base_url = "https://moved.invalid/v1"
        with self.assertRaisesRegex(KnowledgeIngestionError, "differs from this index version"):
            self.ingestion.rebuild(self.identity, "second", "doc")
        self.embedding.base_url = "https://controlled.invalid/v1"
        self.assertEqual(self.ingestion.rebuild(self.identity, "second", "doc")["document_version"], 1)
        self.assertEqual(self.ingestion.activate_space(self.identity, "second")["dimensions"], 3)
        with self.store.transaction(tenant=self.tenant) as tx:
            states = tx.execute("SELECT index_id, state FROM knowledge_vector_spaces ORDER BY index_id").fetchall()
        self.assertEqual([tuple(row) for row in states], [("first", "retired"), ("second", "active")])

    def test_egress_rechecks_document_grant_and_tombstone_replay_purges_restored_content(self):
        import psycopg

        def change_grant(revoke):
            with psycopg.connect(DSN) as admin:
                if revoke:
                    admin.execute("""DELETE FROM ai_native.resource_grants WHERE tenant=%s AND principal='author'
                        AND operation='read' AND kind='document' AND resource_id='doc'""", (self.tenant,))
                else:
                    admin.execute("INSERT INTO ai_native.resource_grants VALUES (%s,'author','read','document','doc','')",
                                  (self.tenant,))

        self.embedding.before_admission = lambda: change_grant(True)
        with self.assertRaises(PermissionError):
            self.ingestion.ingest(self.identity, "first", "doc", "source", "只允许授权发出 1")
        self.assertEqual(self.embedding.calls, [])
        self.assertIsNone(self.current())
        self.embedding.before_admission = None
        change_grant(False)
        self.ingestion.resume(self.identity, "first", "doc", 1)
        tombstone = self.ingestion.retire_document(self.identity, "doc", expected_version=1, delete=True)
        self.assertIsNone(self.current())
        with psycopg.connect(DSN) as admin:
            admin.execute("UPDATE ai_native.knowledge_sources SET status='active' WHERE tenant=%s AND document_id='doc'", (self.tenant,))
            for table in ("knowledge", "knowledge_history"):
                admin.execute(f"INSERT INTO ai_native.{table} VALUES (%s,'doc',1,'restored plaintext')", (self.tenant,))
        self.assertEqual(self.ingestion.reapply_tombstone(self.identity, tombstone), tombstone)
        self.assertIsNone(self.current())
        with self.store.transaction(tenant=self.tenant) as tx:
            for table in ("knowledge_history", "knowledge_vector_documents", "knowledge_vector_chunks"):
                self.assertEqual(tx.execute(f"SELECT count(*) FROM {table}").fetchone()[0], 0)
            self.assertEqual(tx.execute("SELECT count(*) FROM fact_invalidation_outbox").fetchone()[0], 1)

    @unittest.skipUnless(find_spec("litellm"), "Install locked LiteLLM integration")
    def test_core_tenant_write_completes_while_embedding_http_response_is_held(self):
        import psycopg

        from ai_native_system.model_accounting import ModelLimits
        from ai_native_system.model_service import EmbeddingService
        from test_model_backend import embedding_response

        sent, release = Event(), Event()

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                sent.set()
                if release.wait(8):
                    raw = json.dumps(embedding_response(model="fixture-embed", vectors=((1, 0),))).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)

            def log_message(self, format, *args):
                pass

        with psycopg.connect(DSN) as admin:
            admin.execute("INSERT INTO ai_native.resource_grants VALUES (%s,'author','embed','model','held','tenant')",
                          (self.tenant,))
        with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server, patch.dict(os.environ, {"P7_TEST_EMBED_KEY": "fixture-key"}):
            worker = Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                config = {"allow_providers": ["openai"], "embeddings": {"held": {
                    "base_url": f"http://127.0.0.1:{server.server_port}/v1", "model": "fixture-embed",
                    "provider": "openai", "version": "held-1", "dimensions": 2, "scopes": ["tenant"],
                    "api_key_env": "P7_TEST_EMBED_KEY", "timeout": 10,
                    "accounting": {"price_version": "test", "input_nanos": 2, "output_nanos": 0, "max_input_tokens": 64},
                }}}
                service = EmbeddingService(self.store, config, ModelLimits(2, 2, 1000, 10000, 15))
                ingestion = KnowledgeIngestion(self.store, service)
                ingestion.create_space(self.identity, "second", "held")
                with ThreadPoolExecutor(max_workers=1) as pool:
                    processing = pool.submit(ingestion.ingest, self.identity, "second", "doc", "source", "原文内容")
                    try:
                        self.assertTrue(sent.wait(8), "The real provider never received the embedding request")
                        started = time.monotonic()
                        with self.store.transaction(tenant=self.tenant, write=True) as tx:
                            tx.execute("INSERT INTO principals (tenant,id,roles) VALUES (?,'concurrent','[]')",
                                       (self.tenant,))
                        self.assertLess(time.monotonic() - started, 2.0)
                        self.assertFalse(processing.done())
                    finally:
                        release.set()
                    self.assertEqual(processing.result(timeout=10)["state"], "published")
            finally:
                server.shutdown()
                worker.join(timeout=2)

    def test_delete_purges_unpublished_draft_and_prevents_reuse(self):
        self.embedding.fail = True
        with self.assertRaises(TimeoutError):
            self.ingestion.ingest(self.identity, "first", "doc", "source", "原文尚未提交发布")
        self.assertIsNone(self.current())
        self.assertEqual(self.ingestion.retire_document(self.identity, "doc", expected_version=1, delete=True)["status"],
                         "deleted")
        with self.store.transaction(tenant=self.tenant) as tx:
            self.assertEqual(tx.execute("SELECT count(*) FROM knowledge_vector_documents").fetchone()[0], 0)
            self.assertEqual(tx.execute("SELECT count(*) FROM knowledge_vector_chunks").fetchone()[0], 0)
        self.embedding.fail = False
        with self.assertRaisesRegex(KnowledgeIngestionError, "withdrawn or deleted"):
            self.ingestion.ingest(self.identity, "first", "doc", "source", "原文尚未提交发布")
