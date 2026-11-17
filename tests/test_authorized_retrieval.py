"""Actual PostgreSQL and P5 SDK retrieval with document and delegation grants."""

import json
import os
import threading
import unittest
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from uuid import uuid4
from unittest.mock import patch

from ai_native_system.adapters.postgres import migrate_postgres
from ai_native_system.adapters.postgres_runtime import PostgresRuntimeStore
from ai_native_system.identity import IdentityContext, create_delegation, revoke_delegation
from ai_native_system.knowledge import Citation, KnowledgeRetrieval, KnowledgeSearchError, citation_fragment
from ai_native_system.knowledge_evidence import record_document_revocation
from ai_native_system.model_accounting import ModelLimits
from ai_native_system.model_service import EmbeddingService
from ai_native_system.policy import Policy
from ai_native_system.storage import digest

from p2b_support import restricted_role


DSN = os.environ.get("AI_NATIVE_P7_TEST_DSN")
INDEX = "vectors.1"
ROUTE = "vectors"
CONTROL_GRANTS = (
    "SELECT, INSERT, UPDATE ON ai_native.resource_grants, ai_native.enterprise_delegations, ai_native.enterprise_delegation_scopes",
    "DELETE ON ai_native.resource_grants",
    "SELECT, INSERT ON ai_native.fact_invalidation_outbox",
)
READ_GRANTS = (
    "SELECT ON ai_native.principals, ai_native.resource_grants, ai_native.governed_tenants, ai_native.enterprise_delegations, ai_native.enterprise_delegation_scopes",
    "SELECT ON ai_native.knowledge, ai_native.knowledge_sources, ai_native.knowledge_vector_documents, ai_native.knowledge_vector_spaces, ai_native.knowledge_vector_chunks, ai_native.fact_invalidation_outbox",
    "SELECT ON ai_native.knowledge_lexical_postings",
    "SELECT, INSERT ON ai_native.model_calls, ai_native.model_attempts, ai_native.model_trace_outbox",
    "UPDATE (outcome, input_tokens, output_tokens, actual_provider, actual_model, finished_at) ON ai_native.model_attempts",
)


class RetrievalFixture:
    @classmethod
    def setUpClass(cls):
        import psycopg

        with psycopg.connect(DSN) as admin:
            admin.execute("CREATE SCHEMA IF NOT EXISTS ai_native")
            admin.execute("CREATE EXTENSION IF NOT EXISTS vector WITH SCHEMA public")
        migrate_postgres(DSN)
        cls.control_dsn = restricted_role(CONTROL_GRANTS, DSN)
        cls.reader_dsn = restricted_role(READ_GRANTS, DSN)

    def setUp(self):
        self.tenant = "retrieval-" + uuid4().hex
        self.other = "retrieval-" + uuid4().hex
        self.calls = []
        self.on_embed = None
        self.embed_failure = None
        self.embedding_vector = [1, 0]
        fixture = self

        class Provider(BaseHTTPRequestHandler):
            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                fixture.calls.append((self.path, request))
                if fixture.on_embed is not None:
                    try:
                        fixture.on_embed()
                    except BaseException as error:
                        fixture.embed_failure = error
                response = {"object": "list", "model": request["model"], "data": [
                    {"object": "embedding", "index": i, "embedding": fixture.embedding_vector}
                    for i, _ in enumerate(request["input"])
                ], "usage": {"prompt_tokens": 3, "total_tokens": 3}}
                body = json.dumps(response).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        server = self.enterContext(ThreadingHTTPServer(("127.0.0.1", 0), Provider))
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        thread.start()
        self.addCleanup(thread.join, 5)
        self.addCleanup(server.shutdown)
        self.enterContext(patch.dict(os.environ, {"P7_RETRIEVAL_TEST_KEY": "p7-local-test-key"}))
        self.configuration = {
            "allow_providers": ["openai"], "max_context_bytes": 4096,
            "embeddings": {ROUTE: {"base_url": f"http://127.0.0.1:{server.server_port}/v1", "provider": "openai",
                                   "model": "fixture-embedding", "api_key_env": "P7_RETRIEVAL_TEST_KEY", "dimensions": 2,
                                   "version": "embedding.1", "scopes": ["tenant"], "accounting": {
                                       "price_version": "fixture-price", "input_nanos": 1, "output_nanos": 0,
                                       "max_input_tokens": 50}}},
        }
        self.store = self.enterContext(PostgresRuntimeStore(self.reader_dsn, max_connections=1))
        self.control = self.enterContext(PostgresRuntimeStore(self.control_dsn, max_connections=1))
        self.limits = ModelLimits(2, 1, 100_000, 100_000, 10)
        self.embedding = EmbeddingService(self.store, self.configuration, self.limits)
        self.retrieval = KnowledgeRetrieval(self.store, self.embedding)
        self.actor = IdentityContext(self.tenant, "reader")
        self.other_actor = IdentityContext(self.other, "reader")
        self.seed_tenant(self.tenant)
        self.seed_tenant(self.other)

    def seed_tenant(self, tenant):
        import psycopg

        manifest = self.embedding.describe(ROUTE)
        with psycopg.connect(DSN) as admin:
            admin.execute("INSERT INTO ai_native.governed_tenants (tenant) VALUES (%s)", (tenant,))
            with admin.cursor() as cursor:
                cursor.executemany("INSERT INTO ai_native.principals (tenant,id,roles) VALUES (%s,%s,'[]')",
                                   [(tenant, actor) for actor in ("reader", "service")])
            admin.execute("""INSERT INTO ai_native.knowledge_vector_spaces
                (tenant,index_id,route,provider,model,model_version,preprocessing_version,dimensions,binding_digest,
                 metric,parser_version,chunk_bytes,state) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,'cosine','fixture',256,'active')""",
                (tenant, INDEX, ROUTE, manifest["provider"], manifest["response_model"], manifest["version"],
                 manifest["preprocessing_version"], manifest["dimensions"], digest(manifest)),
            )
        with self.control.transaction(tenant=tenant, write=True) as connection:
            for actor in ("reader", "service"):
                Policy().grant(connection, tenant, actor, "embed", "model", ROUTE, "tenant")
            Policy().grant(connection, tenant, "reader", "read", "knowledge-index", INDEX)

    def seed_documents(self, tenant, records):
        """Load a known vector corpus without making an embedding call per synthetic row."""
        import psycopg

        with psycopg.connect(DSN) as admin, admin.cursor() as cursor:
            cursor.executemany("INSERT INTO ai_native.knowledge (tenant,id,version,text) VALUES (%s,%s,1,%s)",
                               [(tenant, document_id, text) for document_id, text, _ in records])
            cursor.executemany("""INSERT INTO ai_native.knowledge_sources
                (tenant,document_id,source_id,format,status,last_version) VALUES (%s,%s,%s,'text','active',1)""",
                [(tenant, document_id, tenant + "/" + document_id) for document_id, _, _ in records],
            )
            digests = {document_id: sha256(text.encode("utf-8")).hexdigest() for document_id, text, _ in records}
            cursor.executemany("""INSERT INTO ai_native.knowledge_vector_documents
                (tenant,index_id,document_id,document_version,dimensions,content_digest,chunk_count,state,base_version,
                 base_digest,write_current) VALUES (%s,%s,%s,1,2,%s,1,'published',1,%s,false)""",
                [(tenant, INDEX, document_id, digests[document_id], digests[document_id])
                 for document_id, _, _ in records],
            )
            cursor.executemany("""INSERT INTO ai_native.knowledge_vector_chunks
                (tenant,index_id,document_id,document_version,dimensions,chunk_id,ordinal,start_char,end_char,
                 start_byte,end_byte,text,content_digest,embedding)
                VALUES (%s,%s,%s,1,2,%s,0,0,%s,0,%s,%s,%s,%s::public.vector)""",
                [(tenant, INDEX, document_id, digest((tenant, INDEX, document_id)), len(text), len(text.encode("utf-8")),
                  text, digests[document_id], json.dumps(vector)) for document_id, text, vector in records],
            )

    def grant_docs(self, tenant, actor, *document_ids):
        with self.control.transaction(tenant=tenant, write=True) as connection:
            for document_id in document_ids:
                Policy().grant(connection, tenant, actor, "read", "document", document_id)


@unittest.skipUnless(DSN, "Use verify_p7.py for PostgreSQL and pgvector retrieval")
class AuthorizedRetrievalTests(RetrievalFixture, unittest.TestCase):
    def test_search_checks_resolved_index_access_before_embedding(self):
        self.seed_documents(self.tenant, [("visible", "Visible content", [1, 0])])
        self.grant_docs(self.tenant, "reader", "visible")
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            Policy().revoke(connection, self.tenant, "reader", "read", "knowledge-index", INDEX)

        for index_version, method in ((None, "exact"), (INDEX, "exact"), (INDEX, "hnsw"), ("missing", "exact")):
            with self.subTest(index_version=index_version, method=method):
                with self.assertRaisesRegex(PermissionError, "Resource access denied"):
                    self.retrieval.search(self.actor, "question", index_version=index_version, method=method)
        with self.assertRaisesRegex(PermissionError, "Resource access denied"):
            self.retrieval.compare(self.actor, "question", index_version=INDEX)
        self.assertEqual(self.calls, [])

        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            Policy().grant(connection, self.tenant, "reader", "read", "knowledge-index", INDEX)
        hit, = self.retrieval.search(self.actor, "question").hits
        self.assertEqual(hit.text, "Visible content")
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            Policy().revoke(connection, self.tenant, "reader", "read", "document", "visible")
        self.assertEqual(self.retrieval.search(self.actor, "question").hits, ())

    def test_tenant_scope_document_acl_and_citation_exact_offsets(self):
        import psycopg

        self.seed_documents(self.tenant, [("accessible", "中文锚点🧩", [0.9, 0.08]), ("private", "Restricted", [1, 0])])
        self.seed_documents(self.other, [("accessible", "中文锚点🧩", [0.9, 0.08]), ("other-private", "Other", [1, 0])])
        self.grant_docs(self.tenant, "reader", "accessible")
        self.grant_docs(self.other, "reader", "other-private")
        first = self.retrieval.search(self.actor, "question", limit=5)
        other = self.retrieval.search(self.other_actor, "question", limit=5)
        hit, = first.hits
        self.assertEqual(hit.text, "中文锚点🧩")
        self.assertEqual((hit.citation.start_char, hit.citation.end_char, hit.citation.end_byte), (0, 5, 16))
        self.assertEqual([hit.citation.document_id for hit in other.hits], ["other-private"])
        # Switch tenants twice on a one-connection pool, and verify the exact source identifier is maintained.
        self.assertEqual(self.retrieval.search(self.actor, "question").hits[0].citation, hit.citation)
        self.assertEqual(self.retrieval.search(self.actor, "question", document_ids=["private"]).hits, ())
        with self.store.transaction(tenant=self.tenant) as connection:
            self.assertEqual(citation_fragment(connection, self.actor, hit.citation)["id"], hit.id)
            forged = {**hit.citation.to_document(), "source_id": self.other + "/accessible"}
            with self.assertRaises(PermissionError):
                citation_fragment(connection, self.actor, Citation.from_document(forged))
        with psycopg.connect(self.reader_dsn) as raw:
            self.assertEqual(raw.execute("SELECT count(*) FROM ai_native.knowledge_vector_chunks").fetchone()[0], 0)

    def test_delegated_search_intersects_scopes_and_both_principals(self):
        self.seed_documents(self.tenant, [("one", "One", [1, 0]), ("two", "Two", [0.9, 0.1]),
                                         ("three", "Three", [0.8, 0.2])])
        self.grant_docs(self.tenant, "reader", "one", "two", "three")
        self.grant_docs(self.tenant, "service", "one", "three")
        delegated = IdentityContext(self.tenant, "reader", "service", "test-delegation")
        unscoped = IdentityContext(self.tenant, "reader", "service", "without-index-scope")
        now = datetime.now(timezone.utc)
        index_scope = ("read", "knowledge-index", INDEX, None)
        scopes = [("read", "document", "one", None), ("read", "document", "two", None),
                  ("embed", "model", ROUTE, "tenant")]
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            create_delegation(connection, delegated, [*scopes, index_scope],
                              starts_at=now - timedelta(seconds=5), expires_at=now + timedelta(minutes=1))
            create_delegation(connection, unscoped, scopes,
                              starts_at=now - timedelta(seconds=5), expires_at=now + timedelta(minutes=1))
        with self.assertRaises(PermissionError):
            self.retrieval.search(delegated, "service lacks index permission")
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            Policy().grant(connection, self.tenant, "service", *index_scope)
        with self.assertRaises(PermissionError):
            self.retrieval.search(unscoped, "delegation lacks index scope")
        self.assertEqual(self.calls, [])

        found = self.retrieval.search(delegated, "bounded delegation").hits
        self.assertEqual([item.citation.document_id for item in found], ["one"])
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.assertTrue(revoke_delegation(connection, self.tenant, delegated.delegation_id))
        old_calls = len(self.calls)
        with self.assertRaises(PermissionError):
            self.retrieval.search(delegated, "revoked delegation")
        self.assertEqual(len(self.calls), old_calls)

    def test_index_revoked_during_embedding_invalidates_search_and_prior_citation(self):
        self.seed_documents(self.tenant, [("visible", "Previously readable", [1, 0])])
        self.grant_docs(self.tenant, "reader", "visible")
        hit, = self.retrieval.search(self.actor, "before").hits

        def revoke_before_provider_response():
            with self.control.transaction(tenant=self.tenant, write=True) as connection:
                Policy().revoke(connection, self.tenant, "reader", "read", "knowledge-index", INDEX)

        self.on_embed = revoke_before_provider_response
        with self.assertRaises(PermissionError):
            self.retrieval.search(self.actor, "in flight")
        if self.embed_failure is not None:
            raise self.embed_failure
        self.assertEqual(len(self.calls), 2)
        with self.store.transaction(tenant=self.tenant) as connection:
            with self.assertRaises(PermissionError):
                citation_fragment(connection, self.actor, hit.citation)

    def test_retired_index_preserves_authorized_pinned_citation(self):
        import psycopg

        self.seed_documents(self.tenant, [("visible", "Retained evidence", [1, 0])])
        self.grant_docs(self.tenant, "reader", "visible")
        hit, = self.retrieval.search(self.actor, "original").hits
        with psycopg.connect(DSN) as admin:
            admin.execute("UPDATE ai_native.knowledge_vector_spaces SET state='retired' WHERE tenant=%s AND index_id=%s",
                          (self.tenant, INDEX))
        with self.assertRaisesRegex(KnowledgeSearchError, "Requested knowledge index is unavailable"):
            self.retrieval.search(self.actor, "no active index")
        self.assertEqual(self.retrieval.search(self.actor, "pinned", index_version=INDEX).hits[0].citation, hit.citation)
        with self.store.transaction(tenant=self.tenant) as connection:
            self.assertEqual(citation_fragment(connection, self.actor, hit.citation)["text"], hit.text)
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            Policy().revoke(connection, self.tenant, "reader", "read", "knowledge-index", INDEX)
        with self.store.transaction(tenant=self.tenant) as connection:
            with self.assertRaises(PermissionError):
                citation_fragment(connection, self.actor, hit.citation)

    def test_permissions_revoked_during_network_call_and_snapshot_updated(self):
        import psycopg

        self.seed_documents(self.tenant, [("during", "Permission changes in flight", [1, 0]),
                                        ("updated", "Stale document chunk", [0.9, 0.1]),
                                        ("withdrawn", "Withdrawn proof", [0.8, 0.2])])
        self.grant_docs(self.tenant, "reader", "during", "updated", "withdrawn")
        before = self.retrieval.search(self.actor, "before").hits
        self.assertEqual(len(before), 3)

        def revoke_before_provider_response():
            with self.control.transaction(tenant=self.tenant, write=True) as connection:
                Policy().revoke(connection, self.tenant, "reader", "read", "document", "during")
                record_document_revocation(connection, self.tenant, "withdrawn", 1, reason="test withdrawal")
            with psycopg.connect(DSN) as admin:
                admin.execute("UPDATE ai_native.knowledge SET text='Updated!', version=2 WHERE tenant=%s AND id='updated'",
                              (self.tenant,))

        self.on_embed = revoke_before_provider_response
        self.assertEqual(self.retrieval.search(self.actor, "after").hits, ())
        if self.embed_failure is not None:
            raise self.embed_failure
        with self.store.transaction(tenant=self.tenant) as connection:
            for hit in before:
                with self.assertRaises(PermissionError):
                    citation_fragment(connection, self.actor, hit.citation)

    def test_pinned_model_manifest_rejects_dimension_or_version_drift_without_send(self):
        configured = deepcopy(self.configuration)
        configured["embeddings"][ROUTE].update(version="embedding.2", dimensions=3)
        retrieval = KnowledgeRetrieval(self.store, EmbeddingService(self.store, configured, self.limits))
        with self.assertRaisesRegex(KnowledgeSearchError, "does not match"):
            retrieval.search(self.actor, "different namespace")
        self.assertEqual(self.calls, [])

    def test_release_index_binding_mismatch_rejects_before_embedding(self):
        with self.assertRaisesRegex(KnowledgeSearchError, "release binding"):
            self.retrieval.search(self.actor, "已发布检索", index_version=INDEX, binding_digest="0" * 64)
        self.assertEqual(self.calls, [])

    def test_query_embedding_must_remain_finite_and_nonzero_at_pgvector_precision(self):
        for vector in ([1e40, 0], [1e-100, 0]):
            with self.subTest(vector=vector):
                self.embedding_vector = vector
                with self.assertRaisesRegex(KnowledgeSearchError, "invalid for cosine search"):
                    self.retrieval.search(self.actor, "float32 boundary")
