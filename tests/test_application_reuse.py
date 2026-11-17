"""Exercise three published app declarations against the same governed backend."""

import json
import os
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

import test_p7_workflow as p7
from test_model import model_server
from test_model_backend import completion_response

from ai_native_system.api import ApplicationAPI
from ai_native_system.applications import ApplicationCatalog
from ai_native_system.fact_gate import bind_rule
from ai_native_system.gateway import configured_gateway
from ai_native_system.model import ModelError
from ai_native_system.model_accounting import ModelAccounting
from ai_native_system.policy import Policy
from ai_native_system.registry import Registry
from ai_native_system.releases import AUTHORIZED_FRAGMENTS, ReleaseError, ReleaseSnapshot, ReleaseStore
from ai_native_system.runtime import Runtime


DSN = os.environ.get("AI_NATIVE_P8_TEST_DSN")
ROOT = Path(__file__).resolve().parents[1]


class ApplicationReuseTests(p7.KnowledgeWorkflowTests):
    test_dsn = DSN
    __unittest_skip__ = not DSN
    __unittest_skip_why__ = "Use verify_p8.py with real PostgreSQL and pgvector"

    @classmethod
    def setUpClass(cls):
        with patch.object(p7, "DSN", DSN):
            super().setUpClass()

    def setUp(self):
        super().setUp()
        self.reply = completion_response(action=None, rationale="PRIVATE-UNSUPPORTED-MODEL-TEXT", evidence=[])
        generation, self.generations = self.enterContext(model_server(result=self.reply))
        config = {**self.config, "routes": {**self.config["routes"], "advisory": {
            "adapter": "litellm", "base_url": generation, "model": "advisory-fixture", "provider": "openai",
            "api_key_env": "P7_LOOPBACK_KEY", "max_output_tokens": 256,
            "policy": {"data": {"object_fields": ["request"], "knowledge_ids": ["asset-policy", "review-guide"]},
                       "accounting": {"price_version": "test-v1", "input_nanos": 2, "output_nanos": 3,
                                      "max_input_tokens": 500}},
        }}}
        model = configured_gateway(config)
        self.registry = Registry.load(ROOT / "fixtures/p8-registry.json")
        tools = self.runtime.tools
        self.runtime = Runtime(self.store, self.registry, model, tools, owp_ledgers={self.tenant: self.ledger})
        self.catalog = ApplicationCatalog.load(self.runtime, self.retrieval, ROOT / "fixtures/p8-applications.json")
        self.published = {}
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            for spec in self.catalog.applications.values():
                controlled = spec.kind == "action"
                snapshot = ReleaseSnapshot.capture(
                    self.registry, spec.application, model, tools,
                    owp_profile=self.owp_profile if controlled else None,
                    knowledge_strategy=AUTHORIZED_FRAGMENTS if controlled else None,
                )
                self.published[spec.id] = snapshot.digest
                ReleaseStore.draft(connection, self.tenant, snapshot, publisher="operator")
                if controlled:
                    bind_rule(connection, self.tenant, snapshot.digest, "verify_asset", actor="operator")
                ReleaseStore.publish(connection, self.tenant, snapshot.digest, publisher="operator")
                ReleaseStore.select(connection, self.tenant, spec.application, snapshot.digest, publisher="operator")
                self.grant(connection, "requester", "read", "app", spec.application)
                self.grant(connection, "requester", spec.operation, "app", spec.application)
                self.grant(connection, "requester", "read", "release", snapshot.digest)
            self.grant(connection, "requester", "use", "model", "advisory")
            self.grant(connection, "requester", "read", "document", "review-guide")
            self.grant(connection, "requester", "write", "document", "review-guide")
        self.ingestion.ingest(self.reader, "v1", "review-guide", "sample:restricted", "PRIVATE-DOCUMENT-TEXT")
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            Policy().revoke(connection, self.tenant, "requester", "read", "document", "review-guide")
        self.citation = self.cite()
        self.set_reply(evidence=[self.citation.id])

    def set_reply(self, *, evidence, action=None):
        self.reply["choices"][0]["message"]["content"] = json.dumps({
            "action": action, "rationale": "PRIVATE-UNSUPPORTED-MODEL-TEXT", "evidence_ids": evidence,
        })

    def test_three_apps_share_live_retrieval_and_protected_execution(self):
        entries = self.catalog.list(self.reader)["applications"]
        self.assertEqual([entry["id"] for entry in entries], ["ask-knowledge", "draft-evidence", "controlled-action"])
        self.assertTrue(all(entry["documents"] == ["asset-policy"] for entry in entries))
        question = self.catalog.run(self.reader, "ask-knowledge", {"query": "如何提交校验？"})
        artifact = self.catalog.run(self.reader, "draft-evidence", {
            "query": "摘录校验条件", "document_ids": ["asset-policy"],
        })
        self.assertEqual(question["status"], "completed")
        self.assertEqual(question["citations"], [self.citation.to_document()])
        self.assertEqual(artifact["citations"], question["citations"])
        self.assertTrue(artifact["text"].startswith("# 依据摘编\n\n> "))
        for result in (question, artifact):
            self.assertNotIn("PRIVATE-", json.dumps(result))
        for _, _, request in self.generations:
            model_input = json.loads(request["messages"][-1]["content"])
            self.assertEqual(model_input["allowed_actions"], [])
            self.assertEqual([item["id"] for item in model_input["knowledge"]], [self.citation.id])
            self.assertNotIn("PRIVATE-DOCUMENT-TEXT", json.dumps(model_input))
        report = ModelAccounting(self.store).usage(self.tenant)
        self.assertEqual(sum(item["purpose"] == "generation" for item in report["attempts"]), 2)
        self.assertEqual(self.counts(), (0, 0, 0))

        payload = {"object_id": "asset-1", "expected_version": 1, "request_key": "p8-controlled",
                   "release_digest": self.published["controlled-action"],
                   "knowledge_citations": [self.citation.to_document()]}
        queued = self.catalog.run(self.reader, "controlled-action", payload)
        task = queued["id"]
        self.assertEqual(queued["status"], "planning")
        self.assertEqual(self.catalog.run(self.reader, "controlled-action", payload)["id"], task)
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.grant(connection, "reviewer", "read", "task", task)
            self.grant(connection, "reviewer", "approve", "task", task)
        self.assertEqual(self.runtime.advance(self.tenant, task)["status"], "awaiting_approval")
        reviewer = self.identity["reviewer"]
        review = self.runtime.inspect(self.tenant, task, identity=reviewer)["review"]
        self.assertEqual(review["proposal"]["evidence_ids"], [self.citation.id])
        self.runtime.decide(self.tenant, task, reviewer.actor, "approve", identity=reviewer,
                            proposal_digest=review["proposal_digest"])
        self.assertEqual(self.counts(), (0, 0, 0))
        self.authorize(task)
        self.assertEqual(self.runtime.advance(self.tenant, task)["status"], "completed")
        self.assertEqual(self.catalog.run(self.reader, "controlled-action", payload)["id"], task)
        self.assertEqual(self.counts(), (1, 1, 1))

    def test_artifact_denies_unreadable_explicit_scope_and_provider_action(self):
        before = len(self.requests)
        with self.assertRaises(PermissionError):
            self.catalog.run(self.reader, "draft-evidence", {"query": "检索", "document_ids": ["review-guide"]})
        self.assertEqual(len(self.requests), before)
        self.assertEqual(self.generations, [])
        self.set_reply(evidence=[self.citation.id], action="verify_asset")
        with self.assertRaises(ModelError):
            self.catalog.run(self.reader, "ask-knowledge", {"query": "立即改写对象"})
        self.assertEqual(self.counts(), (0, 0, 0))

    def test_knowledge_app_checks_active_index_before_model_calls(self):
        declarations = json.loads((ROOT / "fixtures/p8-applications.json").read_text(encoding="utf-8"))
        declarations["applications"][0]["retrieval_method"] = "hybrid"
        catalog = ApplicationCatalog(self.runtime, self.retrieval, declarations)
        authenticator = Mock()
        authenticator.authenticate.return_value = self.reader
        api = ApplicationAPI(self.runtime, {}, enterprise_identity=authenticator, catalog=catalog)
        path = "/v1/applications/ask-knowledge/run"
        payload = {"query": "如何提交校验？"}
        requests_before = len(self.requests)
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.assertTrue(Policy().revoke(connection, self.tenant, self.reader.actor, "read", "knowledge-index",
                                            self.citation.index_version))
        with self.assertRaises(PermissionError):
            api.dispatch("POST", path, "test-credential", payload)
        self.assertEqual(len(self.requests), requests_before)
        self.assertEqual(self.generations, [])
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.grant(connection, self.reader.actor, "read", "knowledge-index", self.citation.index_version)
        with patch.object(self.retrieval, "search", wraps=self.retrieval.search) as search:
            result = api.dispatch("POST", path, "test-credential", payload)
        self.assertEqual(search.call_args.kwargs["method"], "hybrid")
        self.assertEqual(result["citations"], [self.citation.to_document()])
        model_input = json.loads(self.generations[0][2]["messages"][-1]["content"])
        self.assertEqual([item["id"] for item in model_input["knowledge"]], [self.citation.id])
        with self.assertRaises(ValueError):
            api.dispatch("POST", path, "test-credential", {**payload, "retrieval_method": "exact"})

    def test_published_retrieval_stays_pinned_and_rolls_back_only_to_current_coverage(self):
        app = "ask-knowledge"
        requester = self.reader.actor
        publisher = self.identity["reviewer"]
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            for operation in ("read", "write", "publish"):
                self.grant(connection, requester, operation, "knowledge-index", "v2")
            self.grant(connection, requester, "read", "document", "review-guide")
            self.grant(connection, publisher.actor, "manage", "app", app)
            for index in ("v1", "v2"):
                self.grant(connection, publisher.actor, "read", "knowledge-index", index)
            self.grant(connection, publisher.actor, "read", "document", "review-guide")

        authenticator = Mock()
        authenticator.authenticate.return_value = publisher
        api = ApplicationAPI(self.runtime, {}, enterprise_identity=authenticator, catalog=self.catalog,
                             control_store=self.control)

        def publish(index_id, method):
            draft = api.dispatch("POST", "/v1/releases/draft", "operator-credential", {
                "application": app, "retrieval": {"index_id": index_id, "method": method},
            })
            digest = draft["digest"]
            result = api.dispatch("POST", f"/v1/releases/{digest}/publish", "operator-credential", {
                "migration_ref": "Fixture retrieval release",
            })
            self.assertEqual(result["status"], "published")
            with self.control.transaction(tenant=self.tenant, write=True) as connection:
                self.grant(connection, requester, "read", "release", digest)
                self.grant(connection, publisher.actor, "read", "release", digest)
            return digest

        def select(digest):
            result = api.dispatch("POST", f"/v1/releases/{digest}/select", "operator-credential", {})
            self.assertEqual(result["digest"], digest)

        catalog = self.catalog
        payload = {"query": "如何提交校验？", "document_ids": ["asset-policy"]}

        def expect_citation(release, citation, method):
            self.set_reply(evidence=[citation.id])
            with patch.object(self.retrieval, "search", wraps=self.retrieval.search) as search:
                result = catalog.run(self.reader, app, payload)
            self.assertEqual(search.call_args.kwargs["method"], method)
            self.assertEqual(search.call_args.kwargs["index_version"], citation.index_version)
            self.assertEqual(result["release_digest"], release)
            self.assertEqual(result["status"], "completed")
            self.assertEqual(result["citations"], [citation.to_document()])

        release_a = publish("v1", "hybrid")
        select(release_a)
        expect_citation(release_a, self.citation, "hybrid")

        self.ingestion.create_space(self.reader, "v2", "vectors")
        for document in ("asset-policy", "review-guide"):
            self.ingestion.rebuild(self.reader, "v2", document)
        self.ingestion.activate_space(self.reader, "v2")
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            Policy().revoke(connection, self.tenant, requester, "read", "document", "review-guide")

        declarations = json.loads((ROOT / "fixtures/p8-applications.json").read_text(encoding="utf-8"))
        declarations["applications"][0]["retrieval_method"] = "hnsw"
        catalog = ApplicationCatalog(self.runtime, self.retrieval, declarations)
        citation_b = self.cite()
        self.assertEqual(citation_b.index_version, "v2")
        expect_citation(release_a, self.citation, "hybrid")
        release_b = publish("v2", "exact")
        select(release_b)
        expect_citation(release_b, citation_b, "exact")

        self.ingestion.ingest(self.reader, "v2", "asset-policy", self.citation.source_id,
                              "现行制度要求登记对象版本并由审核员确认。", expected_version=1)
        current_b = self.cite()

        def selection():
            with self.control.transaction(tenant=self.tenant) as connection:
                pointer = connection.execute(
                    """SELECT digest, changed_by, changed_at FROM application_release_selections
                       WHERE tenant=? AND application=?""", (self.tenant, app),
                ).fetchone()
                rows = connection.execute(
                    """SELECT previous_digest, digest, changed_by FROM application_release_selection_history
                       WHERE tenant=? AND application=? ORDER BY id""", (self.tenant, app),
                ).fetchall()
            return dict(pointer), [dict(row) for row in rows]

        selected_b = selection()
        self.assertEqual(selected_b[1][-1], {
            "previous_digest": release_a, "digest": release_b, "changed_by": publisher.actor,
        })
        with self.assertRaisesRegex(ReleaseError, "lacks current document coverage"):
            select(release_a)
        self.assertEqual(selection(), selected_b)
        expect_citation(release_b, current_b, "exact")

        self.ingestion.rebuild(self.reader, "v1", "asset-policy")
        current_a, = self.retrieval.search(self.reader, payload["query"], method="hybrid", index_version="v1",
                                           document_ids=["asset-policy"]).hits
        self.assertEqual(current_a.citation.document_version, current_b.document_version)
        routes = self.retrieval.embedding.routes
        with patch.dict(routes, vectors=replace(routes["vectors"], scopes=("public",))):
            with self.assertRaisesRegex(ReleaseError, "embedding route is unavailable"):
                select(release_a)
        self.assertEqual(selection(), selected_b)
        select(release_a)
        pointer, history = selection()
        self.assertEqual(pointer["digest"], release_a)
        self.assertEqual(history[len(selected_b[1]):], [{
            "previous_digest": release_b, "digest": release_a, "changed_by": publisher.actor,
        }])
        self.assertEqual(self.cite().index_version, "v2")
        expect_citation(release_a, current_a.citation, "hybrid")

        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.assertTrue(Policy().revoke(connection, self.tenant, requester, "read", "knowledge-index", "v1"))
        calls = (len(self.requests), len(self.generations))
        with self.assertRaises(PermissionError):
            catalog.run(self.reader, app, payload)
        self.assertEqual((len(self.requests), len(self.generations)), calls)
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.grant(connection, requester, "read", "knowledge-index", "v1")
        self.ingestion.retire_document(self.reader, "asset-policy", expected_version=current_b.document_version)
        withdrawn = catalog.run(self.reader, app, payload)
        self.assertEqual(withdrawn["status"], "insufficient_evidence")
        self.assertEqual(withdrawn["citations"], [])
        self.assertEqual(len(self.generations), calls[1])

    def test_action_stops_when_bound_object_version_changes_before_planning(self):
        payload = {"object_id": "asset-1", "expected_version": 1, "request_key": "version-gated",
                   "knowledge_citations": [self.citation.to_document()]}
        queued = self.catalog.run(self.reader, "controlled-action", payload)
        with self.store.transaction(tenant=self.tenant, write=True) as connection:
            connection.execute("UPDATE objects SET version=version+1 WHERE tenant=? AND id='asset-1'", (self.tenant,))
        self.assertEqual(self.runtime.advance(self.tenant, queued["id"])["status"], "blocked")
        self.assertEqual(self.counts(), (0, 0, 0))


def load_tests(loader, _suite, _pattern):
    names = (name for name, item in vars(ApplicationReuseTests).items()
             if name.startswith(loader.testMethodPrefix) and callable(item))
    return unittest.TestSuite(ApplicationReuseTests(name) for name in sorted(names))
