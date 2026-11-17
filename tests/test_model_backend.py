import importlib.util
import json
import os
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from ai_native_system.adapters.litellm import LiteLLMEmbedding, LiteLLMModel, ProviderCallError, _sdk
from ai_native_system.model import ModelError
from test_model import CONTEXT, model_server, reply


def completion_response(**kwargs):
    response = reply(**kwargs)
    response.update(id="completion-1", object="chat.completion", created=1)
    choice = response["choices"][0]
    choice["index"] = 0
    choice["message"]["role"] = "assistant"
    response["usage"]["total_tokens"] = 52
    return response


def embedding_response(model="embedding-v1", vectors=((1, 0), (0, 1))):
    return {
        "object": "list",
        "model": model,
        "data": [
            {"object": "embedding", "index": index, "embedding": list(vector)}
            for index, vector in reversed(list(enumerate(vectors)))
        ],
        "usage": {"prompt_tokens": 6, "total_tokens": 6},
    }


@unittest.skipUnless(importlib.util.find_spec("litellm"), "Install the pinned LiteLLM dependency")
class LiteLLMBackendTests(unittest.TestCase):
    def test_completion_preserves_message_roles_and_reported_usage(self):
        with model_server(result=completion_response()) as (base_url, requests):
            with patch.dict(os.environ, {
                "P5_TEST_KEY": "explicit-test-key",
                "OPENAI_API_KEY": "ambient-test-key",
                "OPENAI_BASE_URL": "https://example.invalid/v1",
                "HTTP_PROXY": "http://127.0.0.1:1",
                "NO_PROXY": "",
            }):
                model = LiteLLMModel(base_url, "test-model", api_key_env="P5_TEST_KEY")
                proposal = model.propose(CONTEXT)

        self.assertEqual((proposal.provider, proposal.model), ("openai", "test-model-2026"))
        self.assertEqual((proposal.input_tokens, proposal.output_tokens), (40, 12))
        self.assertEqual(proposal.action, "request_review")
        self.assertEqual(proposal.evidence_ids, ("policy-v1",))
        self.assertEqual(len(requests), 1)
        path, auth, data = requests[0]
        self.assertEqual((path, auth, data["model"]), ("/v1/chat/completions", "Bearer explicit-test-key", "test-model"))
        self.assertEqual(data["response_format"], {"type": "json_object"})
        system, user = data["messages"]
        self.assertEqual((system["role"], user["role"]), ("system", "user"))
        self.assertNotIn(CONTEXT["agent"]["instructions"], system["content"])
        self.assertEqual(json.loads(user["content"]), CONTEXT)
        self.assertNotIn("explicit-test-key", json.dumps(model.manifest))

    def test_provider_failure_preserves_usage_without_retry_or_error_body(self):
        body = {
            "error": {"message": "Last message must have role `user`: secret request body"},
            "model": "test-model-2026",
            "usage": {"prompt_tokens": 6, "completion_tokens": 1},
        }
        with model_server(result=body, status=503) as (base_url, requests):
            with self.assertRaises(ProviderCallError) as caught:
                LiteLLMModel(base_url, "test-model", "secret-test-key").propose(CONTEXT)

        error = caught.exception
        self.assertEqual(len(requests), 1)
        self.assertTrue(error.sent)
        self.assertEqual((error.provider, error.model), ("openai", "test-model-2026"))
        self.assertEqual((error.input_tokens, error.output_tokens), (6, 1))
        self.assertTrue(error.retryable)
        self.assertNotIn("secret", str(error))

    def test_invalid_proposal_and_malformed_choices_preserve_usage(self):
        invalid_action = completion_response(action="approve_without_review")
        invalid_choices = {**completion_response(), "choices": [{"message": None}]}
        duplicate_keys = completion_response()
        duplicate_keys["choices"][0]["message"]["content"] = (
            '{"action":"approve_without_review","action":null,"rationale":"reviewed","evidence_ids":[]}'
        )
        for data in (invalid_action, invalid_choices, duplicate_keys):
            with self.subTest(data=data), model_server(result=data) as (base_url, requests):
                with self.assertRaises(ProviderCallError) as caught:
                    LiteLLMModel(base_url, "test-model", "test-key").propose(CONTEXT)
                self.assertEqual(caught.exception.model, "test-model-2026")
                self.assertEqual((caught.exception.input_tokens, caught.exception.output_tokens), (40, 12))
                self.assertEqual(len(requests), 1)

    def test_embedding_uses_a_distinct_endpoint_and_returns_vectors_in_input_order(self):
        with model_server(result=embedding_response()) as (base_url, requests):
            embedder = LiteLLMEmbedding(base_url, "embedding-v1", "test-key", dimensions=2, version="2026-09")
            result = embedder.embed(["first", "second"])

        self.assertEqual(result.vectors, ((1.0, 0.0), (0.0, 1.0)))
        self.assertEqual((result.model, result.version, result.dimensions), ("embedding-v1", "2026-09", 2))
        self.assertEqual((result.input_tokens, result.output_tokens), (6, 0))
        self.assertEqual(len(requests), 1)
        path, _, data = requests[0]
        self.assertEqual(path, "/v1/embeddings")
        self.assertEqual(data["input"], ["first", "second"])

    def test_rejects_non_finite_vectors_wrong_identity_and_dimensions(self):
        cases = [
            embedding_response(vectors=((1, 0), (0,))),
            embedding_response(vectors=((1, 0), (0, float("inf")))),
            embedding_response(vectors=((1, 0), (0, True))),
            embedding_response(model="another-embedding-space"),
        ]
        duplicate_index = embedding_response()
        duplicate_index["data"][1]["index"] = 1
        for data in [*cases, duplicate_index]:
            with self.subTest(data=data), model_server(result=data) as (base_url, _):
                with self.assertRaises(ProviderCallError):
                    LiteLLMEmbedding(base_url, "embedding-v1", "test-key", dimensions=2, version="v1").embed(["a", "b"])

    def test_redirect_and_unapproved_provider_are_blocked(self):
        with model_server(result=completion_response()) as (destination, destination_requests):
            with model_server(status=307, headers={"Location": destination}) as (base_url, requests):
                with self.assertRaises(ModelError):
                    LiteLLMModel(base_url, "model", "test-key", provider="other")
                self.assertEqual(requests, [])
                with self.assertRaises(ProviderCallError):
                    LiteLLMModel(base_url, "model", "test-key").propose(CONTEXT)
                self.assertEqual(len(requests), 1)
        self.assertEqual(destination_requests, [])

    def test_missing_explicit_credentials_are_rejected_before_sdk_send(self):
        with patch.dict(os.environ, {"OPENAI_API_KEY": "ambient-test-key", "P5_TEST_KEY": ""}):
            model = LiteLLMModel("http://127.0.0.1:1/v1", "test-model", api_key_env="P5_TEST_KEY")
            with self.assertRaisesRegex(ModelError, "explicit LiteLLM API key"):
                model.validate_credentials()
            with self.assertRaises(ProviderCallError) as caught:
                model.propose(CONTEXT)
            self.assertFalse(caught.exception.sent)

    def test_total_deadline_cancels_a_provider_that_drips_http_headers(self):
        _sdk()
        accepted = threading.Event()
        finished = threading.Event()

        class DripHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers["Content-Length"]))
                accepted.set()
                try:
                    self.request.sendall(b"HTTP/1.1 200 OK\r\nX-Test-Drip: ")
                    for _ in range(100):
                        self.request.sendall(b"a")
                        time.sleep(0.02)
                    self.request.sendall(b"\r\nContent-Length: 0\r\n\r\n")
                except OSError:
                    pass
                finally:
                    finished.set()

        with ThreadingHTTPServer(("127.0.0.1", 0), DripHandler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                model = LiteLLMModel(f"http://127.0.0.1:{server.server_port}/v1", "test-model", "test-key")
                start = time.monotonic()
                with self.assertRaises(ProviderCallError) as caught:
                    model.propose(CONTEXT, timeout_seconds=0.2)
                self.assertTrue(caught.exception.timeout)
                self.assertTrue(accepted.is_set())
                self.assertLess(time.monotonic() - start, 1)
                self.assertTrue(finished.wait(1))
            finally:
                server.shutdown()
                thread.join()

    def test_oversized_transport_response_is_rejected(self):
        with model_server(raw=b"A" * (65 * 1024)) as (base_url, _):
            with self.assertRaises(ProviderCallError):
                LiteLLMModel(base_url, "test-model", "test-key").propose(CONTEXT)
