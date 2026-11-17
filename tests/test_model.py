import json
import os
import threading
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

from ai_native_system.model import DemoModel, ModelError, OpenAICompatibleModel, load_model


CONTEXT = {
    "scenario": "tracked_item_review",
    "object": {"id": "item-1", "status": "new"},
    "related": {},
    "knowledge": [{"id": "policy-v1", "text": "Queue new items for review."}],
    "allowed_actions": [{"name": "request_review", "description": "Queue item for review."}],
    "agent": {"id": "reviewer", "instructions": "Check the applicable policy."},
    "handoff": {"action": "request_review", "rationale": "Review needed.", "evidence_ids": ["policy-v1"]},
}


@contextmanager
def model_server(*, result=None, status=200, headers=None, raw=None):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append((self.path, self.headers.get("Authorization"), None))
            self.send_response(200)
            self.end_headers()

        def do_POST(self):
            request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append((self.path, self.headers.get("Authorization"), request))
            self.send_response(status)
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            if raw is not None:
                self.wfile.write(raw)
            else:
                self.wfile.write(json.dumps(result).encode())

        def log_message(self, format, *args):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}/v1", requests
        finally:
            server.shutdown()
            thread.join()


def reply(action="request_review", rationale="Apply the review policy.", evidence=None):
    return {
        "model": "test-model-2026",
        "choices": [
            {
                "finish_reason": "stop",
                "message": {
                    "content": json.dumps({
                        "action": action,
                        "rationale": rationale,
                        "evidence_ids": ["policy-v1"] if evidence is None else evidence,
                    })
                },
            }
        ],
        "usage": {"prompt_tokens": 40, "completion_tokens": 12},
    }


class ModelTests(unittest.TestCase):
    def test_demo_model_chooses_a_candidate_and_uses_retrieved_evidence(self):
        with patch.dict(os.environ, {}, clear=True):
            model = load_model()
        self.assertIsInstance(model, DemoModel)
        proposal = model.propose(CONTEXT)
        self.assertEqual(proposal.action, "request_review")
        self.assertEqual(proposal.evidence_ids, ("policy-v1",))
        self.assertIsNone(model.propose({**CONTEXT, "allowed_actions": []}).action)

    def test_http_adapter_uses_json_output_and_reports_provider_usage(self):
        with model_server(result=reply()) as (base_url, requests):
            model = OpenAICompatibleModel(base_url, "test-model", "local-test-key")
            proposal = model.propose(CONTEXT)

        self.assertEqual(proposal.action, "request_review")
        self.assertEqual(proposal.evidence_ids, ("policy-v1",))
        self.assertEqual(proposal.model, "test-model-2026")
        self.assertEqual((proposal.input_tokens, proposal.output_tokens), (40, 12))
        self.assertEqual(len(requests), 1)
        path, auth, request = requests[0]
        self.assertEqual(path, "/v1/chat/completions")
        self.assertEqual(auth, "Bearer local-test-key")
        self.assertEqual(request["model"], "test-model")
        self.assertEqual(request["response_format"], {"type": "json_object"})
        system, user = request["messages"]
        self.assertEqual(system["role"], "system")
        self.assertIn("handoff", system["content"])
        self.assertNotIn(CONTEXT["agent"]["instructions"], system["content"])
        self.assertEqual(user["role"], "user")
        self.assertEqual(json.loads(user["content"]), CONTEXT)

    def test_http_adapter_rejects_wrong_types_actions_and_evidence(self):
        cases = [
            reply(action=True),
            reply(action="approve_without_review"),
            reply(rationale=" "),
            reply(evidence=["fabricated-id"]),
            reply(evidence="policy-v1"),
        ]
        for response in cases:
            with self.subTest(response=response):
                with model_server(result=response) as (base_url, _):
                    model = OpenAICompatibleModel(base_url, "test-model")
                    with self.assertRaises(ModelError):
                        model.propose(CONTEXT)

    def test_http_error_does_not_expose_response_or_key(self):
        with model_server(status=503, raw=b"private provider error") as (base_url, _):
            model = OpenAICompatibleModel(base_url, "test-model", "local-test-key")
            with self.assertRaises(ModelError) as caught:
                model.propose(CONTEXT)

        error = str(caught.exception)
        self.assertIn("503", error)
        self.assertNotIn("private provider error", error)
        self.assertNotIn("local-test-key", error)

    def test_http_redirect_is_not_followed_with_an_api_key(self):
        with model_server(result=reply()) as (destination, requests):
            with model_server(status=302, headers={"Location": destination}) as (base_url, _):
                model = OpenAICompatibleModel(base_url, "test-model", "local-test-key")
                with self.assertRaises(ModelError):
                    model.propose(CONTEXT)
        self.assertEqual(requests, [])

    def test_configured_endpoint_requires_a_model_name_and_https_or_loopback(self):
        with patch.dict(os.environ, {"AI_NATIVE_MODEL_BASE_URL": "https://example.test/v1"}, clear=True):
            with self.assertRaises(ModelError):
                load_model()
        with self.assertRaises(ModelError):
            OpenAICompatibleModel("http://example.test/v1", "test-model", "local-test-key")


if __name__ == "__main__":
    unittest.main()
