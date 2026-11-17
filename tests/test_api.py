import json
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import test_runtime
from ai_native_system.api import make_server


class ApiTests(unittest.TestCase):
    def setUp(self):
        test_runtime.RuntimeTests.setUp(self)
        self.request_token = "r" * 32
        self.review_token = "v" * 32
        self.server = make_server(self.runtime, {
            self.request_token: {"tenant": "local", "actor": "requester"},
            self.review_token: {"tenant": "local", "actor": "reviewer"},
            "x" * 32: {"tenant": "other", "actor": "outsider"},
        }, 0)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.addCleanup(self.stop)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def request(self, path, token, body=None):
        req = Request(
            f"http://127.0.0.1:{self.server.server_port}{path}",
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
        )
        try:
            with urlopen(req, timeout=3) as response:
                return json.load(response)
        except HTTPError as error:
            error.close()
            raise

    def test_normal_api_flow_and_bound_identity(self):
        task = self.request("/v1/tasks", self.request_token, {
            "application": "single", "object_id": "asset-1", "request_key": "http",
        })
        path = "/v1/tasks/" + task["id"]
        self.assertEqual(self.request(path + "/advance", self.request_token, {})["status"], "awaiting_approval")
        with self.assertRaises(HTTPError) as error:
            self.request(path + "/decision", self.request_token, {"verdict": "approve"})
        self.assertEqual(error.exception.code, 403)
        self.request(path + "/decision", self.review_token, {"verdict": "approve"})
        self.assertEqual(self.request(path + "/advance", self.request_token, {})["status"], "completed")
        self.assertEqual(len(self.request(path, self.review_token)["effects"]), 1)
        for token in ("invalid", "x" * 32):
            with self.subTest(token=token), self.assertRaises(HTTPError):
                self.request(path, token)

    def test_body_cannot_override_authenticated_identity(self):
        with self.assertRaises(HTTPError) as error:
            self.request("/v1/tasks", self.request_token, {
                "application": "single", "object_id": "asset-1", "request_key": "bad",
                "tenant": "other", "actor": "reviewer",
            })
        self.assertEqual(error.exception.code, 400)

    def test_requester_can_inspect_after_application_removed_without_reviving_execution(self):
        task = self.request("/v1/tasks", self.request_token, {
            "application": "single", "object_id": "asset-1", "request_key": "historical",
        })
        path = "/v1/tasks/" + task["id"]
        self.request(path + "/advance", self.request_token, {})
        self.request(path + "/decision", self.review_token, {"verdict": "approve"})
        del self.runtime.registry.applications["single"]
        self.assertEqual(self.request(path, self.request_token)["task"]["status"], "ready")
        with self.assertRaises(HTTPError) as error:
            self.request(path, self.review_token)
        self.assertEqual(error.exception.code, 403)
        self.assertEqual(self.request(path + "/advance", self.request_token, {})["status"], "blocked")
        self.assertEqual(self.request(path, self.request_token)["effects"], [])
