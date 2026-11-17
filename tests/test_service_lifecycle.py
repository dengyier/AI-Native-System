import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import test_runtime
from ai_native_system.api import make_server


class ServiceLifecycleTests(unittest.TestCase):
    def setUp(self):
        test_runtime.RuntimeTests.setUp(self)
        self.token = "r" * 32
        self.server = make_server(self.runtime, {self.token: {"tenant": "local", "actor": "requester"}}, 0)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.addCleanup(self.stop)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def request(self, path, body=None, authenticated=False):
        request = Request(
            f"http://127.0.0.1:{self.server.server_port}{path}",
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": f"Bearer {self.token}"} if authenticated else {},
        )
        try:
            with urlopen(request, timeout=3) as response:
                return response.status, json.load(response)
        except HTTPError as error:
            with error:
                return error.code, json.load(error)

    def test_health_stays_live_with_missing_database_and_never_creates_it(self):
        self.assertEqual(self.request("/health/live"), (200, {"status": "live"}))
        self.assertEqual(self.request("/health/ready"), (200, {"status": "ready"}))
        path = Path(self.runtime.path)
        backup = path.with_suffix(".hidden")
        path.rename(backup)
        try:
            self.assertEqual(self.request("/health/ready"), (503, {"status": "not_ready"}))
            self.assertEqual(self.request("/health/live"), (200, {"status": "live"}))
            self.assertFalse(path.exists())
        finally:
            backup.rename(path)
        self.assertEqual(self.request("/health/ready"), (200, {"status": "ready"}))
        self.assertEqual(self.request("/v1/tasks/unknown")[0], 403)

    def test_drain_rejects_new_posts_and_allows_admitted_post_to_finish(self):
        entered, finished = threading.Event(), threading.Event()
        real_submit = self.runtime.submit

        def blocked_submit(*args):
            entered.set()
            if not finished.wait(5):
                raise RuntimeError("Test did not release admitted handler")
            return real_submit(*args)

        request = {"application": "single", "object_id": "asset-1", "request_key": "admitted"}
        with patch.object(self.runtime, "submit", side_effect=blocked_submit) as submit:
            with ThreadPoolExecutor(max_workers=1) as executor:
                pending = executor.submit(self.request, "/v1/tasks", request, True)
                try:
                    self.assertTrue(entered.wait(3))
                    self.assertFalse(self.server.drain(timeout=0))
                    self.assertEqual(self.request("/health/ready"), (503, {"status": "not_ready"}))
                    self.assertEqual(self.request("/health/live"), (200, {"status": "live"}))
                    rejected = {**request, "request_key": "rejected"}
                    self.assertEqual(self.request("/v1/tasks", rejected, True)[0], 503)
                    submit.assert_called_once()
                finally:
                    finished.set()
                status, task = pending.result(timeout=3)
        self.assertEqual(status, 200)
        self.assertTrue(self.server.drain(timeout=3))
        self.assertEqual(self.request(f"/v1/tasks/{task['id']}", authenticated=True)[0], 200)
