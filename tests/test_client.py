import json
import os
import socket
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from time import monotonic, sleep
from unittest.mock import patch

from ai_native_system.client import APIError, Client


TOKEN = "fixture-operator-bearer"


def reply(response, status=200, *, raw=b'{"status":"ready"}', other_headers=None):
    response.send_response(status)
    headers = {"Content-Type": "application/json; charset=utf-8", "Content-Length": str(len(raw)),
               **(other_headers or {})}
    for name, value in headers.items():
        response.send_header(name, value)
    response.end_headers()
    response.wfile.write(raw)


@contextmanager
def receiver(respond=reply):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            size = int(self.headers.get("content-length", "0"))
            payload = json.loads(self.rfile.read(size)) if size else None
            requests.append((self.command, self.path, self.headers.get("Authorization"), payload))
            try:
                respond(self)
            except (ConnectionError, OSError):
                pass

        do_POST = do_GET

        def log_message(self, *_args):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}", requests
        finally:
            server.shutdown()
            thread.join()


class ClientTests(unittest.TestCase):
    def test_task_operations_and_authorization_on_wire(self):
        proposal = "a" * 64
        release = "b" * 64
        citations = [{"document_id": "术语表"}]
        with receiver() as (origin, received):
            sdk = Client(origin, TOKEN)
            sdk.submit("governed", "物件", "same-key", release_digest=release, knowledge_citations=citations,
                       expected_object_version=7)
            sdk.task("case/#一个")
            sdk.events("task-id", limit=2, cursor="one+/=")
            sdk.advance("task-id")
            sdk.approve("task-id", proposal)
            sdk.reject("task-id", proposal)
            sdk.cancel("task-id")
            sdk.reconcile("task-id")
            sdk.retry_remote("task-id")
            sdk.export_evidence("task-id")
            sdk.query(application="governed", object_id="物件")

        self.assertEqual([(method, path, body) for method, path, _auth, body in received], [
            ("POST", "/v1/tasks", {"application": "governed", "object_id": "物件", "request_key": "same-key",
                                   "release_digest": release, "knowledge_citations": citations,
                                   "expected_object_version": 7}),
            ("GET", "/v1/tasks/case%2F%23%E4%B8%80%E4%B8%AA", None),
            ("GET", "/v1/tasks/task-id/events?limit=2&cursor=one%2B%2F%3D", None),
            ("POST", "/v1/tasks/task-id/advance", {}),
            ("POST", "/v1/tasks/task-id/decision", {"verdict": "approve", "proposal_digest": proposal}),
            ("POST", "/v1/tasks/task-id/decision", {"verdict": "reject", "proposal_digest": proposal}),
            ("POST", "/v1/tasks/task-id/cancel", {}),
            ("POST", "/v1/tasks/task-id/reconcile", {}),
            ("POST", "/v1/tasks/task-id/retry-remote", {}),
            ("GET", "/v1/tasks/task-id/evidence", None),
            ("POST", "/v1/query", {"application": "governed", "object_id": "物件"}),
        ])
        self.assertTrue(all(request[2] == "Bearer " + TOKEN for request in received))
        self.assertNotIn(TOKEN, repr(sdk))

    def test_application_release_fact_and_handover_wire_contracts(self):
        assessment = "9" * 64
        with receiver() as (origin, received):
            sdk = Client(origin, TOKEN)
            sdk.applications()
            sdk.run_application("checked asset", {"object_id": "a", "expected_version": 7})
            sdk.handover("claim")
            sdk.decide_handover("claim", "accept", assessment, "Follow exact source receipt")
            sdk.release("release-a")
            sdk.release_impact("release-a")
            sdk.draft_release("app", ontology={"version": "1"}, knowledge_strategy="authorized-fragments-v1")
            sdk.change_release("release-a", "publish", migration_ref="change-1")
            sdk.change_release("release-a", "select")
            sdk.fact_status("artifact", "a", "verified")
        self.assertEqual([(method, path, body) for method, path, _auth, body in received], [
            ("GET", "/v1/applications", None),
            ("POST", "/v1/applications/checked%20asset/run", {"object_id": "a", "expected_version": 7}),
            ("GET", "/v1/tasks/claim/handover", None),
            ("POST", "/v1/tasks/claim/handover", {"verdict": "accept", "assessment_digest": assessment,
                                                   "reason": "Follow exact source receipt"}),
            ("GET", "/v1/releases/release-a", None),
            ("GET", "/v1/releases/release-a/impact", None),
            ("POST", "/v1/releases/draft", {"application": "app", "ontology": {"version": "1"},
                                             "knowledge_strategy": "authorized-fragments-v1"}),
            ("POST", "/v1/releases/release-a/publish", {"migration_ref": "change-1"}),
            ("POST", "/v1/releases/release-a/select", {}),
            ("POST", "/v1/facts/status", {"object_type": "artifact", "object_id": "a", "field": "verified"}),
        ])

    def test_untrusted_origins_and_invalid_parameters_are_rejected(self):
        for origin in ("http://example.test", "http://127.0.0.1@evil.test", "https://user:token@host.test",
                       "ftp://127.0.0.1", "https://example.test/v1", " https://example.test",
                       "https://example.test?", "https://example.test#x", "https://host.test\\aaa",
                       "http://127.0.0.1:70000", "https://[bad"):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                Client(origin, TOKEN)
        with self.assertRaises(ValueError):
            Client("http://localhost", "secret\r\nx-injected: value")
        with receiver() as (origin, received):
            sdk = Client(origin, TOKEN)
            for call in (lambda: sdk.task(".."), lambda: sdk.approve("task-id", "old"),
                         lambda: sdk.events("task-id", limit=True), lambda: sdk.events("task-id", cursor=""),
                         lambda: sdk.submit("x", "x" * 66_000, "key")):
                with self.assertRaises(ValueError):
                    call()
        self.assertEqual(received, [])

    def test_redirect_does_not_forward_credentials_or_mutation(self):
        with receiver() as (other, forwarded):
            def redirect(handler):
                reply(handler, 307, other_headers={"Location": other + "/v1/tasks"})

            with receiver(redirect) as (origin, received):
                with patch.dict(os.environ, {"HTTP_PROXY": other, "ALL_PROXY": other, "NO_PROXY": ""}):
                    with self.assertRaises(APIError) as error:
                        Client(origin, TOKEN).submit("a", "b", "same-key")
        self.assertEqual(error.exception.status, 307)
        self.assertTrue(error.exception.outcome_unknown)
        self.assertEqual(len(received), 1)
        self.assertEqual(forwarded, [])

    def test_explicit_retry_preserves_request_key_after_no_reply(self):
        attempts = 0

        def lose_first(handler):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                handler.connection.shutdown(socket.SHUT_RDWR)
            else:
                reply(handler, raw=b'{"id":"first-task"}')

        with receiver(lose_first) as (origin, received):
            sdk = Client(origin, TOKEN)
            with self.assertRaises(APIError) as error:
                sdk.submit("a", "b", "idem-key")
            self.assertTrue(error.exception.outcome_unknown)
            self.assertEqual(attempts, 1)
            self.assertEqual(sdk.submit("a", "b", "idem-key"), {"id": "first-task"})
        self.assertEqual([item[3]["request_key"] for item in received], ["idem-key", "idem-key"])

    def test_bad_responses_are_bounded_and_no_server_message_is_exposed(self):
        cases = (
            (b'{"result":1,"result":2}', {}, 200, None),
            (b'{"value": NaN}', {}, 200, None),
            (b'{"value": 1e999}', {}, 200, None),
            (b'{"x":1}', {"Content-Length": str(5 * 1024 * 1024)}, 200, None),
            (b'{"x":1}', {"Content-Length": "10"}, 200, None),
            (b'<html>', {"Content-Type": "text/html"}, 200, None),
            (json.dumps({"error": TOKEN}).encode(), {}, 403, 403),
            (json.dumps({"error": TOKEN}).encode(), {}, 503, 503),
        )
        for raw, headers, status, result_status in cases:
            with self.subTest(status=status, headers=headers), receiver(
                lambda handler: reply(handler, status, raw=raw, other_headers=headers),
            ) as (origin, received):
                with self.assertRaises(APIError) as error:
                    Client(origin, TOKEN).cancel("task-id")
                self.assertEqual(len(received), 1)
                self.assertEqual(error.exception.status, result_status)
                self.assertEqual(error.exception.outcome_unknown, status != 403)
                self.assertNotIn(TOKEN, str(error.exception))

    def test_wall_deadline_also_covers_trickled_headers(self):
        def drip(handler):
            handler.wfile.write(b"HTTP/1.1 200 OK\r\n")
            for _ in range(100):
                handler.wfile.write(b"X-Drip: x\r\n")
                sleep(0.025)

        with receiver(drip) as (origin, requests):
            started = monotonic()
            with self.assertRaises(APIError) as error:
                Client(origin, TOKEN, timeout=0.12).advance("task-id")
            self.assertLess(monotonic() - started, 1)
            self.assertTrue(error.exception.outcome_unknown)
        self.assertEqual(len(requests), 1)
