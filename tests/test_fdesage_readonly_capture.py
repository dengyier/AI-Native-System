"""Readonly source contracts reject ambiguity and never forward service credentials."""

import json
import multiprocessing
import time
import unittest
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Event, Thread

from ai_native_system.fdesage_readonly import (
    MAX_SNAPSHOT_BYTES, SOURCE_RELEASE, SnapshotClient, SnapshotContractError, SnapshotScope,
    SnapshotUnavailable, validate_snapshot,
)


def scope():
    return SnapshotScope(workspace_id="1", project_id="2", document_id="3", document_version=4,
                         subject_user_id="5", membership_generation=1, delegation_id="capture-1",
                         service_id="ains-shadow")


def sample():
    return {
        "profile": "fdesage-ains-readonly-snapshot/1", "application": "fdesage", "contractVersion": 1,
        "coverage": "selected_object", "sourceRelease": SOURCE_RELEASE,
        "workspaceId": "1", "projectId": "2", "documentId": "3", "documentVersion": 4,
        "contentDigest": {"algorithm": "sha256", "canonicalization": "utf8-exact", "value": "a" * 64},
        "sourceVersion": None, "streamPosition": None, "cursor": None,
        "capturedAt": "2026-11-24T01:02:03.000Z",
        "authorization": {"subjectUserId": "5", "membershipGeneration": 1,
                          "delegationId": "capture-1", "serviceId": "ains-shadow"},
    }


class SourceFixture:
    def __init__(self, body=None, status=200, headers=None, drip=None):
        self.body = json.dumps(sample()).encode() if body is None else body
        self.status, self.headers, self.requests = status, headers or {}, []
        self.drip, self.stopped = drip, Event()
        self.fragment_sent = Event()

    def __enter__(self):
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                fixture.requests.append((self.path, dict(self.headers)))
                if fixture.drip:
                    try:
                        header = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n"
                        if fixture.drip == "headers":
                            for byte in header:
                                self.connection.sendall(bytes([byte]))
                                fixture.fragment_sent.set()
                                if fixture.stopped.wait(0.05):
                                    return
                            self.connection.sendall(fixture.body)
                        else:
                            self.connection.sendall(header)
                            for byte in fixture.body:
                                self.connection.sendall(bytes([byte]))
                                fixture.fragment_sent.set()
                                if fixture.stopped.wait(0.05):
                                    return
                    except (BrokenPipeError, ConnectionResetError):
                        pass
                    return
                self.send_response(fixture.status)
                self.send_header("Content-Type", "application/json")
                for name, value in fixture.headers.items():
                    self.send_header(name, value)
                self.end_headers()
                try:
                    self.wfile.write(fixture.body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, *_):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.origin = f"http://127.0.0.1:{self.server.server_port}"
        return self

    def __exit__(self, *_):
        self.stopped.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


NOW = datetime(2026, 11, 24, 1, 2, 3, tzinfo=timezone.utc)


class SnapshotContractTests(unittest.TestCase):
    def test_exact_selected_scope_and_unknown_native_positions_are_preserved(self):
        document = sample()
        accepted = validate_snapshot(document, scope())
        self.assertEqual(accepted, document)
        document["authorization"]["serviceId"] = "modified"
        self.assertEqual(accepted["authorization"]["serviceId"], "ains-shadow")

    def test_unexpected_scope_schema_version_content_and_provenance_fail_closed(self):
        changes = [
            ("workspaceId", "2"), ("documentId", "03"), ("documentVersion", True),
            ("documentVersion", 3), ("contractVersion", True), ("contractVersion", 2),
            ("sourceRelease", "latest"), ("coverage", "complete"), ("cursor", "invented"),
            ("sourceVersion", 1), ("streamPosition", 1), ("capturedAt", "2026-11-24T01:02:03"),
            ("capturedAt", "2026-02-30T01:02:03Z"), ("markdown", "should never leave the source"),
            ("authorization", {**sample()["authorization"], "subjectUserId": "6"}),
            ("authorization", {**sample()["authorization"], "membershipGeneration": 2}),
            ("contentDigest", {"algorithm": "sha256", "canonicalization": "utf8-exact", "value": "A" * 64}),
        ]
        for name, value in changes:
            with self.subTest(name=name, value=value), self.assertRaises(SnapshotContractError):
                validate_snapshot({**sample(), name: value}, scope())
        missing = sample()
        del missing["cursor"]
        with self.assertRaises(SnapshotContractError):
            validate_snapshot(missing, scope())

    def test_scope_cannot_expand_to_arbitrary_urls_or_noncanonical_ids(self):
        for change in ({"project_id": "../payments"}, {"document_version": False}, {"workspace_id": "01"},
                       {"membership_generation": 0}, {"service_id": "line\nbreak"}):
            values = vars(scope()) | change
            with self.subTest(change=change), self.assertRaises(ValueError):
                SnapshotScope(**values)


class SnapshotTransportTests(unittest.TestCase):
    def assert_source_readers_reaped(self):
        self.assertEqual([child.name for child in multiprocessing.active_children()
                          if child.name == "ains-fdesage-source-read"], [])

    def test_total_budget_cancels_dripped_headers_and_reaps_the_reader(self):
        with SourceFixture(drip="headers") as source:
            started = time.monotonic()
            with self.assertRaisesRegex(SnapshotUnavailable, "total time budget") as failure:
                SnapshotClient(source.origin, "secret-test-token", scope(), timeout=0.6, clock=lambda: NOW).capture()
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 1.5)
            self.assertTrue(source.fragment_sent.is_set())
            self.assertNotIn("secret-test-token", str(failure.exception))
            self.assert_source_readers_reaped()

    def test_total_budget_cancels_dripped_body_and_reaps_the_reader(self):
        with SourceFixture(drip="body") as source:
            started = time.monotonic()
            with self.assertRaisesRegex(SnapshotUnavailable, "total time budget"):
                SnapshotClient(source.origin, "secret-test-token", scope(), timeout=0.6, clock=lambda: NOW).capture()
            self.assertLess(time.monotonic() - started, 1.5)
            self.assertTrue(source.fragment_sent.is_set())
            self.assert_source_readers_reaped()

    def test_immediate_source_failure_has_no_live_reader_or_credential_in_error(self):
        with SourceFixture(status=503) as source:
            with self.assertRaises(SnapshotUnavailable) as failure:
                SnapshotClient(source.origin, "secret-test-token", scope(), timeout=2, clock=lambda: NOW).capture()
            self.assertNotIn("secret-test-token", str(failure.exception))
            self.assert_source_readers_reaped()

    def test_actual_loopback_request_uses_exact_route_and_detached_metadata_only(self):
        with SourceFixture() as source:
            client = SnapshotClient(source.origin, "secret-test-token", scope(), clock=lambda: NOW)
            self.assertEqual(client.capture(), sample())
            path, headers = source.requests[0]
            self.assertEqual(path, "/api/integrations/ains/projects/2/documents/3/versions/4/snapshot")
            self.assertEqual(headers["Authorization"], "Bearer secret-test-token")
            self.assertNotIn("secret-test-token", repr(client))

    def test_redirect_does_not_receive_a_second_request_or_forward_credentials(self):
        with SourceFixture() as destination, SourceFixture(status=302, headers={"Location": destination.origin}) as source:
            with self.assertRaises(SnapshotUnavailable) as failure:
                SnapshotClient(source.origin, "secret-test-token", scope(), clock=lambda: NOW).capture()
            self.assertEqual(destination.requests, [])
            self.assertNotIn("secret-test-token", str(failure.exception))

    def test_error_oversize_duplicate_fields_nonfinite_and_stale_responses_are_rejected(self):
        duplicate = json.dumps(sample()).replace('"documentVersion": 4', '"documentVersion": 4,"documentVersion": 4')
        stale = {**sample(), "capturedAt": "2026-11-23T01:02:03Z"}
        cases = [
            {"status": 503}, {"body": b" " * (MAX_SNAPSHOT_BYTES + 1)},
            {"body": duplicate.encode()}, {"body": b'{"secret": NaN}'},
            {"body": json.dumps(stale).encode()}, {"headers": {"Content-Encoding": "gzip"}},
            {"headers": {"Content-Length": str(MAX_SNAPSHOT_BYTES + 1)}},
        ]
        for case in cases:
            with self.subTest(case={k: v for k, v in case.items() if k != "body"}), SourceFixture(**case) as source:
                with self.assertRaises((SnapshotUnavailable, SnapshotContractError)):
                    SnapshotClient(source.origin, "secret-test-token", scope(), clock=lambda: NOW).capture()

    def test_remote_plain_http_credentials_paths_queries_and_unbounded_timeouts_are_rejected(self):
        for origin in ("http://example.com", "https://user:password@example.com", "https://example.com/path",
                       "https://example.com?query=1", "https://example.com#fragment", "file:///tmp/source",
                       "https://example.com\\@127.0.0.1", "https://example.com:0"):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                SnapshotClient(origin, "secret-test-token", scope())
        for timeout in (0, 31, float("nan"), True):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                SnapshotClient("https://example.com", "secret-test-token", scope(), timeout=timeout)


if __name__ == "__main__":
    unittest.main()
