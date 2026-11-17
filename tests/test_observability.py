import base64
import importlib.util
import json
import os
import secrets
import threading
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ai_native_system.observability import (
    LangfuseExporter, TraceExportError, drain_model_traces, enqueue_model_trace, model_trace_id,
)

from p2b_support import restricted_role


TEST_DSN = os.environ.get("AI_NATIVE_P5_TEST_DSN")
LANGFUSE_AVAILABLE = importlib.util.find_spec("langfuse") is not None


@contextmanager
def otlp_server(*responses):
    requests = []
    replies = iter(responses)

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            raw = self.rfile.read(int(self.headers["content-length"]))
            requests.append((self.path, {key.lower(): value for key, value in self.headers.items()}, raw))
            status, body, *content_type = next(replies)
            self.send_response(status)
            self.send_header("Content-Type", content_type[0] if content_type else "application/x-protobuf")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()
        try:
            yield "http://127.0.0.1:" + str(server.server_port), requests
        finally:
            server.shutdown()
            thread.join()


def sample_event():
    return {
        "event_id": "a" * 64, "trace_id": "b" * 32, "kind": "generation", "outcome": "succeeded",
        "tenant_ref": "c" * 64, "call_ref": "d" * 64, "attempt_ref": "e" * 64, "task_ref": "f" * 64,
        "action_ref": None, "evidence_ref": None, "provider_ref": None, "route_ref": None,
        "input_tokens": 10, "output_tokens": 20, "cost_nanos": 560, "elapsed_ms": 42,
        "created_ns": 1_700_000_000_000_000_000,
    }


@unittest.skipUnless(LANGFUSE_AVAILABLE, "Install the Langfuse integration")
class LangfuseExporterTests(unittest.TestCase):
    def test_otlp_span_matches_langfuse_and_uses_allowlisted_fields(self):
        from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

        event = dict(sample_event(), prompt="secret-prompt", output="secret-output", credential="secret-key")
        with otlp_server((200, b""), (200, b"")) as (host, requests):
            exporter = LangfuseExporter(host=host, public_key="local-public", secret_key="local-secret")
            exporter.export(event)
            exporter.export(event)
        path, headers, body = requests[0]
        self.assertEqual(path, "/api/public/otel/v1/traces")
        self.assertEqual(headers["authorization"], "Basic " + base64.b64encode(b"local-public:local-secret").decode())
        self.assertEqual(headers["x-langfuse-ingestion-version"], "4")
        self.assertEqual(headers["x-langfuse-sdk-version"], "5.2.0")
        self.assertEqual(headers["content-type"], "application/x-protobuf")
        self.assertEqual(body, requests[1][2])
        for secret in ("secret-prompt", "secret-output", "secret-key", "local-secret"):
            self.assertNotIn(secret.encode(), body)
        packet = ExportTraceServiceRequest.FromString(body)
        span = packet.resource_spans[0].scope_spans[0].spans[0]
        attrs = {entry.key: entry.value.string_value for entry in span.attributes}
        self.assertEqual(span.trace_id.hex(), event["trace_id"])
        self.assertEqual(span.span_id.hex(), event["event_id"][:16])
        self.assertEqual(span.end_time_unix_nano - span.start_time_unix_nano, 42_000_000)
        self.assertEqual(attrs["langfuse.observation.type"], "generation")
        self.assertEqual(json.loads(attrs["langfuse.observation.usage_details"]), {"input": 10, "output": 20})
        self.assertEqual(json.loads(attrs["langfuse.observation.metadata.task_ref"]), event["task_ref"])

    def test_redirect_unavailable_malformed_and_partial_rejection_are_failures(self):
        from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceResponse

        partial = ExportTraceServiceResponse()
        partial.partial_success.rejected_spans = 1
        cases = ((302, b""), (500, b"remote private error"), (200, b"not protobuf"),
                 (200, partial.SerializeToString()),
                 (200, b'{"error":"unauthorized"}', "application/json"),
                 (200, b'{"partialSuccess":{"rejectedSpans":"1"}}', "application/json"))
        with otlp_server(*cases) as (host, requests):
            exporter = LangfuseExporter(host=host, public_key="local-public", secret_key="local-secret")
            for _ in cases:
                with self.assertRaisesRegex(TraceExportError, "^Langfuse OTLP export failed$"):
                    exporter.export(sample_event())
        self.assertEqual(len(requests), len(cases))

    def test_langfuse_json_job_acknowledges_queue_acceptance(self):
        responses = ((200, b'{"name":"otel-ingestion-job","id":"123"}', "application/json; charset=utf-8"),
                     (200, b"{}", "application/json"))
        with otlp_server(*responses) as (host, requests):
            exporter = LangfuseExporter(host=host, public_key="local-public", secret_key="local-secret")
            for _ in responses:
                exporter.export(sample_event())
        self.assertEqual(len(requests), len(responses))

    def test_invalid_references_and_counts_never_reach_transport(self):
        with otlp_server() as (host, requests):
            exporter = LangfuseExporter(host=host, public_key="local-public", secret_key="local-secret")
            for event in (dict(sample_event(), task_ref="private-task"), dict(sample_event(), cost_nanos="private-cost")):
                with self.assertRaises(TraceExportError):
                    exporter.export(event)
        self.assertEqual(requests, [])


@unittest.skipUnless(TEST_DSN, "Run the P5 PostgreSQL verification runner")
class PostgresTraceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from ai_native_system.adapters.postgres import migrate_postgres
        from ai_native_system.adapters.postgres_runtime import PostgresRuntimeStore

        migrate_postgres(TEST_DSN)
        producer = restricted_role(("SELECT, INSERT ON ai_native.model_trace_outbox",), TEST_DSN)
        worker = restricted_role((
            "SELECT ON ai_native.model_trace_outbox",
            "UPDATE (state, attempts, lease_token, lease_until, available_at, sent_at, last_error) "
            "ON ai_native.model_trace_outbox",
        ), TEST_DSN)
        cls.producer = cls.enterClassContext(PostgresRuntimeStore(producer))
        cls.worker = cls.enterClassContext(PostgresRuntimeStore(worker))

    def setUp(self):
        self.tenant = "p5-trace-" + secrets.token_hex(6)

    def enqueue(self, attempt="private-attempt", *, tenant=None, **fields):
        tenant = tenant or self.tenant
        with self.producer.transaction(tenant=tenant, write=True) as connection:
            return enqueue_model_trace(
                connection, tenant=tenant, call_id="private-call", attempt_id=attempt, kind="embedding",
                status="timeout", task_id="private-task", action_id="private-action", evidence_id="private-evidence",
                provider="private-provider-key", route_id="private-route-key", **fields,
            )

    def row(self, *, tenant=None):
        with self.worker.transaction(tenant=tenant or self.tenant) as connection:
            found = connection.execute("SELECT * FROM model_trace_outbox ORDER BY event_id").fetchall()
            return [dict(row) for row in found]

    def retime(self, column):
        with self.worker.transaction(tenant=self.tenant, write=True) as connection:
            connection.execute(f"UPDATE model_trace_outbox SET {column} = clock_timestamp() - interval '1 hour'")

    def test_atomic_enqueue_tenant_isolation_and_replay(self):
        with self.assertRaisesRegex(RuntimeError, "rollback"):
            with self.producer.transaction(tenant=self.tenant, write=True) as connection:
                enqueue_model_trace(connection, tenant=self.tenant, call_id="call", attempt_id="rollback",
                                    kind="generation", status="succeeded")
                raise RuntimeError("rollback")
        self.assertEqual(self.row(), [])
        event = self.enqueue()
        self.assertEqual(self.enqueue(), event)
        tenant_b = self.tenant + "-b"
        self.assertEqual(self.row(tenant=tenant_b), [])
        peer = self.enqueue(tenant=tenant_b)
        rows = self.row()
        self.assertNotEqual(event, peer)
        self.assertEqual(len(rows), 1)
        self.assertIsNone(rows[0]["input_tokens"])
        self.assertNotIn("private-", repr(rows))
        self.assertEqual(rows[0]["trace_id"], model_trace_id(self.tenant, "private-call"))
        self.assertNotEqual(rows[0]["trace_id"], self.row(tenant=tenant_b)[0]["trace_id"])

    @unittest.skipUnless(LANGFUSE_AVAILABLE, "Install the Langfuse integration")
    def test_http_failure_is_retried_with_stable_ids(self):
        self.enqueue(input_tokens=10, elapsed_ms=15)
        with otlp_server((503, b"secret downstream error"), (200, b"")) as (host, requests):
            exporter = LangfuseExporter(host=host, public_key="local-public", secret_key="local-secret")
            self.assertEqual(drain_model_traces(self.worker, self.tenant, exporter)["retry"], 1)
            self.assertNotIn("secret downstream error", repr(self.row()))
            self.assertEqual(drain_model_traces(self.worker, self.tenant, exporter)["sent"], 0)
            self.retime("available_at")
            self.assertEqual(drain_model_traces(self.worker, self.tenant, exporter)["sent"], 1)
        self.assertEqual(len(requests), 2)
        self.assertEqual(requests[0][2], requests[1][2])
        row, = self.row()
        self.assertEqual((row["state"], row["attempts"]), ("sent", 2))
        self.assertIsNotNone(row["sent_at"])
        self.assertNotIn(b"private-", requests[0][2])

    def test_expired_worker_cannot_acknowledge_and_retries_are_bounded(self):
        self.enqueue()

        class ExpiringWorker:
            def export(_, event):
                self.retime("lease_until")

        class FailedWorker:
            def export(_, event):
                raise RuntimeError("private error")

        self.assertEqual(drain_model_traces(self.worker, self.tenant, ExpiringWorker(), limit=1)["stale"], 1)
        for _ in range(3):
            self.assertEqual(drain_model_traces(self.worker, self.tenant, FailedWorker())["retry"], 1)
            self.retime("available_at")
        self.assertEqual(drain_model_traces(self.worker, self.tenant, FailedWorker())["failed"], 1)
        row, = self.row()
        self.assertEqual((row["state"], row["attempts"]), ("failed", 5))
        self.assertIsNone(row["lease_token"])
        self.assertNotIn("private error", repr(row))
