"""Persist and export allowlisted model-attempt metadata outside the workflow."""

import asyncio
import json
import math
import re
from hashlib import sha256
from urllib.parse import urlsplit
from uuid import uuid4


_LEASE_SECONDS = 30
_MAX_ATTEMPTS = 5
_KINDS = ("generation", "embedding")
_OUTCOMES = ("succeeded", "failed", "timeout", "cancelled")
_REFERENCE_FIELDS = ("tenant_ref", "call_ref", "attempt_ref", "task_ref", "action_ref",
                     "evidence_ref", "provider_ref", "route_ref")
_REFERENCE_FORMAT = re.compile("[0-9a-f]{64}")


def _reference(tenant, purpose, *parts):
    if any(type(value) is not str or not value for value in (tenant, *parts)):
        raise ValueError("Trace references must be nonempty strings")
    material = json.dumps(("ai-native/model-trace/v1", tenant, purpose, *parts), separators=(",", ":"))
    return sha256(material.encode("utf-8")).hexdigest()


def model_trace_id(tenant, call_id):
    """Return the stable trace identifier for all attempts of a logical call."""
    return _reference(tenant, "call", call_id)[:32]


def enqueue_model_trace(connection, *, tenant, call_id, attempt_id, kind, status, task_id=None,
                        action_id=None, evidence_id=None, provider=None, route_id=None,
                        input_tokens=None, output_tokens=None, cost_nanos=None, elapsed_ms=None):
    """Use the caller's transaction. Only fixed outcomes, counts and pseudonyms are stored."""
    if kind not in _KINDS or status not in _OUTCOMES:
        raise ValueError("Invalid model trace kind or outcome")
    counts = (input_tokens, output_tokens, cost_nanos, elapsed_ms)
    if any(value is not None and (type(value) is not int or not 0 <= value < 2**63) for value in counts):
        raise ValueError("Model trace counts must be nonnegative integers")
    call_ref = _reference(tenant, "call", call_id)
    event_id = _reference(tenant, "event", call_id, attempt_id)
    optional = (task_id, action_id, evidence_id, provider, route_id)
    refs = tuple(_reference(tenant, field, value) if value is not None else None
                 for field, value in zip(_REFERENCE_FIELDS[3:], optional, strict=True))
    connection.execute(
        """INSERT INTO model_trace_outbox
           (tenant, event_id, trace_id, tenant_ref, call_ref, attempt_ref, task_ref, action_ref,
            evidence_ref, provider_ref, route_ref, kind, outcome, input_tokens, output_tokens, cost_nanos, elapsed_ms)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT (tenant, event_id) DO NOTHING""",
        (tenant, event_id, call_ref[:32], _reference(tenant, "tenant"), call_ref,
         _reference(tenant, "attempt", call_id, attempt_id), *refs, kind, status, *counts),
    )
    return event_id


class TraceExportError(RuntimeError):
    """The configured endpoint has not acknowledged the observation."""


class LangfuseExporter:
    """Send the Langfuse SDK's OTLP attributes and require an explicit delivery response."""

    def __init__(self, *, host, public_key, secret_key, timeout=5):
        import httpx
        from langfuse import __version__ as langfuse_version

        endpoint = urlsplit(host)
        if (not endpoint.hostname or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment
                or not (endpoint.scheme == "https" or
                        (endpoint.scheme == "http" and endpoint.hostname in ("127.0.0.1", "::1", "localhost")))):
            raise ValueError("Langfuse requires an HTTPS base URL or a local HTTP base URL")
        if (type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 10
                or not public_key or not secret_key):
            raise ValueError("Langfuse requires credentials and a timeout of at most ten seconds")
        self._httpx = httpx
        self._endpoint = host.rstrip("/") + "/api/public/otel/v1/traces"
        self._auth = httpx.BasicAuth(public_key, secret_key)
        self._timeout = timeout
        self._headers = {
            "Content-Type": "application/x-protobuf",
            "Accept-Encoding": "identity",
            "x-langfuse-sdk-name": "python",
            "x-langfuse-sdk-version": langfuse_version,
            "x-langfuse-public-key": public_key,
            "x-langfuse-ingestion-version": "4",
        }

    def export(self, event):
        # Do not enable SDK ambient instrumentation or its asynchronous queue. PostgreSQL
        # owns retries, and this worker must observe acceptance of this exact span.
        try:
            asyncio.run(self._send(_otlp_packet(event)))
        except Exception:
            raise TraceExportError("Langfuse OTLP export failed") from None

    async def _send(self, packet):
        async with asyncio.timeout(self._timeout):
            async with self._httpx.AsyncClient(
                timeout=self._timeout, auth=self._auth, follow_redirects=False, trust_env=False,
            ) as client:
                async with client.stream("POST", self._endpoint, content=packet, headers=self._headers) as response:
                    if response.status_code != 200:
                        raise TraceExportError
                    body = bytearray()
                    async for chunk in response.aiter_raw():
                        body.extend(chunk)
                        if len(body) > 65_536:
                            raise TraceExportError
                    content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                    _require_accepted(bytes(body), content_type)


def _require_accepted(body, content_type):
    from google.protobuf.json_format import ParseDict
    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceResponse

    if content_type == "application/json":
        reply = json.loads(body)
        if not isinstance(reply, dict):
            raise TraceExportError
        # Langfuse's public OTLP endpoint can return its ingestion job in JSON.
        if (reply.get("name") == "otel-ingestion-job"
                and isinstance(reply.get("id"), str) and reply["id"]):
            return
        response = ParseDict(reply, ExportTraceServiceResponse())
    elif content_type == "application/x-protobuf" or not body:
        response = ExportTraceServiceResponse.FromString(body)
    else:
        raise TraceExportError
    if response.partial_success.rejected_spans:
        raise TraceExportError


def _otlp_packet(event):
    from langfuse._client.attributes import LangfuseOtelSpanAttributes, create_generation_attributes
    from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest

    kind, outcome = event["kind"], event["outcome"]
    if kind not in _KINDS or outcome not in _OUTCOMES:
        raise ValueError("Invalid model trace kind or outcome")
    metadata = {name: event[name] for name in _REFERENCE_FIELDS if event[name] is not None}
    if any(not _REFERENCE_FORMAT.fullmatch(value) for value in metadata.values()):
        raise ValueError("Invalid trace reference")
    counts = ("input_tokens", "output_tokens", "elapsed_ms", "cost_nanos")
    if any(event[name] is not None and (type(event[name]) is not int or event[name] < 0) for name in counts):
        raise ValueError("Invalid trace counts")
    metadata.update({name: event[name] for name in ("elapsed_ms", "cost_nanos") if event[name] is not None})
    metadata["outcome"] = outcome
    usage = {name: event[name + "_tokens"] for name in ("input", "output") if event[name + "_tokens"] is not None}
    cost = event["cost_nanos"]
    attributes = create_generation_attributes(
        metadata=metadata, usage_details=usage or None,
        cost_details=None if cost is None else {"total": cost / 1_000_000_000},
        level="DEFAULT" if outcome == "succeeded" else "ERROR",
        observation_type=kind,
    )
    attributes[LangfuseOtelSpanAttributes.TRACE_NAME] = "ai-native.model." + kind
    request = ExportTraceServiceRequest()
    resource = request.resource_spans.add()
    resource.resource.attributes.add(key="service.name").value.string_value = "ai-native-system"
    scope = resource.scope_spans.add()
    scope.scope.name = "ai_native_system.model"
    end = event["created_ns"]
    span = scope.spans.add(
        name="ai-native.model." + kind,
        trace_id=bytes.fromhex(event["trace_id"]),
        span_id=bytes.fromhex(event["event_id"][:16]),
        start_time_unix_nano=max(1, end - (event["elapsed_ms"] or 0) * 1_000_000),
        end_time_unix_nano=end,
    )
    for name, value in attributes.items():
        span.attributes.add(key=name).value.string_value = value
    return request.SerializeToString()


def drain_model_traces(store, tenant, exporter, *, limit=20):
    """Claim events in short transactions and send outside the database lock."""
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Model trace batch limit must be between one and one hundred")
    result = dict.fromkeys(("sent", "retry", "failed", "stale"), 0)
    for _ in range(limit):
        token = uuid4().hex
        with store.transaction(tenant=tenant, write=True) as connection:
            row = connection.execute(
                """SELECT *, (extract(epoch FROM created_at) * 1000000000)::bigint AS created_ns
                   FROM model_trace_outbox
                   WHERE tenant = ? AND ((state = 'pending' AND available_at <= clock_timestamp())
                       OR (state = 'sending' AND lease_until <= clock_timestamp()))
                   ORDER BY COALESCE(lease_until, available_at), event_id LIMIT 1 FOR UPDATE SKIP LOCKED""",
                (tenant,),
            ).fetchone()
            if row is None:
                break
            if row["attempts"] >= _MAX_ATTEMPTS:
                connection.execute(
                    """UPDATE model_trace_outbox SET state = 'failed', lease_token = NULL, lease_until = NULL,
                           last_error = 'lease_expired' WHERE tenant = ? AND event_id = ?""",
                    (tenant, row["event_id"]),
                )
                result["failed"] += 1
                continue
            connection.execute(
                """UPDATE model_trace_outbox SET state = 'sending', attempts = attempts + 1, lease_token = ?,
                       lease_until = clock_timestamp() + (? * interval '1 second')
                   WHERE tenant = ? AND event_id = ?""",
                (token, _LEASE_SECONDS, tenant, row["event_id"]),
            )
        # Pass only the typed envelope to the exporter, excluding tenant and queue state.
        event = {field: row[field] for field in (
            "event_id", "trace_id", "kind", "outcome", "input_tokens", "output_tokens", "cost_nanos",
            "elapsed_ms", "created_ns", *_REFERENCE_FIELDS,
        )}
        try:
            exporter.export(event)
        except Exception:
            outcome = "failed" if row["attempts"] + 1 >= _MAX_ATTEMPTS else "retry"
        else:
            outcome = "sent"
        with store.transaction(tenant=tenant, write=True) as connection:
            updated = connection.execute(
                """UPDATE model_trace_outbox SET state = ?, lease_token = NULL, lease_until = NULL,
                       available_at = clock_timestamp() + (? * interval '1 second'),
                       sent_at = CASE WHEN ? = 'sent' THEN clock_timestamp() END,
                       last_error = CASE WHEN ? = 'sent' THEN NULL ELSE 'export_failed' END
                   WHERE tenant = ? AND event_id = ? AND state = 'sending' AND lease_token = ?
                       AND lease_until > clock_timestamp()""",
                ("pending" if outcome == "retry" else outcome, 2 ** (row["attempts"] + 1),
                 outcome, outcome, tenant, row["event_id"], token),
            ).rowcount
        result[outcome if updated else "stale"] += 1
    return result
