"""Bounded FDE source capture; historical metadata, never an execution authorization.

This adapter does not infer a source event version, continuous cursor or current
end-user permission from a successful point-in-time source read.
"""

import json
import math
import multiprocessing
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from .registry import Registry, unique_keys
from .storage import digest, encode, object_data


PROFILE = "fdesage-ains-readonly-snapshot/1"
SOURCE_RELEASE = "fdesage-backend:31a58ae4d8310a71a0ed3c49971b0a9b6410fb1a+ains-readonly/1"
MAX_SNAPSHOT_BYTES = 64 * 1024
_SAFE_INTEGER = 2**53 - 1
_ID = re.compile(r"[1-9][0-9]{0,19}")
_INSTANT = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z")
_FIELDS = {
    "profile", "application", "contractVersion", "coverage", "sourceRelease", "workspaceId", "projectId",
    "documentId", "documentVersion", "contentDigest", "sourceVersion", "streamPosition", "cursor",
    "capturedAt", "authorization",
}
_OBSERVATION_TYPE = "fdesage_captured_observation"
_PROPERTY_TYPES = {
    "snapshot_json": "string", "source_profile": "string", "source_release": "string", "coverage": "string",
    "captured_at": "string", "source_workspace_id": "string", "source_project_id": "string",
    "source_document_id": "string", "document_version": "integer", "content_sha256": "string",
    "subject_user_id": "string", "membership_generation": "integer", "delegation_id": "string",
    "service_id": "string", "observation_digest": "string", "ontology_digest": "string",
}


class SnapshotContractError(ValueError):
    """The source response does not establish the selected capture contract."""


class SnapshotUnavailable(RuntimeError):
    """The selected source could not supply a bounded, fresh response."""


def _positive_integer(value):
    return type(value) is int and 1 <= value <= _SAFE_INTEGER


def _identifier(value):
    return (type(value) is str and 1 <= len(value) <= 128
            and all(33 <= ord(char) <= 126 for char in value))


@dataclass(frozen=True)
class SnapshotScope:
    """Trusted operator mapping; never populated from an untrusted response."""

    workspace_id: str
    project_id: str
    document_id: str
    document_version: int
    subject_user_id: str
    membership_generation: int
    delegation_id: str
    service_id: str

    def __post_init__(self):
        for value in (self.workspace_id, self.project_id, self.document_id, self.subject_user_id):
            if type(value) is not str or _ID.fullmatch(value) is None:
                raise ValueError("Expected a canonical positive decimal source ID")
        if not all(map(_positive_integer, (self.document_version, self.membership_generation))):
            raise ValueError("Expected positive source document and membership versions")
        if not all(map(_identifier, (self.delegation_id, self.service_id))):
            raise ValueError("Expected bounded service and delegation identifiers")

    @property
    def authorization(self):
        return {"subjectUserId": self.subject_user_id, "membershipGeneration": self.membership_generation,
                "delegationId": self.delegation_id, "serviceId": self.service_id}


def _instant(value):
    if type(value) is not str or _INSTANT.fullmatch(value) is None:
        raise SnapshotContractError("Expected an explicit UTC capture instant")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise SnapshotContractError("Invalid capture instant") from error


def validate_snapshot(document, scope):
    """Validate and detach only metadata for one specifically delegated version."""
    if not isinstance(scope, SnapshotScope):
        raise ValueError("A trusted source scope is required")
    if type(document) is not dict or document.keys() != _FIELDS:
        raise SnapshotContractError("Unexpected source snapshot shape")
    expected = {
        "profile": PROFILE, "application": "fdesage", "coverage": "selected_object", "sourceRelease": SOURCE_RELEASE,
        "workspaceId": scope.workspace_id, "projectId": scope.project_id, "documentId": scope.document_id,
        "documentVersion": scope.document_version, "contractVersion": 1,
        "authorization": scope.authorization, "sourceVersion": None, "streamPosition": None, "cursor": None,
    }
    if any(document[name] != value for name, value in expected.items()):
        raise SnapshotContractError("Source contract or delegated resource differs")
    authorization = document["authorization"]
    if (type(document["contractVersion"]) is not int or not _positive_integer(document["documentVersion"])
            or type(authorization) is not dict or authorization.keys() != scope.authorization.keys()
            or not _positive_integer(authorization["membershipGeneration"])):
        raise SnapshotContractError("Invalid source snapshot versions or authorization")
    content = document["contentDigest"]
    if (type(content) is not dict or content.keys() != {"algorithm", "canonicalization", "value"}
            or content["algorithm"] != "sha256" or content["canonicalization"] != "utf8-exact"
            or type(content["value"]) is not str or re.fullmatch(r"[0-9a-f]{64}", content["value"]) is None):
        raise SnapshotContractError("Unsupported source content digest")
    _instant(document["capturedAt"])
    try:
        payload = encode(document).encode("utf-8")
        if len(payload) > MAX_SNAPSHOT_BYTES:
            raise SnapshotContractError("Snapshot exceeds the metadata limit")
        return json.loads(payload)
    except (ValueError, TypeError, OverflowError, UnicodeError, RecursionError) as error:
        raise SnapshotContractError("Invalid source snapshot metadata") from error


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _reject_constant(_):
    raise ValueError("Non-finite JSON")


def _origin(value):
    if type(value) is not str or not value or any(not 33 <= ord(char) <= 126 or char == "\\" for char in value):
        raise ValueError("Expected an explicit source origin")
    try:
        uri = urlsplit(value)
        port = uri.port
    except ValueError as error:
        raise ValueError("Invalid source origin") from error
    if (uri.scheme not in ("https", "http") or not uri.hostname or uri.username is not None
            or uri.path not in ("", "/") or uri.query or uri.fragment or port == 0
            or (uri.scheme == "http" and uri.hostname not in ("127.0.0.1", "::1"))):
        raise ValueError("Use an HTTPS source origin; HTTP is limited to numeric loopback test hosts")
    return value.rstrip("/")


def _read_source(origin, token, path, timeout):
    request = Request(origin + path, method="GET", headers={
        "Authorization": "Bearer " + token, "Accept": "application/json", "Accept-Encoding": "identity",
    })
    opener = build_opener(ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(request, timeout=timeout) as response:
            if (response.status != 200 or response.headers.get_content_type() != "application/json"
                    or response.headers.get("Content-Encoding", "identity") != "identity"):
                raise SnapshotUnavailable("Source response is unavailable or unsupported")
            size_header = response.headers.get("Content-Length")
            if size_header is not None and (re.fullmatch(r"[0-9]{1,10}", size_header) is None
                                            or int(size_header) > MAX_SNAPSHOT_BYTES):
                raise SnapshotUnavailable("Source response exceeds the metadata limit")
            chunks, size = [], 0
            while True:
                block = response.read1(min(8192, MAX_SNAPSHOT_BYTES + 1 - size))
                if not block:
                    break
                chunks.append(block)
                size += len(block)
                if size > MAX_SNAPSHOT_BYTES:
                    raise SnapshotUnavailable("Source response exceeds the metadata limit")
            if size_header is not None and int(size_header) != size:
                raise SnapshotUnavailable("Source response was incomplete")
            return b"".join(chunks)
    except HTTPError as error:
        error.close()
        raise SnapshotUnavailable("Source capture failed") from None


def _source_reader(connection, origin, token, path, timeout):
    """The child never sends exceptions, URLs, headers or credentials over IPC."""
    try:
        try:
            payload = _read_source(origin, token, path, timeout)
            message = b"\x01" + payload
        except Exception:
            message = b"\x00"
        connection.send_bytes(message)
    except (BrokenPipeError, EOFError, OSError):
        pass
    finally:
        connection.close()


def _reap_reader(process):
    if process.pid is not None:
        if process.is_alive():
            process.terminate()
        process.join(timeout=0.2)
        if process.is_alive():
            process.kill()
            process.join(timeout=0.2)
        if process.is_alive():
            raise SnapshotUnavailable("Source reader cleanup did not finish")
    process.close()


def _bounded_source_read(origin, token, path, timeout):
    """Enforce a parent-owned budget across DNS, TLS, headers and response body.

    A thread timeout leaves blocked network work alive. A spawned helper can be
    terminated and reaped; no source credential is placed in its command line.
    """
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=_source_reader, args=(sender, origin, token, path, timeout),
                              name="ains-fdesage-source-read", daemon=True)
    deadline = time.monotonic() + timeout
    try:
        process.start()
        sender.close()
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not receiver.poll(remaining):
            raise SnapshotUnavailable("Source capture exceeded its total time budget")
        message = receiver.recv_bytes(maxlength=MAX_SNAPSHOT_BYTES + 1)
        if time.monotonic() > deadline:
            raise SnapshotUnavailable("Source capture exceeded its total time budget")
        if not message or message[0] != 1:
            raise SnapshotUnavailable("Source capture failed")
        return message[1:]
    except (EOFError, OSError):
        raise SnapshotUnavailable("Source capture failed") from None
    finally:
        sender.close()
        receiver.close()
        _reap_reader(process)


class SnapshotClient:
    """One credential, fixed origin, one delegated resource; no redirects or proxies."""

    def __init__(self, origin, source_token, scope, *, timeout=5, clock=None):
        self._origin = _origin(origin)
        if not isinstance(scope, SnapshotScope):
            raise ValueError("A trusted source scope is required")
        if (type(source_token) is not str or not 1 <= len(source_token) <= 8192
                or any(not 33 <= ord(char) <= 126 for char in source_token)):
            raise ValueError("A bounded source service token is required")
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 < timeout <= 30:
            raise ValueError("A source timeout between zero and 30 seconds is required")
        self._scope, self._token, self._timeout = scope, source_token, timeout
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def capture(self):
        scope = self._scope
        path = (f"/api/integrations/ains/projects/{scope.project_id}/documents/{scope.document_id}"
                f"/versions/{scope.document_version}/snapshot")
        started = self._clock()
        payload = _bounded_source_read(self._origin, self._token, path, self._timeout)
        try:
            document = json.loads(payload.decode("utf-8"), object_pairs_hook=unique_keys,
                                  parse_constant=_reject_constant)
        except (ValueError, UnicodeError, RecursionError) as error:
            raise SnapshotContractError("Source response is not strict JSON") from error
        document = validate_snapshot(document, scope)
        captured = _instant(document["capturedAt"])
        finished = self._clock()
        if not started.timestamp() - 5 <= captured.timestamp() <= finished.timestamp() + 5:
            raise SnapshotUnavailable("Source response does not belong to this capture interval")
        return document


def observation_registry():
    """Use the existing action-free semantic-query path; no dummy executable action."""
    return Registry({
        "applications": {}, "actions": {},
        "types": {_OBSERVATION_TYPE: {"states": ["captured"], "fields": dict(_PROPERTY_TYPES), "links": {}}},
        "seed": {"actors": [], "objects": [], "knowledge": []},
    })


def observation_ontology():
    return observation_registry().ontology(namespace="fdesage-readonly-observations", version=1)


def observation_row(tenant, snapshot, scope):
    """The object version is local record 1; native source positions remain null."""
    if not _identifier(tenant):
        raise ValueError("An explicit AINS shadow tenant is required")
    document = validate_snapshot(snapshot, scope)
    fingerprint = digest(document)
    row = {
        "tenant": tenant, "id": "fdesage-observation:" + fingerprint, "type": _OBSERVATION_TYPE,
        "state": "captured", "version": 1, "links": {},
        "properties": {
            "snapshot_json": encode(document), "source_profile": PROFILE, "source_release": SOURCE_RELEASE,
            "coverage": "selected_object", "captured_at": document["capturedAt"],
            "source_workspace_id": scope.workspace_id, "source_project_id": scope.project_id,
            "source_document_id": scope.document_id, "document_version": scope.document_version,
            "content_sha256": document["contentDigest"]["value"], "subject_user_id": scope.subject_user_id,
            "membership_generation": scope.membership_generation, "delegation_id": scope.delegation_id,
            "service_id": scope.service_id, "observation_digest": fingerprint,
            "ontology_digest": observation_ontology().digest,
        },
    }
    observation_registry().validate_object(row)
    observation_ontology().validate_object({key: value for key, value in row.items() if key != "links"})
    return row


def import_observation(connection, tenant, snapshot, scope):
    """Append through an explicitly trusted write transaction with INSERT-only rights.

    The source token supplies no AINS identity or write privilege. Callers must
    configure the AINS tenant independently and retain the source scope mapping.
    Grant provisioning and reviewer queries use existing Identity/Policy APIs.
    """
    row = observation_row(tenant, snapshot, scope)
    connection.execute(
        """INSERT INTO objects (tenant, id, type, state, version, properties, links)
           VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (tenant, id) DO NOTHING""",
        (tenant, row["id"], row["type"], row["state"], row["version"], encode(row["properties"]), encode(row["links"])),
    )
    if object_data(connection, tenant, row["id"]) != row:
        raise ValueError("Captured observation is immutable; existing row differs")
    return row["id"]
