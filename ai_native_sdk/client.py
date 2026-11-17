# SPDX-License-Identifier: MIT
"""Small synchronous HTTP SDK for the framework's authenticated application API."""

import http.client
import ipaddress
import json
import math
import re
import socket
from threading import Timer
from time import monotonic
from urllib.parse import quote, urlencode, urlsplit

_MAX_REQUEST_BYTES = 65_536
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_TOKEN = re.compile(r"[A-Za-z0-9._~+/\-]+=*")


def _unique_response_keys(pairs):
    document = {}
    for key, value in pairs:
        if key in document:
            raise ValueError("Duplicate JSON response key")
        document[key] = value
    return document


class APIError(RuntimeError):
    """An HTTP, transport or response error with no credential or payload detail."""

    def __init__(self, message, *, status=None, outcome_unknown=False):
        self.status = status
        self.outcome_unknown = outcome_unknown
        super().__init__(message)


def _origin(base_url):
    if not isinstance(base_url, str) or not base_url.isascii() or not all(33 <= ord(c) <= 126 for c in base_url):
        raise ValueError("An HTTPS or loopback HTTP API origin is required")
    try:
        url = urlsplit(base_url)
        host, port = url.hostname, url.port
    except ValueError:
        raise ValueError("Invalid API origin") from None
    if (url.scheme not in {"https", "http"} or not host or port == 0 or url.username is not None
            or url.password is not None or url.path not in {"", "/"} or any(c in base_url for c in "?#\\%")):
        raise ValueError("Use an API origin without credentials, path, query or fragment")
    if url.scheme == "http":
        if host == "localhost":
            host = "127.0.0.1"
        try:
            if not ipaddress.ip_address(host).is_loopback:
                raise ValueError
        except ValueError:
            raise ValueError("Plain HTTP requires a loopback address") from None
    return url.scheme, host, port


def _segment(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 512 or value in {".", ".."}:
        raise ValueError("A valid path identifier is required")
    return quote(value, safe="")


def _task_path(task_id, action=""):
    return "/v1/tasks/" + _segment(task_id) + action


def _release_path(release_digest, action=""):
    return "/v1/releases/" + _segment(release_digest) + action


def _json_number(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("Nonfinite JSON number")
    return number


def _interrupt(stream):
    try:
        stream.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass


class Client:
    """Send one authenticated request per SDK call.

    Pass the original request key when retrying an uncertain submission and
    the exact proposal digest from the review when submitting a decision.
    Socket deadlines cover HTTP transfer. Hostname resolution also depends on
    the local system resolver.
    """

    def __init__(self, base_url, token, *, timeout=10):
        self._scheme, self._host, self._port = _origin(base_url)
        if not isinstance(token, str) or not 1 <= len(token) <= 8192 or not _TOKEN.fullmatch(token):
            raise ValueError("A valid bearer credential is required")
        if type(timeout) not in (int, float) or not 0 < timeout <= 120:
            raise ValueError("Timeout must be positive and no greater than 120 seconds")
        self._token = token
        self._timeout = timeout

    def _request(self, method, path, data=None):
        sent = False
        headers = {"Authorization": "Bearer " + self._token, "Accept": "application/json",
                   "Accept-Encoding": "identity", "Connection": "close"}
        payload = None
        if data is not None:
            try:
                payload = json.dumps(data, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
            except (TypeError, ValueError, RecursionError):
                raise ValueError("Request body must be valid JSON") from None
            if len(payload) > _MAX_REQUEST_BYTES:
                raise ValueError("Request body exceeds the API byte limit")
            headers["Content-Type"] = "application/json; charset=utf-8"

        connect = http.client.HTTPSConnection if self._scheme == "https" else http.client.HTTPConnection
        connection = connect(self._host, self._port, timeout=self._timeout)
        deadline = monotonic() + self._timeout
        timer = None
        try:
            connection.connect()
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise TimeoutError
            stream = connection.sock
            stream.settimeout(remaining)
            timer = Timer(remaining, _interrupt, (stream,))
            timer.daemon = True
            timer.start()
            sent = True
            connection.request(method, path, body=payload, headers=headers)
            with connection.getresponse() as response:
                if not 200 <= response.status < 300:
                    unknown = method == "POST" and (response.status < 400 or response.status == 408 or response.status >= 500)
                    raise APIError(f"API returned HTTP {response.status}", status=response.status, outcome_unknown=unknown)
                return self._read_response(response, deadline)
        except (OSError, http.client.HTTPException, ValueError, OverflowError, RecursionError):
            raise APIError("Could not obtain a complete API response", outcome_unknown=sent and method == "POST") from None
        finally:
            if timer is not None:
                timer.cancel()
            connection.close()

    @staticmethod
    def _read_response(response, deadline):
        lengths = response.headers.get_all("Content-Length", ())
        declared = None
        if lengths:
            if (len(lengths) != 1 or not re.fullmatch(r"[0-9]{1,10}", lengths[0])
                    or response.headers.get("Transfer-Encoding") is not None):
                raise ValueError("Invalid response length")
            declared = int(lengths[0])
            if declared > _MAX_RESPONSE_BYTES:
                raise ValueError("Response exceeds the size limit")
        if (response.headers.get_content_type() != "application/json"
                or response.headers.get("Content-Encoding", "identity").lower() != "identity"):
            raise ValueError("Invalid response content type")
        raw = response.read(_MAX_RESPONSE_BYTES + 1)
        if (len(raw) > _MAX_RESPONSE_BYTES or (declared is not None and len(raw) != declared)
                or monotonic() >= deadline):
            raise ValueError("Incomplete or oversized response")
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_response_keys,
                            parse_float=_json_number, parse_constant=_json_number)
        if not isinstance(parsed, (dict, list)) or monotonic() >= deadline:
            raise ValueError("A complete JSON result is required")
        return parsed

    def submit(self, application, object_id, request_key, *, release_digest=None, knowledge_citations=None,
               expected_object_version=None):
        payload = {"application": application, "object_id": object_id, "request_key": request_key}
        if release_digest is not None:
            payload["release_digest"] = release_digest
        if knowledge_citations is not None:
            payload["knowledge_citations"] = knowledge_citations
        if expected_object_version is not None:
            if type(expected_object_version) is not int or expected_object_version < 1:
                raise ValueError("Expected object version must be a positive integer")
            payload["expected_object_version"] = expected_object_version
        return self._request("POST", "/v1/tasks", payload)

    def task(self, task_id):
        return self._request("GET", _task_path(task_id))

    def events(self, task_id, *, limit=50, cursor=None):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Event page size must be 1–100")
        options = {"limit": limit}
        if cursor is not None:
            if not isinstance(cursor, str) or not 1 <= len(cursor) <= 8192:
                raise ValueError("Invalid event cursor")
            options["cursor"] = cursor
        return self._request("GET", _task_path(task_id, "/events") + "?" + urlencode(options))

    def advance(self, task_id):
        return self._request("POST", _task_path(task_id, "/advance"), {})

    def decide(self, task_id, verdict, proposal_digest):
        if verdict not in ("approve", "reject") or not isinstance(proposal_digest, str) or not re.fullmatch(
            r"[0-9a-f]{64}", proposal_digest,
        ):
            raise ValueError("Decision requires a verdict and the exact proposal digest")
        return self._request("POST", _task_path(task_id, "/decision"),
                             {"verdict": verdict, "proposal_digest": proposal_digest})

    def approve(self, task_id, proposal_digest):
        return self.decide(task_id, "approve", proposal_digest)

    def reject(self, task_id, proposal_digest):
        return self.decide(task_id, "reject", proposal_digest)

    def cancel(self, task_id):
        return self._request("POST", _task_path(task_id, "/cancel"), {})

    def reconcile(self, task_id):
        return self._request("POST", _task_path(task_id, "/reconcile"), {})

    def retry_remote(self, task_id):
        return self._request("POST", _task_path(task_id, "/retry-remote"), {})

    def export_evidence(self, task_id):
        return self._request("GET", _task_path(task_id, "/evidence"))

    def query(self, **options):
        return self._request("POST", "/v1/query", options)

    def applications(self):
        return self._request("GET", "/v1/applications")

    def run_application(self, application, payload):
        if not isinstance(payload, dict):
            raise ValueError("Application input must be a JSON object")
        return self._request("POST", "/v1/applications/" + _segment(application) + "/run", payload)

    def handover(self, task_id):
        return self._request("GET", _task_path(task_id, "/handover"))

    def decide_handover(self, task_id, verdict, assessment_digest, reason):
        if verdict not in ("accept", "reject") or not isinstance(assessment_digest, str) or not re.fullmatch(
            r"[0-9a-f]{64}", assessment_digest,
        ):
            raise ValueError("Handover requires a verdict and the exact assessment digest")
        return self._request("POST", _task_path(task_id, "/handover"),
                             {"verdict": verdict, "assessment_digest": assessment_digest, "reason": reason})

    def release(self, release_digest):
        return self._request("GET", _release_path(release_digest))

    def release_impact(self, release_digest):
        return self._request("GET", _release_path(release_digest, "/impact"))

    def bind_rule(self, release_digest, rule_id, *, feedback_source=None, feedback_stream=None):
        payload = {"rule_id": rule_id}
        payload.update({key: value for key, value in {"feedback_source": feedback_source, "feedback_stream": feedback_stream}.items()
                        if value is not None})
        return self._request("POST", _release_path(release_digest, "/bind-rule"), payload)

    def draft_release(self, application, *, ontology=None, knowledge_strategy=None, owp_profile=None, policy_version=None,
                      retrieval=None):
        options = {"ontology": ontology, "knowledge_strategy": knowledge_strategy, "owp_profile": owp_profile,
                   "policy_version": policy_version, "retrieval": retrieval}
        payload = {"application": application, **{name: value for name, value in options.items() if value is not None}}
        return self._request("POST", "/v1/releases/draft", payload)

    def change_release(self, release_digest, action, *, migration_ref=None):
        if action not in ("publish", "select", "deprecate", "revoke") or (migration_ref is not None and action != "publish"):
            raise ValueError("Invalid release lifecycle request")
        payload = {} if migration_ref is None else {"migration_ref": migration_ref}
        return self._request("POST", _release_path(release_digest, "/" + action), payload)

    def fact_status(self, object_type, object_id, field):
        return self._request("POST", "/v1/facts/status", {"object_type": object_type, "object_id": object_id, "field": field})
