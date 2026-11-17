"""A Unix-socket Agent worker for credential-separated model proposals."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import asdict
from hashlib import sha256
import fcntl
import json
import math
import os
from pathlib import Path
import re
import signal
import socket
import stat
import struct
import sys
from threading import BoundedSemaphore, Event
from time import monotonic, monotonic_ns

from .adapters.litellm import LiteLLMModel, ProviderCallError, _is_identifier, _reject_duplicate_keys
from .model import ModelError, OpenAICompatibleModel, Proposal


_INPUT_BYTES = 256 * 1024
_REQUEST_BYTES = _INPUT_BYTES + 1024
_RESPONSE_BYTES = 64 * 1024
_SOCKET_MODE = 0o600
_MAX_TIMEOUT = 120
_INITIAL_RECEIVE_TIMEOUT = 3
_FRAME = struct.Struct("!I")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_SENSITIVE_PREFIXES = ("AI_NATIVE_POSTGRES", "AI_NATIVE_OWP", "AI_NATIVE_P4_", "AI_NATIVE_GRAPH_",
                       "AI_NATIVE_KNOWLEDGE_", "AI_NATIVE_P5_USAGE", "AI_NATIVE_P5_OBSERVATION",
                       "AI_NATIVE_CLIENT", "AI_NATIVE_ENTERPRISE", "AI_NATIVE_API_TOKENS",
                       "AI_NATIVE_MCP_", "AI_NATIVE_P8_ATTESTATION", "AI_NATIVE_EMBEDDING_API_KEY",
                       "PGPASSWORD", "PGSERVICE", "PGPASSFILE", "PGHOST", "PGUSER", "PGSSLKEY",
                       "LANGFUSE_SECRET_KEY", "DATABASE_URL")


def _encode(document):
    return json.dumps(document, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def manifest_digest(manifest):
    return sha256(_encode(manifest)).hexdigest()


def _decode(payload):
    def reject_constant(_):
        raise ValueError("Nonfinite Agent protocol number")

    def finite_float(value):
        parsed = float(value)
        if not math.isfinite(parsed):
            raise ValueError("Nonfinite Agent protocol number")
        return parsed

    return json.loads(payload.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys,
                      parse_constant=reject_constant, parse_float=finite_float)


def _remaining(deadline):
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise TimeoutError("Agent protocol deadline expired")
    return remaining


def _receive(stream, count, deadline):
    data = bytearray()
    while len(data) < count:
        stream.settimeout(_remaining(deadline))
        part = stream.recv(count - len(data))
        if not part:
            raise EOFError("The Agent connection closed before completing a message")
        data.extend(part)
    return data


def _read(stream, limit, deadline):
    size, = _FRAME.unpack(_receive(stream, _FRAME.size, deadline))
    if not 1 <= size <= limit:
        raise ValueError("Agent protocol message length is invalid")
    return _decode(_receive(stream, size, deadline))


def _write(stream, payload, deadline):
    stream.settimeout(_remaining(deadline))
    stream.sendall(_FRAME.pack(len(payload)) + payload)


def _endpoint(path):
    given = Path(path)
    if given.name in ("", ".", ".."):
        raise ValueError("An Agent Unix socket file path is required")
    parent = given.parent.resolve(strict=True)
    directory = parent.stat()
    if not stat.S_ISDIR(directory.st_mode) or stat.S_IMODE(directory.st_mode) != 0o700:
        raise ValueError("The Agent socket directory must have mode 0700")
    path = parent / given.name
    return path, directory.st_uid


def _socket_metadata(path, owner):
    metadata = path.lstat()
    if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != owner or stat.S_IMODE(metadata.st_mode) != _SOCKET_MODE:
        raise ValueError("The Agent endpoint must be an owner-only Unix socket")
    return metadata


def _verify_linux_peer(stream, owner):
    if sys.platform.startswith("linux"):
        credentials = struct.Struct("=3i")
        _, uid, _ = credentials.unpack(stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, credentials.size))
        if uid != owner:
            raise PermissionError("The Agent peer differs from the socket owner")


def _fields(value, keys):
    return isinstance(value, dict) and value.keys() == keys


def _projected_context(context):
    """Reject raw Grounding or tool envelopes before they cross the boundary."""
    expected = {"agent", "scenario", "allowed_actions", "object", "related", "knowledge", "handoff"}
    if not _fields(context, expected) or not isinstance(context["scenario"], str):
        return False
    agent = context["agent"]
    if (not isinstance(agent, dict) or not {"id", "instructions"} <= agent.keys() <= {"id", "instructions", "model"}
            or any(not isinstance(value, str) for value in agent.values())):
        return False

    def projected_object(value):
        return (_fields(value, {"type", "state", "version", "properties"}) and isinstance(value["properties"], dict)
                and type(value["version"]) is int and isinstance(value["type"], str) and isinstance(value["state"], str))

    if (not projected_object(context["object"]) or not isinstance(context["related"], dict)
            or not all(projected_object(item) for item in context["related"].values())):
        return False
    actions = context["allowed_actions"]
    if not isinstance(actions, list) or not all(
        _fields(item, {"name", "description"}) and all(isinstance(value, str) for value in item.values()) for item in actions
    ):
        return False
    knowledge = context["knowledge"]
    if not isinstance(knowledge, list) or not all(
        _fields(item, {"id", "version", "text"}) and type(item["version"]) is int
        and isinstance(item["id"], str) and isinstance(item["text"], str) for item in knowledge
    ):
        return False
    handoff = context["handoff"]
    return handoff is None or (_fields(handoff, {"action"})
                               and (handoff["action"] is None or isinstance(handoff["action"], str)))


def _token_count(value):
    return value is None or (type(value) is int and 0 <= value < 2**63)


def _parse_reply(reply, manifest, context):
    provider = manifest["provider"]
    if _fields(reply, {"ok", "kind"}) and reply["ok"] is False and reply["kind"] == "rejected":
        raise ProviderCallError("Agent request was refused", provider=provider, model=None, sent=False)
    if _fields(reply, {"ok", "failure"}) and reply["ok"] is False:
        failure = reply["failure"]
        if (not _fields(failure, {"model", "input_tokens", "output_tokens", "retryable", "timeout", "status", "sent"})
                or (failure["model"] is not None and not _is_identifier(failure["model"]))
                or any(not _token_count(failure[key]) for key in ("input_tokens", "output_tokens"))
                or any(type(failure[key]) is not bool for key in ("retryable", "timeout", "sent"))
                or (failure["status"] is not None
                    and (type(failure["status"]) is not int or not 100 <= failure["status"] <= 599))
                or (not failure["sent"] and any(failure[key] is not None
                                                 for key in ("model", "input_tokens", "output_tokens", "status")))):
            raise ValueError("Invalid Agent provider failure")
        raise ProviderCallError("Agent provider request failed", provider=provider, **failure)
    if not _fields(reply, {"ok", "proposal"}) or reply["ok"] is not True:
        raise ValueError("Invalid Agent reply")
    payload = reply["proposal"]
    if (not _fields(payload, {"action", "rationale", "evidence_ids", "provider", "model", "input_tokens", "output_tokens"})
            or payload["provider"] != provider or not _is_identifier(payload["model"])
            or any(not _token_count(payload[key]) for key in ("input_tokens", "output_tokens"))):
        raise ValueError("Invalid Agent proposal metadata")
    proposal = {key: payload[key] for key in ("action", "rationale", "evidence_ids")}
    action, rationale, evidence = OpenAICompatibleModel._validate_proposal(proposal, context)
    return Proposal(action, rationale, tuple(evidence), provider, payload["model"],
                    payload["input_tokens"], payload["output_tokens"])


class AgentProcessClient:
    """Execute one isolated proposal request and validate its result locally."""

    def __init__(self, socket_path):
        self.socket_path = Path(socket_path)

    def propose(self, manifest, context, *, timeout_seconds=None):
        provider = manifest["provider"]
        if timeout_seconds is None:
            timeout_seconds = manifest["timeout"]
        if (type(timeout_seconds) not in (float, int) or not math.isfinite(timeout_seconds) or timeout_seconds <= 0
                or not _projected_context(context)):
            raise ProviderCallError("Invalid isolated Agent request", provider=provider, model=None, sent=False)
        deadline = monotonic() + min(timeout_seconds, _MAX_TIMEOUT, manifest["timeout"])
        handed_off = False
        try:
            path, owner = _endpoint(self.socket_path)
            _socket_metadata(path, owner)
            if len(_encode(context)) > _INPUT_BYTES:
                raise ValueError("Agent context is too large")
            request = _encode({"manifest_digest": manifest_digest(manifest), "context": context,
                               "deadline_ns": int(deadline * 1_000_000_000)})
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
                stream.settimeout(_remaining(deadline))
                stream.connect(os.fspath(path))
                _verify_linux_peer(stream, owner)
                _remaining(deadline)
                handed_off = True
                _write(stream, request, deadline)
                reply = _read(stream, _RESPONSE_BYTES, deadline)
            return _parse_reply(reply, manifest, context)
        except ProviderCallError:
            raise
        except (OSError, ValueError, TypeError, EOFError, RecursionError, ModelError) as error:
            # Once transmission starts the provider outcome may be unknown. In
            # that case the executor keeps its reserved budget and avoids fallback.
            raise ProviderCallError("The isolated Agent request could not be verified", provider=provider, model=None,
                                    sent=handed_off, timeout=isinstance(error, TimeoutError)) from None


def _load_models(path):
    with Path(path).open("rb") as source:
        payload = source.read(_REQUEST_BYTES + 1)
    if len(payload) > _REQUEST_BYTES:
        raise ValueError("Agent model configuration is too large")
    config = _decode(payload)
    if not isinstance(config, dict) or not isinstance(config.get("routes"), dict):
        raise ValueError("Agent model routes are required")
    models = {}
    for route in config["routes"].values():
        if not isinstance(route, dict) or type(route.get("enabled", True)) is not bool:
            raise ValueError("Invalid Agent route")
        if route.get("adapter") != "litellm" or not route.get("enabled", True):
            continue
        env = route.get("api_key_env")
        if not isinstance(env, str) or not env or env.startswith(_SENSITIVE_PREFIXES):
            raise ValueError("Agent routes require a dedicated model credential")
        model = LiteLLMModel(route["base_url"], route["model"], api_key_env=env, provider=route["provider"],
                             timeout=route.get("timeout", 15), allow_providers=config["allow_providers"],
                             max_output_tokens=route.get("max_output_tokens", 512))
        model.validate_credentials()
        models[manifest_digest(model.manifest)] = model
    if not models:
        raise ValueError("At least one enabled LiteLLM generation route is required")
    return models


@contextmanager
def _listener(socket_path):
    path, owner = _endpoint(socket_path)
    if owner != os.geteuid():
        raise PermissionError("The Agent must own its socket directory")
    lock_path = path.with_name(path.name + ".lock")
    descriptor = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, _SOCKET_MODE)
    try:
        lock = os.fstat(descriptor)
        if not stat.S_ISREG(lock.st_mode) or lock.st_uid != owner or stat.S_IMODE(lock.st_mode) != _SOCKET_MODE:
            raise PermissionError("Invalid Agent socket lock")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            _socket_metadata(path, owner)
        except FileNotFoundError:
            pass
        else:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as previous:
                previous.settimeout(0.1)
                try:
                    previous.connect(os.fspath(path))
                except ConnectionRefusedError:
                    path.unlink()
                else:
                    raise PermissionError("The Agent socket is already active")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            mask = os.umask(0o177)
            try:
                listener.bind(os.fspath(path))
            finally:
                os.umask(mask)
            bound = _socket_metadata(path, owner)
            try:
                listener.listen(16)
                listener.settimeout(0.25)
                yield listener
            finally:
                try:
                    if path.lstat().st_ino == bound.st_ino:
                        path.unlink()
                except FileNotFoundError:
                    pass
    finally:
        os.close(descriptor)


def _run_request(stream, models):
    request = _read(stream, _REQUEST_BYTES, monotonic() + _INITIAL_RECEIVE_TIMEOUT)
    if (not _fields(request, {"manifest_digest", "context", "deadline_ns"}) or not isinstance(request["manifest_digest"], str)
            or _DIGEST.fullmatch(request["manifest_digest"]) is None
            or type(request["deadline_ns"]) is not int or not 1 <= request["deadline_ns"] < 2**63
            or not _projected_context(request["context"]) or len(_encode(request["context"])) > _INPUT_BYTES):
        raise ValueError("Invalid Agent request")
    model = models.get(request["manifest_digest"])
    if model is None:
        raise ValueError("Unregistered Agent model route")
    # Both processes share the host monotonic clock over a Unix socket. Work
    # that sat behind a stalled caller cannot receive a fresh provider budget.
    remaining = (request["deadline_ns"] - monotonic_ns()) / 1_000_000_000
    if not 0 < remaining <= _MAX_TIMEOUT:
        raise ValueError("Agent request deadline expired or exceeds its bound")
    try:
        result = model.propose(request["context"], timeout_seconds=remaining)
    except ProviderCallError as error:
        return {"ok": False, "failure": {key: getattr(error, key) for key in
                ("model", "input_tokens", "output_tokens", "retryable", "timeout", "status", "sent")}}
    except (ModelError, TypeError, ValueError, RecursionError, OSError):
        return {"ok": False, "kind": "unverified"}
    return {"ok": True, "proposal": asdict(result)}


def _handle(stream, models, slots):
    try:
        with stream:
            try:
                _verify_linux_peer(stream, os.geteuid())
                reply = _run_request(stream, models)
            except (OSError, ValueError, TypeError, EOFError, RecursionError):
                reply = {"ok": False, "kind": "rejected"}
            try:
                payload = _encode(reply)
                if len(payload) <= _RESPONSE_BYTES:
                    _write(stream, payload, monotonic() + 1)
            except (OSError, ValueError, TypeError, RecursionError):
                pass
    finally:
        slots.release()


def serve_agent(socket_path, models, stop, *, max_inflight=4):
    if type(max_inflight) is not int or not 1 <= max_inflight <= 16:
        raise ValueError("Agent concurrency must be between 1 and 16")
    slots = BoundedSemaphore(max_inflight)
    with _listener(socket_path) as listener, ThreadPoolExecutor(max_workers=max_inflight) as workers:
        while not stop.is_set():
            # Leave extra clients in the bounded kernel backlog.
            if not slots.acquire(timeout=0.25):
                continue
            try:
                stream, _ = listener.accept()
            except TimeoutError:
                slots.release()
                continue
            workers.submit(_handle, stream, models, slots)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Serve isolated Agent proposals over a private Unix socket")
    parser.add_argument("--socket", required=True)
    parser.add_argument("--models", type=Path, action="append", required=True,
                        help="Trusted generation config (repeat for archived release routes)")
    parser.add_argument("--max-inflight", type=int, default=4)
    args = parser.parse_args(argv)
    stop = Event()
    for name in (signal.SIGINT, signal.SIGTERM):
        signal.signal(name, lambda _signum, _frame: stop.set())
    try:
        if any(value and key.startswith(_SENSITIVE_PREFIXES) for key, value in os.environ.items()):
            raise PermissionError("The Agent environment includes framework authority credentials")
        models = {}
        for configuration in args.models:
            models.update(_load_models(configuration))
        serve_agent(args.socket, models, stop, max_inflight=args.max_inflight)
    except (ModelError, OSError, ValueError, TypeError, KeyError, RecursionError):
        print("Agent startup was refused. Check its private socket directory, model credentials and isolated environment.",
              file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
