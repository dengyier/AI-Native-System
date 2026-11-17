"""Loopback fixture and probes used by the disposable P9 security exercise."""

import hmac
import json
import os
import socket
import struct
import sys
from time import monotonic_ns
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen


TOKEN_PATH = Path("/run/secrets/business_token")
SOCKET_PATH = "/run/agent/proposal.sock"
MODEL_URL = "http://127.0.0.1:18789/v1"
MODEL_NAME = "isolation-fixture"
MODEL_ENV = "P9_FIXTURE_MODEL_KEY"
MODEL_KEY = "fixture-model-key-only"


def serve(mode):
    token = TOKEN_PATH.read_text(encoding="ascii").strip() if mode == "source" else None
    state = {"mutations": 0, "requests": 0}

    class Handler(BaseHTTPRequestHandler):
        def send(self, status, result):
            body = json.dumps(result).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

        def do_GET(self):
            if self.path == "/health":
                self.send(200, {"ready": True})
            elif mode == "source" and self.path == "/state":
                supplied = self.headers.get("Authorization", "")
                if not hmac.compare_digest(supplied, "Bearer " + token):
                    self.send(403, {})
                else:
                    self.send(200, {"mutations": state["mutations"]})
            elif mode == "model" and self.path == "/count":
                self.send(200, {"requests": state["requests"]})
            else:
                self.send(404, {})

        def do_POST(self):
            if mode == "source" and self.path == "/mutate":
                supplied = self.headers.get("Authorization", "")
                if not hmac.compare_digest(supplied, "Bearer " + token):
                    self.send(403, {})
                else:
                    state["mutations"] += 1
                    self.send(200, {"mutations": state["mutations"]})
                return
            if mode != "model" or self.path != "/v1/chat/completions":
                self.send(404, {})
                return
            if not hmac.compare_digest(self.headers.get("Authorization", ""), "Bearer " + MODEL_KEY):
                self.send(403, {})
                return
            # The deterministic local provider returns an unavailable action on the injection test.
            data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            context = json.loads(data["messages"][1]["content"])
            state["requests"] += 1
            action = "unavailable_action" if context["object"]["properties"]["name"] == "inject" else "verify_asset"
            proposed = {"action": action, "rationale": "Check the retained source reference.", "evidence_ids": ["policy"]}
            self.send(200, {"id": "fixture-completion", "object": "chat.completion", "created": 1,
                            "model": MODEL_NAME, "choices": [{"index": 0, "finish_reason": "stop",
                            "message": {"role": "assistant", "content": json.dumps(proposed)}}],
                            "usage": {"prompt_tokens": 11, "completion_tokens": 3, "total_tokens": 14}})

    address = {"model": ("127.0.0.1", 18789), "executor": ("0.0.0.0", 18082), "source": ("0.0.0.0", 18083)}
    with HTTPServer(address[mode], Handler) as server:
        server.serve_forever()


def try_tcp(host, port):
    try:
        with socket.create_connection((host, port), timeout=0.6):
            return True
    except OSError:
        return False


def network_probe(targets):
    return {name: try_tcp(*address) for name, address in targets.items()}


def readable(path):
    try:
        handle = os.open(path, os.O_RDONLY)
    except OSError:
        return False
    os.close(handle)
    return True


def cannot_open_for_write(path):
    try:
        handle = os.open(path, os.O_WRONLY)
    except OSError:
        return True
    os.close(handle)
    return False


def filesystem_probe():
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    pid_environment = Path("/proc/1/environ").read_bytes()
    return {"uid": os.getuid(), "capabilities": int(status["CapEff"].strip(), 16),
            "no_new_privileges": status["NoNewPrivs"].strip() == "1", "seccomp": int(status["Seccomp"].strip()),
            "source_secret_readable": readable(TOKEN_PATH), "docker_socket_exists": Path("/var/run/docker.sock").exists(),
            "business_environment": b"P9_FIXTURE_BUSINESS_TOKEN=" in pid_environment or b"AI_NATIVE_POSTGRES_DSN=" in pid_environment,
            "model_environment": b"P9_FIXTURE_MODEL_KEY=" in pid_environment,
            "image_root_readonly": cannot_open_for_write("/etc/passwd"),
            "executor_module": readable("/app/ai_native_system/runtime.py")}


def trusted_source_probe(mode):
    if mode == "socket_read_only":
        try:
            Path("/run/agent/executor-created-file").touch(exist_ok=False)
        except OSError:
            return {"socket_volume_readonly": True}
        return {"socket_volume_readonly": False}
    action = "mutate" if mode in ("trusted", "untrusted") else "state"
    token = TOKEN_PATH.read_text(encoding="ascii").strip() if mode != "untrusted" else MODEL_KEY
    request = Request("http://source-fixture:18083/" + action, headers={"Authorization": "Bearer " + token},
                      method="POST" if action == "mutate" else "GET")
    try:
        with urlopen(request, timeout=2) as response:
            return {"status": response.status, **json.load(response)}
    except HTTPError as response:
        return {"status": response.code}


def context_for(name):
    return {"scenario": "fixture", "agent": {"id": "reviewer", "instructions": "Cite the fixture policy."},
            "object": {"type": "asset", "state": "pending", "version": 1, "properties": {"name": name}},
            "related": {}, "knowledge": [{"id": "policy", "version": 1, "text": "Yield a recommendation only."}],
            "handoff": None, "allowed_actions": [{"name": "verify_asset", "description": "Verify asset"}]}


def socket_frame(request):
    data = json.dumps(request).encode()
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(2)
        client.connect(SOCKET_PATH)
        client.sendall(struct.pack("!I", len(data)) + data)
        with client.makefile("rb") as stream:
            size, = struct.unpack("!I", stream.read(4))
            if not 0 < size <= 65_536:
                raise ValueError("Invalid isolated fixture reply")
            return json.loads(stream.read(size))


def agent_probe(mode):
    from dataclasses import asdict

    from ai_native_system.adapters.litellm import LiteLLMModel
    from ai_native_system.agent_process import AgentProcessClient, manifest_digest
    from ai_native_system.model import ModelError

    agent = AgentProcessClient(SOCKET_PATH)
    model = LiteLLMModel(MODEL_URL, MODEL_NAME, provider="openai", api_key_env=MODEL_ENV,
                        timeout=10, max_output_tokens=256, agent=agent)
    if mode == "method":
        response = socket_frame({"manifest_digest": manifest_digest(model.manifest), "context": context_for("safe"),
                                 "deadline_ns": monotonic_ns() + 1_000_000_000, "action": "mutate"})
        return {"blocked": response.get("ok") is False}
    if mode == "manifest":
        response = socket_frame({"manifest_digest": "0" * 64, "context": context_for("safe"),
                                 "deadline_ns": monotonic_ns() + 1_000_000_000})
        return {"blocked": response.get("ok") is False}
    try:
        proposal = model.propose(context_for("inject" if mode == "inject" else "safe"), timeout_seconds=10)
    except ModelError as exc:
        return {"blocked": True, "error": type(exc).__name__}
    return {"blocked": False, **asdict(proposal)}


if __name__ == "__main__":
    command = sys.argv[1]
    if command in ("model", "executor", "source"):
        serve(command)
    elif command == "network":
        print(json.dumps(network_probe(json.loads(sys.argv[2]))))
    elif command == "filesystem":
        print(json.dumps(filesystem_probe()))
    elif command == "trusted_source":
        print(json.dumps(trusted_source_probe(sys.argv[2])))
    elif command == "agent":
        print(json.dumps(agent_probe(sys.argv[2])))
    elif command == "model_count":
        with urlopen("http://127.0.0.1:18789/count", timeout=2) as response:
            print(response.read().decode())
