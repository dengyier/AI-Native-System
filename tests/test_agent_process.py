import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import threading
from time import monotonic, monotonic_ns, sleep
import unittest

from ai_native_system.adapters.litellm import LiteLLMModel, ProviderCallError
from ai_native_system.agent_process import (
    AgentProcessClient, _encode, _read, _REQUEST_BYTES, _RESPONSE_BYTES, _SENSITIVE_PREFIXES, _write, manifest_digest,
)
from ai_native_system.model_policy import GenerationData
from test_model import CONTEXT, model_server
from test_model_backend import completion_response


ROOT = Path(__file__).resolve().parents[1]
MODEL_CREDENTIAL = "P9_AGENT_TEST_MODEL_KEY"
PROJECTED = GenerationData(object_fields=("allowed",), knowledge_ids=("policy-v1",), include_handoff=True).project({
    **CONTEXT,
    "object": {"type": "item", "state": "new", "version": 1, "properties": {"allowed": True, "private": "hidden"}},
    "knowledge": [{**CONTEXT["knowledge"][0], "version": 1}],
})


def unix_stream(path):
    stream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stream.settimeout(2)
    try:
        stream.connect(os.fspath(path))
    except OSError:
        stream.close()
        raise
    return stream


class AgentProcessTests(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory(prefix="p9agent-", dir="/tmp"))
        self.directory = Path(directory).resolve()
        self.path = self.directory / "agent.sock"
        self.client = AgentProcessClient(self.path)

    def test_client_rejects_untrusted_socket_path_and_raw_context(self):
        manifest = LiteLLMModel("http://127.0.0.1:1/v1", "test-model", api_key_env=MODEL_CREDENTIAL).manifest
        self.directory.chmod(0o750)
        with self.assertRaises(ProviderCallError) as not_private:
            self.client.propose(manifest, PROJECTED)
        self.assertFalse(not_private.exception.sent)

        self.directory.chmod(0o700)
        self.path.symlink_to("/does-not-exist")
        with self.assertRaises(ProviderCallError) as symlink:
            self.client.propose(manifest, PROJECTED)
        self.assertFalse(symlink.exception.sent)

        with self.assertRaisesRegex(ProviderCallError, "Invalid isolated Agent request") as raw_context:
            self.client.propose(manifest, {**PROJECTED, "tool_call": {"name": "invoke"}})
        self.assertFalse(raw_context.exception.sent)

    def test_client_rejects_forged_proposals_as_unverified_provider_outcomes(self):
        manifest = LiteLLMModel("http://127.0.0.1:1/v1", "test-model", api_key_env=MODEL_CREDENTIAL).manifest
        valid_proposal = {"action": "request_review", "rationale": "Reviewed", "evidence_ids": ["policy-v1"],
                          "provider": "openai", "model": "test-model", "input_tokens": 1, "output_tokens": 1}
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
            listener.bind(os.fspath(self.path))
            self.path.chmod(0o600)
            listener.listen()
            listener.settimeout(2)
            for invalid in ({"action": "execute_source_write"}, {"evidence_ids": ["unseen"]}, {"input_tokens": True}):
                with self.subTest(invalid=invalid):
                    received = []

                    def respond():
                        with listener.accept()[0] as incoming:
                            received.append(_read(incoming, _REQUEST_BYTES, monotonic() + 2))
                            reply = {"ok": True, "proposal": {**valid_proposal, **invalid}}
                            _write(incoming, _encode(reply), monotonic() + 2)

                    responder = threading.Thread(target=respond, daemon=True)
                    responder.start()
                    try:
                        with self.assertRaisesRegex(ProviderCallError, "could not be verified") as caught:
                            self.client.propose(manifest, PROJECTED, timeout_seconds=2)
                    finally:
                        responder.join(2)
                    self.assertTrue(caught.exception.sent)
                    self.assertFalse(caught.exception.retryable)
                    self.assertIsNone(caught.exception.input_tokens)
                    self.assertEqual(len(received), 1)
                    self.assertEqual(received[0].keys(), {"manifest_digest", "context", "deadline_ns"})
                    self.assertEqual(received[0]["context"], PROJECTED)


@unittest.skipUnless(importlib.util.find_spec("litellm"), "Install the pinned LiteLLM dependency")
class StandaloneAgentProcessTests(unittest.TestCase):
    def setUp(self):
        directory = self.enterContext(tempfile.TemporaryDirectory(prefix="p9agent-", dir="/tmp"))
        self.directory = Path(directory).resolve()
        self.path = self.directory / "agent.sock"
        self.models = self.directory / "models.json"
        self.client = AgentProcessClient(self.path)

    def configure(self, base_url, *, configuration=None, providers=("openai",)):
        configuration = self.models if configuration is None else configuration
        configuration.write_text(json.dumps({"allow_providers": providers, "routes": {"release-route": {
            "adapter": "litellm", "provider": "openai", "model": "test-model", "base_url": base_url,
            "api_key_env": MODEL_CREDENTIAL,
        }}}), encoding="utf-8")
        return LiteLLMModel(base_url, "test-model", api_key_env=MODEL_CREDENTIAL, allow_providers=providers).manifest

    def spawn(self, extra_environment=None, *, wait=True, archived_configuration=None):
        environment = {key: value for key, value in os.environ.items() if not key.startswith(_SENSITIVE_PREFIXES)}
        environment[MODEL_CREDENTIAL] = "agent-only-test-key"
        environment.update(extra_environment or {})
        arguments = [sys.executable, "-B", "-m", "ai_native_system.agent_process", "--socket", self.path,
                     "--models", self.models]
        if archived_configuration is not None:
            arguments.extend(("--models", archived_configuration))
        process = subprocess.Popen(
            arguments,
            cwd=ROOT, env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        )

        def stop():
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            process.stderr.close()

        self.addCleanup(stop)
        if wait:
            deadline = monotonic() + 10
            while monotonic() < deadline and process.poll() is None:
                try:
                    with unix_stream(self.path):
                        return process
                except (FileNotFoundError, ConnectionRefusedError):
                    sleep(0.02)
            self.fail("Standalone Agent did not offer its private socket")
        return process

    def request(self, payload):
        with unix_stream(self.path) as stream:
            _write(stream, _encode(payload), monotonic() + 2)
            return _read(stream, _RESPONSE_BYTES, monotonic() + 2)

    def test_agent_uses_its_model_key_and_rejects_unknown_and_expired_work(self):
        with model_server(result=completion_response()) as (base_url, requests):
            manifest = self.configure(base_url)
            self.spawn()
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
            valid = {"manifest_digest": manifest_digest(manifest), "context": PROJECTED}
            for changes in ({"dispatch": {"tool": "shell"}}, {"context": {**PROJECTED, "database": "dsn"}},
                            {"deadline_ns": monotonic_ns() - 1}, {"manifest_digest": "0" * 64}):
                with self.subTest(changes=changes):
                    self.assertEqual(self.request({**valid, "deadline_ns": monotonic_ns() + 10**9, **changes}),
                                     {"ok": False, "kind": "rejected"})
            self.assertEqual(requests, [])
            proposal = self.client.propose(manifest, PROJECTED)
            self.assertEqual(proposal.action, "request_review")
            self.assertEqual(proposal.evidence_ids, ("policy-v1",))
            self.assertEqual((proposal.input_tokens, proposal.output_tokens), (40, 12))
            self.assertEqual(len(requests), 1)
            path, authorization, body = requests[0]
            self.assertEqual((path, authorization), ("/v1/chat/completions", "Bearer agent-only-test-key"))
            self.assertEqual(json.loads(body["messages"][-1]["content"]), PROJECTED)

    def test_agent_preserves_archived_routes_with_separate_provider_allowlists(self):
        with model_server(result=completion_response()) as (base_url, requests):
            archived = self.directory / "archived.json"
            old = self.configure(base_url, configuration=archived)
            current = self.configure(base_url, providers=("openai", "another-approved-provider"))
            self.assertNotEqual(manifest_digest(old), manifest_digest(current))
            self.spawn(archived_configuration=archived)
            for manifest in (old, current):
                self.assertEqual(self.client.propose(manifest, PROJECTED).action, "request_review")
            self.assertEqual(len(requests), 2)

    def test_agent_strips_provider_error_body_and_preserves_usage(self):
        body = {"error": {"message": "sensitive-provider-body"}, "model": "test-model-2026",
                "usage": {"prompt_tokens": 6, "completion_tokens": 1}}
        with model_server(result=body, status=503) as (base_url, requests):
            manifest = self.configure(base_url)
            self.spawn()
            with self.assertRaises(ProviderCallError) as caught:
                self.client.propose(manifest, PROJECTED)
            self.assertEqual(len(requests), 1)
        error = caught.exception
        self.assertTrue(error.sent)
        self.assertTrue(error.retryable)
        self.assertEqual((error.model, error.status, error.input_tokens, error.output_tokens),
                         ("test-model-2026", 503, 6, 1))
        self.assertNotIn("sensitive-provider-body", str(error))
        self.assertNotIn("agent-only-test-key", str(error))

    def test_agent_refuses_authority_credentials_and_recovers_its_socket_after_sigkill(self):
        self.configure("http://127.0.0.1:1/v1")
        for key in ("AI_NATIVE_POSTGRES_DSN", "AI_NATIVE_P8_ATTESTATION_KEY"):
            with self.subTest(key=key):
                refused = self.spawn({key: "authority-credential-fixture"}, wait=False)
                _, stderr = refused.communicate(timeout=5)
                self.assertEqual(refused.returncode, 2)
                self.assertFalse(self.path.exists())
                self.assertNotIn(b"authority-credential-fixture", stderr)

        crashed = self.spawn()
        duplicate = self.spawn(wait=False)
        self.assertEqual(duplicate.wait(timeout=5), 2)
        crashed.kill()
        crashed.wait(timeout=5)
        self.assertTrue(self.path.is_socket())
        self.spawn()
        self.assertEqual(self.request({}), {"ok": False, "kind": "rejected"})
