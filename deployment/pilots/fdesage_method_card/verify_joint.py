"""Run synthetic, isolated FDE HTTP → AINS → official MCP → real MySQL acceptance.

This command provisions fresh test databases and SQL roles. It supplies a
synthetic advisory model and synthetic independent decisions, never a real
production human approval. No production process or database is selected.
"""

import argparse
import hashlib
import importlib.metadata
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener
from uuid import uuid4

from ai_native_system.adapters.owp import key_id
from ai_native_system.evidence import deliver_effect, sign_effect, verify_effect
from ai_native_system.fdesage_source import EXECUTE_TOOL, LOOKUP_TOOL, TENANT, tool_schema_pins
from ai_native_system.identity import IdentityContext
from ai_native_system.policy import Policy
from ai_native_system.source_receipt import verify_source_receipt
from ai_native_system.storage import digest
from ai_native_system.tools import configured_tools
from deployment.pilots.fdesage_method_card.workflow_fixture import MethodWorkflowFixture


ROOT = Path(__file__).resolve().parents[3]
OPENER = build_opener(ProxyHandler({}))


def _port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def _request(url, body, token):
    request = Request(url, method="POST", data=json.dumps(body).encode(),
                      headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"})
    try:
        with OPENER.open(request, timeout=10) as response:
            return response.status, json.load(response)
    except HTTPError as error:
        with error:
            return error.code, json.load(error)


def _stop(process):
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=4)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=4)


def _wait_port(process, port):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and process.poll() is None:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.03)
    raise AssertionError("An isolated source process did not open its loopback endpoint")


class _DropResponseProxy:
    """Forward once to the real source, then lose one committed response at transport."""

    def __init__(self):
        self.origin = None
        self.drop_next = False
        self.calls = []

    def start(self, stack):
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                fixture.calls.append(self.path.rsplit("/", 1)[-1])
                token = self.headers["Authorization"].removeprefix("Bearer ")
                status, result = _request(fixture.origin + self.path, body, token)
                if self.path.endswith("/execute") and fixture.drop_next:
                    fixture.drop_next = False
                    status, result = 503, {"error": "synthetic_response_lost_after_real_source_returned"}
                payload = json.dumps(result).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *arguments):
                pass

        server = stack.enter_context(ThreadingHTTPServer(("127.0.0.1", 0), Handler))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        stack.callback(thread.join, 2)
        stack.callback(server.shutdown)
        return f"http://127.0.0.1:{server.server_port}"


def verify(private_config, backend_root, output, node):
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    import ai_native_system

    assert Path(ai_native_system.__file__).resolve().is_relative_to(ROOT)
    verified_files = [ROOT / "ai_native_system/fdesage_source.py", ROOT / "ai_native_system/fdesage_method_card.py",
                      Path(__file__).resolve(), Path(__file__).with_name("workflow_fixture.py"),
                      Path(__file__).with_name("backend_fixture.cjs"),
                      *[backend_root / name for name in ("src/ainsMethodSourceServer.js", "src/routes/methodCardSource.js",
                                                        "src/services/protectedActions/methodCardGovernance.js",
                                                        "src/services/integrations/ains/profiles.js",
                                                        "src/services/integrations/ains/methodCardSource.js")]]
    fingerprints = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in verified_files}
    private = json.loads(private_config.read_text())
    output.mkdir(parents=True, exist_ok=False)
    result = {"kind": "isolated-synthetic-method-card-write-chain", "productionTouched": False,
              "humanApproval": "synthetic independent acceptance decision", "model": "synthetic DemoModel",
              "scenarios": [], "processes": [], "frameworkSource": ai_native_system.__file__, "interpreter": sys.executable,
              "versions": {name: importlib.metadata.version(name) for name in ("openworkproof", "mcp", "psycopg")}}
    private_material = output / "private"
    private_material.mkdir(mode=0o700)
    authority, source_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    files = {}
    for name, key in (("authority", authority), ("source", source_key)):
        secret = private_material / (name + "-private.pem")
        secret.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()))
        secret.chmod(0o600)
        public = private_material / (name + "-public.pem")
        public.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        files[name] = (secret, public)
    with ExitStack() as stack:
        helper = subprocess.Popen(
            [node, str(Path(__file__).with_name("backend_fixture.cjs")), str(backend_root)], cwd=ROOT,
            env={"PATH": os.environ.get("PATH", ""), "FDE_METHOD_JOINT_PRIVATE_CONFIG": str(private_config)},
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        stack.callback(_stop, helper)
        ready = json.loads(helper.stdout.readline())
        if not ready.get("ready"):
            raise AssertionError("The restricted FDE user API fixture did not start")

        def command(name, **fields):
            helper.stdin.write(json.dumps({"name": name, **fields}) + "\n")
            helper.stdin.flush()
            reply = json.loads(helper.stdout.readline())
            if reply.get("fixtureError"):
                raise AssertionError("Isolated MySQL fixture command failed")
            return reply

        result["sourceDatabase"] = ready["database"]
        reviewer = next(row["actor"] for row in ready["bindings"] if int(row["userId"]) == ready["reviewer"])
        mcp_port = _port()
        node_execute, node_lookup, mcp_execute, mcp_lookup = (secrets.token_hex(32) for _ in range(4))
        pins = tool_schema_pins()
        tools = {"tools": [{
            "name": "method-card.verify", "version": "1", "transport": "mcp-sdk-http",
            "endpoint": f"http://127.0.0.1:{mcp_port}/mcp", "execute_tool": EXECUTE_TOOL, "lookup_tool": LOOKUP_TOOL,
            "execute_schema_digest": pins[EXECUTE_TOOL], "lookup_schema_digest": pins[LOOKUP_TOOL],
            "token_env": "FDE_JOINT_MCP_EXECUTE", "lookup_token_env": "FDE_JOINT_MCP_LOOKUP", "idempotent": True,
            "source": {"source": "fdesage-method-cards", "lookup_principal": "fde-method-source-lookup",
                       "retention_seconds": 86400, "receipt_public_keys": [str(files["source"][1])]},
        }]}
        os.environ["FDE_JOINT_MCP_EXECUTE"], os.environ["FDE_JOINT_MCP_LOOKUP"] = mcp_execute, mcp_lookup
        destination = configured_tools(tools).resolve({"tool": "method-card.verify", "tool_version": "1"})
        configuration = {
            "profile": "fdesage-method-source-config/1", "appDbUser": ready["appUser"],
            "database": {"host": "127.0.0.1", "port": int(private["mysqlPort"]), "name": ready["database"],
                         "user": ready["sourceUser"], "passwordEnv": "FDE_JOINT_SOURCE_DB_PASSWORD"},
            "executeTokenEnv": "FDE_JOINT_NODE_EXECUTE", "lookupTokenEnv": "FDE_JOINT_NODE_LOOKUP",
            "signingKeyFile": str(files["source"][0]), "authorityKeyFiles": [str(files["authority"][1])],
            "source": {"epoch": ready["epoch"], "destinationDigest": digest(destination.identity),
                       "actorBindings": {row["actor"]: {"userId": int(row["userId"]), "service": None, "delegationId": None}
                                         for row in ready["bindings"]}},
        }
        source_config = private_material / "source-node.json"
        source_config.write_text(json.dumps(configuration))
        source_process = subprocess.Popen(
            [node, str(backend_root / "src/ainsMethodSourceServer.js")], cwd=backend_root,
            env={"PATH": os.environ.get("PATH", ""), "FDE_METHOD_SOURCE_ENABLED": "1",
                 "FDE_METHOD_SOURCE_CONFIG": str(source_config), "FDE_METHOD_SOURCE_PORT": "0",
                 "FDE_JOINT_SOURCE_DB_PASSWORD": ready["sourcePassword"], "FDE_JOINT_NODE_EXECUTE": node_execute,
                 "FDE_JOINT_NODE_LOOKUP": node_lookup}, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        stack.callback(_stop, source_process)
        source_ready = json.loads(source_process.stdout.readline())
        assert source_ready["host"] == "127.0.0.1"
        proxy = _DropResponseProxy()
        proxy.origin = f"http://127.0.0.1:{source_ready['port']}"
        proxy_origin = proxy.start(stack)
        bridge_config = private_material / "source-mcp.json"
        bridge_config.write_text(json.dumps({
            "source_origin": proxy_origin, "port": mcp_port, "receipt_public_keys": [str(files["source"][1])],
            "node_execute_token_env": "FDE_JOINT_NODE_EXECUTE", "node_lookup_token_env": "FDE_JOINT_NODE_LOOKUP",
            "mcp_execute_token_env": "FDE_JOINT_MCP_EXECUTE", "mcp_lookup_token_env": "FDE_JOINT_MCP_LOOKUP",
        }))
        bridge = subprocess.Popen(
            [sys.executable, "-B", "-m", "ai_native_system.fdesage_source", "--config", str(bridge_config)], cwd=ROOT,
            env={**os.environ, "FDE_JOINT_NODE_EXECUTE": node_execute, "FDE_JOINT_NODE_LOOKUP": node_lookup},
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        stack.callback(_stop, bridge)
        _wait_port(bridge, mcp_port)

        def intent(card_id, expected_revision=1):
            status, body = _request(ready["origin"] + f"/api/ops/wiki/method-cards/{card_id}/verification-requests",
                                    {"expectedRevision": expected_revision, "requestId": str(uuid4())}, ready["userToken"])
            if status != 200:
                raise AssertionError("The actual restricted FDE API did not capture an intent: " + str(status))
            return body["submission"]

        def workflow(capture, name):
            database = "fde_method_joint_" + secrets.token_hex(5) + "_" + name + "_test"
            with psycopg.connect(private["pgDSN"], autocommit=True) as connection:
                connection.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(database)))
            dsn = make_conninfo(private["pgDSN"], dbname=database)
            with psycopg.connect(dsn) as connection:
                connection.execute("CREATE SCHEMA ai_native")
            return MethodWorkflowFixture(dsn, capture, reviewer_actor=reviewer, tools_document=tools,
                                          authority_private_key_file=str(files["authority"][0]))

        for scenario in ("approve", "reject", "response_lost", "supersede", "source_revoke"):
            card_id = command("newCard")["cardId"]
            capture = intent(card_id)
            with workflow(capture, scenario) as fixture:
                review = fixture.plan()
                release_before = fixture.release.digest
                if scenario == "reject":
                    assert fixture.decide("reject")["status"] == "rejected"
                    counts = fixture.counts()
                    native = command("state", cardId=card_id)
                    assert counts["effects"] == counts["owp_authorizations"] == counts["owp_consumptions"] == 0
                    assert native["card"]["review_status"] == "draft" and int(native["operations"]["n"]) == 0
                    result["scenarios"].append({"name": scenario, "passed": True, "counts": counts, "native": native})
                    continue
                if scenario == "approve":
                    try:
                        fixture.decide(proposal_digest="0" * 64)
                    except ValueError:
                        pass
                    else:
                        raise AssertionError("A changed proposal digest was approved")
                    try:
                        fixture.runtime.decide(TENANT, fixture.task_id, reviewer, "approve",
                                               identity=IdentityContext(TENANT, reviewer, service=reviewer),
                                               proposal_digest=review["proposal_digest"])
                    except PermissionError:
                        pass
                    else:
                        raise AssertionError("A service identity was treated as a human approver")
                    requester = capture["requester"]["actor"]
                    with fixture.control.transaction(tenant=TENANT, write=True) as connection:
                        Policy().grant(connection, TENANT, requester, "approve", "task", fixture.task_id)
                    try:
                        fixture.runtime.decide(TENANT, fixture.task_id, requester, "approve",
                                               identity=IdentityContext(TENANT, requester),
                                               proposal_digest=review["proposal_digest"])
                    except PermissionError:
                        pass
                    else:
                        raise AssertionError("A requester approved their own task")
                assert fixture.decide()["status"] == "ready"
                authorization = fixture.authorize()
                if scenario == "supersede":
                    old_task = fixture.task_id
                    replacement = intent(card_id, capture["cardRevision"])
                    assert fixture.import_next_intent(replacement).status == "applied"
                    assert fixture.release.digest == release_before
                    previous_calls = len(proxy.calls)
                    assert fixture.runtime.advance(TENANT, old_task)["status"] == "blocked"
                    assert len(proxy.calls) == previous_calls
                    fixture.plan()
                    assert fixture.decide()["status"] == "ready"
                    authorization = fixture.authorize()
                    capture = replacement
                if scenario == "source_revoke":
                    status, revoked = _request(ready["origin"] + f"/api/ops/wiki/method-card-verifications/{capture['id']}/revoke",
                                               {}, ready["userToken"])
                    assert status == 200 and revoked["cut"] == "source_transaction_committed"
                    execute_before = proxy.calls.count("execute")
                    assert fixture.runtime.advance(TENANT, fixture.task_id)["status"] == "failed"
                    native = command("state", cardId=card_id)
                    counts = fixture.counts()
                    assert native["card"]["review_status"] == "draft" and int(native["card"]["revision"]) == capture["cardRevision"]
                    assert int(native["operations"]["n"]) == int(native["audits"]["n"]) == 1
                    assert counts["effects"] == counts["owp_effect_evidence"] == 0
                    stored = fixture.operation()
                    rejected = verify_source_receipt(stored["response"], destination.source.trusted_keys,
                                                     operation=stored["payload"], authorization_digest=authorization["digest"])
                    assert rejected["status"] == "rejected" and rejected["reason"] == "condition_mismatch"
                    task = fixture.runtime.advance(TENANT, fixture.task_id)
                    assert task["status"] == "failed"
                    assert proxy.calls.count("execute") == execute_before + 1
                    result["scenarios"].append({"name": scenario, "passed": True, "counts": counts, "native": native,
                                                "sourceCut": revoked["cut"], "ainsStatus": task["status"],
                                                "sourceReceipt": rejected,
                                                "note": "A valid sealed late grant received a signed conditional rejection; no card effect or fabricated cancellation status."})
                    continue
                if scenario == "response_lost":
                    proxy.drop_next = True
                execute_before = proxy.calls.count("execute")
                task = fixture.runtime.advance(TENANT, fixture.task_id)
                if scenario == "response_lost":
                    assert task["status"] == "reconciling"
                    assert fixture.counts()["effects"] == 0
                    native_after_commit = command("state", cardId=card_id)
                    assert native_after_commit["card"]["review_status"] == "verified"
                    assert int(native_after_commit["operations"]["n"]) == 1
                    task, jobs = fixture.reconcile()
                    assert len(jobs) == 1 and jobs[0]["status"] == "completed"
                assert task["status"] == "completed", task
                stored = fixture.operation()
                proof = verify_source_receipt(stored["response"], destination.source.trusted_keys,
                                              operation=stored["payload"], authorization_digest=authorization["digest"])
                assert proof["status"] == "succeeded"
                native = command("state", cardId=card_id)
                counts = fixture.counts()
                assert native["card"]["review_status"] == "verified"
                assert int(native["card"]["revision"]) == capture["cardRevision"] + 1
                assert int(native["operations"]["n"]) == int(native["audits"]["n"]) == 1
                assert counts["effects"] == counts["owp_consumptions"] == counts["owp_effect_evidence"] == 1
                fixture.runtime.advance(TENANT, fixture.task_id)
                assert proxy.calls.count("execute") == execute_before + 1
                attestation = Ed25519PrivateKey.generate()
                trust = {key_id(attestation.public_key()): attestation.public_key()}
                delivered = deliver_effect(fixture.attester, TENANT, fixture.task_id,
                                           lambda body: sign_effect(body, attestation), trust)
                checked = verify_effect(delivered["proof"], trust)
                assert checked["authorization_digest"] == authorization["digest"]
                result["scenarios"].append({"name": scenario, "passed": True, "counts": counts, "native": native,
                                            "sourceReceipt": proof, "effectEvidence": checked,
                                            "releaseDigest": fixture.release.digest,
                                            "negativeApprovalChecks": ["changed_proposal_digest", "service_identity", "requester_self_approval"] if scenario == "approve" else [],
                                            "sameReleaseAcrossSupersedingIntents": fixture.release.digest == release_before})
        stopped = command("stop")
        assert stopped["apiChildExit"] == 0
        helper.wait(timeout=4)
        assert helper.returncode == 0
        _stop(bridge)
        _stop(source_process)
        result["processes"] = [{"name": "FDE user API", "exit": stopped["apiChildExit"]},
                               {"name": "test-only MySQL preparer", "exit": helper.returncode},
                               {"name": "official MCP bridge", "exit": bridge.returncode},
                               {"name": "actual Node source server", "exit": source_process.returncode}]
        assert source_process.returncode == 0
        # The official SDK fixture is stopped by SIGTERM; reaping is distinct
        # from claiming an application-coordinated zero-exit shutdown.
        assert bridge.returncode in (0, -signal.SIGTERM)
        assert all(hashlib.sha256(Path(path).read_bytes()).hexdigest() == fingerprint
                   for path, fingerprint in fingerprints.items())
        result["unchangedSourceFingerprints"] = fingerprints
        result["sourceTransportCalls"] = proxy.calls
        result["status"] = "passed"
    (output / "result.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-config", type=Path, required=True)
    parser.add_argument("--backend-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--node", required=True)
    arguments = parser.parse_args()
    result = verify(arguments.private_config.resolve(), arguments.backend_root.resolve(), arguments.output.resolve(), arguments.node)
    print(json.dumps({"status": result["status"], "scenarios": len(result["scenarios"]),
                      "syntheticApproval": True, "productionTouched": False}))


if __name__ == "__main__":
    main()
