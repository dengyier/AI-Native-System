"""A loopback downstream with independent, durable idempotency receipts."""

import json
import socket
import threading
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ai_native_system.storage import database, digest, encode


REQUIRED_OPERATION = {
    "operation_id", "request_hash", "tenant", "action", "object_id", "expected_version",
    "from_state", "to_state", "requester", "approver", "executor",
}


class RemoteFixture:
    def __init__(self, path):
        self.path = path
        self.calls = []
        self.committed = threading.Event()
        self.release_response = threading.Event()
        self.hold_execute_response = False
        self.drop_before_commit = False
        self.drop_after_commit = False
        self.lookup_unavailable = False
        self.wrong_execute_hash = False
        self.wrong_lookup_hash = False
        with database(self.path, write=True) as connection:
            connection.execute("""CREATE TABLE remote_objects (
                tenant TEXT NOT NULL, id TEXT NOT NULL, state TEXT NOT NULL,
                version INTEGER NOT NULL, PRIMARY KEY (tenant, id)
            )""")
            connection.execute("""CREATE TABLE remote_operations (
                id TEXT PRIMARY KEY, request TEXT NOT NULL, response TEXT NOT NULL
            )""")
            connection.execute("INSERT INTO remote_objects VALUES ('local', 'asset-1', 'pending', 1)")

    def __enter__(self):
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                try:
                    size = int(self.headers.get("content-length", "0"))
                    if not 1 <= size <= 16_384:
                        raise ValueError("invalid request size")
                    payload = json.loads(self.rfile.read(size))
                    if not isinstance(payload, dict):
                        raise ValueError("invalid request body")
                    status, body = fixture.respond(self.path, payload)
                except (ValueError, KeyError, TypeError):
                    status, body = 400, {"error": "invalid request"}
                if status is None:
                    self.close_connection = True
                    with suppress(OSError):
                        self.connection.shutdown(socket.SHUT_RDWR)
                    return
                raw = encode(body).encode("utf-8")
                with suppress(BrokenPipeError, ConnectionResetError):
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)

            def log_message(self, format, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.endpoint = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.release_response.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)

    def respond(self, path, payload):
        self.calls.append((path, payload))
        if path == "/lookup":
            if self.lookup_unavailable:
                return 503, {"error": "downstream lookup unavailable"}
            status, body = self.lookup(payload)
            if self.wrong_lookup_hash and status == 200:
                body["request_hash"] = "b" * 64
            return status, body
        if path != "/execute":
            return 404, {"error": "unknown endpoint"}
        if self.drop_before_commit:
            return None, None
        status, body = self.execute(payload)
        if status == 200 and body["status"] == "succeeded":
            self.committed.set()
            if self.hold_execute_response:
                self.release_response.wait(4)
            if self.drop_after_commit:
                return None, None
        if self.wrong_execute_hash and status == 200:
            body["request_hash"] = "a" * 64
        return status, body

    @staticmethod
    def receipt(payload, status):
        return {"operation_id": payload["operation_id"], "request_hash": payload["request_hash"], "status": status}

    def execute(self, payload):
        if not REQUIRED_OPERATION <= payload.keys():
            raise ValueError("missing operation fields")
        identity = {key: value for key, value in payload.items() if key != "request_hash"}
        if payload["request_hash"] != digest(identity):
            raise ValueError("request hash does not match payload")
        with database(self.path, write=True) as connection:
            prior = connection.execute(
                "SELECT request, response FROM remote_operations WHERE id = ?", (payload["operation_id"],),
            ).fetchone()
            if prior is not None:
                if prior["request"] != encode(payload):
                    return 409, self.receipt(payload, "rejected")
                return 200, json.loads(prior["response"])
            changed = connection.execute(
                """UPDATE remote_objects SET state = ?, version = version + 1
                   WHERE tenant = ? AND id = ? AND state = ? AND version = ?""",
                (payload["to_state"], payload["tenant"], payload["object_id"],
                 payload["from_state"], payload["expected_version"]),
            )
            result = self.receipt(payload, "succeeded" if changed.rowcount == 1 else "rejected")
            if changed.rowcount == 1:
                result["result"] = {"state": payload["to_state"], "version": payload["expected_version"] + 1}
            connection.execute("INSERT INTO remote_operations VALUES (?, ?, ?)",
                               (payload["operation_id"], encode(payload), encode(result)))
            return 200, result

    def lookup(self, payload):
        tenant = payload["tenant"]
        with database(self.path) as connection:
            prior = connection.execute(
                "SELECT request, response FROM remote_operations WHERE id = ?", (payload["operation_id"],),
            ).fetchone()
            if prior is None:
                return 200, self.receipt(payload, "not_found")
            request = json.loads(prior["request"])
            if request["request_hash"] != payload["request_hash"] or request["tenant"] != tenant:
                return 409, self.receipt(payload, "rejected")
            return 200, json.loads(prior["response"])

    def operation_states(self):
        with database(self.path) as connection:
            return [json.loads(row["response"]) for row in connection.execute("SELECT response FROM remote_operations")]

    def object_status(self, tenant="local", object_id="asset-1"):
        with database(self.path) as connection:
            row = connection.execute(
                "SELECT state,version FROM remote_objects WHERE tenant = ? AND id = ?", (tenant, object_id),
            ).fetchone()
            return dict(row)
