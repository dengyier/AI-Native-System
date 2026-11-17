import json
import threading
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from ai_native_system.remote import HttpRemote, MCPRemote, RemoteError


TOKEN = "secret-bearer-credential"
SESSION = "local-mcp-session"
VERSION = "2025-11-25"
OPERATION = {"idempotency_key": "one", "target": "item-1"}
RECEIPT = {"state": "completed", "operation_key": "one"}


def json_bytes(payload):
    return json.dumps(payload).encode("utf-8")


@contextmanager
def endpoint(handler):
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def dispatch(self):
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length)) if length else None
            headers = {key.lower(): value for key, value in self.headers.items()}
            calls.append((self.command, self.path, headers, body))
            status, reply_headers, payload = handler(*calls[-1])
            self.send_response(status)
            for key, value in reply_headers.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = do_POST = do_DELETE = dispatch

        def log_message(self, format, *args):
            pass

    with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, args=(0.01,), daemon=True)
        thread.start()
        try:
            yield f"http://127.0.0.1:{server.server_port}", calls
        finally:
            server.shutdown()
            thread.join()


def json_response(payload, headers=None):
    return 200, {"Content-Type": "application/json", **(headers or {})}, json_bytes(payload)


def mcp_server(*, sse=False, newline=b"\n", version=VERSION, tool_error=False, missing_tool=False, wrong_id=False):
    def respond(method, path, headers, body):
        if method == "DELETE":
            return 204, {}, b""
        rpc = body["method"]
        if rpc == "notifications/initialized":
            return 202, {}, b""
        if rpc == "initialize":
            return json_response({
                "jsonrpc": "2.0",
                "id": body["id"],
                "result": {"protocolVersion": version, "capabilities": {"tools": {}}, "serverInfo": {
                    "name": "test", "version": "1",
                }},
            }, {"Mcp-Session-Id": SESSION})
        if rpc == "tools/list":
            if body.get("params", {}).get("cursor") == "next":
                tools = [] if missing_tool else [{"name": "lookup_tool"}]
                result = {"tools": tools}
            else:
                result = {"tools": [{"name": "execute_tool"}], "nextCursor": "next"}
        else:
            if tool_error:
                result = {"isError": True, "content": [{"type": "text", "text": TOKEN}]}
            elif body["params"]["name"] == "lookup_tool":
                result = {"content": [{"type": "text", "text": json.dumps(RECEIPT)}]}
            else:
                result = {"structuredContent": RECEIPT, "content": []}
        envelope = {"jsonrpc": "2.0", "id": 999 if wrong_id else body["id"], "result": result}
        if sse:
            lines = [
                b": ready", b"", b"id: cursor", b"data:", b"",
                b'data: {"jsonrpc":"2.0","method":"notifications/progress"}',
                b"", b"event: message", b"data: " + json_bytes(envelope), b"", b"",
            ]
            return 200, {"Content-Type": "text/event-stream"}, newline.join(lines)
        return json_response(envelope)

    return respond


class RemoteTransportTests(unittest.TestCase):
    def test_http_methods_pass_opaque_operation_and_never_expose_token_in_identity(self):
        with endpoint(lambda *args: json_response(RECEIPT)) as (base, calls):
            remote = HttpRemote(base + "/tools/", token=TOKEN)
            self.assertEqual(remote.execute(OPERATION), RECEIPT)
            self.assertEqual(remote.lookup(OPERATION), RECEIPT)
            self.assertEqual(remote.identity, {"type": "http", "endpoint": base + "/tools"})
            self.assertEqual([call[:2] for call in calls], [
                ("POST", "/tools/execute"), ("POST", "/tools/lookup"),
            ])
            self.assertTrue(all(call[2]["authorization"] == f"Bearer {TOKEN}" and call[3] == OPERATION for call in calls))

    def test_http_rejects_invalid_mapping_and_limits_response_size(self):
        for result in (["not a mapping"], {"oversized": "x" * 300_000}):
            with self.subTest(small=len(str(result)) < 100):
                with endpoint(lambda *args: json_response(result)) as (base, _):
                    with self.assertRaises(RemoteError):
                        HttpRemote(base).execute(OPERATION)

    def test_http_redirect_does_not_send_an_authenticated_request_elsewhere(self):
        with endpoint(lambda *args: json_response(RECEIPT)) as (destination, leaked):
            with endpoint(lambda *args: (302, {"Location": destination}, TOKEN.encode())) as (base, _):
                with self.assertRaises(RemoteError) as caught:
                    HttpRemote(base, token=TOKEN).execute(OPERATION)
        self.assertEqual(leaked, [])
        self.assertNotIn(TOKEN, str(caught.exception))

    def test_remote_rejects_cleartext_and_embedded_url_credentials(self):
        for url in ("http://example.org", "https://user:password@example.org", "https://example.org?t=secret"):
            with self.subTest(url=url):
                with self.assertRaises(RemoteError):
                    HttpRemote(url)

    def test_mcp_negotiates_discovers_calls_and_closes_fresh_sessions(self):
        for newline in (None, b"\n", b"\r\n", b"\r"):
            with self.subTest(newline=newline):
                with endpoint(mcp_server(sse=newline is not None, newline=newline)) as (base, calls):
                    remote = MCPRemote(base + "/mcp", "execute_tool", "lookup_tool", token=TOKEN)
                    self.assertEqual(remote.identity, {
                        "type": "mcp", "endpoint": base + "/mcp",
                        "execute_tool": "execute_tool", "lookup_tool": "lookup_tool",
                    })
                    self.assertEqual(remote.execute(OPERATION), RECEIPT)
                    self.assertEqual(remote.lookup(OPERATION), RECEIPT)

                expected = ["initialize", "notifications/initialized", "tools/list", "tools/list", "tools/call", None]
                self.assertEqual([c[3]["method"] if c[3] else None for c in calls], expected * 2)
                self.assertEqual(calls[4][3]["params"], {"name": "execute_tool", "arguments": OPERATION})
                self.assertEqual(calls[10][3]["params"], {"name": "lookup_tool", "arguments": OPERATION})
                for verb, path, headers, packet in calls:
                    self.assertEqual((path, headers["authorization"]), ("/mcp", f"Bearer {TOKEN}"))
                    if verb == "POST":
                        self.assertIn("application/json", headers["accept"])
                        self.assertIn("text/event-stream", headers["accept"])
                    if packet and packet["method"] == "initialize":
                        self.assertEqual(packet["params"]["protocolVersion"], VERSION)
                        self.assertEqual(packet["params"]["capabilities"], {})
                        self.assertNotIn("mcp-session-id", headers)
                    else:
                        self.assertEqual(headers["mcp-session-id"], SESSION)
                        self.assertEqual(headers["mcp-protocol-version"], VERSION)

    def test_mcp_stops_before_calling_unknown_tools_and_sanitizes_tool_errors(self):
        for options in (
            {"version": "2024-11-05"}, {"missing_tool": True}, {"wrong_id": True}, {"tool_error": True},
        ):
            with self.subTest(options=options):
                with endpoint(mcp_server(**options)) as (base, calls):
                    with self.assertRaises(RemoteError) as caught:
                        MCPRemote(base + "/mcp", "execute_tool", "lookup_tool", token=TOKEN).execute(OPERATION)
                packets = [packet for _, _, _, packet in calls if packet]
                self.assertEqual(any(p["method"] == "tools/call" for p in packets), options.get("tool_error", False))
                self.assertNotIn(TOKEN, str(caught.exception))
                if "version" in options:
                    self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
