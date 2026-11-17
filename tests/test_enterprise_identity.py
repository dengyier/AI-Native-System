import base64
import json
import shutil
import ssl
import subprocess
import tempfile
import time
import unittest
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from unittest.mock import patch
from urllib.parse import parse_qs

from ai_native_system.identity import EnterpriseIdentity, HttpIntrospector, IdentityBinding, IdentityContext, IdentityError


ISSUER, AUDIENCE = "https://issuer.example", "ai-native-system"
SUBJECT, CLIENT = "idp-alice", "registered-oauth-client"
BINDINGS = [
    IdentityBinding(SUBJECT, CLIENT, "alpha", "alice"),
    IdentityBinding(SUBJECT, CLIENT, "alpha", "alice", "automation", "idp-automation"),
    IdentityBinding("idp-automation", CLIENT, "alpha", "automation", "automation"),
]


def claims(**updates):
    return {
        "active": True, "iss": ISSUER, "aud": [AUDIENCE], "token_type": "Bearer",
        "sub": SUBJECT, "client_id": CLIENT, "scope": "openid ai-native.access", "exp": int(time.time()) + 120,
        **updates,
    }


class EnterpriseIdentityTests(unittest.TestCase):
    def test_direct_human_machine_and_delegated_bindings(self):
        scenarios = (
            (claims(actor="admin", service="admin", tenant="other"), IdentityContext("alpha", "alice")),
            (claims(sub="idp-automation", aud=AUDIENCE), IdentityContext("alpha", "automation", "automation")),
            (claims(act={"sub": "idp-automation"}, delegation_id="approval-a"),
             IdentityContext("alpha", "alice", "automation", "approval-a")),
        )
        for response, expected in scenarios:
            with self.subTest(expected=expected):
                def introspect(token):
                    self.assertEqual(token, "opaque-token")
                    return response
                verifier = EnterpriseIdentity(ISSUER, AUDIENCE, BINDINGS, introspect)
                actual = verifier.authenticate("opaque-token")
                self.assertEqual(actual.as_document(), {**expected.as_document(), "expires_at": response["exp"]})
                self.assertEqual(actual, IdentityContext.from_document(actual.as_document()))
                self.assertEqual(actual.principals, expected.principals)

    def test_invalid_claims_and_unmapped_delegations_fail_closed(self):
        old, future = int(time.time()) - 1, int(time.time()) + 60
        for update in (
            {"active": False}, {"active": 1}, {"iss": "https://forged.example"},
            {"aud": "different-service"}, {"aud": [AUDIENCE, 1]}, {"token_type": "refresh_token"},
            {"token_use": "id"}, {"scope": "openid"}, {"scope": ["ai-native.access"]},
            {"exp": old}, {"exp": True}, {"exp": None}, {"exp": 2**63}, {"nbf": future}, {"iat": future},
            {"client_id": "other-client"}, {"client_id": []}, {"sub": "unmapped"},
            {"delegation_id": "grant"}, {"act": {"sub": "idp-automation"}},
            {"act": {"sub": "forged"}, "delegation_id": "grant"},
            {"act": {"sub": "idp-automation", "iss": "https://different.example"}, "delegation_id": "grant"},
            {"act": {"sub": "idp-automation", "act": {"sub": "idp-2"}}, "delegation_id": "grant"},
            {"act": {"sub": "idp-automation"}, "delegation_id": []},
        ):
            with self.subTest(update=update), self.assertRaises(IdentityError):
                verifier = EnterpriseIdentity(ISSUER, AUDIENCE, BINDINGS, lambda _: claims(**update))
                verifier.authenticate("opaque-token")

    def test_rejects_bad_token_before_contacting_transport_and_hides_errors(self):
        def introspect(token):
            raise RuntimeError(f"transport failed for {token}")

        verifier = EnterpriseIdentity(ISSUER, AUDIENCE, BINDINGS, introspect)
        for invalid in ("", "malformed\nheader", "with spaces", "令牌", "x" * 8193, None):
            with self.subTest(invalid_type=type(invalid)), self.assertRaisesRegex(IdentityError, "Invalid enterprise"):
                verifier.authenticate(invalid)
        with self.assertRaisesRegex(IdentityError, "^Enterprise identity could not be verified$"):
            verifier.authenticate("secret-token")

    def test_binding_and_configuration_validation(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            EnterpriseIdentity(ISSUER, AUDIENCE, BINDINGS * 2, lambda _: claims())
        with self.assertRaises(ValueError):
            IdentityBinding(SUBJECT, CLIENT, "alpha", "alice", "automation")
        with self.assertRaises(ValueError):
            IdentityContext.from_document({"tenant": "alpha", "actor": "alice", "service": "automation"})
        with self.assertRaises(ValueError):
            IdentityContext.from_document({"tenant": "alpha", "actor": "alice", "roles": ["admin"]})
        document = {
            "issuer": ISSUER, "audience": AUDIENCE, "endpoint": ISSUER + "/introspect", "introspection_client_id": "api",
            "introspection_secret_env": "SECRET", "bindings": [
                {"subject": SUBJECT, "client_id": CLIENT, "tenant": "alpha", "actor": "alice"}
            ],
        }
        with self.assertRaisesRegex(ValueError, "credentials"):
            EnterpriseIdentity.from_config(document, env={})
        self.assertIsInstance(EnterpriseIdentity.from_config(document, env={"SECRET": "local-test"}), EnterpriseIdentity)
        for endpoint in (
            "http://localhost/introspect", "https://user:password@issuer.example",
            "https://issuer.example/path?redirect=other", "https://issuer.example/path#fragment",
            "https://issuer.example:0/path", "https://issuer.example/bad path",
        ):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                HttpIntrospector(endpoint, "client", "test-secret")


@contextmanager
def https_provider():
    received = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_GET(self):
            received.append((self.path, self.headers.get("Authorization"), {}))
            self.send_response(200)
            self.end_headers()

        def do_POST(self):
            form = parse_qs(self.rfile.read(int(self.headers["Content-Length"])).decode("ascii"))
            received.append((self.path, self.headers["Authorization"], form))
            if self.path in ("/redirect", "/redirect-preserve-method"):
                self.send_response(302 if self.path == "/redirect" else 307)
                self.send_header("Location", "/trap")
                self.end_headers()
                return
            body = {
                "/duplicate": b'{"active":false,"active":true}',
                "/large": b" " * 65537,
            }.get(self.path, json.dumps(claims()).encode())
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            try:
                self.wfile.write(body)
            except ConnectionError:
                pass

    with tempfile.TemporaryDirectory() as directory:
        key, cert = directory + "/key.pem", directory + "/cert.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=127.0.0.1",
             "-addext", "subjectAltName=IP:127.0.0.1", "-keyout", key, "-out", cert],
            check=True, capture_output=True, timeout=15,
        )
        with ThreadingHTTPServer(("127.0.0.1", 0), Handler) as server:
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(cert, key)
            server.socket = tls.wrap_socket(server.socket, server_side=True)
            worker = Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                yield f"https://127.0.0.1:{server.server_port}", cert, received
            finally:
                server.shutdown()
                worker.join()


@unittest.skipUnless(shutil.which("openssl"), "openssl is needed for the local TLS fixture")
class HttpIntrospectionTests(unittest.TestCase):
    def test_tls_form_post_and_no_redirect_forwarding(self):
        with https_provider() as (endpoint, cert, received):
            def verifier(path):
                return EnterpriseIdentity(ISSUER, AUDIENCE, BINDINGS,
                                          HttpIntrospector(endpoint + path, "api:scoped", "local secret"))

            with self.assertRaises(IdentityError):
                verifier("/introspect").authenticate("opaque+token")
            self.assertEqual(received, [])
            with patch.dict("os.environ", {"SSL_CERT_FILE": cert, "HTTPS_PROXY": "http://127.0.0.1:1", "NO_PROXY": ""}):
                self.assertEqual(verifier("/introspect").authenticate("opaque+token").actor, "alice")
                for path in ("/redirect", "/redirect-preserve-method", "/duplicate", "/large"):
                    with self.subTest(path=path), self.assertRaises(IdentityError):
                        verifier(path).authenticate("opaque+token")
            auth = "Basic " + base64.b64encode(b"api%3Ascoped:local+secret").decode()
            self.assertEqual(received, [
                (path, auth, {"token": ["opaque+token"], "token_type_hint": ["access_token"]})
                for path in ("/introspect", "/redirect", "/redirect-preserve-method", "/duplicate", "/large")
            ])


if __name__ == "__main__":
    unittest.main()
