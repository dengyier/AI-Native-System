"""Authenticated loopback HTTP entry point for applications."""
import hmac
import json
import sqlite3
from contextlib import closing, contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Condition
from urllib.parse import unquote, urlsplit

from . import governance
from .identity import require_identity
from .registry import unique_keys
from .model import ModelError
from .runtime import permitted
from .storage import RuntimeStore, database, task_data


_RUNTIME_TABLES = frozenset({
    "principals", "objects", "knowledge", "tasks", "steps", "events",
    "execution_claims", "remote_operations", "effects",
})


def _storage_ready(path):
    try:
        if isinstance(path, RuntimeStore):
            path.check_ready()
            return True
        uri = Path(path).resolve().as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, timeout=1)) as connection:
            tables = {name for name, in connection.execute("SELECT name FROM sqlite_schema WHERE type='table'")}
            return _RUNTIME_TABLES <= tables
    except Exception:
        return False


class _ApplicationServer(ThreadingHTTPServer):
    def __init__(self, address, handler):
        self._condition = Condition()
        self._draining = False
        self._pending_posts = 0
        super().__init__(address, handler)

    @property
    def draining(self):
        with self._condition:
            return self._draining

    @contextmanager
    def admit_post(self):
        with self._condition:
            admitted = not self._draining
            if admitted:
                self._pending_posts += 1
        try:
            yield admitted
        finally:
            if admitted:
                with self._condition:
                    self._pending_posts -= 1
                    if self._pending_posts == 0:
                        self._condition.notify_all()

    def drain(self, timeout=20):
        """Refuse new POSTs and wait up to timeout seconds for admitted POSTs."""
        with self._condition:
            self._draining = True
            return self._condition.wait_for(lambda: self._pending_posts == 0, timeout=timeout)


class ApplicationAPI:
    def __init__(self, runtime, credentials, *, enterprise_identity=None, catalog=None, console=False,
                 control_store=None, delivery_store=None, attestation_keys=None):
        if enterprise_identity is not None and (credentials or not isinstance(runtime.path, RuntimeStore)):
            raise ValueError("Enterprise authentication requires PostgreSQL and a dedicated API configuration")
        if not credentials and enterprise_identity is None:
            raise ValueError("Configure at least one API credential")
        self.runtime = runtime
        self.credentials = credentials
        self.enterprise_identity = enterprise_identity
        self.catalog = catalog
        self.workspace = None
        if enterprise_identity is not None and (console or catalog is not None):
            from .console_api import ConsoleOperations

            retrieval = catalog.retrieval if catalog is not None else None
            self.workspace = ConsoleOperations(runtime, control=control_store, delivery=delivery_store,
                                               attestation_keys=attestation_keys,
                                               embedding=retrieval.embedding if retrieval is not None else None)
        for token, identity in credentials.items():
            if not isinstance(token, str) or len(token) < 24:
                raise ValueError("API credentials must contain at least 24 characters")
            if set(identity) != {"tenant", "actor"} or not all(isinstance(v, str) and v for v in identity.values()):
                raise ValueError("Each credential needs tenant and actor")

    def authenticate(self, token):
        if self.enterprise_identity is not None:
            identity = self.enterprise_identity.authenticate(token)
            with database(self.runtime.path, tenant=identity.tenant) as connection:
                if not governance.enabled(connection, identity.tenant):
                    raise PermissionError("Enterprise mode is required")
                require_identity(connection, identity)
            return identity
        for expected, identity in self.credentials.items():
            if hmac.compare_digest(token.encode(), expected.encode()):
                with database(self.runtime.path, tenant=identity["tenant"]) as connection:
                    if identity["tenant"] in self.runtime.owp_ledgers or governance.enabled(connection, identity["tenant"]):
                        raise PermissionError("Enterprise authentication is required")
                    principal = connection.execute(
                        "SELECT active FROM principals WHERE tenant=? AND id=?",
                        (identity["tenant"], identity["actor"]),
                    ).fetchone()
                if principal is not None and principal["active"]:
                    return identity
        raise PermissionError("Invalid credential")

    def dispatch(self, method, path, token, body):
        target = urlsplit(path)
        return self._dispatch_authenticated(method, target.path, self.authenticate(token), body, query=target.query)

    def _dispatch_authenticated(self, method, path, identity, body, *, query=""):
        if self.enterprise_identity is not None:
            return self._dispatch_enterprise(method, path, identity, body, query=query)
        tenant, actor = identity["tenant"], identity["actor"]
        if method == "POST" and path == "/v1/tasks":
            if set(body) != {"application", "object_id", "request_key"}:
                raise ValueError("Expected application, object_id and request_key")
            return self.runtime.submit(tenant, body["application"], body["object_id"], actor, body["request_key"])
        parts = path.strip("/").split("/")
        if len(parts) not in (3, 4) or parts[:2] != ["v1", "tasks"]:
            raise LookupError("Unknown endpoint")
        task_id = parts[2]
        with database(self.runtime.path, tenant=tenant) as connection:
            task = task_data(connection, tenant, task_id)
            if actor != task["requester"]:
                try:
                    _, action, revision = self.runtime.registry.definition(task["application"])
                except ValueError as exc:
                    raise PermissionError("Task access denied") from exc
                if revision != task["definition_hash"] or not permitted(connection, tenant, actor, action["approval_role"]):
                    raise PermissionError("Task access denied")
        if method == "GET" and len(parts) == 3:
            return self.runtime.inspect(tenant, task_id)
        if method != "POST" or len(parts) != 4:
            raise LookupError("Unknown endpoint")
        if parts[3] == "decision" and set(body) == {"verdict"}:
            return self.runtime.decide(tenant, task_id, actor, body["verdict"])
        if body:
            raise ValueError("This endpoint accepts an empty object")
        if parts[3] == "advance":
            return self.runtime.advance(tenant, task_id, worker=False)
        if parts[3] == "reconcile":
            return self.runtime.reconcile(tenant, task_id, worker=False)
        if parts[3] == "retry-remote":
            return self.runtime.retry_remote(tenant, task_id, actor)
        if parts[3] == "cancel":
            return self.runtime.cancel(tenant, task_id, actor)
        raise LookupError("Unknown endpoint")


    def _dispatch_enterprise(self, method, path, identity, body, *, query):
        tenant, actor = identity.tenant, identity.actor
        workspace = self.workspace
        parts = []
        for component in path.strip("/").split("/"):
            decoded = unquote(component, errors="strict")
            if "/" in decoded or "\\" in decoded or any(ord(char) < 32 for char in decoded):
                raise ValueError("Invalid route parameter")
            parts.append(decoded)
        if workspace is not None:
            if method == "GET" and parts == ["v1", "applications"] and not body:
                return {"applications": []} if self.catalog is None else self.catalog.list(identity)
            if method == "POST" and len(parts) == 4 and parts[:2] == ["v1", "applications"] and parts[3] == "run":
                if self.catalog is None:
                    raise LookupError("Applications are unavailable")
                return self.catalog.run(identity, parts[2], body)
            if parts[:2] == ["v1", "releases"] and len(parts) in (3, 4):
                return workspace.release(identity, method, parts[2], parts[3] if len(parts) == 4 else None, body)
            if method == "POST" and parts == ["v1", "facts", "status"]:
                return workspace.facts(identity, body)
        if method == "POST" and path == "/v1/query":
            from .policy import Policy
            from .releases import ReleaseStore
            from .semantic_query import SemanticQuery

            authoritative = "authoritative" in body
            if authoritative and (set(body) != {"application", "object_type", "object_id", "authoritative"}
                                  or body["application"] is None):
                raise ValueError("Authoritative queries require an application and one canonical object")
            if body.keys() - {"application", "object_type", "object_id", "filters", "limit", "follow",
                              "count", "discover_actions", "explain", "authoritative"}:
                raise ValueError("Invalid query options")
            body = dict(body)
            application = body.pop("application", None)
            if application is None:
                return SemanticQuery(self.runtime.path, self.runtime.registry).query(identity, **body)
            with database(self.runtime.path, tenant=tenant) as connection:
                policy = Policy()
                policy.require(connection, identity, "read", "app", application)
                record = ReleaseStore.resolve(connection, tenant, application)
                if record is None:
                    raise ValueError("Application has no selected release")
                snapshot = record.snapshot
                policy.require(connection, identity, "read", "release", snapshot.digest)
                if authoritative:
                    from .authoritative_query import AuthoritativeQuery

                    return AuthoritativeQuery(self.runtime.path, policy, snapshot).query(
                        connection, identity, body["object_type"], body["object_id"], body["authoritative"],
                    )
                query = SemanticQuery(self.runtime.path, snapshot.registry(), policy, ontology=snapshot.ontology())
                return query.query(identity, connection=connection, **body)
        if method == "POST" and path == "/v1/tasks":
            required = {"application", "object_id", "request_key"}
            if not required <= body.keys() <= required | {"release_digest", "knowledge_citations", "expected_object_version"}:
                raise ValueError("Invalid task submission")
            task = self.runtime.submit(
                tenant, body["application"], body["object_id"], actor, body["request_key"],
                identity=identity, release_digest=body.get("release_digest"),
                knowledge_citations=body.get("knowledge_citations"),
                expected_object_version=body.get("expected_object_version"),
            )
            return {"id": task["id"], "status": task["status"]}
        if len(parts) not in (3, 4) or parts[:2] != ["v1", "tasks"]:
            raise LookupError("Unknown endpoint")
        task_id = parts[2]
        if method == "GET":
            if len(parts) == 3:
                return (workspace.task(identity, task_id) if workspace is not None else
                        self.runtime.inspect(tenant, task_id, identity=identity))
            if parts[3] == "evidence":
                return (workspace.evidence(identity, task_id) if workspace is not None else
                        self.runtime.inspect(tenant, task_id, identity=identity, evidence=True))
            if parts[3] == "events":
                from .console_api import ConsoleOperations

                return (workspace or ConsoleOperations(self.runtime)).events(identity, task_id, query)
            if parts[3] == "handover" and workspace is not None:
                return workspace.handover(identity, task_id)
        if method != "POST" or len(parts) != 4:
            raise LookupError("Unknown endpoint")
        operation = parts[3]
        if workspace is not None and operation == "handover":
            return workspace.handover(identity, task_id, body)
        if operation == "decision":
            if set(body) != {"verdict", "proposal_digest"}:
                raise ValueError("Decision requires the proposal digest")
            task = self.runtime.decide(
                tenant, task_id, actor, body["verdict"], identity=identity, proposal_digest=body["proposal_digest"],
            )
        else:
            if body:
                raise ValueError("This endpoint accepts an empty object")
            if operation == "advance":
                task = self.runtime.advance(tenant, task_id, identity=identity, worker=False)
            elif operation == "reconcile":
                task = (workspace.reconcile(identity, task_id) if workspace is not None else
                        self.runtime.reconcile(tenant, task_id, identity=identity, worker=False))
            elif operation == "retry-remote":
                task = self.runtime.retry_remote(tenant, task_id, actor, identity=identity)
            elif operation == "cancel":
                task = self.runtime.cancel(tenant, task_id, actor, identity=identity)
            else:
                raise LookupError("Unknown endpoint")
        summary = {"id": task["id"], "status": task["status"]}
        if "authorization" in task:
            summary["authorization"] = task["authorization"]
        return summary


def make_server(runtime, credentials, port=8789, *, enterprise_identity=None, catalog=None, console=False,
                control_store=None, delivery_store=None, attestation_keys=None):
    api = ApplicationAPI(runtime, credentials, enterprise_identity=enterprise_identity, catalog=catalog, console=console,
                         control_store=control_store, delivery_store=delivery_store, attestation_keys=attestation_keys)
    package_directory = Path(__file__).resolve().parent
    asset_directory = package_directory / "_console"
    if not asset_directory.is_dir():
        asset_directory = package_directory.parent / "console"
    assets = {
        "/console/": ("index.html", "text/html; charset=utf-8"),
        "/console/style.css": ("style.css", "text/css; charset=utf-8"),
        "/console/app.js": ("app.js", "text/javascript; charset=utf-8"),
    } if console else {}

    class Handler(BaseHTTPRequestHandler):
        timeout = 20

        def log_message(self, *args):
            pass

        def do_GET(self):
            if self.path == "/health/live":
                self.write_json(200, {"status": "live"})
                return
            if self.path == "/health/ready":
                ready = not self.server.draining and _storage_ready(runtime.path) and not self.server.draining
                self.write_json(200 if ready else 503, {"status": "ready" if ready else "not_ready"})
                return
            target = urlsplit(self.path).path
            if target in assets:
                name, mime = assets[target]
                try:
                    content = (asset_directory / name).read_bytes()
                except OSError:
                    self.write_json(404, {"error": "console asset unavailable"})
                    return
                self.write_bytes(200, content, mime)
                return
            self.respond()

        def do_POST(self):
            with self.server.admit_post() as admitted:
                if not admitted:
                    self.write_json(503, {"error": "service is draining"})
                    return
                self.respond()

        def respond(self):
            try:
                auth = self.headers.get("Authorization", "")
                if not auth.startswith("Bearer "):
                    raise PermissionError("Bearer credential required")
                # Reject unauthenticated requests before reading any request body.
                identity = api.authenticate(auth[7:])
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 <= length <= 65536:
                    raise ValueError("Request body limit is 64 KiB")
                body = json.loads(self.rfile.read(length), object_pairs_hook=unique_keys) if length else {}
                if not isinstance(body, dict):
                    raise ValueError("Expected a JSON object")
                target = urlsplit(self.path)
                result = api._dispatch_authenticated(self.command, target.path, identity, body, query=target.query)
                status = 200
            except PermissionError:
                status, result = 403, {"error": "access denied"}
            except (ValueError, TypeError, KeyError):
                status, result = 400, {"error": "invalid request or unavailable task"}
            except LookupError:
                status, result = 404, {"error": "unknown endpoint"}
            except ModelError:
                status, result = 503, {"error": "model unavailable; task can be retried"}
            except Exception:
                status, result = 500, {"error": "execution failed; inspect task before retry"}
            self.write_json(status, result)

        def write_json(self, status, result):
            self.write_bytes(status, json.dumps(result, ensure_ascii=False).encode(), "application/json; charset=utf-8")

        def write_bytes(self, status, payload, content_type):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; "
                             "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

    return _ApplicationServer(("127.0.0.1", port), Handler)
