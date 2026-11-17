"""Short-lived task and explicit private cross-task citation memory."""

from datetime import datetime, timedelta, timezone

from . import governance
from .identity import IdentityContext, _name
from .knowledge_evidence import EvidenceStore, _citation, _governed, _live_fragment
from .policy import Policy
from .storage import database, digest, encode


_MAX_TTL = {"task": 86400, "cross_task": 604800}
_ACTIVE_TASKS = ("planning", "awaiting_approval", "ready", "reconciling")
_MAX_SCOPE_ENTRIES = 32
_MAX_OWNER_ENTRIES = 256


def _validate(identity, scope, scope_id):
    if not isinstance(identity, IdentityContext):
        raise PermissionError("Trusted identity required")
    if not isinstance(scope, str) or scope not in _MAX_TTL or not _name(scope_id):
        raise ValueError("Expected a task or explicit cross-task memory scope")


def _owner(identity):
    return identity.tenant, identity.actor, identity.service or "", identity.delegation_id or ""


def _access(connection, identity, scope, scope_id, operation):
    _governed(connection, identity)
    if scope == "task":
        task = governance.read_task(connection, identity.tenant, scope_id, identity, operation, active=True)
        deadline = task.get("graph_deadline")
        active = task["status"] in _ACTIVE_TASKS and (deadline is None or deadline > connection.database_time())
        return active, deadline
    policy = Policy()
    policy.require(connection, identity, "read", "memory_scope", scope_id)
    if operation != "read":
        policy.require(connection, identity, operation, "memory_scope", scope_id)
    return True, None


def _entry(row, fragment):
    return {"id": row["id"], "scope": row["scope"], "scope_id": row["scope_id"],
            "expires_at": row["expires_at"].isoformat(), "citation": row["citation"], "candidate_id": row["candidate_id"],
            "fragment": fragment}


def _require_supported_candidate(connection, identity, citation, candidate_id):
    if candidate_id is not None:
        candidate = EvidenceStore._get(connection, identity, candidate_id, citation)
        if candidate["verdict"] != "supported":
            raise PermissionError("Memory evidence candidate requires independent review")


class MemoryStore:
    """Remember existing evidence references; check current grants and content on recall."""

    def __init__(self, store):
        self.store = store

    def remember(self, identity, scope, scope_id, citation, *, ttl_seconds, candidate_id=None):
        _validate(identity, scope, scope_id)
        if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= _MAX_TTL[scope]:
            raise ValueError("Memory lifetime exceeds its scope limit")
        citation = _citation(citation)
        reference = citation.to_document()
        owner = _owner(identity)
        memory_id = digest(["p7.memory/v1", owner, scope, scope_id, reference, candidate_id])
        with database(self.store, tenant=identity.tenant, write=True) as connection:
            active, deadline = _access(connection, identity, scope, scope_id, "remember")
            if not active:
                raise PermissionError("Task memory is closed")
            fragment = _live_fragment(connection, identity, citation)
            _require_supported_candidate(connection, identity, citation, candidate_id)
            now, = connection.execute("SELECT clock_timestamp()").fetchone()
            expires = now + timedelta(seconds=ttl_seconds)
            if deadline is not None:
                expires = min(expires, datetime.fromtimestamp(deadline, timezone.utc))
                if expires <= now:
                    raise PermissionError("Task memory is closed")
            connection.execute("""DELETE FROM knowledge_memories
                WHERE tenant=? AND actor=? AND service=? AND delegation=? AND expires_at<=?""", (*owner, now))
            existing = connection.execute("SELECT * FROM knowledge_memories WHERE tenant=? AND id=?",
                                          (identity.tenant, memory_id)).fetchone()
            if existing is not None:
                return _entry(existing, fragment)
            capacity = connection.execute("""SELECT count(*) AS owner_count,
                count(*) FILTER (WHERE scope=? AND scope_id=?) AS scope_count
                FROM knowledge_memories WHERE tenant=? AND actor=? AND service=? AND delegation=?""",
                (scope, scope_id, *owner)).fetchone()
            if capacity["owner_count"] >= _MAX_OWNER_ENTRIES or capacity["scope_count"] >= _MAX_SCOPE_ENTRIES:
                raise ValueError("Memory limit reached")
            row = connection.execute("""INSERT INTO knowledge_memories
                (tenant,actor,service,delegation,id,scope,scope_id,document_id,document_version,chunk_id,
                 citation,candidate_id,created_at,expires_at) VALUES (?,?,?,?,?,?,?,?,?,?,?::jsonb,?,?,?) RETURNING *""",
                (*owner, memory_id, scope, scope_id, citation.document_id, citation.document_version,
                 citation.chunk_id, encode(reference), candidate_id, now, expires)).fetchone()
            return _entry(row, fragment)

    def recall(self, identity, scope, scope_id, *, limit=16):
        _validate(identity, scope, scope_id)
        if type(limit) is not int or not 1 <= limit <= _MAX_SCOPE_ENTRIES:
            raise ValueError("Memory recall limit exceeds the stored scope limit")
        with database(self.store, tenant=identity.tenant) as connection:
            active, _ = _access(connection, identity, scope, scope_id, "read")
            if not active:
                return []
            rows = connection.execute("""SELECT * FROM knowledge_memories
                WHERE tenant=? AND actor=? AND service=? AND delegation=? AND scope=? AND scope_id=?
                  AND expires_at>clock_timestamp() ORDER BY created_at DESC,id LIMIT 32""",
                (*_owner(identity), scope, scope_id)).fetchall()
            result = []
            for row in rows:
                try:
                    citation = _citation(row["citation"])
                    fragment = _live_fragment(connection, identity, citation)
                    _require_supported_candidate(connection, identity, citation, row["candidate_id"])
                except PermissionError:
                    continue
                result.append(_entry(row, fragment))
                if len(result) == limit:
                    break
            return result

    def forget(self, identity, scope, scope_id, memory_id):
        _validate(identity, scope, scope_id)
        if not _name(memory_id):
            raise ValueError("Memory ID required")
        with database(self.store, tenant=identity.tenant, write=True) as connection:
            _access(connection, identity, scope, scope_id, "forget")
            return connection.execute("""DELETE FROM knowledge_memories
                WHERE tenant=? AND actor=? AND service=? AND delegation=? AND scope=? AND scope_id=? AND id=?""",
                (*_owner(identity), scope, scope_id, memory_id)).rowcount == 1
