"""Versioned document evidence, scoped review, and replayable invalidation."""

from . import governance
from .fact_contracts import EvidenceRef, EvidenceRevocation, SourceIdentity, canonical_json
from .facts import Facts, _assertion_document
from .identity import IdentityContext, _name, require_identity
from .ontology import _value
from .policy import Policy
from .releases import ReleaseStore
from .storage import database, digest


_KINDS = {"field": "field", "relation": "edge", "rule": "rule"}
_MAX_VALUE_BYTES = 4096


def revocation_filter(tenant_expr, document_expr, version_expr, chunk_expr=None):
    """A live anti-join for trusted SQL aliases and parameter expressions."""
    identifiers = document_expr if chunk_expr is None else f"{document_expr}, {chunk_expr}"
    return f"""NOT EXISTS (
        SELECT 1 FROM fact_invalidation_outbox ev
        WHERE ev.tenant = {tenant_expr} AND ev.document::jsonb->>'kind' = 'evidence.revocation'
          AND ev.document::jsonb#>>'{{event,evidence_id}}' IN ({identifiers})
          AND ev.document::jsonb#>'{{event,revision}}' = to_jsonb({version_expr})
          AND (ev.document::jsonb#>>'{{event,revoked_at}}')::timestamptz <= statement_timestamp()
          AND ev.enqueued_at <= statement_timestamp())"""


def document_revoked(connection, tenant, document_id, document_version):
    statement = "SELECT " + revocation_filter("?", "?", "?::bigint")
    return not connection.execute(statement, (tenant, document_id, document_version)).fetchone()[0]


def record_document_revocation(connection, tenant, document_id, version, *, reason):
    """Write the P2b event inside the authorized document lifecycle transaction."""
    event_id = digest(["p7.document.revoked/v1", tenant, document_id, version])
    if connection.execute("SELECT 1 FROM fact_invalidation_outbox WHERE tenant=? AND event_id=?",
                          (tenant, event_id)).fetchone() is not None:
        return False
    now, = connection.execute("SELECT clock_timestamp()").fetchone()
    event = EvidenceRevocation(event_id, tenant, document_id, version, now, reason)
    return Facts._enqueue(connection, tenant, event_id, {"kind": "evidence.revocation", "event": _assertion_document(event)})


def _governed(connection, identity):
    require_identity(connection, identity)
    if not governance.enabled(connection, identity.tenant):
        raise PermissionError("Governed PostgreSQL identity required")


def _tenant(identity):
    if not isinstance(identity, IdentityContext):
        raise PermissionError("Trusted identity required")
    return identity.tenant


def _citation(value):
    from .knowledge import Citation

    return value if isinstance(value, Citation) else Citation.from_document(value)


def _live_fragment(connection, identity, citation):
    from .knowledge import citation_fragment

    return citation_fragment(connection, identity, citation)


def _fact_revision(connection, tenant, object_id):
    row = connection.execute("""SELECT event_id FROM fact_invalidation_outbox
        WHERE tenant=? AND document::jsonb->>'kind'='fact.change'
          AND document::jsonb#>>'{event,field,subject,object_id}'=?
        ORDER BY enqueued_at DESC, event_id DESC LIMIT 1""", (tenant, object_id)).fetchone()
    return row[0] if row is not None else None


def _target_grants(connection, identity, release_digest, kind, object_id, name, related_id=None):
    policy = Policy()
    policy.require(connection, identity, "read", "release", release_digest)
    policy.require(connection, identity, "read", "object", object_id)
    if kind == "rule":
        policy.require(connection, identity, "read", "rule", name)
    else:
        policy.require(connection, identity, "read", _KINDS[kind], object_id, name)
    if related_id is not None:
        policy.require(connection, identity, "read", "object", related_id)


def _object_version(connection, tenant, object_id):
    return connection.execute("SELECT type, version FROM objects WHERE tenant=? AND id=?", (tenant, object_id)).fetchone()


def _get_target(connection, identity, release_digest, kind, object_id, name, value):
    related_id = value if kind == "relation" else None
    _target_grants(connection, identity, release_digest, kind, object_id, name, related_id)
    release = ReleaseStore.pinned(connection, identity.tenant, release_digest)
    ontology = release.snapshot.ontology()
    domain = ontology.to_document()
    subject = _object_version(connection, identity.tenant, object_id)
    if subject is None or subject["type"] not in domain["types"]:
        raise ValueError("Evidence target is outside the pinned ontology")
    object_type, version = subject["type"], subject["version"]
    related_version = None
    if kind == "field":
        definition = domain["types"][object_type]["properties"].get(name)
        if definition is None:
            raise ValueError("Unknown evidence field in the pinned ontology")
        _value(value, definition, "Candidate value")
    elif kind == "relation":
        definition = domain["relations"].get(name)
        related = _object_version(connection, identity.tenant, related_id)
        if (definition is None or related is None or definition["source_type"] != object_type
                or definition["target_type"] != related["type"]):
            raise ValueError("Evidence relation does not match the pinned ontology")
        related_version = related["version"]
    else:
        definition = domain["rules"].get(name)
        if definition is None or definition["object_type"] != object_type or type(value) is not bool:
            raise ValueError("Evidence rule does not match the pinned ontology")
    return (ontology.digest, object_type, version, related_id, related_version,
            _fact_revision(connection, identity.tenant, object_id),
            _fact_revision(connection, identity.tenant, related_id) if related_id is not None else None)


def _require_current(connection, identity, row, verified_citation=None):
    citation = _citation(row["citation"])
    if verified_citation is None:
        _live_fragment(connection, identity, citation)
    elif citation != verified_citation:
        raise PermissionError("Evidence candidate does not support this citation")
    if row["invalidated_at"] is not None:
        raise PermissionError("Evidence candidate is stale")
    try:
        current = _get_target(connection, identity, row["release_digest"], row["target_kind"], row["object_id"],
                              row["target_name"], row["value"])
    except ValueError:
        raise PermissionError("Evidence candidate is stale") from None
    bound = tuple(row[key] for key in ("ontology_digest", "object_type", "object_version", "related_object_id",
                                      "related_object_version", "fact_revision", "related_fact_revision"))
    if current != bound:
        raise PermissionError("Evidence candidate is stale")
    return citation


def _view(row):
    fields = ("id", "citation", "release_digest", "ontology_digest", "object_type", "object_id", "object_version",
              "target_kind", "target_name", "related_object_id", "related_object_version", "value", "reviewed_by")
    result = {key: row[key] for key in fields}
    result["state"] = row["verdict"] or "candidate"
    result["created_at"] = row["created_at"].isoformat()
    result["reviewed_at"] = row["reviewed_at"].isoformat() if row["reviewed_at"] is not None else None
    return result


class EvidenceStore:
    """Record source support without writing an authoritative fact or granting privileges."""

    def __init__(self, store):
        self.store = store

    def propose(self, identity, citation, *, release_digest, kind, object_id, name, value):
        if (not isinstance(kind, str) or kind not in _KINDS or not all(map(_name, (release_digest, object_id, name)))
                or (kind == "relation" and not _name(value))):
            raise ValueError("Invalid candidate target")
        serialized = canonical_json(value)
        if len(serialized.encode("utf-8")) > _MAX_VALUE_BYTES:
            raise ValueError("Candidate value exceeds the size limit")
        citation = _citation(citation)
        with database(self.store, write=True, tenant=_tenant(identity)) as connection:
            _governed(connection, identity)
            Policy().require(connection, identity, "propose", "evidence", citation.document_id)
            _live_fragment(connection, identity, citation)
            target = _get_target(connection, identity, release_digest, kind, object_id, name, value)
            document = citation.to_document()
            candidate_id = digest(["p7.candidate/v1", identity.tenant, identity.principals, identity.delegation_id,
                                   document, release_digest, kind, object_id, name, target, value])
            connection.execute("""INSERT INTO knowledge_candidates
                (tenant,id,document_id,document_version,chunk_id,citation,release_digest,ontology_digest,
                 object_id,object_type,object_version,target_kind,target_name,related_object_id,related_object_version,
                 fact_revision,related_fact_revision,value,created_by)
                VALUES (?,?,?,?,?,?::jsonb,?,?,?,?,?,?,?,?,?,?,?,?::jsonb,?) ON CONFLICT (tenant,id) DO NOTHING""",
                (identity.tenant, candidate_id, citation.document_id, citation.document_version, citation.chunk_id,
                 canonical_json(document), release_digest, target[0], object_id, target[1], target[2], kind, name,
                 *target[3:], serialized, identity.actor))
            row = self._get(connection, identity, candidate_id)
            return _view(row)

    @staticmethod
    def _get(connection, identity, candidate_id, verified_citation=None):
        if not _name(candidate_id):
            raise ValueError("Candidate ID is required")
        row = connection.execute("SELECT * FROM knowledge_candidates WHERE tenant=? AND id=?",
                                 (identity.tenant, candidate_id)).fetchone()
        if row is None:
            raise PermissionError("Evidence candidate unavailable")
        _require_current(connection, identity, row, verified_citation)
        return row

    def get(self, identity, candidate_id):
        with database(self.store, tenant=_tenant(identity)) as connection:
            _governed(connection, identity)
            return _view(self._get(connection, identity, candidate_id))

    def review(self, identity, candidate_id, verdict):
        if verdict not in ("supported", "rejected"):
            raise ValueError("Evidence verdict must be supported or rejected")
        with database(self.store, write=True, tenant=_tenant(identity)) as connection:
            _governed(connection, identity)
            row = self._get(connection, identity, candidate_id)
            Policy().require(connection, identity, "review", "evidence", row["document_id"])
            if identity.service is not None or identity.actor == row["created_by"]:
                raise PermissionError("Evidence review requires an independent human")
            if row["verdict"] is not None:
                if (row["verdict"], row["reviewed_by"]) != (verdict, identity.actor):
                    raise ValueError("Evidence review is already recorded")
                return _view(row)
            row = connection.execute("""UPDATE knowledge_candidates
                SET verdict=?, reviewed_by=?, reviewed_at=clock_timestamp() WHERE tenant=? AND id=? RETURNING *""",
                (verdict, identity.actor, identity.tenant, candidate_id)).fetchone()
            return _view(row)

    def fact_evidence(self, identity, candidate_id):
        """Export reviewed live references for the independently authorized Facts pipeline."""
        with database(self.store, tenant=_tenant(identity)) as connection:
            _governed(connection, identity)
            row = self._get(connection, identity, candidate_id)
            if row["verdict"] != "supported":
                raise PermissionError("Evidence candidate requires independent review")
            citation = _citation(row["citation"])
            source = SourceIdentity(identity.tenant, "p7.knowledge", "document", citation.source_id)
            locator = f"{citation.document_id}@{citation.document_version}:{citation.start_byte}-{citation.end_byte}"
            return tuple(EvidenceRef(identity.tenant, reference, citation.document_version, source, locator,
                                     citation.content_sha256, row["reviewed_at"])
                         for reference in (citation.document_id, citation.chunk_id))


def process_invalidations(store, tenant, *, limit=50):
    """Apply the P2b outbox to derived P7 records, acknowledging events per consumer."""
    if type(limit) is not int or not 1 <= limit <= 100:
        raise ValueError("Knowledge invalidation batch limit must be 1–100")
    counts = {"events": 0, "candidates": 0, "memories": 0}
    with database(store, tenant=tenant, write=True) as connection:
        rows = connection.execute("""SELECT ev.event_id,ev.enqueued_at,ev.document::jsonb AS payload
            FROM fact_invalidation_outbox ev
            LEFT JOIN knowledge_invalidation_receipts seen USING (tenant,event_id)
            WHERE ev.tenant=? AND seen.event_id IS NULL
              AND (ev.document::jsonb->>'kind'='fact.change'
                   OR (ev.document::jsonb->>'kind'='evidence.revocation'
                       AND (ev.document::jsonb#>>'{event,revoked_at}')::timestamptz<=statement_timestamp()))
            ORDER BY ev.enqueued_at,ev.event_id LIMIT ?""", (tenant, limit)).fetchall()
        for row in rows:
            payload = row["payload"]
            event = payload["event"]
            if payload["kind"] == "evidence.revocation":
                key = (tenant, event["evidence_id"], event["evidence_id"], canonical_json(event["revision"]))
                match = "WHERE tenant=? AND (document_id=? OR chunk_id=?) AND to_jsonb(document_version)=?::jsonb"
                counts["candidates"] += connection.execute(
                    "UPDATE knowledge_candidates SET invalidated_at=clock_timestamp(),value=NULL " + match
                    + " AND invalidated_at IS NULL", key,
                ).rowcount
                counts["memories"] += connection.execute("DELETE FROM knowledge_memories " + match, key).rowcount
            else:
                object_id = event["field"]["subject"]["object_id"]
                changed, removed = connection.execute("""WITH invalidated AS (
                    UPDATE knowledge_candidates SET invalidated_at=clock_timestamp(),value=NULL
                    WHERE tenant=? AND (object_id=? OR related_object_id=?)
                      AND created_at<=? AND invalidated_at IS NULL RETURNING tenant,id
                ), removed AS (
                    DELETE FROM knowledge_memories m USING invalidated c
                    WHERE m.tenant=c.tenant AND m.candidate_id=c.id RETURNING m.id
                ) SELECT (SELECT count(*) FROM invalidated), (SELECT count(*) FROM removed)""",
                    (tenant, object_id, object_id, row["enqueued_at"])).fetchone()
                counts["candidates"] += changed
                counts["memories"] += removed
            connection.execute("INSERT INTO knowledge_invalidation_receipts (tenant,event_id) VALUES (?,?)",
                               (tenant, row["event_id"]))
        counts["events"] = len(rows)
        counts["memories"] += connection.execute("""DELETE FROM knowledge_memories WHERE tenant=? AND id IN (
            SELECT id FROM knowledge_memories WHERE tenant=? AND expires_at<=statement_timestamp()
            ORDER BY expires_at,id LIMIT ?)""", (tenant, tenant, limit)).rowcount
    return counts
