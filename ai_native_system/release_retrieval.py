"""Readiness checks for pinned knowledge retrieval on an application release."""

from . import governance
from .identity import IdentityContext, _name
from .knowledge import _hnsw_index
from .knowledge_evidence import revocation_filter
from .model import ModelError
from .policy import Policy
from .releases import RETRIEVAL_METHODS, ReleaseError
from .storage import digest


def _space(connection, tenant, index_id):
    row = connection.execute(
        """SELECT index_id, route, state, binding_digest FROM knowledge_vector_spaces
           WHERE tenant=? AND index_id=?""", (tenant, index_id),
    ).fetchone()
    if row is None:
        raise ReleaseError("The target knowledge index is unavailable")
    return row


def prepare_binding(connection, tenant, index_id, method):
    if not _name(index_id) or method not in RETRIEVAL_METHODS:
        raise ReleaseError("Invalid release knowledge index or retrieval method")
    space = _space(connection, tenant, index_id)
    return {"index_id": index_id, "method": method, "binding_digest": space["binding_digest"]}


def _has_missing_documents(connection, tenant, index_id, documents):
    current = revocation_filter("request.tenant", "ref.document_id", "k.version")
    return connection.execute(
        f"""WITH request AS (SELECT ?::text AS tenant, ?::text AS index_id)
            SELECT 1 FROM request CROSS JOIN unnest(?::text[]) AS ref(document_id)
            LEFT JOIN knowledge_sources s ON s.tenant=request.tenant AND s.document_id=ref.document_id
            LEFT JOIN knowledge k ON k.tenant=request.tenant AND k.id=ref.document_id
            WHERE (s.status IS NULL OR s.status='active')
              AND (k.id IS NULL OR {current})
              AND NOT EXISTS (
                  SELECT 1 FROM knowledge_vector_documents d
                  WHERE d.tenant=request.tenant AND d.index_id=request.index_id AND d.document_id=ref.document_id
                    AND d.document_version=k.version AND d.state='published'
                    AND d.content_digest=encode(sha256(convert_to(k.text, 'UTF8')), 'hex')
                    AND (
                        SELECT count(*)=d.chunk_count
                               AND bool_and(c.embedding IS NOT NULL AND
                                            c.content_digest=encode(sha256(convert_to(c.text, 'UTF8')), 'hex'))
                        FROM knowledge_vector_chunks c
                        WHERE (c.tenant, c.index_id, c.document_id, c.document_version) =
                              (d.tenant, d.index_id, d.document_id, d.document_version)
                    )
              )
            LIMIT 1""",
        (tenant, index_id, documents),
    ).fetchone() is not None


def require_ready(connection, tenant, snapshot, *, publisher, embedding=None, identity=None):
    binding = snapshot.retrieval_binding()
    if binding is None:
        return
    if identity is None:
        identity = IdentityContext(tenant, publisher)
    if (not isinstance(identity, IdentityContext) or (identity.tenant, identity.actor) != (tenant, publisher)
            or not governance.enabled(connection, tenant)):
        raise PermissionError("A governed release publisher is required for a pinned knowledge index")
    index_id = binding["index_id"]
    Policy().require(connection, identity, "read", "knowledge-index", index_id)
    space = _space(connection, tenant, index_id)
    if space["state"] not in ("active", "retired"):
        raise ReleaseError("The target knowledge index must be published")
    if embedding is None or binding["binding_digest"] != space["binding_digest"]:
        raise ReleaseError("The target knowledge index embedding binding is unavailable or has changed")
    try:
        manifest_digest = digest(embedding.describe(space["route"], scope="tenant"))
    except ModelError:
        raise ReleaseError("The target knowledge index embedding route is unavailable") from None
    if manifest_digest != binding["binding_digest"]:
        raise ReleaseError("The target knowledge index embedding binding is unavailable or has changed")
    if binding["method"] == "hnsw" and _hnsw_index(connection, tenant, space)[0] is None:
        raise ReleaseError("Build the target knowledge HNSW index before selecting this release")
    documents = snapshot.to_document()["knowledge"]["references"]
    if _has_missing_documents(connection, tenant, index_id, documents):
        raise ReleaseError("The target knowledge index lacks current document coverage")
