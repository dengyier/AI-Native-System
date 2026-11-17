"""Tenant-authorized pgvector retrieval and exact versioned citations."""

import math
from dataclasses import asdict, dataclass
from hashlib import sha256
from time import monotonic

from . import governance
from .identity import IdentityContext, _name, require_identity
from .knowledge_evidence import revocation_filter
from .knowledge_lexical import lexical_rows, parse_lexical_query
from .model import ModelError
from .policy import Policy
from .storage import digest


_MAX_EXACT_CANDIDATES = 20_000
_MAX_INDEX_DIMENSIONS = 2_000
_MAX_HYBRID_CANDIDATES = 100
_SOURCE_JOIN = """
    FROM knowledge_vector_chunks c
    JOIN knowledge_vector_documents d USING (tenant, index_id, document_id, document_version)
    JOIN knowledge_sources s USING (tenant, document_id)
    JOIN knowledge k ON k.tenant = c.tenant AND k.id = c.document_id
                     AND k.version = c.document_version
"""
_PROJECTION = """c.document_id, c.document_version, c.chunk_id, c.index_id AS index_version,
                 s.source_id, c.start_char, c.end_char, c.start_byte, c.end_byte,
                 c.content_digest AS content_sha256, c.text"""
_CURRENT = """
    d.state = 'published' AND s.status = 'active' AND c.embedding IS NOT NULL
    AND pg_catalog.encode(pg_catalog.sha256(pg_catalog.convert_to(k.text, 'UTF8')), 'hex') = d.content_digest
"""
_DOCUMENT_ACL = """
    (SELECT count(*) FROM resource_grants g
     WHERE g.tenant=c.tenant AND g.principal=ANY(?::text[]) AND g.operation='read' AND g.kind='document'
       AND g.resource_id=c.document_id AND g.member='') = ?
    AND (?::text IS NULL OR EXISTS (
        SELECT 1 FROM enterprise_delegations a JOIN enterprise_delegation_scopes x
          ON x.tenant=a.tenant AND x.delegation_id=a.id
        WHERE a.tenant=c.tenant AND a.id=? AND a.actor=? AND a.service=?
          AND a.revoked_at IS NULL AND a.starts_at<=clock_timestamp() AND a.expires_at>clock_timestamp()
          AND x.operation='read' AND x.kind='document' AND x.resource_id=c.document_id AND x.member=''
    ))
"""


class KnowledgeSearchError(ModelError):
    """A knowledge query cannot be safely completed under its declared bounds."""


class _ExactCandidateLimit(KnowledgeSearchError):
    """The authorized set exceeds the exact vector search budget."""


@dataclass(frozen=True)
class Citation:
    document_id: str
    document_version: int
    chunk_id: str
    index_version: str
    source_id: str
    start_char: int
    end_char: int
    start_byte: int
    end_byte: int
    content_sha256: str

    def __post_init__(self):
        if not all(map(_name, (self.document_id, self.chunk_id, self.index_version, self.source_id))):
            raise ValueError("Invalid citation identifiers")
        if type(self.document_version) is not int or not 1 <= self.document_version <= 2**31 - 1:
            raise ValueError("Invalid citation document version")
        for start, end in ((self.start_char, self.end_char), (self.start_byte, self.end_byte)):
            if type(start) is not int or type(end) is not int or not 0 <= start < end <= 2**31 - 1:
                raise ValueError("Invalid citation boundaries")
        if (not isinstance(self.content_sha256, str) or len(self.content_sha256) != 64
                or any(char not in "0123456789abcdef" for char in self.content_sha256)):
            raise ValueError("Invalid citation content digest")

    @property
    def id(self):
        return "fragment:" + digest(self.to_document())

    def to_document(self):
        return asdict(self)

    def as_document(self):
        return self.to_document()

    @classmethod
    def from_document(cls, document):
        if not isinstance(document, dict) or set(document) != set(cls.__dataclass_fields__):
            raise ValueError("Invalid citation document")
        return cls(**document)


@dataclass(frozen=True)
class SearchHit:
    citation: Citation
    text: str
    distance: float

    @property
    def id(self):
        return self.citation.id


@dataclass(frozen=True)
class SearchResult:
    index_version: str
    hits: tuple[SearchHit, ...]
    requested_method: str
    method: str
    fallback: str | None
    elapsed_ms: float

    def to_document(self):
        return asdict(self)


def _require_identity(connection, identity):
    if not isinstance(identity, IdentityContext) or not governance.enabled(connection, identity.tenant):
        raise PermissionError("Knowledge retrieval requires a governed tenant identity")
    require_identity(connection, identity)


def _acl_parameters(identity):
    return (list(identity.principals), len(identity.principals), identity.delegation_id,
            identity.delegation_id, identity.actor, identity.service)


def _not_revoked():
    return revocation_filter("c.tenant", "c.document_id", "c.document_version", "c.chunk_id")


def _citation(row):
    return Citation(**{key: row[key] for key in Citation.__dataclass_fields__})


def citation_fragment(connection, identity, citation):
    """Resolve the exact current fragment without a vector lookup or model call."""
    if not isinstance(citation, Citation):
        citation = Citation.from_document(citation)
    _require_identity(connection, identity)
    Policy().require(connection, identity, "read", "knowledge-index", citation.index_version)
    row = connection.execute(
        f"""SELECT {_PROJECTION}, k.text AS canonical_text {_SOURCE_JOIN}
            JOIN knowledge_vector_spaces v ON v.tenant=c.tenant AND v.index_id=c.index_id
            WHERE c.tenant=? AND c.index_id=? AND c.document_id=? AND c.document_version=? AND c.chunk_id=?
              AND v.state IN ('active', 'retired') AND {_CURRENT} AND {_DOCUMENT_ACL} AND {_not_revoked()}""",
        (identity.tenant, citation.index_version, citation.document_id, citation.document_version,
         citation.chunk_id, *_acl_parameters(identity)),
    ).fetchone()
    if row is None or _citation(row) != citation:
        raise PermissionError("Citation is no longer available to this identity")
    fragment = row["text"]
    canonical = row["canonical_text"]
    if (canonical[citation.start_char:citation.end_char] != fragment
            or canonical.encode("utf-8")[citation.start_byte:citation.end_byte] != fragment.encode("utf-8")
            or _content_sha256(fragment) != citation.content_sha256):
        raise PermissionError("Citation no longer matches the anchored content")
    return {**citation.to_document(), "id": citation.id, "version": citation.document_version, "text": fragment}


def _content_sha256(text):
    return sha256(text.encode("utf-8")).hexdigest()


def _space(connection, identity, index_version, *, compare=False):
    _require_identity(connection, identity)
    if index_version is None:
        condition, parameters = "state='active'", ()
    else:
        Policy().require(connection, identity, "read", "knowledge-index", index_version)
        condition, parameters = "index_id=?", (index_version,)
    row = connection.execute(f"""SELECT index_id, route, provider, model, model_version, preprocessing_version,
                              dimensions, metric, state, binding_digest FROM knowledge_vector_spaces
                              WHERE tenant=? AND {condition}""", (identity.tenant, *parameters)).fetchone()
    if row is None or row["metric"] != "cosine":
        raise KnowledgeSearchError("Requested knowledge index is unavailable")
    if index_version is None:
        Policy().require(connection, identity, "read", "knowledge-index", row["index_id"])
    if row["state"] not in ("active", "retired") and not compare:
        raise KnowledgeSearchError("Knowledge search requires a published index")
    return dict(row)


def _hnsw_name(tenant, index_version):
    return "knowledge_hnsw_" + digest((tenant, index_version))[:40]


def _hnsw_index(connection, tenant, space):
    name = _hnsw_name(tenant, space["index_id"])
    row = connection.execute("""SELECT pg_relation_size(c.oid) FROM pg_class c
        JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_index i ON i.indexrelid=c.oid
        JOIN pg_am m ON m.oid=c.relam
        WHERE n.nspname='ai_native' AND c.relname=? AND m.amname='hnsw' AND i.indisvalid AND i.indisready""",
        (name,),
    ).fetchone()
    return (name, row[0]) if row is not None else (None, None)


def build_hnsw(dsn, tenant, index_version):
    """Build one partial, dimension-specific cosine index as the schema owner."""
    import psycopg
    from psycopg import sql

    if not isinstance(dsn, str) or not dsn.strip() or not all(map(_name, (tenant, index_version))):
        raise ValueError("Knowledge HNSW requires an operator DSN, tenant and index version")
    index = _hnsw_name(tenant, index_version)
    started = monotonic()
    with psycopg.connect(dsn, autocommit=True, connect_timeout=5, target_session_attrs="read-write") as connection:
        connection.execute("SET search_path TO pg_catalog, ai_native, pg_temp")
        connection.execute("SELECT set_config('ai_native.tenant', %s, false), set_config('lock_timeout', '5s', false),"
                           " set_config('statement_timeout', '120s', false)", (tenant,))
        row = connection.execute("""SELECT dimensions, metric FROM ai_native.knowledge_vector_spaces
                                    WHERE tenant=%s AND index_id=%s""", (tenant, index_version)).fetchone()
        if row is None or row[1] != "cosine" or not 1 <= row[0] <= _MAX_INDEX_DIMENSIONS:
            raise KnowledgeSearchError("HNSW requires an existing cosine index version with 1–2000 dimensions")
        dimension = sql.Literal(row[0])
        locked = connection.execute("SELECT pg_try_advisory_lock(hashtextextended(%s, 0))", (index,)).fetchone()[0]
        if not locked:
            raise KnowledgeSearchError("This knowledge index is already being built")
        existing = connection.execute("""SELECT i.indisvalid AND i.indisready FROM pg_index i
            WHERE i.indexrelid=to_regclass(%s)""", (f"ai_native.{index}",)).fetchone()
        if existing is not None and not existing[0]:
            connection.execute(sql.SQL("DROP INDEX CONCURRENTLY {}").format(sql.Identifier("ai_native", index)))
        connection.execute(sql.SQL("""CREATE INDEX CONCURRENTLY IF NOT EXISTS {} ON ai_native.knowledge_vector_chunks
            USING hnsw ((embedding::public.vector({})) public.vector_cosine_ops)
            WHERE tenant={} AND index_id={} AND dimensions={} AND embedding IS NOT NULL""").format(
            sql.Identifier(index), dimension, sql.Literal(tenant), sql.Literal(index_version), dimension,
        ))
        size, = connection.execute("SELECT pg_relation_size(to_regclass(%s))", (f"ai_native.{index}",)).fetchone()
    return {"name": index, "bytes": size, "dimensions": row[0], "elapsed_ms": round((monotonic() - started) * 1000, 3)}


def _rank_scope(space):
    dimension = space["dimensions"]
    # The dimension is recorded by validated operator metadata, never query input.
    if type(dimension) is not int or not 1 <= dimension <= 4096:
        raise KnowledgeSearchError("Unsupported vector dimension")
    predicate = f"""c.tenant=? AND c.index_id=? AND c.dimensions={dimension}
                     AND (?::text[] IS NULL OR c.document_id=ANY(?::text[]))
                     AND {_CURRENT} AND {_DOCUMENT_ACL} AND {_not_revoked()}"""
    vector_type = f"public.vector({dimension})"
    return predicate, vector_type


def _rank_parameters(identity, space, documents):
    return (identity.tenant, space["index_id"], documents, documents, *_acl_parameters(identity))


def _rank_statement(space, *, approximate):
    predicate, vector_type = _rank_scope(space)
    if approximate:
        # Keep distance as the only sort key so PostgreSQL can use the HNSW index.
        return f"""SELECT {_PROJECTION}, c.embedding::{vector_type}
                   OPERATOR(public.<=>) ?::{vector_type} AS distance {_SOURCE_JOIN}
                   WHERE {predicate} ORDER BY distance LIMIT ?"""
    return f"""WITH allowed AS MATERIALIZED (
                SELECT {_PROJECTION}, c.embedding {_SOURCE_JOIN} WHERE {predicate} LIMIT ?)
            SELECT a.*, (SELECT count(*) FROM allowed) AS allowed_count,
                   a.embedding::{vector_type} OPERATOR(public.<=>) ?::{vector_type} AS distance
            FROM allowed a ORDER BY distance, document_id, chunk_id LIMIT ?"""


def _read_hits(connection, identity, space, documents, vector, limit, *, approximate, explain=False):
    base = _rank_parameters(identity, space, documents)
    statement = _rank_statement(space, approximate=approximate)
    if approximate:
        connection.execute("""SELECT set_config('hnsw.iterative_scan', 'strict_order', true),
             set_config('hnsw.ef_search', '40', true), set_config('hnsw.max_scan_tuples', '1000', true),
             set_config('plan_cache_mode', 'force_custom_plan', true), set_config('enable_sort', 'off', true)""")
        parameters = (vector, *base, limit)
    else:
        connection.execute("SELECT set_config('enable_sort', 'on', true)")
        parameters = (*base, _MAX_EXACT_CANDIDATES + 1, vector, limit)
    started = monotonic()
    rows = connection.execute(statement, parameters).fetchall()
    elapsed = round((monotonic() - started) * 1000, 3)
    if not approximate and rows and rows[0]["allowed_count"] > _MAX_EXACT_CANDIDATES:
        raise _ExactCandidateLimit("Exact search candidate limit exceeded; narrow the authorized document set")
    plan = connection.execute("EXPLAIN (FORMAT JSON) " + statement, parameters).fetchone()[0] if explain else None
    hits = [SearchHit(_citation(row), row["text"], row["distance"]) for row in rows if math.isfinite(row["distance"])]
    return tuple(sorted(hits, key=lambda hit: (hit.distance, hit.citation.document_id, hit.citation.chunk_id))), elapsed, plan


def _hybrid_hits(connection, identity, space, documents, vector, query, limit):
    candidate_limit = min(_MAX_HYBRID_CANDIDATES, max(20, limit * 3))
    lexical_query = parse_lexical_query(query)
    predicate, vector_type = _rank_scope(space)
    rows = lexical_rows(
        connection, lexical_query,
        projection=f"{_PROJECTION}, c.embedding::{vector_type} OPERATOR(public.<=>) ?::{vector_type} AS distance",
        projection_parameters=(vector,), source_join=_SOURCE_JOIN, predicate=predicate,
        parameters=_rank_parameters(identity, space, documents), limit=candidate_limit,
    )
    lexical = [SearchHit(_citation(row), row["text"], row["distance"])
               for row in rows if math.isfinite(row["distance"])]
    if lexical_query.requires_literal and not lexical:
        return (), "hybrid", None

    dense, fallback = (), None
    index, _ = _hnsw_index(connection, identity.tenant, space)
    if index is not None:
        dense, _, _ = _read_hits(connection, identity, space, documents, vector, candidate_limit, approximate=True)
    if len(dense) < candidate_limit:
        try:
            dense, _, _ = _read_hits(connection, identity, space, documents, vector, candidate_limit, approximate=False)
            if index is not None:
                fallback = "filtered_candidates"
        except _ExactCandidateLimit:
            fallback = "exact_candidate_limit"
            if not dense:
                return tuple(lexical[:limit]), "lexical", fallback

    # Reciprocal rank fusion works with lexical and cosine rankings on different scales.
    lexical_ranks = {hit.id: rank for rank, hit in enumerate(lexical, 1)}
    vector_ranks = {hit.id: rank for rank, hit in enumerate(dense, 1)}
    candidates = {hit.id: hit for hit in lexical}
    if not lexical_query.requires_literal:
        candidates.update((hit.id, hit) for hit in dense)

    def priority(hit_id):
        lexical_rank = lexical_ranks.get(hit_id, math.inf)
        vector_rank = vector_ranks.get(hit_id, math.inf)
        score = 1 / (60 + lexical_rank) + 1 / (60 + vector_rank)
        return -score, lexical_rank, vector_rank

    ranked = sorted(candidates, key=priority)
    return tuple(candidates[hit_id] for hit_id in ranked[:limit]), "hybrid", fallback


def _index_scan(plan, name):
    if plan.get("Index Name") == name and name is not None:
        return True
    return any(_index_scan(child, name) for child in plan.get("Plans", ()))


class KnowledgeRetrieval:
    def __init__(self, store, embedding_service):
        self.store = store
        self.embedding = embedding_service

    @staticmethod
    def _parameters(identity, query, limit, index_version, document_ids):
        if not isinstance(identity, IdentityContext):
            raise PermissionError("Knowledge retrieval requires an authenticated identity")
        if not isinstance(query, str) or not query.strip() or len(query.encode("utf-8")) > 8192:
            raise ValueError("Knowledge query must contain 1–8192 UTF-8 bytes")
        if type(limit) is not int or not 1 <= limit <= 50:
            raise ValueError("Knowledge search limit must be between 1 and 50")
        if index_version is not None and not _name(index_version):
            raise ValueError("Invalid knowledge index version")
        if document_ids is None:
            return None
        if not isinstance(document_ids, (tuple, list)) or len(document_ids) > 200 or not all(map(_name, document_ids)):
            raise ValueError("Expected up to 200 permitted document identifiers")
        return list(dict.fromkeys(document_ids))

    def _query_vector(self, identity, query, index_version, *, compare=False, binding_digest=None):
        from .knowledge_ingest import KnowledgeIngestionError, _vector_literal

        with self.store.transaction(tenant=identity.tenant) as connection:
            space = _space(connection, identity, index_version, compare=compare)

        if binding_digest is not None and space["binding_digest"] != binding_digest:
            raise KnowledgeSearchError("Knowledge index no longer matches the release binding")

        def authorize(connection):
            current = _space(connection, identity, index_version, compare=compare)
            if current != space or digest(self.embedding.describe(space["route"])) != space["binding_digest"]:
                raise KnowledgeSearchError("The index changed or its embedding route no longer matches")

        if digest(self.embedding.describe(space["route"])) != space["binding_digest"]:
            raise KnowledgeSearchError("Configured embedding route does not match the index version")
        result = self.embedding.embed(identity.tenant, space["route"], (query,), scope="tenant", purpose="query",
                                      identity=identity, authorize=authorize)
        expected = tuple(space[key] for key in ("provider", "model", "model_version", "preprocessing_version", "dimensions"))
        returned = (result.provider, result.model, result.version, result.preprocessing_version, result.dimensions)
        if returned != expected or len(result.vectors) != 1:
            raise KnowledgeSearchError("Query embedding does not match the index version")
        vector, = result.vectors
        try:
            return space, _vector_literal(vector, space["dimensions"])
        except KnowledgeIngestionError:
            raise KnowledgeSearchError("Query embedding is invalid for cosine search") from None

    def search(self, identity, query, *, limit=10, method="exact", index_version=None, document_ids=None,
               binding_digest=None):
        documents = self._parameters(identity, query, limit, index_version, document_ids)
        if method not in ("exact", "hnsw", "hybrid"):
            raise ValueError("Unknown knowledge search method")
        started = monotonic()
        space, vector = self._query_vector(identity, query, index_version, binding_digest=binding_digest)
        fallback, used = None, method
        with self.store.transaction(tenant=identity.tenant) as connection:
            if _space(connection, identity, index_version) != space:
                raise KnowledgeSearchError("Knowledge index changed during query embedding")
            if method == "hybrid":
                hits, used, fallback = _hybrid_hits(connection, identity, space, documents, vector, query, limit)
            elif method == "hnsw":
                name, _ = _hnsw_index(connection, identity.tenant, space)
                if name is None:
                    fallback = "index_unavailable"
                else:
                    hits, _, _ = _read_hits(connection, identity, space, documents, vector, limit, approximate=True)
                    if len(hits) < limit:
                        fallback = "filtered_candidates"
            if method == "exact" or (method == "hnsw" and fallback is not None):
                hits, _, _ = _read_hits(connection, identity, space, documents, vector, limit, approximate=False)
                used = "exact"

        # A fresh snapshot narrows the race with document/delegation changes after ranking.
        verified = []
        with self.store.transaction(tenant=identity.tenant) as connection:
            if _space(connection, identity, index_version) != space:
                raise KnowledgeSearchError("Knowledge index changed during retrieval")
            for hit in hits:
                try:
                    fragment = citation_fragment(connection, identity, hit.citation)
                except PermissionError:
                    continue
                verified.append(SearchHit(hit.citation, fragment["text"], hit.distance))
            _require_identity(connection, identity)
        return SearchResult(space["index_id"], tuple(verified), method, used, fallback,
                            round((monotonic() - started) * 1000, 3))

    def compare(self, identity, query, *, limit=10, index_version=None, document_ids=None):
        """Compare ANN against the same authorized exact set and embedding."""
        documents = self._parameters(identity, query, limit, index_version, document_ids)
        space, vector = self._query_vector(identity, query, index_version, compare=True)
        with self.store.transaction(tenant=identity.tenant) as connection:
            if _space(connection, identity, index_version, compare=True) != space:
                raise KnowledgeSearchError("Knowledge index changed during comparison")
            index, size = _hnsw_index(connection, identity.tenant, space)
            if index is None:
                raise KnowledgeSearchError("Build the knowledge HNSW index before comparison")
            exact, exact_ms, _ = _read_hits(connection, identity, space, documents, vector, limit, approximate=False)
            approx, approx_ms, plan = _read_hits(connection, identity, space, documents, vector, limit,
                                               approximate=True, explain=True)
        with self.store.transaction(tenant=identity.tenant) as connection:
            if _space(connection, identity, index_version, compare=True) != space:
                raise KnowledgeSearchError("Knowledge index changed during comparison")
        exact_ids, approx_ids = {hit.id for hit in exact}, {hit.id for hit in approx}
        return {"index_version": space["index_id"], "recall_at_k": len(exact_ids & approx_ids) / len(exact_ids)
                if exact_ids else None, "exact_count": len(exact_ids), "hnsw_count": len(approx_ids),
                "exact_ms": exact_ms, "hnsw_ms": approx_ms, "hnsw_index_bytes": size,
                "used_hnsw_index": _index_scan(plan[0]["Plan"], index)}
