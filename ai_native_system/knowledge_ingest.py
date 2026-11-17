"""Bounded document staging, embedding and atomic PostgreSQL publication."""

import math
import struct
from dataclasses import asdict
from uuid import uuid4

from .adapters.llamaindex import PARSER_VERSION, split_document, text_digest
from .governance import enabled, require_identity_match
from .identity import _name
from .policy import Policy
from .storage import database, digest, encode


_CLAIM_SECONDS = 180
_KEY = "tenant = ? AND index_id = ? AND document_id = ? AND document_version = ?"


class KnowledgeIngestionError(ValueError):
    """The document revision cannot be safely staged, embedded or published."""


def _identifier(*values):
    if not all(map(_name, values)):
        raise KnowledgeIngestionError("Expected nonempty knowledge identifiers")


def _version(value):
    if type(value) is not int or not 1 <= value < 2**31 - 1:
        raise KnowledgeIngestionError("Expected a positive document version")


def _batches(value):
    if type(value) is not int or not 1 <= value <= 32:
        raise KnowledgeIngestionError("Ingestion can run 1–32 embedding batches per call")


def _vector_literal(vector, dimensions):
    if not isinstance(vector, (list, tuple)) or len(vector) != dimensions or any(
        type(coordinate) not in (int, float) for coordinate in vector
    ):
        raise KnowledgeIngestionError("Embedding dimensions do not match the knowledge space")
    try:
        rounded = struct.unpack(f"!{dimensions}f", struct.pack(f"!{dimensions}f", *vector))
    except (OverflowError, struct.error):
        raise KnowledgeIngestionError("Embedding exceeds the pgvector coordinate range") from None
    if not all(map(math.isfinite, rounded)) or not any(rounded):
        raise KnowledgeIngestionError("Cosine search requires a finite nonzero embedding")
    return encode(rounded)


class KnowledgeIngestion:
    """Prepare embeddings outside the database transaction and publish complete revisions."""

    def __init__(self, store, embedding):
        self.store = store
        self.embedding = embedding
        self.policy = Policy()

    def _require(self, connection, identity, operation, kind, resource):
        require_identity_match(identity, identity.tenant)
        if not enabled(connection, identity.tenant):
            raise PermissionError("Knowledge indexing requires a governed PostgreSQL tenant")
        self.policy.require(connection, identity, operation, kind, resource)

    def _source_access(self, connection, identity, document_id, index_id):
        self._require(connection, identity, "write", "knowledge-index", index_id)
        self.policy.require(connection, identity, "write", "document", document_id)
        self.policy.require(connection, identity, "read", "document", document_id)

    @staticmethod
    def _space(connection, tenant, index_id):
        row = connection.execute("SELECT * FROM knowledge_vector_spaces WHERE tenant = ? AND index_id = ?",
                                 (tenant, index_id)).fetchone()
        if row is None:
            raise KnowledgeIngestionError("Knowledge index version is unavailable")
        return dict(row)

    @staticmethod
    def _source(connection, tenant, document_id):
        return connection.execute("SELECT * FROM knowledge_sources WHERE tenant = ? AND document_id = ?",
                                  (tenant, document_id)).fetchone()

    @staticmethod
    def _canonical(connection, tenant, document_id):
        return connection.execute("SELECT version, text FROM knowledge WHERE tenant = ? AND id = ?",
                                  (tenant, document_id)).fetchone()

    @staticmethod
    def _active(connection, tenant):
        row = connection.execute("SELECT index_id FROM knowledge_vector_spaces WHERE tenant = ? AND state = 'active'",
                                 (tenant,)).fetchone()
        return None if row is None else row["index_id"]

    def _binding(self, space):
        if (digest(self.embedding.describe(space["route"])) != space["binding_digest"]
                or space["parser_version"] != PARSER_VERSION):
            raise KnowledgeIngestionError("The configured embedding or parser differs from this index version")

    def _writable(self, connection, space, write_current):
        if write_current and (
            space["state"] == "retired" or self._active(connection, space["tenant"]) not in (None, space["index_id"])
        ):
            raise KnowledgeIngestionError("Use the active knowledge index for document updates")

    def create_space(self, identity, index_id, route, *, chunk_bytes=None):
        """Freeze the request and response embedding identities in a new staged space."""
        _identifier(index_id, route)
        tenant = identity.tenant
        with database(self.store, write=True, tenant=tenant) as connection:
            self._require(connection, identity, "write", "knowledge-index", index_id)
            manifest = self.embedding.describe(route)
            byte_limit = min(self.embedding.max_input_bytes, 8192)
            if chunk_bytes is None:
                chunk_bytes = min(byte_limit, 1024)
            if type(chunk_bytes) is not int or not 16 <= chunk_bytes <= byte_limit:
                raise KnowledgeIngestionError("Chunk bytes must fit the configured embedding input limit")
            binding = {"route": route, "provider": manifest["provider"], "model": manifest["response_model"],
                       "model_version": manifest["version"], "preprocessing_version": manifest["preprocessing_version"],
                       "dimensions": manifest["dimensions"], "binding_digest": digest(manifest), "metric": "cosine",
                       "parser_version": PARSER_VERSION, "chunk_bytes": chunk_bytes}
            connection.execute("""INSERT INTO knowledge_vector_spaces (tenant, index_id, route, provider, model,
                model_version, preprocessing_version, dimensions, binding_digest, metric, parser_version, chunk_bytes, state)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'staged') ON CONFLICT (tenant, index_id) DO NOTHING""",
                (tenant, index_id, *binding.values()))
            existing = self._space(connection, tenant, index_id)
            if any(existing[key] != expected for key, expected in binding.items()):
                raise KnowledgeIngestionError("The knowledge index version already has a different binding")
            return existing

    def activate_space(self, identity, index_id):
        """Switch readers after the staged space covers every current managed document."""
        from .knowledge_evidence import revocation_filter

        _identifier(index_id)
        tenant = identity.tenant
        with database(self.store, write=True, tenant=tenant) as connection:
            self._require(connection, identity, "publish", "knowledge-index", index_id)
            space = self._space(connection, tenant, index_id)
            self._binding(space)
            if space["state"] == "retired":
                raise KnowledgeIngestionError("Retired knowledge index versions cannot be selected")
            if space["state"] == "active":
                return space
            valid = revocation_filter("s.tenant", "s.document_id", "k.version")
            missing = connection.execute(f"""SELECT 1 FROM knowledge_sources s
                JOIN knowledge k ON (k.tenant,k.id) = (s.tenant,s.document_id)
                WHERE s.tenant = ? AND s.status = 'active' AND {valid} AND NOT EXISTS (
                    SELECT 1 FROM knowledge_vector_documents d
                    WHERE d.tenant = s.tenant AND d.document_id = s.document_id AND d.index_id = ?
                      AND d.document_version = k.version AND d.state = 'published'
                      AND d.content_digest = encode(sha256(convert_to(k.text, 'UTF8')), 'hex')
                ) LIMIT 1""", (tenant, index_id)).fetchone()
            if missing:
                raise KnowledgeIngestionError("The staged index is missing a current managed document")
            connection.execute("UPDATE knowledge_vector_spaces SET state = 'retired' WHERE tenant = ? AND state = 'active'",
                               (tenant,))
            connection.execute("UPDATE knowledge_vector_spaces SET state = 'active' WHERE tenant = ? AND index_id = ?",
                               (tenant, index_id))
            return {**space, "state": "active"}

    def ingest(self, identity, index_id, document_id, source_id, text, *, format="text", expected_version=None,
               max_batches=16):
        """Stage a versioned document update. A repeated submission resumes its draft."""
        _identifier(index_id, document_id, source_id)
        if expected_version is not None:
            _version(expected_version)
        _batches(max_batches)
        with database(self.store, tenant=identity.tenant) as connection:
            self._source_access(connection, identity, document_id, index_id)
            space = self._space(connection, identity.tenant, index_id)
        chunks = split_document(text, format, space["chunk_bytes"])
        key = self._stage(identity, space, document_id, source_id, text, format, chunks, expected_version, True)
        return self.resume(identity, *key[1:], max_batches=max_batches)

    def rebuild(self, identity, index_id, document_id, *, source_id=None, format="text", max_batches=16):
        """Backfill the current canonical revision into an index version."""
        _identifier(index_id, document_id)
        _batches(max_batches)
        tenant = identity.tenant
        with database(self.store, tenant=tenant) as connection:
            self._source_access(connection, identity, document_id, index_id)
            space = self._space(connection, tenant, index_id)
            source = self._source(connection, tenant, document_id)
            record = self._canonical(connection, tenant, document_id)
            if record is None or (source is not None and source["status"] != "active"):
                raise KnowledgeIngestionError("The current knowledge document is unavailable")
        if source is not None:
            if source_id is not None and source_id != source["source_id"]:
                raise KnowledgeIngestionError("Document source identity differs")
            source_id, format = source["source_id"], source["format"]
        elif source_id is None:
            source_id = "local-knowledge:" + digest(document_id)
        _identifier(source_id)
        chunks = split_document(record["text"], format, space["chunk_bytes"])
        key = self._stage(identity, space, document_id, source_id, record["text"], format, chunks, record["version"], False)
        return self.resume(identity, *key[1:], max_batches=max_batches)

    def _stage(self, identity, spec, doc, source_id, text, file_format, chunks, expected_version, write_current):
        tenant, index_id = identity.tenant, spec["index_id"]
        content_digest = text_digest(text)
        with database(self.store, write=True, tenant=tenant) as connection:
            self._source_access(connection, identity, doc, index_id)
            space = self._space(connection, tenant, index_id)
            self._binding(space)
            if space["chunk_bytes"] != spec["chunk_bytes"]:
                raise KnowledgeIngestionError("The knowledge chunk configuration changed")
            prior = self._canonical(connection, tenant, doc)
            current = prior["version"] if prior is not None else None
            if prior is not None and text == prior["text"] and write_current:
                prior_base = current - 1 if current > 1 else None
                if expected_version not in (current, prior_base):
                    raise KnowledgeIngestionError("Knowledge document version conflict")
                write_current, expected_version = False, current
            if current != expected_version or (not write_current and (prior is None or text != prior["text"])):
                raise KnowledgeIngestionError("Knowledge document version conflict")
            document_version = (current or 0) + 1 if write_current else current
            _version(document_version)
            self._writable(connection, space, write_current)
            connection.execute("""INSERT INTO knowledge_sources (tenant, document_id, source_id, format, status, last_version)
                VALUES (?, ?, ?, ?, 'active', ?) ON CONFLICT DO NOTHING""", (tenant, doc, source_id, file_format, current or 0))
            source = self._source(connection, tenant, doc)
            if source is None or (source["source_id"], source["format"], source["status"]) != (source_id, file_format, "active"):
                raise KnowledgeIngestionError("The document source is different, withdrawn or deleted")
            key = (tenant, index_id, doc, document_version)
            inserted = connection.execute("""INSERT INTO knowledge_vector_documents (tenant, index_id, document_id,
                document_version, dimensions, content_digest, chunk_count, state, base_version, base_digest,
                write_current, draft_text)
                VALUES (?, ?, ?, ?, ?, ?, ?, 'staged', ?, ?, ?, ?) ON CONFLICT DO NOTHING""",
                (*key, space["dimensions"], content_digest, len(chunks), current,
                 text_digest(prior["text"]) if prior is not None else None, write_current, text)).rowcount
            existing = self._document(connection, key)
            if existing["content_digest"] != content_digest or existing["chunk_count"] != len(chunks):
                raise KnowledgeIngestionError("A different draft already occupies this document version")
            if inserted:
                rows = [{**asdict(chunk), "chunk_id": digest([*key, chunk.ordinal, chunk.content_digest])} for chunk in chunks]
                connection.execute("""INSERT INTO knowledge_vector_chunks (tenant, index_id, document_id, document_version,
                    dimensions, chunk_id, ordinal, start_char, end_char, start_byte, end_byte, text, content_digest)
                    SELECT ?, ?, ?, ?, ?, chunk_id, ordinal, start_char, end_char, start_byte, end_byte, text, content_digest
                    FROM jsonb_to_recordset(?::jsonb) AS c(chunk_id text, ordinal int, start_char int, end_char int,
                         start_byte int, end_byte int, text text, content_digest text)""",
                    (*key, space["dimensions"], encode(rows)))
        return key

    @staticmethod
    def _document(connection, key):
        row = connection.execute(f"SELECT * FROM knowledge_vector_documents WHERE {_KEY}", key).fetchone()
        if row is None:
            raise KnowledgeIngestionError("Knowledge draft is unavailable")
        return row

    def _current(self, connection, key, doc):
        from .knowledge_evidence import document_revoked

        source = self._source(connection, key[0], key[2])
        current = self._canonical(connection, key[0], key[2])
        version = current["version"] if current is not None else None
        if (source is None or source["status"] != "active" or version != doc["base_version"]
                or (current is not None and text_digest(current["text"]) != doc["base_digest"])):
            raise KnowledgeIngestionError("The source document changed during indexing")
        if not doc["write_current"] and document_revoked(connection, key[0], key[2], version):
            raise KnowledgeIngestionError("The source document revision is revoked")
        return current

    def _continue(self, connection, identity, key, token):
        tenant, index_id, document_id, _ = key
        self._source_access(connection, identity, document_id, index_id)
        doc = self._document(connection, key)
        if (doc["claim_token"] != token or doc["claim_until"] is None
                or doc["claim_until"].timestamp() <= connection.database_time()):
            raise KnowledgeIngestionError("The knowledge ingestion claim expired")
        space = self._space(connection, tenant, index_id)
        self._binding(space)
        self._writable(connection, space, doc["write_current"])
        self._current(connection, key, doc)
        return space, doc

    def _report(self, connection, key):
        row = self._document(connection, key)
        embedded = connection.execute(
            f"SELECT count(*) FROM knowledge_vector_chunks WHERE {_KEY} AND embedding IS NOT NULL", key,
        ).fetchone()[0]
        return {"tenant": key[0], "index_id": key[1], "document_id": key[2], "document_version": key[3],
                "state": row["state"], "chunks": row["chunk_count"], "embedded": embedded}

    def _reuse(self, connection, key):
        connection.execute(f"""WITH pending AS (
                SELECT chunk_id, text, content_digest FROM knowledge_vector_chunks WHERE {_KEY} AND embedding IS NULL
            ), reusable AS (
                SELECT DISTINCT ON (p.chunk_id) p.chunk_id, previous.embedding FROM pending p
                JOIN knowledge_vector_chunks previous
                  ON previous.tenant = ? AND previous.index_id = ? AND previous.document_id = ?
                 AND previous.content_digest = p.content_digest AND previous.text = p.text AND previous.embedding IS NOT NULL
                ORDER BY p.chunk_id, previous.document_version DESC
            ) UPDATE knowledge_vector_chunks c SET embedding = r.embedding FROM reusable r
              WHERE c.tenant = ? AND c.chunk_id = r.chunk_id""", (*key, *key[:3], key[0]))

    def _publish(self, connection, key, doc):
        from .knowledge_evidence import record_document_revocation

        if self._report(connection, key)["embedded"] != doc["chunk_count"]:
            raise KnowledgeIngestionError("Knowledge draft still has incomplete embeddings")
        tenant, _, document_id, version = key
        if doc["write_current"]:
            if doc["base_version"] is not None:
                connection.execute("""INSERT INTO knowledge_history (tenant, id, version, text)
                    SELECT tenant, id, version, text FROM knowledge WHERE tenant = ? AND id = ?
                    ON CONFLICT (tenant, id, version) DO NOTHING""", (tenant, document_id))
                record_document_revocation(connection, tenant, document_id, doc["base_version"], reason="superseded")
            connection.execute("INSERT INTO knowledge_history (tenant, id, version, text) VALUES (?, ?, ?, ?)",
                               (tenant, document_id, version, doc["draft_text"]))
            connection.execute("""INSERT INTO knowledge (tenant, id, version, text) VALUES (?, ?, ?, ?)
                ON CONFLICT (tenant, id) DO UPDATE SET version = excluded.version, text = excluded.text""",
                (tenant, document_id, version, doc["draft_text"]))
            connection.execute("UPDATE knowledge_sources SET last_version = ? WHERE tenant = ? AND document_id = ?",
                               (version, tenant, document_id))
        connection.execute(f"""UPDATE knowledge_vector_documents SET state = 'published', draft_text = NULL,
            claim_until = NULL, claim_token = NULL WHERE {_KEY}""", key)
        return self._report(connection, key)

    def resume(self, identity, index_id, document_id, document_version, *, max_batches=16):
        """Resume bounded draft work without recomputing completed chunks."""
        _identifier(index_id, document_id)
        _version(document_version)
        _batches(max_batches)
        tenant = identity.tenant
        key, token = (tenant, index_id, document_id, document_version), uuid4().hex
        with database(self.store, write=True, tenant=tenant) as connection:
            self._source_access(connection, identity, document_id, index_id)
            doc = self._document(connection, key)
            if doc["state"] == "published":
                from .knowledge_evidence import document_revoked

                source = self._source(connection, tenant, document_id)
                current = self._canonical(connection, tenant, document_id)
                if (source is None or source["status"] != "active" or current is None
                        or current["version"] != document_version or text_digest(current["text"]) != doc["content_digest"]
                        or document_revoked(connection, tenant, document_id, document_version)):
                    raise KnowledgeIngestionError("The requested knowledge revision is no longer current")
                return self._report(connection, key)
            if doc["claim_until"] is not None and doc["claim_until"].timestamp() > connection.database_time():
                return self._report(connection, key)
            connection.execute(f"""UPDATE knowledge_vector_documents SET claim_token = ?,
                claim_until = clock_timestamp() + ? * interval '1 second' WHERE {_KEY}""", (token, _CLAIM_SECONDS, *key))
            self._continue(connection, identity, key, token)

        try:
            for _ in range(max_batches):
                with database(self.store, write=True, tenant=tenant) as connection:
                    space, doc = self._continue(connection, identity, key, token)
                    self._reuse(connection, key)
                    rows = connection.execute(f"""SELECT DISTINCT ON (content_digest) text, content_digest
                        FROM knowledge_vector_chunks WHERE {_KEY} AND embedding IS NULL
                        ORDER BY content_digest, ordinal LIMIT 64""", key).fetchall()
                    if not rows:
                        return self._publish(connection, key, doc)
                    connection.execute(f"""UPDATE knowledge_vector_documents
                        SET claim_until = clock_timestamp() + ? * interval '1 second' WHERE {_KEY}""",
                        (_CLAIM_SECONDS, *key))
                batch, size = [], 0
                for row in rows:
                    size += len(row["text"].encode("utf-8"))
                    if size > self.embedding.max_input_bytes:
                        break
                    batch.append(row)
                if not batch:
                    raise KnowledgeIngestionError("A chunk exceeds the current embedding input limit")

                def authorize(connection):
                    self._continue(connection, identity, key, token)

                result = self.embedding.embed(tenant, space["route"], [row["text"] for row in batch], scope="tenant",
                                              purpose="document", identity=identity, authorize=authorize)
                expected = (space["provider"], space["model"], space["model_version"], space["preprocessing_version"], space["dimensions"])
                actual = (result.provider, result.model, result.version, result.preprocessing_version, result.dimensions)
                if actual != expected or len(result.vectors) != len(batch):
                    raise KnowledgeIngestionError("The provider returned an incompatible knowledge embedding space")
                with database(self.store, write=True, tenant=tenant) as connection:
                    _, doc = self._continue(connection, identity, key, token)
                    connection.executemany(f"""UPDATE knowledge_vector_chunks SET embedding = ?::public.vector
                        WHERE {_KEY} AND content_digest = ? AND embedding IS NULL""",
                        ((_vector_literal(vector, space["dimensions"]), *key, row["content_digest"])
                         for row, vector in zip(batch, result.vectors, strict=True)))
                    report = self._report(connection, key)
                    if report["embedded"] == doc["chunk_count"]:
                        return self._publish(connection, key, doc)
            return report
        finally:
            with database(self.store, write=True, tenant=tenant) as connection:
                connection.execute(f"""UPDATE knowledge_vector_documents SET claim_token = NULL, claim_until = NULL
                    WHERE {_KEY} AND claim_token = ?""", (*key, token))

    def retire_document(self, identity, document_id, *, expected_version, delete=False):
        """Withdraw the managed revision, optionally purging its stored document bodies."""
        _identifier(document_id)
        _version(expected_version)
        if type(delete) is not bool:
            raise KnowledgeIngestionError("Knowledge delete flag must be boolean")
        tenant = identity.tenant
        with database(self.store, write=True, tenant=tenant) as connection:
            self._require(connection, identity, "delete" if delete else "withdraw", "document", document_id)
            source = self._source(connection, tenant, document_id)
            current = self._canonical(connection, tenant, document_id)
            if source is None:
                raise KnowledgeIngestionError("The managed document version changed")
            version = current["version"] if current is not None else source["last_version"]
            if version == 0 and connection.execute("""SELECT 1 FROM knowledge_vector_documents
                    WHERE tenant = ? AND document_id = ? AND document_version = 1 AND state = 'staged' LIMIT 1""",
                    (tenant, document_id)).fetchone() is not None:
                version = 1
            if version != expected_version:
                raise KnowledgeIngestionError("The managed document version changed")
            status = "deleted" if delete or source["status"] == "deleted" else "withdrawn"
            return self._retire(connection, tenant, document_id, source, version, status, current)

    @staticmethod
    def _retire(connection, tenant, document_id, source, version, status, current):
        from .knowledge_evidence import record_document_revocation

        if current is not None:
            if status == "withdrawn":
                connection.execute("""INSERT INTO knowledge_history (tenant, id, version, text)
                    VALUES (?, ?, ?, ?) ON CONFLICT (tenant, id, version) DO NOTHING""",
                    (tenant, document_id, current["version"], current["text"]))
            record_document_revocation(connection, tenant, document_id, current["version"], reason=status)
        connection.execute("DELETE FROM knowledge WHERE tenant = ? AND id = ?", (tenant, document_id))
        connection.execute("DELETE FROM knowledge_vector_documents WHERE tenant = ? AND document_id = ?",
                           (tenant, document_id))
        if status == "deleted":
            connection.execute("DELETE FROM knowledge_history WHERE tenant = ? AND id = ?", (tenant, document_id))
        connection.execute("UPDATE knowledge_sources SET status = ?, last_version = ? WHERE tenant = ? AND document_id = ?",
                           (status, version, tenant, document_id))
        return {"tenant": tenant, "document_id": document_id, "source_id": source["source_id"], "format": source["format"],
                "document_version": version, "status": status}

    def reapply_tombstone(self, identity, tombstone):
        """Reapply an operator-retained withdrawal record after a database restore."""
        required = {"tenant", "document_id", "source_id", "format", "document_version", "status"}
        if not isinstance(tombstone, dict) or tombstone.keys() != required or tombstone["tenant"] != identity.tenant:
            raise KnowledgeIngestionError("The tombstone does not match the tenant")
        tenant, document_id, source_id = (tombstone[k] for k in ("tenant", "document_id", "source_id"))
        version, status, file_format = (tombstone[k] for k in ("document_version", "status", "format"))
        _identifier(document_id, source_id)
        _version(version)
        if status not in ("withdrawn", "deleted") or file_format not in ("text", "markdown"):
            raise KnowledgeIngestionError("Invalid knowledge tombstone")
        with database(self.store, write=True, tenant=tenant) as connection:
            self._require(connection, identity, "delete" if status == "deleted" else "withdraw", "document", document_id)
            source = self._source(connection, tenant, document_id)
            current = self._canonical(connection, tenant, document_id)
            if source is None:
                connection.execute("""INSERT INTO knowledge_sources (tenant, document_id, source_id, format, status, last_version)
                    VALUES (?, ?, ?, ?, 'active', 0) ON CONFLICT DO NOTHING""", (tenant, document_id, source_id, file_format))
                source = self._source(connection, tenant, document_id)
            if (source is None or (source["source_id"], source["format"]) != (source_id, file_format)
                    or source["last_version"] > version or (current is not None and current["version"] > version)):
                raise KnowledgeIngestionError("The tombstone does not match the restored source or version")
            if source["status"] == "deleted":
                status = "deleted"
            return self._retire(connection, tenant, document_id, source, version, status, current)
