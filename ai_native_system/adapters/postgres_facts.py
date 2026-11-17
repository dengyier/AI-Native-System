"""Tenant-scoped persistence of validated semantic records before fact projection."""

import json
from contextlib import contextmanager
from dataclasses import dataclass, fields, is_dataclass
from datetime import datetime
from enum import StrEnum
from hashlib import sha256

from psycopg import sql

from ..fact_contracts import (
    EvidenceRevocation, FactAssertion, FactChange, FactField, IdentityMapping, SourceCursor,
    SourceEvent, SourceIdentity, canonical_json, json_data,
)
from ..ontology import OntologyRelease
from .postgres import _locked_transaction, require_compatible_schema
from .postgres_runtime import _tenant_lock


class SemanticConflictError(ValueError):
    """A record has different content or a checkpoint predecessor does not match."""


@dataclass(frozen=True)
class StoredDocument:
    created: bool
    digest: str
    document: dict


@dataclass(frozen=True)
class AssertionRef:
    assertion_id: str
    revision: int | str

    def __post_init__(self):
        _name(self.assertion_id)
        _version_key(self.revision)

    def _key(self):
        return self.assertion_id, _version_key(self.revision)


@dataclass(frozen=True)
class CursorCheckpoint:
    cursor: SourceCursor
    revision: int

    def __post_init__(self):
        if not isinstance(self.cursor, SourceCursor) or type(self.revision) is not int or self.revision < 1:
            raise ValueError("Expected a source cursor and positive checkpoint revision")


def _document(value):
    if is_dataclass(value):
        return {field.name: _document(getattr(value, field.name)) for field in fields(value)}
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, tuple):
        return [_document(item) for item in value]
    return json_data(value)


def _name(value):
    if type(value) is not str or not value.strip() or "\0" in value:
        raise ValueError("Expected a nonempty identifier")
    return value


def _version_key(value):
    if not (type(value) is int and value > 0):
        _name(value)
    # A numeric revision and a text revision with the same spelling are distinct keys.
    return canonical_json(value)


def _source_key(identity):
    return {"tenant": identity.tenant, "source": identity.source, "source_type": identity.source_type,
            "source_id": identity.source_id}


def _get(connection, table, key):
    where = sql.SQL(" AND ").join(sql.SQL("{} = %s").format(sql.Identifier(column)) for column in key)
    return connection.execute(sql.SQL("SELECT digest, document FROM {} WHERE {}").format(
        sql.Identifier("ai_native", table), where), tuple(key.values())).fetchone()


class PostgresFacts:
    """A trusted tenant-scoped store with explicit history and checkpoint operations.

    The caller supplies a trusted tenant and a database role with table grants.
    Use Facts and FactSync for authoritative evaluation and source processing.
    """

    def __init__(self, dsn: str, tenant: str):
        self._dsn = dsn
        self._tenant = _name(tenant)

    def _require_tenant(self, value):
        if value != self._tenant:
            raise ValueError("Semantic record is outside the store's tenant")

    @contextmanager
    def _transaction(self, *, write=False):
        with _locked_transaction(self._dsn, shared=True) as connection:
            require_compatible_schema(connection)
            connection.execute("SELECT set_config('ai_native.tenant', %s, true)", (self._tenant,))
            if write:
                connection.execute("SELECT pg_advisory_xact_lock(%s::bigint)", (_tenant_lock(self._tenant),))
            yield connection

    def _append(self, table, key, metadata, document, *, digest, tolerate_repeated_delivery=False):
        serialized = canonical_json(document)
        record = {**key, **metadata, "digest": digest, "document": serialized}
        query = sql.SQL("INSERT INTO {} ({}) VALUES ({}) ON CONFLICT ({}) DO NOTHING RETURNING digest, document").format(
            sql.Identifier("ai_native", table), sql.SQL(", ").join(map(sql.Identifier, record)),
            sql.SQL(", ").join(sql.Placeholder() for _ in record), sql.SQL(", ").join(map(sql.Identifier, key)),
        )
        with self._transaction(write=True) as connection:
            inserted = connection.execute(query, tuple(record.values())).fetchone()
            if inserted is not None:
                return StoredDocument(True, inserted[0], json.loads(inserted[1]))
            existing = _get(connection, table, key)
            if existing is None or existing[0] != digest or (
                not tolerate_repeated_delivery and existing[1] != serialized
            ):
                raise SemanticConflictError(f"{table} key already identifies different content")
            return StoredDocument(False, existing[0], json.loads(existing[1]))

    def _read(self, table, key):
        with self._transaction() as connection:
            row = _get(connection, table, key)
            return StoredDocument(False, row[0], json.loads(row[1])) if row is not None else None

    def save_release(self, release: OntologyRelease) -> StoredDocument:
        if not isinstance(release, OntologyRelease):
            raise ValueError("Expected a validated ontology release")
        document = release.to_document()
        if "publisher" in document:
            self._require_tenant(document["publisher"]["tenant"])
        key = {"tenant": self._tenant, "namespace": _name(document["namespace"]),
               "version_key": _version_key(document["version"])}
        return self._append("ontology_releases", key, {}, document, digest=release.digest)

    def get_release(self, namespace: str, version: str | int) -> OntologyRelease | None:
        saved = self._read("ontology_releases", {"tenant": self._tenant, "namespace": _name(namespace),
                                                "version_key": _version_key(version)})
        if saved is None:
            return None
        release = OntologyRelease.from_document(saved.document)
        if release.digest != saved.digest or saved.document["namespace"] != namespace or saved.document["version"] != version:
            raise SemanticConflictError("Stored ontology release identity or digest does not match its document")
        return release

    def append_mapping(self, mapping: IdentityMapping) -> StoredDocument:
        if not isinstance(mapping, IdentityMapping):
            raise ValueError("Expected a validated identity mapping")
        self._require_tenant(mapping.source.tenant)
        key = {**_source_key(mapping.source), "revision_key": _version_key(mapping.revision)}
        document = _document(mapping)
        digest = sha256(canonical_json(document).encode("utf-8")).hexdigest()
        return self._append("identity_mappings", key, {"recorded_at": mapping.recorded_at}, document, digest=digest)

    def mapping_history(self, identity: SourceIdentity) -> tuple[dict, ...]:
        if not isinstance(identity, SourceIdentity):
            raise ValueError("Expected a source identity")
        self._require_tenant(identity.tenant)
        with self._transaction() as connection:
            return tuple(json.loads(document) for document, in connection.execute(
                """SELECT document FROM ai_native.identity_mappings
                   WHERE tenant=%s AND source=%s AND source_type=%s AND source_id=%s
                   ORDER BY recorded_at, revision_key""", tuple(_source_key(identity).values())))

    def append_assertion(self, assertion: FactAssertion) -> StoredDocument:
        if not isinstance(assertion, FactAssertion):
            raise ValueError("Expected a validated fact assertion")
        self._require_tenant(assertion.field.subject.tenant)
        key = {"tenant": self._tenant, "assertion_id": assertion.assertion_id,
               "revision_key": _version_key(assertion.revision)}
        metadata = {"object_type": assertion.field.subject.object_type, "object_id": assertion.field.subject.object_id,
                    "field_name": assertion.field.name, "relationship_id": assertion.field.relationship_id,
                    "valid_from": assertion.valid_from, "valid_to": assertion.valid_to, "recorded_at": assertion.recorded_at}
        document = _document(assertion)
        digest = sha256(canonical_json(document).encode("utf-8")).hexdigest()
        return self._append("fact_assertions", key, metadata, document, digest=digest)

    def assertion_history(self, field: FactField) -> tuple[dict, ...]:
        if not isinstance(field, FactField):
            raise ValueError("Expected a fact field")
        self._require_tenant(field.subject.tenant)
        with self._transaction() as connection:
            return tuple(json.loads(document) for document, in connection.execute(
                """SELECT document FROM ai_native.fact_assertions
                   WHERE tenant=%s AND object_type=%s AND object_id=%s AND field_name=%s
                     AND relationship_id IS NOT DISTINCT FROM %s
                   ORDER BY recorded_at, assertion_id, revision_key""",
                (self._tenant, field.subject.object_type, field.subject.object_id, field.name, field.relationship_id)))

    def receive_event(self, event: SourceEvent) -> StoredDocument:
        if not isinstance(event, SourceEvent):
            raise ValueError("Expected a validated source event")
        tenant, source, event_id = event.dedupe_key
        self._require_tenant(tenant)
        epoch = event.version.epoch if event.version is not None else event.cursor.epoch if event.cursor else None
        return self._append("source_events", {"tenant": tenant, "source": source, "event_id": event_id},
                            {"source_epoch": epoch, "received_at": event.received_at}, _document(event),
                            digest=event.content_digest, tolerate_repeated_delivery=True)

    def get_event(self, source: str, event_id: str) -> StoredDocument | None:
        return self._read("source_events", {"tenant": self._tenant, "source": _name(source), "event_id": _name(event_id)})

    def _field_key(self, field):
        if not isinstance(field, FactField):
            raise ValueError("Expected a fact field")
        self._require_tenant(field.subject.tenant)
        return self._tenant, field.subject.object_type, field.subject.object_id, field.name, field.relationship_id or ""

    def get_projection(self, field: FactField) -> AssertionRef | None:
        key = self._field_key(field)
        with self._transaction() as connection:
            row = connection.execute(
                """SELECT assertion_id, revision_key FROM ai_native.fact_projections
                   WHERE tenant=%s AND object_type=%s AND object_id=%s AND field_name=%s AND relationship_key=%s""",
                key,
            ).fetchone()
        return AssertionRef(row[0], json.loads(row[1])) if row is not None else None

    def set_projection(self, field: FactField, assertion: AssertionRef, *, expected: AssertionRef | None) -> None:
        """Set an explicit pointer without interpreting assertion authority or effective time."""
        if not isinstance(assertion, AssertionRef) or (expected is not None and not isinstance(expected, AssertionRef)):
            raise ValueError("Expected assertion references for the projection and predecessor")
        key = self._field_key(field)
        with self._transaction(write=True) as connection:
            target = connection.execute(
                """SELECT 1 FROM ai_native.fact_assertions
                   WHERE tenant=%s AND object_type=%s AND object_id=%s AND field_name=%s AND relationship_key=%s
                     AND assertion_id=%s AND revision_key=%s""", (*key, *assertion._key()),
            ).fetchone()
            if target is None:
                raise ValueError("Projection target must be an existing assertion for the same tenant and field")
            if expected is None:
                updated = connection.execute(
                    """INSERT INTO ai_native.fact_projections
                       (tenant,object_type,object_id,field_name,relationship_key,assertion_id,revision_key)
                       VALUES (%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING""", (*key, *assertion._key()),
                )
            else:
                updated = connection.execute(
                    """UPDATE ai_native.fact_projections SET assertion_id=%s, revision_key=%s
                       WHERE tenant=%s AND object_type=%s AND object_id=%s AND field_name=%s AND relationship_key=%s
                         AND assertion_id=%s AND revision_key=%s""", (*assertion._key(), *key, *expected._key()),
                )
            if updated.rowcount != 1:
                raise SemanticConflictError("Projection predecessor no longer matches")

    def get_cursor(self, source: str, stream: str) -> CursorCheckpoint | None:
        key = self._tenant, _name(source), _name(stream)
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT epoch, token, revision FROM ai_native.source_cursors WHERE tenant=%s AND source=%s AND stream=%s",
                key,
            ).fetchone()
        return CursorCheckpoint(SourceCursor(*key, row[0], row[1]), row[2]) if row is not None else None

    def checkpoint_cursor(self, cursor: SourceCursor, *, expected: CursorCheckpoint | None) -> CursorCheckpoint:
        """Compare a checkpoint predecessor without deriving order from opaque tokens."""
        if not isinstance(cursor, SourceCursor) or (expected is not None and not isinstance(expected, CursorCheckpoint)):
            raise ValueError("Expected a source cursor and an explicit checkpoint predecessor")
        self._require_tenant(cursor.tenant)
        key = cursor.tenant, cursor.source, cursor.stream
        if expected is not None:
            prior = expected.cursor
            if (prior.tenant, prior.source, prior.stream) != key or prior.epoch != cursor.epoch:
                raise ValueError("Cursor predecessor must match the tenant, source, stream and epoch")
        with self._transaction(write=True) as connection:
            if expected is None:
                row = connection.execute(
                    """INSERT INTO ai_native.source_cursors (tenant,source,stream,epoch,token,revision)
                       VALUES (%s,%s,%s,%s,%s,1) ON CONFLICT DO NOTHING RETURNING revision""",
                    (*key, cursor.epoch, cursor.token),
                ).fetchone()
            else:
                row = connection.execute(
                    """UPDATE ai_native.source_cursors SET token=%s, revision=revision+1
                       WHERE tenant=%s AND source=%s AND stream=%s AND epoch=%s AND token=%s AND revision=%s
                       RETURNING revision""", (cursor.token, *key, prior.epoch, prior.token, expected.revision),
                ).fetchone()
            if row is None:
                raise SemanticConflictError("Source cursor predecessor no longer matches")
        return CursorCheckpoint(cursor, row[0])

    def enqueue_invalidation(self, event: FactChange | EvidenceRevocation) -> StoredDocument:
        if isinstance(event, FactChange):
            tenant, kind = event.field.subject.tenant, "fact.change"
        elif isinstance(event, EvidenceRevocation):
            tenant, kind = event.tenant, "evidence.revocation"
        else:
            raise ValueError("Expected a validated fact change or evidence revocation")
        self._require_tenant(tenant)
        document = {"kind": kind, "event": _document(event)}
        digest = sha256(canonical_json(document).encode("utf-8")).hexdigest()
        return self._append("fact_invalidation_outbox", {"tenant": tenant, "event_id": event.event_id},
                            {}, document, digest=digest)

    def pending_invalidations(self, *, limit: int = 100) -> tuple[StoredDocument, ...]:
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("Pending invalidation limit must be 1–1000")
        with self._transaction() as connection:
            return tuple(StoredDocument(False, digest, json.loads(document)) for digest, document in connection.execute(
                """SELECT digest, document FROM ai_native.fact_invalidation_outbox
                   WHERE tenant=%s AND status='pending' ORDER BY enqueued_at, event_id LIMIT %s""",
                (self._tenant, limit),
            ))
