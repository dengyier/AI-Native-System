"""Versioned fact, evidence and source connector contracts."""

import json
import math
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import StrEnum
from hashlib import sha256
from types import MappingProxyType


def json_data(value):
    """Copy JSON values, accepting tuples and mapping proxies from freeze_json."""
    def copy(item):
        if item is None or type(item) in (str, int, bool):
            return item
        if type(item) is float and math.isfinite(item):
            return item
        if isinstance(item, Mapping):
            if any(type(key) is not str for key in item):
                raise ValueError("JSON object keys must be strings")
            return {key: copy(child) for key, child in item.items()}
        if isinstance(item, (tuple, list)):
            return [copy(child) for child in item]
        raise ValueError("Expected a finite JSON value")

    try:
        return copy(value)
    except RecursionError as error:
        raise ValueError("JSON value is recursive or nested too deeply") from error


def canonical_json(value):
    """Canonical JSON for new contracts. Legacy request hashes use storage.digest."""
    return json.dumps(json_data(value), sort_keys=True, separators=(",", ":"), allow_nan=False)


def freeze_json(value):
    """Snapshot input so callers cannot change data after validation."""
    def freeze(item):
        if isinstance(item, dict):
            return MappingProxyType({key: freeze(child) for key, child in item.items()})
        if isinstance(item, list):
            return tuple(freeze(child) for child in item)
        return item

    return freeze(json_data(value))


def _hash(value):
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _names(*values):
    if any(type(value) is not str or not value.strip() for value in values):
        raise ValueError("Identifiers must be nonempty strings")


def _revision(value):
    if type(value) is int and value > 0:
        return
    _names(value)


def _utc(value):
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError("Expected a timezone-aware datetime")
    return value.astimezone(timezone.utc)


def _time_fields(instance, required, optional=()):
    for field in (*required, *optional):
        value = getattr(instance, field)
        if field in required or value is not None:
            object.__setattr__(instance, field, _utc(value))


def _time_text(value):
    return value.isoformat() if value is not None else None


def _interval(start, end):
    if start is not None and end is not None and end <= start:
        raise ValueError("Validity end must follow start")


def _enumeration(instance, field, enum_type):
    value = enum_type(getattr(instance, field))
    object.__setattr__(instance, field, value)


def _typed_tuple(values, item_type):
    if not isinstance(values, (list, tuple)) or any(not isinstance(value, item_type) for value in values):
        raise ValueError(f"Expected a sequence of {item_type.__name__}")
    return tuple(values)


def _sorted_unique(values, key):
    result = tuple(sorted(values, key=key))
    if len({key(value) for value in result}) != len(result):
        raise ValueError("Duplicate key in contract collection")
    return result


@dataclass(frozen=True, order=True)
class ObjectIdentity:
    tenant: str
    object_type: str
    object_id: str

    def __post_init__(self):
        _names(self.tenant, self.object_type, self.object_id)


@dataclass(frozen=True, order=True)
class SourceIdentity:
    tenant: str
    source: str
    source_type: str
    source_id: str

    def __post_init__(self):
        _names(self.tenant, self.source, self.source_type, self.source_id)


@dataclass(frozen=True)
class IdentityMapping:
    source: SourceIdentity
    target: ObjectIdentity
    revision: int | str
    recorded_at: datetime

    def __post_init__(self):
        if not isinstance(self.source, SourceIdentity) or not isinstance(self.target, ObjectIdentity):
            raise ValueError("Expected source and canonical object identities")
        if self.source.tenant != self.target.tenant:
            raise ValueError("Source mapping cannot cross tenants")
        _revision(self.revision)
        _time_fields(self, ("recorded_at",))


class IdentityChangeKind(StrEnum):
    MERGE = "merge"
    SPLIT = "split"


@dataclass(frozen=True)
class IdentityChange:
    """Explicit mapping history for a merge or split of existing identities."""

    change_id: str
    kind: IdentityChangeKind
    before: tuple[IdentityMapping, ...]
    after: tuple[IdentityMapping, ...]
    recorded_at: datetime

    def __post_init__(self):
        _names(self.change_id)
        _enumeration(self, "kind", IdentityChangeKind)
        _time_fields(self, ("recorded_at",))
        for field in ("before", "after"):
            mappings = _typed_tuple(getattr(self, field), IdentityMapping)
            object.__setattr__(self, field, _sorted_unique(mappings, lambda mapping: mapping.source))
        sources = {mapping.source for mapping in self.before}
        if sources != {mapping.source for mapping in self.after} or len({source.tenant for source in sources}) != 1:
            raise ValueError("Identity history must preserve the tenant and source identities")
        old_targets, new_targets = (len({mapping.target for mapping in group}) for group in (self.before, self.after))
        if self.kind == IdentityChangeKind.MERGE:
            valid_shape = old_targets >= 2 and new_targets == 1
        else:
            valid_shape = old_targets == 1 and new_targets >= 2
        if not valid_shape:
            raise ValueError("Mapping sets do not describe the declared identity change")
        for before, after in zip(self.before, self.after):
            if not before.recorded_at <= after.recorded_at <= self.recorded_at:
                raise ValueError("Invalid mapping history timestamps")
            if before.target != after.target and before.revision == after.revision:
                raise ValueError("A reassigned source requires a new mapping revision")


@dataclass(frozen=True)
class SourceVersion:
    """Opaque version token, optionally ordered inside one source record and epoch."""

    identity: SourceIdentity
    epoch: str
    token: str
    sequence: int | None = None

    def __post_init__(self):
        if not isinstance(self.identity, SourceIdentity):
            raise ValueError("Source version requires its source identity")
        _names(self.epoch, self.token)
        if self.sequence is not None and (type(self.sequence) is not int or self.sequence < 0):
            raise ValueError("Source sequence must be a nonnegative integer")

    def compare(self, other: "SourceVersion") -> int | None:
        """Return order when proven, or None for incomparable tokens."""
        if self.identity != other.identity or self.epoch != other.epoch:
            return None
        if self.token == other.token and self.sequence == other.sequence:
            return 0
        if self.sequence is None or other.sequence is None or self.sequence == other.sequence:
            return None
        return -1 if self.sequence < other.sequence else 1


@dataclass(frozen=True)
class FactField:
    subject: ObjectIdentity
    name: str
    relationship_id: str | None = None

    def __post_init__(self):
        if not isinstance(self.subject, ObjectIdentity):
            raise ValueError("A fact field requires a canonical object identity")
        _names(self.name)
        if self.relationship_id is not None:
            _names(self.relationship_id)


@dataclass(frozen=True)
class FieldAuthority:
    field: FactField
    source_names: tuple[str, ...]
    revision: int | str

    def __post_init__(self):
        if not isinstance(self.field, FactField):
            raise ValueError("Expected a fact field")
        _revision(self.revision)
        names = _typed_tuple(self.source_names, str)
        _names(*names)
        object.__setattr__(self, "source_names", _sorted_unique(names, lambda name: name))


class FactOrigin(StrEnum):
    SOURCE = "source"
    MODEL_CANDIDATE = "model_candidate"
    HUMAN_CORRECTION = "human_correction"
    IMPORTED_SNAPSHOT = "imported_snapshot"


class FactQuality(StrEnum):
    UNKNOWN = "unknown"
    CANDIDATE = "candidate"
    VERIFIED = "verified"
    REJECTED = "rejected"


class FactConflict(StrEnum):
    UNKNOWN = "unknown"
    CONFLICTING = "conflicting"
    CLEAR = "clear"


class FactFreshness(StrEnum):
    UNKNOWN = "unknown"
    FRESH = "fresh"
    STALE = "stale"


@dataclass(frozen=True)
class EvidenceRef:
    tenant: str
    evidence_id: str
    revision: int | str
    source: SourceIdentity
    locator: str
    content_digest: str
    retrieved_at: datetime
    access_scope: tuple[str, ...] = ()
    revoked_at: datetime | None = None

    def __post_init__(self):
        _names(self.tenant, self.evidence_id, self.locator, self.content_digest)
        _revision(self.revision)
        if not isinstance(self.source, SourceIdentity) or self.source.tenant != self.tenant:
            raise ValueError("Evidence source must belong to the same tenant")
        _time_fields(self, ("retrieved_at",), ("revoked_at",))
        if self.revoked_at is not None and self.revoked_at < self.retrieved_at:
            raise ValueError("Evidence revocation cannot precede retrieval")
        scope = _typed_tuple(self.access_scope, str)
        _names(*scope)
        object.__setattr__(self, "access_scope", _sorted_unique(scope, lambda value: value))


@dataclass(frozen=True)
class FactAssertion:
    assertion_id: str
    revision: int | str
    field: FactField
    origin: FactOrigin
    value: object
    recorded_at: datetime
    source: SourceIdentity | None = None
    source_version: SourceVersion | None = None
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    fresh_until: datetime | None = None
    quality: FactQuality = FactQuality.UNKNOWN
    conflict: FactConflict = FactConflict.UNKNOWN
    evidence: tuple[EvidenceRef, ...] = ()
    authorization_ref: str | None = None
    correction_reason: str | None = None

    def __post_init__(self):
        _names(self.assertion_id)
        _revision(self.revision)
        if not isinstance(self.field, FactField):
            raise ValueError("Expected a fact field")
        tenant = self.field.subject.tenant
        for field, enum_type in (("origin", FactOrigin), ("quality", FactQuality), ("conflict", FactConflict)):
            _enumeration(self, field, enum_type)
        if self.source is not None and (not isinstance(self.source, SourceIdentity) or self.source.tenant != tenant):
            raise ValueError("Assertion source must belong to the same tenant")
        if self.origin == FactOrigin.SOURCE and self.source is None:
            raise ValueError("A source assertion requires provenance")
        if self.source_version is not None and (
            not isinstance(self.source_version, SourceVersion) or self.source_version.identity != self.source
        ):
            raise ValueError("Assertion source version must belong to its source record")
        if self.origin == FactOrigin.HUMAN_CORRECTION:
            _names(self.authorization_ref, self.correction_reason)
        if self.origin == FactOrigin.MODEL_CANDIDATE and self.quality == FactQuality.VERIFIED:
            raise ValueError("Candidate model output cannot be a verified assertion")
        _time_fields(self, ("recorded_at",), ("valid_from", "valid_to", "fresh_until"))
        _interval(self.valid_from, self.valid_to)
        evidence = _typed_tuple(self.evidence, EvidenceRef)
        if any(item.tenant != tenant for item in evidence):
            raise ValueError("Evidence cannot cross tenants")
        object.__setattr__(self, "evidence", _sorted_unique(evidence, lambda item: item.evidence_id))
        object.__setattr__(self, "value", freeze_json(self.value))

    def freshness_at(self, instant: datetime) -> FactFreshness:
        """Classify the data deadline independently of its business validity interval."""
        instant = _utc(instant)
        if self.fresh_until is None or instant < self.recorded_at:
            return FactFreshness.UNKNOWN
        return FactFreshness.FRESH if instant < self.fresh_until else FactFreshness.STALE


class Capability(StrEnum):
    UNKNOWN = "unknown"
    SUPPORTED = "supported"
    UNSUPPORTED = "unsupported"


@dataclass(frozen=True)
class ConnectorCapabilities:
    snapshot: Capability = Capability.UNKNOWN
    delta: Capability = Capability.UNKNOWN
    deletion: Capability = Capability.UNKNOWN
    source_versions: Capability = Capability.UNKNOWN
    conditional_write: Capability = Capability.UNKNOWN
    idempotency: Capability = Capability.UNKNOWN
    result_lookup: Capability = Capability.UNKNOWN

    def __post_init__(self):
        for field in ("snapshot", "delta", "deletion", "source_versions", "conditional_write",
                      "idempotency", "result_lookup"):
            _enumeration(self, field, Capability)


@dataclass(frozen=True)
class ConnectorContract:
    tenant: str
    source: str
    revision: int | str
    capabilities: ConnectorCapabilities = ConnectorCapabilities()
    idempotency_scope: str | None = None
    idempotency_window_seconds: int | None = None
    result_lookup_window_seconds: int | None = None

    def __post_init__(self):
        _names(self.tenant, self.source)
        _revision(self.revision)
        if not isinstance(self.capabilities, ConnectorCapabilities):
            raise ValueError("Expected connector capabilities")
        if self.idempotency_scope is not None:
            _names(self.idempotency_scope)
        for window in (self.idempotency_window_seconds, self.result_lookup_window_seconds):
            if window is not None and (type(window) is not int or window <= 0):
                raise ValueError("Retention windows must be positive seconds or unknown")
        if self.capabilities.idempotency == Capability.SUPPORTED and self.idempotency_scope is None:
            raise ValueError("Support for idempotency requires a key scope")
        if self.idempotency_window_seconds is not None and self.capabilities.idempotency != Capability.SUPPORTED:
            raise ValueError("Idempotency retention requires declared support")
        if self.result_lookup_window_seconds is not None and self.capabilities.result_lookup != Capability.SUPPORTED:
            raise ValueError("Result lookup retention requires declared support")


@dataclass(frozen=True)
class SourceCursor:
    tenant: str
    source: str
    stream: str
    epoch: str
    token: str

    def __post_init__(self):
        _names(self.tenant, self.source, self.stream, self.epoch, self.token)


class Coverage(StrEnum):
    UNKNOWN = "unknown"
    PARTIAL = "partial"
    COMPLETE = "complete"


@dataclass(frozen=True)
class SnapshotBoundary:
    tenant: str
    source: str
    snapshot_id: str
    epoch: str
    started_at: datetime
    finished_at: datetime | None = None
    coverage: Coverage = Coverage.UNKNOWN
    resume_cursor: SourceCursor | None = None

    def __post_init__(self):
        _names(self.tenant, self.source, self.snapshot_id, self.epoch)
        _time_fields(self, ("started_at",), ("finished_at",))
        _enumeration(self, "coverage", Coverage)
        if self.finished_at is not None and self.finished_at < self.started_at:
            raise ValueError("Snapshot cannot finish before it starts")
        if self.coverage == Coverage.COMPLETE and self.finished_at is None:
            raise ValueError("An unfinished snapshot cannot be complete")
        if self.resume_cursor is not None and (
            not isinstance(self.resume_cursor, SourceCursor)
            or (self.resume_cursor.tenant, self.resume_cursor.source, self.resume_cursor.epoch)
            != (self.tenant, self.source, self.epoch)
        ):
            raise ValueError("Snapshot cursor must match the source epoch")


class ChangeKind(StrEnum):
    UPSERT = "upsert"
    DELETE = "delete"


@dataclass(frozen=True)
class SourceEvent:
    event_id: str
    identity: SourceIdentity
    kind: ChangeKind
    received_at: datetime
    payload: Mapping | None = None
    version: SourceVersion | None = None
    cursor: SourceCursor | None = None
    occurred_at: datetime | None = None
    operation_id: str | None = None

    def __post_init__(self):
        _names(self.event_id)
        if not isinstance(self.identity, SourceIdentity):
            raise ValueError("Event requires a source identity")
        _time_fields(self, ("received_at",), ("occurred_at",))
        _enumeration(self, "kind", ChangeKind)
        if self.operation_id is not None:
            _names(self.operation_id)
        if self.kind == ChangeKind.UPSERT and not isinstance(self.payload, Mapping):
            raise ValueError("An upsert event requires a payload object")
        if self.kind == ChangeKind.DELETE and self.payload is not None:
            raise ValueError("A deletion tombstone cannot have an upsert payload")
        object.__setattr__(self, "payload", freeze_json(self.payload))
        if self.version is not None and (
            not isinstance(self.version, SourceVersion) or self.version.identity != self.identity
        ):
            raise ValueError("Event version must belong to its source record")
        if self.cursor is not None and (
            not isinstance(self.cursor, SourceCursor)
            or (self.cursor.tenant, self.cursor.source) != (self.identity.tenant, self.identity.source)
            or self.version is not None and self.cursor.epoch != self.version.epoch
        ):
            raise ValueError("Event cursor must match the source and version epoch")

    @property
    def dedupe_key(self):
        return self.identity.tenant, self.identity.source, self.event_id

    @property
    def content_digest(self):
        """Bind the source epoch while tolerating repeated delivery with a new cursor token."""
        epoch = self.version.epoch if self.version is not None else self.cursor.epoch if self.cursor else None
        return _hash({
            "contract": "source-event/1", "source": asdict(self.identity), "event_id": self.event_id,
            "kind": self.kind.value, "payload": self.payload, "operation_id": self.operation_id,
            "source_epoch": epoch,
            "version": asdict(self.version) if self.version is not None else None,
            "occurred_at": _time_text(self.occurred_at),
        })


@dataclass(frozen=True)
class FactChange:
    event_id: str
    field: FactField
    revision: int | str
    kind: ChangeKind
    recorded_at: datetime
    operation_id: str | None = None

    def __post_init__(self):
        _names(self.event_id)
        if not isinstance(self.field, FactField):
            raise ValueError("Fact change requires an affected field")
        _revision(self.revision)
        _enumeration(self, "kind", ChangeKind)
        _time_fields(self, ("recorded_at",))
        if self.operation_id is not None:
            _names(self.operation_id)


@dataclass(frozen=True)
class EvidenceRevocation:
    event_id: str
    tenant: str
    evidence_id: str
    revision: int | str
    revoked_at: datetime
    reason: str

    def __post_init__(self):
        _names(self.event_id, self.tenant, self.evidence_id, self.reason)
        _revision(self.revision)
        _time_fields(self, ("revoked_at",))


class ReadKind(StrEnum):
    OBJECT = "object"
    RELATIONSHIP = "relationship"
    ASSERTION = "assertion"
    EVIDENCE = "evidence"


@dataclass(frozen=True)
class FactRead:
    tenant: str
    kind: ReadKind
    resource_id: str
    revision: int | str
    valid_from: datetime | None = None
    valid_to: datetime | None = None
    fresh_until: datetime | None = None
    source_version: SourceVersion | None = None

    def __post_init__(self):
        _names(self.tenant, self.resource_id)
        _revision(self.revision)
        _enumeration(self, "kind", ReadKind)
        _time_fields(self, (), ("valid_from", "valid_to", "fresh_until"))
        _interval(self.valid_from, self.valid_to)
        if self.source_version is not None and (
            not isinstance(self.source_version, SourceVersion) or self.source_version.identity.tenant != self.tenant
        ):
            raise ValueError("Fact read source version must belong to the same tenant")

    def as_payload(self):
        return {**asdict(self), "kind": self.kind.value, "valid_from": _time_text(self.valid_from),
                "valid_to": _time_text(self.valid_to), "fresh_until": _time_text(self.fresh_until)}


class CollectionKind(StrEnum):
    RELATIONSHIP = "relationship"
    QUERY = "query"


@dataclass(frozen=True)
class CollectionRead:
    tenant: str
    kind: CollectionKind
    scope: Mapping
    revision: int | str
    member_ids: tuple[str, ...]
    coverage: Coverage = Coverage.UNKNOWN

    def __post_init__(self):
        _names(self.tenant)
        _revision(self.revision)
        _enumeration(self, "kind", CollectionKind)
        _enumeration(self, "coverage", Coverage)
        if not isinstance(self.scope, Mapping) or not self.scope:
            raise ValueError("Collection read requires a query or relationship scope")
        object.__setattr__(self, "scope", freeze_json(self.scope))
        members = _typed_tuple(self.member_ids, str)
        _names(*members)
        object.__setattr__(self, "member_ids", _sorted_unique(members, lambda member: member))

    @property
    def scope_digest(self):
        return _hash({"tenant": self.tenant, "kind": self.kind.value, "scope": self.scope})

    def as_payload(self):
        return {"tenant": self.tenant, "kind": self.kind.value, "scope": json_data(self.scope),
                "revision": self.revision, "member_ids": list(self.member_ids), "coverage": self.coverage.value}


@dataclass(frozen=True)
class FactReadSet:
    tenant: str
    reads: tuple[FactRead, ...] = ()
    collections: tuple[CollectionRead, ...] = ()
    as_of: datetime | None = None
    source_cursors: tuple[SourceCursor, ...] = ()

    def __post_init__(self):
        _names(self.tenant)
        _time_fields(self, (), ("as_of",))
        for field, item_type, key in (
            ("reads", FactRead, lambda item: (item.kind, item.resource_id)),
            ("collections", CollectionRead, lambda item: item.scope_digest),
            ("source_cursors", SourceCursor, lambda item: (item.source, item.stream)),
        ):
            items = _typed_tuple(getattr(self, field), item_type)
            if any(item.tenant != self.tenant for item in items):
                raise ValueError("A fact read set cannot cross tenants")
            object.__setattr__(self, field, _sorted_unique(items, key))

    def as_payload(self):
        return {
            "contract": "fact-read-set/1", "tenant": self.tenant, "as_of": _time_text(self.as_of),
            "reads": [item.as_payload() for item in self.reads],
            "collections": [item.as_payload() for item in self.collections],
            "source_cursors": [asdict(item) for item in self.source_cursors],
        }

    @property
    def digest(self):
        return _hash(self.as_payload())
