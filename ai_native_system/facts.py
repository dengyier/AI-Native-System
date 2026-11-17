"""Tenant-scoped assertion selection, provenance and effective/system-time history."""
import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256

from .fact_contracts import (
    ChangeKind, CollectionKind, CollectionRead, Coverage, EvidenceRef, EvidenceRevocation,
    FactAssertion, FactChange, FactField, FactOrigin, FactQuality, FactRead, FieldAuthority,
    IdentityMapping, ObjectIdentity, ReadKind, SourceCursor, SourceIdentity, SourceVersion,
    canonical_json, json_data,
)
from .identity import IdentityContext
from .policy import Policy

STATE = "$state"
EXISTS = "$exists"
_RECORD = "$record"


class MappingConflict(ValueError):
    """A native identity has no unambiguous provisioned mapping."""


@dataclass(frozen=True)
class Observation:
    available: bool = False
    value: object = None
    coverage: Coverage = Coverage.UNKNOWN
    reason: str = "missing"
    selected: str | None = None
    reads: tuple[FactRead, ...] = ()
    source_cursors: tuple[SourceCursor, ...] = ()
    conflicts: tuple[str, ...] = ()
    deleted: bool = False

    @property
    def complete(self):
        return self.coverage == Coverage.COMPLETE


@dataclass(frozen=True)
class RelationObservation:
    available: bool
    collection: CollectionRead
    reads: tuple[FactRead, ...] = ()
    source_cursors: tuple[SourceCursor, ...] = ()
    reason: str = "missing"
    dependency_targets: tuple[str, ...] = ()


def _digest(value):
    return sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _time(value):
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    if not isinstance(value, datetime) or value.utcoffset() is None:
        raise ValueError("A timezone-aware time is required")
    return value.astimezone(timezone.utc)


def _date(value):
    return _time(value) if value is not None else None


def _now(connection):
    return connection.execute("SELECT clock_timestamp()").fetchone()[0]


def _keys(field):
    obj = field.subject
    return obj.tenant, obj.object_type, obj.object_id, field.name, field.relationship_id or ""


def _source_keys(identity):
    return identity.tenant, identity.source, identity.source_type, identity.source_id


def _assertion_document(assertion):
    from .adapters.postgres_facts import _document

    return _document(assertion)


def _mapping(row):
    item = json.loads(row["document"])
    return IdentityMapping(SourceIdentity(**item["source"]), ObjectIdentity(**item["target"]),
                           item["revision"], _time(item["recorded_at"]))


def _assertion_read(document, deadline):
    version = document["source_version"]
    if version is not None:
        version = SourceVersion(SourceIdentity(**version["identity"]), version["epoch"],
                                version["token"], version["sequence"])
    return FactRead(document["field"]["subject"]["tenant"], ReadKind.ASSERTION,
                    document["assertion_id"], document["revision"],
                    _date(document["valid_from"]), _date(document["valid_to"]), deadline, version)


def _dedupe_reads(reads):
    return tuple(sorted({(read.kind, read.resource_id): read for read in reads}.values(),
                        key=lambda read: (read.kind, read.resource_id)))


def _dedupe_cursors(cursors):
    return tuple(sorted({(cursor.source, cursor.stream): cursor for cursor in cursors}.values(),
                        key=lambda cursor: (cursor.source, cursor.stream)))


class Facts:
    """Write through a trusted tenant transaction and read with the caller's snapshot."""

    def __init__(self, store=None, tenant=None, *, freshness=timedelta(minutes=5)):
        if not isinstance(freshness, timedelta) or freshness <= timedelta(0):
            raise ValueError("Fact freshness must be positive")
        self.store, self.tenant, self.freshness = store, tenant, freshness

    def _tenant(self, tenant):
        if not isinstance(tenant, str) or not tenant.strip() or (self.tenant is not None and tenant != self.tenant):
            raise ValueError("Fact is outside the service tenant")

    def target_for(self, connection, identity, *, known_at=None):
        self._tenant(identity.tenant)
        rows = connection.execute(
            """SELECT revision_key, document FROM identity_mappings
               WHERE tenant=? AND source=? AND source_type=? AND source_id=? AND recorded_at<=?
               ORDER BY recorded_at DESC, revision_key DESC""",
            (*_source_keys(identity), known_at or _now(connection)),
        ).fetchall()
        if not rows:
            raise MappingConflict("Source identity has no explicit binding")
        if "changed_by" not in json.loads(rows[0]["document"]):
            if len({_mapping(row).target for row in rows}) != 1:
                raise MappingConflict("Legacy source identity has conflicting mappings")
        return _mapping(rows[0])

    def bind_mapping(self, connection, mapping, *, expected=None, actor, reason):
        """Publish an explicit mapping revision using a separately privileged operator."""
        self._tenant(mapping.source.tenant)
        if not all(isinstance(value, str) and value.strip() for value in (actor, reason)):
            raise ValueError("Mapping changes require an operator and a reason")
        key = _source_keys(mapping.source)
        now = _now(connection)
        row = connection.execute(
            """SELECT revision_key, document FROM identity_mappings
               WHERE tenant=? AND source=? AND source_type=? AND source_id=?
               ORDER BY recorded_at DESC, revision_key DESC LIMIT 1""", key,
        ).fetchone()
        if row is not None and json.loads(row["revision_key"]) == mapping.revision:
            if _mapping(row).target == mapping.target:
                return _mapping(row)
            raise MappingConflict("Mapping revision already identifies another target")
        if (None if row is None else json.loads(row["revision_key"])) != expected:
            raise MappingConflict("Mapping predecessor does not match")
        actual = IdentityMapping(mapping.source, mapping.target, mapping.revision, now)
        document = {**_assertion_document(actual), "changed_by": actor, "reason": reason, "previous_revision": expected}
        inserted = connection.execute(
            """INSERT INTO identity_mappings(tenant,source,source_type,source_id,revision_key,recorded_at,digest,document)
               VALUES (?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING""",
            (*key, canonical_json(actual.revision), now, _digest(document), canonical_json(document)),
        )
        if inserted.rowcount != 1:
            raise MappingConflict("Mapping revision was already used")
        if row is not None:
            previous = _mapping(row).target
            for member in connection.execute(
                """SELECT DISTINCT a.field_name, a.relationship_key FROM fact_assertions a
                   JOIN fact_observations o USING(tenant,assertion_id,revision_key)
                   WHERE a.tenant=? AND a.object_type=? AND a.object_id=? AND o.source=?
                     AND o.source_type=? AND o.source_id=?""",
                (previous.tenant, previous.object_type, previous.object_id, *key[1:]),
            ).fetchall():
                field = FactField(previous, member["field_name"], member["relationship_key"] or None)
                self._project(connection, field, now, revision=_digest(document))
        return actual

    def set_authority(self, connection, authority, *, expected=None, actor, reason):
        """Publish per-field authority from a separately privileged operator transaction."""
        if not isinstance(authority, FieldAuthority) or not authority.source_names:
            raise ValueError("Field authority requires at least one named source")
        key = _keys(authority.field)
        self._tenant(key[0])
        if not all(isinstance(value, str) and value.strip() for value in (actor, reason)):
            raise ValueError("Authority changes require an operator and a reason")
        now = _now(connection)
        current = self._authority(connection, authority.field, now, fallback=False)
        if current is not None and current.revision == authority.revision:
            if current.source_names == authority.source_names:
                return current
            raise ValueError("Authority revision already identifies different sources")
        if (None if current is None else current.revision) != expected:
            raise ValueError("Authority predecessor does not match")
        result = connection.execute(
            """INSERT INTO fact_authorities(tenant,object_type,object_id,field_name,relationship_key,
                                            revision_key,recorded_at,sources,actor,reason)
               VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING""",
            (*key, canonical_json(authority.revision), now, list(authority.source_names), actor, reason),
        )
        if result.rowcount != 1:
            raise ValueError("Authority revision was already used")
        self._project(connection, authority.field, now)
        if authority.field.relationship_id is None and not authority.field.name.startswith("$"):
            for row in connection.execute(
                """SELECT DISTINCT a.relationship_key FROM fact_assertions a JOIN fact_observations o
                     USING (tenant, assertion_id, revision_key)
                   WHERE a.tenant=? AND a.object_type=? AND a.object_id=? AND a.field_name=?
                     AND a.relationship_key<>''""", key[:4],
            ).fetchall():
                self._project(connection, FactField(authority.field.subject, authority.field.name, row[0]), now)
        return authority

    def _authority(self, connection, field, known_at, *, fallback=True):
        relation = field.relationship_id or ""
        for member in dict.fromkeys((relation, "") if fallback else (relation,)):
            row = connection.execute(
                """SELECT revision_key, sources FROM fact_authorities
                   WHERE tenant=? AND object_type=? AND object_id=? AND field_name=? AND relationship_key=?
                     AND recorded_at<=? ORDER BY recorded_at DESC,revision_key DESC LIMIT 1""",
                (*_keys(field)[:4], member, known_at),
            ).fetchone()
            if row is not None:
                scope = FactField(field.subject, field.name, member or None)
                return FieldAuthority(scope, tuple(row["sources"]), json.loads(row["revision_key"]))
        return None

    def _append(self, connection, assertion, *, stream=None, mapping=None, deleted=False, operation_id=None):
        key = _keys(assertion.field)
        revision = canonical_json(assertion.revision)
        document = _assertion_document(assertion)
        text = canonical_json(document)
        identity = assertion.source
        version = assertion.source_version
        inserted = connection.execute(
            """INSERT INTO fact_assertions(tenant,assertion_id,revision_key,object_type,object_id,field_name,
                                           relationship_id,valid_from,valid_to,recorded_at,digest,document)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING""",
            (key[0], assertion.assertion_id, revision, *key[1:4], assertion.field.relationship_id,
             assertion.valid_from, assertion.valid_to, assertion.recorded_at, _digest(document), text),
        ).rowcount
        if not inserted:
            row = connection.execute(
                "SELECT digest FROM fact_assertions WHERE tenant=? AND assertion_id=? AND revision_key=?",
                (key[0], assertion.assertion_id, revision),
            ).fetchone()
            if row is None or row[0] != _digest(document):
                raise ValueError("Assertion revision already identifies different evidence")
            return
        connection.execute(
            """INSERT INTO fact_observations(tenant,assertion_id,revision_key,source,stream,source_type,source_id,
                                             mapping_revision,epoch,source_sequence,deleted,operation_id)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (key[0], assertion.assertion_id, revision, identity.source if identity else None, stream,
             identity.source_type if identity else None, identity.source_id if identity else None,
             canonical_json(mapping.revision) if mapping else None, version.epoch if version else None,
             version.sequence if version else None, deleted, operation_id),
        )

    def write_source(self, connection, event, *, stream, changes, observed_at=None, observation_id=None):
        """Apply a trusted connector's full record or an explicit source tombstone."""
        mapping = self.target_for(connection, event.identity)
        if event.version is None or event.version.sequence is None or not isinstance(stream, str) or not stream:
            raise ValueError("Source facts require an ordered native version and a stream")
        values = {} if changes is None else dict(changes)
        for (name, relation), value in values.items():
            FactField(mapping.target, name, relation)
            if name in {EXISTS, _RECORD} or (name == STATE and (relation is not None or not isinstance(value, str))):
                raise ValueError("Invalid reserved source field")
            if relation is not None:
                if (not isinstance(value, Mapping) or value.keys() != {"target_type", "target_id", "properties"}
                        or not isinstance(value["properties"], Mapping)):
                    raise ValueError("A relation observation requires its canonical target and properties")
                ObjectIdentity(mapping.target.tenant, value["target_type"], value["target_id"])
        now = _now(connection)
        evidence_time = _date(observed_at) or event.occurred_at
        deadline = min(evidence_time, now) + self.freshness if evidence_time is not None else None
        valid_from = event.occurred_at or now
        prior = connection.execute(
            """SELECT DISTINCT a.field_name, a.relationship_key
               FROM fact_observations o JOIN fact_assertions a USING(tenant,assertion_id,revision_key)
               WHERE a.tenant=? AND a.object_type=? AND a.object_id=?
                 AND o.source=? AND o.source_type=? AND o.source_id=? AND o.stream=?""",
            (*_keys(FactField(mapping.target, EXISTS))[:3], *_source_keys(event.identity)[1:], stream),
        ).fetchall()
        relations = [
            {"type": name, "id": relation, **json_data(value)}
            for (name, relation), value in sorted(values.items(), key=lambda pair: (pair[0][0], pair[0][1] or ""))
            if relation is not None
        ]
        deleted = changes is None
        values[(EXISTS, None)] = not deleted
        if not deleted:
            values[(_RECORD, None)] = {"relations": relations}
        previous = {(row[0], row[1] or None) for row in prior}
        delivery = {"source_event": event.content_digest, "observation": observation_id}
        evidence = EvidenceRef(mapping.target.tenant, _digest(delivery), 1, event.identity,
                               event.event_id, event.content_digest, now)
        for name, relation in sorted(previous | values.keys(), key=lambda item: (item[0], item[1] or "")):
            field = FactField(mapping.target, name, relation)
            missing = (name, relation) not in values
            assertion_id = _digest({**delivery, "field": _keys(field)})
            assertion = FactAssertion(
                assertion_id, 1, field, FactOrigin.SOURCE, values.get((name, relation)), now,
                source=event.identity, source_version=event.version, valid_from=valid_from, fresh_until=deadline,
                quality=FactQuality.VERIFIED, evidence=(evidence,),
            )
            tombstone = missing or (deleted and name == EXISTS)
            self._append(connection, assertion, stream=stream, mapping=mapping, deleted=tombstone,
                         operation_id=event.operation_id)
            self._project(connection, field, now, operation_id=event.operation_id, revision=assertion_id)
        return mapping

    def correct(self, connection, field, identity, value, *, reason, expires_at, correction_id):
        """Save a scoped human correction with its deadline and authorization provenance."""
        self._tenant(field.subject.tenant)
        if (not isinstance(identity, IdentityContext) or identity.tenant != field.subject.tenant
                or identity.service is not None):
            raise PermissionError("Fact correction requires an independent human identity")
        if (not isinstance(reason, str) or not reason.strip() or field.name in {EXISTS, _RECORD}
                or field.relationship_id is not None):
            raise ValueError("A correction reason and a correctable object field are required")
        Policy().require(connection, identity, "correct", "field", field.subject.object_id, field.name)
        now, end = _now(connection), _time(expires_at)
        prior = connection.execute(
            """SELECT a.document FROM fact_assertions a JOIN fact_observations o USING(tenant,assertion_id,revision_key)
               WHERE a.tenant=? AND a.assertion_id=? AND a.revision_key='1'""",
            (field.subject.tenant, correction_id),
        ).fetchone()
        prior_document = json.loads(prior[0]) if prior is not None else None
        recorded_at = _time(prior_document["recorded_at"]) if prior_document is not None else now
        if prior_document is None and end <= now:
            raise ValueError("A correction must expire in the future")
        assertion = FactAssertion(
            correction_id, 1, field, FactOrigin.HUMAN_CORRECTION, value, recorded_at, valid_from=recorded_at,
            valid_to=end, fresh_until=end, quality=FactQuality.VERIFIED,
            authorization_ref=f"principal:{identity.actor}", correction_reason=reason,
        )
        self._append(connection, assertion)
        if prior_document is None:
            self._project(connection, field, now, revision=correction_id)
        return assertion

    def revoke_evidence(self, connection, event, identity):
        if not isinstance(event, EvidenceRevocation) or not isinstance(identity, IdentityContext):
            raise ValueError("Expected a trusted evidence revocation")
        self._tenant(event.tenant)
        if event.tenant != identity.tenant or identity.service is not None:
            raise PermissionError("Evidence revocation requires an independent human identity")
        Policy().require(connection, identity, "revoke", "evidence", event.evidence_id)
        document = {"kind": "evidence.revocation", "event": _assertion_document(event), "actor": identity.actor}
        if self._enqueue(connection, event.tenant, event.event_id, document):
            evidence_key = canonical_json([{"evidence_id": event.evidence_id, "revision": event.revision}])
            fields = connection.execute(
                """SELECT DISTINCT a.object_type,a.object_id,a.field_name,a.relationship_key
                   FROM fact_assertions a JOIN fact_observations o USING(tenant,assertion_id,revision_key)
                   WHERE a.tenant=? AND a.document::jsonb->'evidence' @> ?::jsonb""",
                (event.tenant, evidence_key),
            ).fetchall()
            now = _now(connection)
            for row in fields:
                subject = ObjectIdentity(event.tenant, row["object_type"], row["object_id"])
                field = FactField(subject, row["field_name"], row["relationship_key"] or None)
                self._project(connection, field, now, revision=event.event_id)

    def history(self, connection, field, *, as_of=None, known_at=None):
        """Return the append-only ledger with independent business and system time."""
        self._tenant(field.subject.tenant)
        return self._records(connection, field, as_of, known_at)

    @staticmethod
    def _records(connection, field, as_of, known_at, *, source_heads=False):
        conditions = ""
        parameters = list(_keys(field))
        if known_at is not None:
            conditions += " AND a.recorded_at<=?"
            parameters.append(_time(known_at))
        if as_of is not None:
            instant = _time(as_of)
            conditions += " AND (a.valid_from IS NULL OR a.valid_from<=?) AND (a.valid_to IS NULL OR a.valid_to>?)"
            parameters.extend((instant, instant))
        projection = "a.document, o.deleted, o.stream, o.mapping_revision, o.operation_id"
        statement = """ FROM fact_assertions a JOIN fact_observations o USING(tenant,assertion_id,revision_key)
                        WHERE a.tenant=? AND a.object_type=? AND a.object_id=?
                          AND a.field_name=? AND a.relationship_key=?""" + conditions
        order = "a.recorded_at DESC, o.source_sequence DESC, a.assertion_id"
        if source_heads:
            # Eligibility still checks the mapping and current source generation after grouping.
            scope = "o.source,o.stream,o.source_type,o.source_id,o.mapping_revision,o.epoch"
            statement = (f"SELECT DISTINCT ON ({scope}) {projection}, a.recorded_at, o.source_sequence, a.assertion_id"
                         f"{statement} AND o.source IS NOT NULL ORDER BY {scope}, {order}")
            statement = f"SELECT * FROM ({statement}) heads ORDER BY recorded_at DESC, source_sequence DESC, assertion_id"
        else:
            statement = f"SELECT {projection}{statement} ORDER BY {order}"
        rows = connection.execute(statement, tuple(parameters)).fetchall()
        return tuple({
            **json.loads(row["document"]), "deleted": row["deleted"], "stream": row["stream"],
            "mapping_revision": json.loads(row["mapping_revision"]) if row["mapping_revision"] else None,
            "operation_id": row["operation_id"],
        } for row in rows)

    def _progress(self, connection, document, known_at):
        native = document["source"]
        progress = connection.execute(
            """SELECT epoch, token, coverage, status, fresh_until, revision FROM source_sync_progress
               WHERE tenant=? AND source=? AND stream=? AND updated_at<=?
               ORDER BY updated_at DESC, revision DESC LIMIT 1""",
            (native["tenant"], native["source"], document["stream"], known_at),
        ).fetchone()
        if progress is None:
            return None, None, False
        cursor = SourceCursor(native["tenant"], native["source"], document["stream"], progress["epoch"], progress["token"])
        proof = FactRead(native["tenant"], "assertion",
                         "progress:" + _digest((native["tenant"], native["source"], document["stream"])),
                         progress["revision"], fresh_until=progress["fresh_until"])
        return cursor, proof, (
            progress["status"] == "ready" and progress["coverage"] == Coverage.COMPLETE
            and progress["epoch"] == document["source_version"]["epoch"]
        )

    @staticmethod
    def _evidence(connection, document, known_at, deadline):
        result = []
        for evidence in document["evidence"]:
            if connection.execute(
                """SELECT 1 FROM fact_invalidation_outbox WHERE tenant=?
                   AND document::jsonb->>'kind'='evidence.revocation'
                   AND document::jsonb#>>'{event,evidence_id}'=?
                   AND document::jsonb#>'{event,revision}'=?::jsonb
                   AND (document::jsonb#>>'{event,revoked_at}')::timestamptz<=?
                   AND enqueued_at<=? LIMIT 1""",
                (evidence["tenant"], evidence["evidence_id"], canonical_json(evidence["revision"]), known_at, known_at),
            ).fetchone() is not None:
                return tuple(result), False
            result.append(FactRead(evidence["tenant"], "evidence", evidence["evidence_id"], evidence["revision"],
                                   fresh_until=deadline))
        return tuple(result), True

    @staticmethod
    def _latest_correction(connection, field, as_of, known_at):
        row = connection.execute(
            """SELECT a.document FROM fact_assertions a JOIN fact_observations o USING(tenant,assertion_id,revision_key)
               WHERE a.tenant=? AND a.object_type=? AND a.object_id=? AND a.field_name=? AND a.relationship_key=?
                 AND o.source IS NULL AND a.recorded_at<=? AND a.valid_from<=?
               ORDER BY a.recorded_at DESC, a.assertion_id LIMIT 1""",
            (*_keys(field), known_at, as_of),
        ).fetchone()
        return json.loads(row[0]) if row is not None else None

    def _resolve(self, connection, field, as_of, known_at, *, projection=False, authority=None, transform=None):
        authority = self._authority(connection, field, known_at) if authority is None else authority
        if transform is None and field.relationship_id is None and field.name not in {EXISTS, _RECORD}:
            manual = self._latest_correction(connection, field, as_of, known_at)
            if manual is not None and (deadline := _time(manual["fresh_until"])) > max(as_of, known_at):
                proof = _assertion_read(manual, deadline)
                return Observation(True, manual["value"], Coverage.COMPLETE, "human_correction",
                                   manual["assertion_id"], (proof,))
        if authority is None:
            return Observation(reason="no_authority")
        authority_read = FactRead(field.subject.tenant, "assertion",
                                  "authority:" + _digest(_keys(authority.field)), authority.revision)
        reads, cursors, selected = [authority_read], {}, {}
        mapping_cache = {}
        records = self._records(connection, field, as_of, known_at, source_heads=True)
        for record in records:
            identity = SourceIdentity(**record["source"])
            # Ignore previous generations or explicit remaps even if their evidence exists.
            if identity not in mapping_cache:
                try:
                    mapping_cache[identity] = self.target_for(connection, identity, known_at=known_at)
                except MappingConflict:
                    mapping_cache[identity] = None
            mapping = mapping_cache[identity]
            if mapping is None or mapping.target != field.subject or mapping.revision != record["mapping_revision"]:
                continue
            if (identity, record["stream"]) in selected:
                # Never promote an older fact when its current source revision is stale or revoked.
                continue
            deadline = _date(record["fresh_until"])
            if not projection:
                cursor, progress_read, ready = self._progress(connection, record, known_at)
                stream_deadline = progress_read.fresh_until if progress_read is not None else None
                if cursor is not None and cursor.epoch != record["source_version"]["epoch"]:
                    # A complete new generation may omit this previously observed mark; it is no longer current.
                    continue
                if cursor is not None and identity.source in authority.source_names:
                    cursors[(cursor.source, cursor.stream)] = cursor
                    reads.append(progress_read)
                if stream_deadline is not None and deadline is not None:
                    deadline = min(stream_deadline, deadline)
                eligible = (ready and stream_deadline is not None and deadline is not None
                            and deadline > as_of and deadline > known_at)
            else:
                eligible = True
            evidence, unrevoked = self._evidence(connection, record, known_at, deadline)
            supported = eligible and unrevoked
            value = transform(record["value"]) if transform and not record["deleted"] else record["value"]
            selected[(identity, record["stream"])] = (record, value, supported)
            if identity.source in authority.source_names:
                reads.append(_assertion_read(record, deadline))
                reads.extend(evidence)
        active = [entry for (identity, _), entry in selected.items() if identity.source in authority.source_names]
        available_sources = {identity.source for (identity, _), entry in selected.items()
                             if entry[2] and identity.source in authority.source_names}
        covered = available_sources == set(authority.source_names) and all(entry[2] for entry in active)
        material = {canonical_json((entry[0]["deleted"], entry[1])) for entry in active}
        common = dict(reads=_dedupe_reads(reads), source_cursors=_dedupe_cursors(cursors.values()))
        if len(material) > 1:
            return Observation(coverage=Coverage.PARTIAL, reason="source_conflict",
                               conflicts=tuple(sorted(entry[0]["assertion_id"] for entry in active)), **common)
        if not covered:
            return Observation(coverage=Coverage.PARTIAL if selected else Coverage.UNKNOWN,
                               reason="insufficient_authoritative_coverage", **common)
        row, value, _ = min(active, key=lambda entry: entry[0]["assertion_id"])
        competing = tuple(sorted(entry[0]["assertion_id"] for (identity, _), entry in selected.items()
                                 if identity.source not in authority.source_names
                                 and canonical_json((entry[0]["deleted"], entry[1])) not in material))
        reason = "authority_preferred" if competing else "authoritative_agreement"
        if row["deleted"]:
            reason = "authoritative_tombstone"
        # A proven deletion is a meaningful false existence claim. Never interpret a missing attribute as false.
        available = not row["deleted"] or field.name == EXISTS
        return Observation(available, value, Coverage.COMPLETE, reason, row["assertion_id"],
                           conflicts=competing, deleted=row["deleted"], **common)

    def read_fact(self, connection, field, *, as_of, known_at):
        self._tenant(field.subject.tenant)
        as_of, known_at = _time(as_of), _time(known_at)
        return self._resolve(connection, field, as_of, known_at)

    def read_relation(self, connection, subject, relation, *, as_of, known_at, target_type=None, max_members=200,
                      target_visible=None):
        """Read a fresh relation, optionally projecting membership before resolving a caller-visible view."""
        self._tenant(subject.tenant)
        as_of, known_at = _time(as_of), _time(known_at)
        scope = {"object_type": subject.object_type, "object_id": subject.object_id, "relation": relation}
        authority = self._authority(connection, FactField(subject, relation), known_at)

        def members(value):
            return sorted(
                ({"id": edge["id"], "target_type": edge["target_type"], "target_id": edge["target_id"]}
                 for edge in value["relations"] if edge["type"] == relation
                 and (target_visible is None or target_visible(edge["target_id"]))), key=lambda edge: edge["id"],
            )

        if authority is None:
            observation = Observation(reason="no_authority")
        else:
            observation = self._resolve(connection, FactField(subject, _RECORD), as_of, known_at,
                                        authority=authority, transform=members)
        reads = list(observation.reads)
        cursors = list(observation.source_cursors)
        targets = set()
        dependencies = set()
        available = observation.available
        reason = observation.reason
        if type(max_members) is not int or not 1 <= max_members <= 1000:
            raise ValueError("Relation member limit must be 1–1000")
        if available:
            members = observation.value
            if len(members) > max_members:
                available, reason = False, "relation_member_limit"
            elif any(target_type is not None and edge["target_type"] != target_type for edge in members):
                available, reason = False, "invalid_relation_target_type"
            elif len({(edge["target_type"], edge["target_id"]) for edge in members}) != len(members):
                available, reason = False, "duplicate_relation_target"
        for member in observation.value if available else ():
            target = ObjectIdentity(subject.tenant, member["target_type"], member["target_id"])
            dependencies.add(target.object_id)
            existence = self.read_fact(connection, FactField(target, EXISTS), as_of=as_of, known_at=known_at)
            reads.extend(existence.reads)
            cursors.extend(existence.source_cursors)
            if not existence.available or type(existence.value) is not bool:
                available = False
                reason = "target_existence_unknown"
                continue
            if existence.value:
                targets.add(target.object_id)
        coverage = observation.coverage if available else (
            Coverage.UNKNOWN if observation.coverage == Coverage.UNKNOWN else Coverage.PARTIAL
        )
        proofs = _dedupe_reads(reads)
        cursors = _dedupe_cursors(cursors)
        revision = _digest({"scope": scope, "members": sorted(targets), "coverage": coverage.value,
                            "reads": [proof.as_payload() for proof in proofs],
                            "cursors": [asdict(cursor) for cursor in cursors]})
        collection = CollectionRead(subject.tenant, CollectionKind.RELATIONSHIP, scope, revision,
                                    tuple(sorted(targets)), coverage)
        return RelationObservation(available, collection, proofs, cursors, reason, tuple(sorted(dependencies)))

    @staticmethod
    def _enqueue(connection, tenant, event_id, document):
        text = canonical_json(document)
        inserted = connection.execute(
            """INSERT INTO fact_invalidation_outbox(tenant,event_id,digest,document) VALUES (?,?,?,?)
               ON CONFLICT DO NOTHING""", (tenant, event_id, _digest(document), text),
        )
        if not inserted.rowcount:
            prior = connection.execute(
                "SELECT digest FROM fact_invalidation_outbox WHERE tenant=? AND event_id=?", (tenant, event_id),
            ).fetchone()
            if prior is None or prior[0] != _digest(document):
                raise ValueError("Invalidation ID already identifies different evidence")
        return inserted.rowcount == 1

    def _project(self, connection, field, now, *, operation_id=None, revision=None):
        key = _keys(field)
        prior = connection.execute(
            """SELECT assertion_id, revision_key FROM fact_projections
               WHERE tenant=? AND object_type=? AND object_id=? AND field_name=? AND relationship_key=?""",
            key,
        ).fetchone()
        decision = self._resolve(connection, field, now, now, projection=True)
        selected = decision.selected if decision.available else None
        if selected is None:
            if prior is not None:
                connection.execute(
                    """DELETE FROM fact_projections WHERE tenant=? AND object_type=? AND object_id=?
                       AND field_name=? AND relationship_key=?""", key,
                )
        elif prior is None or prior[0] != selected:
            proof = next(item for item in decision.reads if item.resource_id == selected)
            connection.execute(
                """INSERT INTO fact_projections(tenant,object_type,object_id,field_name,relationship_key,
                                                assertion_id,revision_key)
                   VALUES (?,?,?,?,?,?,?)
                   ON CONFLICT (tenant,object_type,object_id,field_name,relationship_key)
                   DO UPDATE SET assertion_id=excluded.assertion_id,revision_key=excluded.revision_key""",
                (*key, selected, canonical_json(proof.revision)),
            )
        if revision is None and (prior[0] if prior is not None else None) == selected:
            return
        identity = _digest({"field": key, "selected": decision.selected, "input": revision, "now": now.isoformat()})
        change = FactChange(identity, field, revision or identity, ChangeKind.UPSERT
                            if selected is not None and not decision.deleted else ChangeKind.DELETE, now, operation_id)
        self._enqueue(connection, key[0], identity, {
            "kind": "fact.change", "event": _assertion_document(change),
            "selection": {"reason": decision.reason, "chosen": decision.selected, "conflicts": list(decision.conflicts)},
        })
