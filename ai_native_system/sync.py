"""Atomic synchronization of a connector stream into canonical facts."""

import json
from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import timedelta
from hashlib import sha256

from .fact_contracts import (
    ChangeKind, Coverage, SnapshotBoundary, SourceCursor, SourceEvent, SourceIdentity,
    SourceVersion, canonical_json,
)
from .storage import row_data


_MAX_POSITION = (1 << 63) - 1


def _key(value):
    return isinstance(value, str) and bool(value.strip()) and "\0" not in value


def _position(value):
    return type(value) is int and 0 <= value <= _MAX_POSITION


def _digest(document):
    return sha256(canonical_json(document).encode("utf-8")).hexdigest()


def _document(value):
    from .adapters.postgres_facts import _document as serialize
    return serialize(value)


def _changes(event):
    if event.kind == ChangeKind.DELETE:
        return None
    payload = event.payload
    if payload.keys() - {"properties", "state", "relations"} or not {"properties"} <= payload.keys():
        raise ValueError("Source record requires properties and may include state and relations")
    properties = payload["properties"]
    if not isinstance(properties, Mapping) or not all(_key(name) and not name.startswith("$") for name in properties):
        raise ValueError("Invalid source record properties")
    result = {(name, None): value for name, value in properties.items()}
    if "state" in payload:
        if not _key(payload["state"]):
            raise ValueError("Source state must be a nonempty string")
        result["$state", None] = payload["state"]
    relations = payload.get("relations", ())
    if not isinstance(relations, tuple):
        raise ValueError("Source relations must be an array")
    for relation in relations:
        if (not isinstance(relation, Mapping)
                or relation.keys() != {"type", "id", "target_type", "target_id", "properties"}
                or not all(_key(relation[name]) and not relation[name].startswith("$")
                           for name in ("type", "id", "target_type", "target_id"))
                or not isinstance(relation["properties"], Mapping)):
            raise ValueError("Invalid source relation")
        key = relation["type"], relation["id"]
        if key in result:
            raise ValueError("Duplicate source relation")
        result[key] = {name: relation[name] for name in ("target_type", "target_id", "properties")}
    return result


class _Rejected(ValueError):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class SyncResult:
    status: str
    reason: str | None = None


@contextmanager
def _projection_work(connection):
    # Inbox and rejected-delivery evidence survive expected domain errors.
    # Unexpected infrastructure failures abort the enclosing transaction.
    connection.execute("SAVEPOINT sync_projection")
    try:
        yield
    except ValueError:
        connection.execute("ROLLBACK TO SAVEPOINT sync_projection")
        connection.execute("RELEASE SAVEPOINT sync_projection")
        raise
    connection.execute("RELEASE SAVEPOINT sync_projection")


class FactSync:
    """Trusted connector service scoped to one tenant, source and stream.

    A stream owns each native record it sees. Stream position is an upstream
    contiguous ordinal, independent of per-record versions. Snapshot position
    denotes the last event covered by the captured cut.
    """

    def __init__(self, store, tenant, source, stream, facts, *, freshness=timedelta(minutes=5)):
        SourceCursor(tenant, source, stream, "validate", "validate")
        if not isinstance(freshness, timedelta) or freshness <= timedelta():
            raise ValueError("Source freshness must be a positive duration")
        self.store = store
        self.tenant = tenant
        self.source = source
        self.stream = stream
        self.facts = facts
        self.freshness = freshness
        self.scope = tenant, source, stream

    def _status(self, connection):
        row = connection.execute(
            "SELECT * FROM source_sync_streams WHERE tenant=? AND source=? AND stream=?", self.scope,
        ).fetchone()
        return row_data(row)

    def status(self):
        with self.store.transaction(tenant=self.tenant) as connection:
            return self._status(connection)

    def invalidate(self, predecessor):
        """Record rejection of an upstream resume token even if no event arrived."""
        self._check_predecessor(predecessor)
        if predecessor is None:
            raise ValueError("Invalidating a cursor requires its exact checkpoint")
        with self.store.transaction(tenant=self.tenant, write=True) as connection:
            if predecessor != self._expected(self._status(connection)):
                return SyncResult("stale", "cursor_predecessor_changed")
            return self._conflict(connection, "cursor_invalidated", {"cursor": _document(predecessor)})

    def conflicts(self, *, limit=100):
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("Conflict history limit must be 1–1000")
        with self.store.transaction(tenant=self.tenant) as connection:
            return tuple(row_data(row, "document") for row in connection.execute(
                """SELECT conflict_id,event_id,reason,document,recorded_at FROM source_sync_conflicts
                   WHERE tenant=? AND source=? AND stream=?
                   ORDER BY recorded_at DESC, conflict_id LIMIT ?""", (*self.scope, limit)))

    def _check_scope(self, event):
        if not isinstance(event, SourceEvent) or (event.identity.tenant, event.identity.source) != self.scope[:2]:
            raise ValueError("Event is outside the connector source")
        if event.cursor is not None and event.cursor.stream != self.stream:
            raise ValueError("Event is outside the connector stream")

    def _check_predecessor(self, predecessor):
        if predecessor is not None and (not isinstance(predecessor, SourceCursor)
                                        or (predecessor.tenant, predecessor.source, predecessor.stream) != self.scope):
            raise ValueError("Cursor predecessor is outside the connector stream")

    def _expected(self, row):
        return None if row is None else SourceCursor(*self.scope, row["epoch"], row["token"])

    @staticmethod
    def _epoch(event):
        if event.version is not None:
            return event.version.epoch
        return event.cursor.epoch if event.cursor is not None else None

    def _retired(self, connection, current, epoch):
        return current is not None and epoch is not None and epoch != current["epoch"] and connection.execute(
            """SELECT 1 FROM source_sync_snapshots WHERE tenant=? AND source=? AND stream=? AND epoch=?
               AND document::jsonb ->> 'status' = 'applied' LIMIT 1""", (*self.scope, epoch),
        ).fetchone() is not None

    def _receive(self, connection, event):
        inserted = connection.execute(
            """INSERT INTO source_events (tenant,source,event_id,source_epoch,received_at,digest,document)
               VALUES (?,?,?,?,?,?,?) ON CONFLICT DO NOTHING""",
            (*event.dedupe_key, self._epoch(event), event.received_at, event.content_digest, canonical_json(_document(event))),
        )
        if inserted.rowcount:
            return True
        existing = connection.execute(
            "SELECT digest FROM source_events WHERE tenant=? AND source=? AND event_id=?", event.dedupe_key,
        ).fetchone()
        return existing[0] == event.content_digest

    def _delivery(self, connection, event):
        row = connection.execute(
            "SELECT * FROM source_sync_deliveries WHERE tenant=? AND source=? AND event_id=?", event.dedupe_key,
        ).fetchone()
        return row_data(row)

    def _outcome(self, connection, event, position, status, snapshot_id=None):
        connection.execute(
            """INSERT INTO source_sync_deliveries
               (tenant,source,event_id,stream,epoch,position,status,snapshot_id,recorded_at)
               VALUES (?,?,?,?,?,?,?,?,clock_timestamp())
               ON CONFLICT (tenant, source, event_id) DO UPDATE
               SET status=excluded.status, epoch=excluded.epoch, position=excluded.position,
                   snapshot_id=excluded.snapshot_id, recorded_at=clock_timestamp()
               WHERE source_sync_deliveries.status='blocked' AND source_sync_deliveries.stream=excluded.stream""",
            (*event.dedupe_key, self.stream, self._epoch(event), position, status, snapshot_id),
        )

    def _conflict(self, connection, reason, detail, *, event_id=None, block=True):
        document = {"reason": reason, "detail": detail}
        connection.execute(
            """INSERT INTO source_sync_conflicts (tenant,source,stream,conflict_id,event_id,reason,document,recorded_at)
               VALUES (?,?,?,?,?,?,?,clock_timestamp()) ON CONFLICT DO NOTHING""",
            (*self.scope, _digest(document), event_id, reason, canonical_json(document)),
        )
        if block:
            changed = connection.execute(
                """UPDATE source_sync_streams SET status='blocked',coverage='unknown',
                          fresh_until=NULL,updated_at=clock_timestamp()
                   WHERE tenant=? AND source=? AND stream=? AND status <> 'blocked' RETURNING *""", self.scope,
            ).fetchone()
            if changed is not None:
                self._progress(connection, changed, reason)
        return SyncResult("blocked", reason)

    def _reject_event(self, connection, event, position, reason, *, outcome=True, block=True):
        if outcome:
            self._outcome(connection, event, position, "blocked")
        return self._conflict(connection, reason, {"event": _document(event), "position": position},
                              event_id=event.event_id, block=block)

    def _checkpoint(self, connection, cursor, position, status, coverage, fresh_until, snapshot_id):
        current = connection.execute(
            """INSERT INTO source_sync_streams
               (tenant,source,stream,epoch,position,token,snapshot_id,status,coverage,fresh_until,updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,clock_timestamp())
               ON CONFLICT (tenant,source,stream) DO UPDATE SET epoch=excluded.epoch,
                   position=excluded.position,token=excluded.token,snapshot_id=excluded.snapshot_id,
                   status=excluded.status,coverage=excluded.coverage,fresh_until=excluded.fresh_until,
                   updated_at=clock_timestamp() RETURNING *""",
            (*self.scope, cursor.epoch, position, cursor.token, snapshot_id, status, coverage, fresh_until),
        ).fetchone()
        connection.execute(
            """INSERT INTO source_cursors (tenant,source,stream,epoch,token,revision)
               VALUES (?,?,?,?,?,1)
               ON CONFLICT (tenant,source,stream) DO UPDATE SET epoch=excluded.epoch, token=excluded.token,
                   revision=source_cursors.revision+1""", (*self.scope, cursor.epoch, cursor.token),
        )
        self._progress(connection, current, "checkpoint")

    def _progress(self, connection, current, reason):
        revision = connection.execute(
            """INSERT INTO source_sync_progress
               (tenant,source,stream,epoch,position,token,snapshot_id,status,coverage,updated_at,fresh_until,revision)
               SELECT ?,?,?,?,?,?,?,?,?,?,?,coalesce(max(revision),0)+1 FROM source_sync_progress
               WHERE tenant=? AND source=? AND stream=? RETURNING revision""",
            (*self.scope, current["epoch"], current["position"], current["token"], current["snapshot_id"],
             current["status"], current["coverage"], current["updated_at"], current["fresh_until"], *self.scope),
        ).fetchone()[0]
        event_id = _digest(["source-coverage/1", *self.scope, revision])
        document = {"kind": "source.coverage", "event": {
            "event_id": event_id, "tenant": self.tenant, "source": self.source, "stream": self.stream,
            "epoch": current["epoch"], "position": current["position"], "status": current["status"],
            "coverage": current["coverage"], "revision": revision, "reason": reason,
            "fresh_until": _document(current["fresh_until"]), "recorded_at": _document(current["updated_at"]),
        }}
        connection.execute(
            """INSERT INTO fact_invalidation_outbox (tenant,event_id,digest,document)
               VALUES (?,?,?,?)""", (self.tenant, event_id, _digest(document), canonical_json(document)),
        )

    def _record(self, connection, event):
        row = connection.execute(
            """SELECT * FROM source_sync_records WHERE tenant=? AND source=? AND source_type=? AND source_id=?""",
            (self.tenant, self.source, event.identity.source_type, event.identity.source_id),
        ).fetchone()
        return row_data(row)

    def _store_record(self, connection, event, mapping, fingerprint):
        connection.execute(
            """INSERT INTO source_sync_records
               (tenant,source,stream,source_type,source_id,epoch,version_token,version_sequence,
                record_digest,object_type,object_id,mapping_revision,tombstone,document,recorded_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,clock_timestamp())
               ON CONFLICT (tenant,source,source_type,source_id) DO UPDATE SET
                   epoch=excluded.epoch, version_token=excluded.version_token, version_sequence=excluded.version_sequence,
                   record_digest=excluded.record_digest,object_type=excluded.object_type,object_id=excluded.object_id,
                   mapping_revision=excluded.mapping_revision,tombstone=excluded.tombstone,document=excluded.document,
                   recorded_at=clock_timestamp()
               WHERE source_sync_records.stream=excluded.stream""",
            (*self.scope, event.identity.source_type, event.identity.source_id, event.version.epoch,
             event.version.token, event.version.sequence, fingerprint, mapping.target.object_type,
             mapping.target.object_id, canonical_json(mapping.revision), event.kind == ChangeKind.DELETE,
             canonical_json(_document(event))),
        )

    def _record_version(self, connection, event, *, complete=False, observed_at=None,
                        observation_id=None, inferred=False):
        from .fact_feedback import observe

        previous = self._record(connection, event)
        if previous is not None and previous["stream"] != self.stream:
            raise _Rejected("record_belongs_to_other_stream")
        if event.version is None or not _position(event.version.sequence):
            raise _Rejected("unsequenced_record")
        try:
            mapping = self.facts.target_for(connection, event.identity)
        except ValueError as error:
            raise _Rejected("identity_mapping_conflict") from error
        if previous is not None and not complete and previous["mapping_revision"] != canonical_json(mapping.revision):
            raise _Rejected("identity_mapping_changed")
        fingerprint = _digest({"kind": event.kind.value, "payload": event.payload})
        if previous is not None and previous["epoch"] == event.version.epoch and not inferred:
            order = event.version.sequence - previous["version_sequence"]
            if order < 0:
                if complete:
                    raise _Rejected("snapshot_contains_older_record")
                return "stale"
            if not order:
                if (previous["version_token"], previous["record_digest"]) != (event.version.token, fingerprint):
                    raise _Rejected("record_version_collision")
                if not complete:
                    observe(connection, event, self.stream, mapping.target)
                    return "stale"
        try:
            self.facts.write_source(connection, event, stream=self.stream, changes=_changes(event),
                                    observed_at=observed_at, observation_id=observation_id)
        except ValueError as error:
            raise _Rejected("invalid_canonical_record") from error
        self._store_record(connection, event, mapping, fingerprint)
        observe(connection, event, self.stream, mapping.target)
        return "applied"

    def apply(self, event, *, position, predecessor):
        """Ingest one event and compare its stream cursor predecessor exactly."""
        self._check_scope(event)
        if position is not None and not _position(position):
            raise ValueError("Invalid source stream position")
        self._check_predecessor(predecessor)
        with self.store.transaction(tenant=self.tenant, write=True) as connection:
            current = self._status(connection)
            retired = self._retired(connection, current, self._epoch(event))
            if not self._receive(connection, event):
                return self._reject_event(connection, event, position, "event_id_collision", outcome=False, block=not retired)
            prior = self._delivery(connection, event)
            if prior is not None and prior["stream"] != self.stream:
                return self._reject_event(connection, event, position, "event_belongs_to_other_stream", outcome=False)
            if retired:
                if prior is None or prior["status"] == "blocked":
                    self._outcome(connection, event, position, "stale")
                return SyncResult("stale", "retired_epoch")
            if position is None or event.cursor is None or event.version is None or not _position(event.version.sequence):
                return self._reject_event(connection, event, position, "unsequenced_delivery")
            if current is None:
                return self._reject_event(connection, event, position, "snapshot_required")
            if event.cursor.epoch != current["epoch"]:
                return self._reject_event(connection, event, position, "resnapshot_for_new_epoch")
            if position <= current["position"]:
                if prior is not None and prior["status"] != "blocked":
                    return SyncResult("duplicate")
                self._outcome(connection, event, position, "stale")
                return SyncResult("stale", "older_stream_position")
            if current["status"] == "blocked":
                return self._reject_event(connection, event, position, "resnapshot_required")
            if position != current["position"] + 1 or predecessor != self._expected(current):
                return self._reject_event(connection, event, position, "cursor_gap")
            try:
                status = "duplicate"
                if prior is None or prior["status"] == "blocked":
                    with _projection_work(connection):
                        status = self._record_version(connection, event, observed_at=event.occurred_at)
                    self._outcome(connection, event, position, status)
            except _Rejected as error:
                return self._reject_event(connection, event, position, error.reason)
            fresh_until = current["fresh_until"]
            if current["status"] == "ready" and event.occurred_at is not None and status == "applied":
                deadline = self._deadline(connection, event.occurred_at)
                fresh_until = deadline if fresh_until is None else max(deadline, fresh_until)
            self._checkpoint(connection, event.cursor, position, current["status"], current["coverage"],
                             fresh_until, current["snapshot_id"])
            return SyncResult(status)

    def _deadline(self, connection, observed_at):
        if observed_at is None:
            return None
        now = connection.execute("SELECT clock_timestamp()").fetchone()[0]
        return min(observed_at, now) + self.freshness

    def _snapshot_row(self, connection, boundary, fingerprint, document, result):
        received = {**document, "status": result.status, "reason": result.reason}
        connection.execute(
            """INSERT INTO source_sync_snapshots (tenant,source,stream,snapshot_id,epoch,digest,document,recorded_at)
               VALUES (?,?,?,?,?,?,?,clock_timestamp())""",
            (*self.scope, boundary.snapshot_id, boundary.epoch, fingerprint, canonical_json(received)),
        )
        return result

    def _snapshot_validity(self, connection, boundary, position, predecessor, current):
        if boundary.resume_cursor is None or position is None:
            return "unsequenced_snapshot"
        if predecessor != self._expected(current):
            return "snapshot_predecessor_changed"
        if self._retired(connection, current, boundary.epoch):
            return "retired_epoch"
        if current is None:
            return None
        if boundary.epoch == current["epoch"] and position < current["position"]:
            return "snapshot_older_than_checkpoint"
        if ((current["status"] == "blocked" or boundary.epoch != current["epoch"])
                and boundary.coverage != Coverage.COMPLETE):
            return "complete_resnapshot_required"
        return None

    def _tombstones(self, connection, boundary, observed):
        rows = connection.execute(
            """SELECT source_type,source_id,epoch,version_sequence FROM source_sync_records
               WHERE tenant=? AND source=? AND stream=? AND NOT tombstone ORDER BY source_type,source_id""",
            self.scope,
        ).fetchall()
        received = connection.execute("SELECT clock_timestamp()").fetchone()[0]
        for row in rows:
            key = row["source_type"], row["source_id"]
            if key in observed:
                continue
            identity = SourceIdentity(self.tenant, self.source, *key)
            marker = _digest(["snapshot-delete", *self.scope, boundary.epoch, boundary.snapshot_id, *key])
            version = SourceVersion(identity, boundary.epoch, marker,
                                    row["version_sequence"] if row["epoch"] == boundary.epoch else 0)
            yield SourceEvent(f"snapshot-delete:{marker}", identity, ChangeKind.DELETE, received,
                              version=version, occurred_at=boundary.finished_at)

    def snapshot(self, boundary, records, *, position, predecessor=None):
        """Apply an entire snapshot. Only a complete cut can imply a deletion."""
        if not isinstance(boundary, SnapshotBoundary) or (boundary.tenant, boundary.source) != self.scope[:2]:
            raise ValueError("Snapshot is outside the connector source")
        if boundary.resume_cursor is not None and boundary.resume_cursor.stream != self.stream:
            raise ValueError("Snapshot is outside the connector stream")
        if position is not None and not _position(position):
            raise ValueError("Invalid source stream position")
        self._check_predecessor(predecessor)
        by_identity = {}
        event_ids = set()
        for record in records:
            self._check_scope(record)
            key = record.identity.source_type, record.identity.source_id
            if key in by_identity or record.event_id in event_ids or record.kind != ChangeKind.UPSERT:
                raise ValueError("A snapshot contains one live entry per source identity")
            by_identity[key] = record
            event_ids.add(record.event_id)
        document = {"boundary": _document(boundary), "position": position,
                    "records": [[event.event_id, event.content_digest] for _, event in sorted(by_identity.items())]}
        fingerprint = _digest(document)
        with self.store.transaction(tenant=self.tenant, write=True) as connection:
            prior = connection.execute(
                """SELECT digest,document FROM source_sync_snapshots
                   WHERE tenant=? AND source=? AND stream=? AND snapshot_id=?""",
                (*self.scope, boundary.snapshot_id),
            ).fetchone()
            if prior is not None:
                if prior["digest"] != fingerprint:
                    return self._conflict(connection, "snapshot_id_collision", document)
                receipt = json.loads(prior["document"])
                return SyncResult("duplicate" if receipt["status"] == "applied" else receipt["status"], receipt["reason"])
            current = self._status(connection)
            reason = self._snapshot_validity(connection, boundary, position, predecessor, current)
            if reason is not None:
                block = reason not in ("retired_epoch", "snapshot_older_than_checkpoint", "snapshot_predecessor_changed")
                result = self._conflict(connection, reason, document, block=block)
                return self._snapshot_row(connection, boundary, fingerprint, document, result)
            for key in sorted(by_identity):
                event = by_identity[key]
                if self._epoch(event) != boundary.epoch or not self._receive(connection, event):
                    result = self._conflict(connection, "snapshot_event_conflict", _document(event), event_id=event.event_id)
                    return self._snapshot_row(connection, boundary, fingerprint, document, result)
            complete = boundary.coverage == Coverage.COMPLETE
            try:
                with _projection_work(connection):
                    for key in sorted(by_identity):
                        event = by_identity[key]
                        status = self._record_version(
                            connection, event, complete=complete, observed_at=boundary.finished_at,
                            observation_id=boundary.snapshot_id,
                        )
                        self._outcome(connection, event, position, status, boundary.snapshot_id)
                    if complete:
                        for tombstone in self._tombstones(connection, boundary, by_identity):
                            if not self._receive(connection, tombstone):
                                raise _Rejected("snapshot_tombstone_collision")
                            self._record_version(
                                connection, tombstone, complete=True, observed_at=boundary.finished_at,
                                observation_id=boundary.snapshot_id, inferred=True,
                            )
                            self._outcome(connection, tombstone, position, "applied", boundary.snapshot_id)
            except _Rejected as error:
                result = self._conflict(connection, error.reason, document)
                return self._snapshot_row(connection, boundary, fingerprint, document, result)
            self._checkpoint(connection, boundary.resume_cursor, position, "ready" if complete else "partial",
                             boundary.coverage.value, self._deadline(connection, boundary.finished_at) if complete else None,
                             boundary.snapshot_id)
            return self._snapshot_row(connection, boundary, fingerprint, document, SyncResult("applied"))
