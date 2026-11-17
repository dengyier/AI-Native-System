"""Bounded repair jobs for lookup and evidence, plus integrity-checked proof files."""
import json
import os
import re
import stat
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from secrets import token_hex

from .storage import encode


_JOBS = frozenset(("reconcile", "evidence"))
_PROOFS = frozenset(("source_receipt", "runtime_attestation"))
_VIEWS = frozenset(("raw", "redacted"))
_HEX = re.compile(r"[0-9a-f]{64}")
_MAX_PROOF_BYTES = 2 * 1024 * 1024


def _identifier(value):
    return (type(value) is str and 1 <= len(value) <= 512 and bool(value.strip())
            and all(32 <= ord(character) != 127 for character in value))


def _integer(value, minimum, maximum):
    return type(value) is int and minimum <= value <= maximum


def _job_scope(tenant, kind):
    if not _identifier(tenant) or kind not in _JOBS:
        raise ValueError("Expected a tenant and a reconciliation or evidence job kind")


def enqueue_delivery(connection, *, tenant, task_id, operation_id, kind, scope, max_attempts=8):
    """Register only query or evidence work, in the transaction owning the operation."""
    _job_scope(tenant, kind)
    if not all(map(_identifier, (task_id, operation_id, scope))) or not _integer(max_attempts, 1, 32):
        raise ValueError("Invalid delivery job")
    inserted = connection.execute(
        """INSERT INTO p4_delivery_jobs (tenant, task_id, operation_id, kind, scope, max_attempts)
           VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING""",
        (tenant, task_id, operation_id, kind, scope, max_attempts),
    )
    if inserted.rowcount:
        return True
    prior = connection.execute(
        """SELECT task_id, scope, max_attempts FROM p4_delivery_jobs
           WHERE tenant = ? AND operation_id = ? AND kind = ?""", (tenant, operation_id, kind),
    ).fetchone()
    if prior is None or tuple(prior) != (task_id, scope, max_attempts):
        raise ValueError("Delivery operation is already bound to different work")
    return False


@dataclass(frozen=True)
class Lease:
    tenant: str
    task_id: str
    operation_id: str
    kind: str
    scope: str
    token: str
    attempts: int
    max_attempts: int
    manual: bool = False


def _retry_policy(base_seconds, max_delay):
    if not _integer(base_seconds, 1, 600) or not _integer(max_delay, base_seconds, 3600):
        raise ValueError("Invalid delivery backoff")


def claim_delivery(store, tenant, kind, *, lease_seconds=30, active_limit=4, per_scope_limit=1,
                   scope_interval_seconds=1, base_seconds=2, max_delay=300, manual_operation_id=None):
    """Claim one due job, or a named manual job for a single operator lookup."""
    _job_scope(tenant, kind)
    _retry_policy(base_seconds, max_delay)
    manual = manual_operation_id is not None
    if manual and not _identifier(manual_operation_id):
        raise ValueError("Invalid manual delivery operation")
    if (not _integer(lease_seconds, 1, 900) or not _integer(active_limit, 1, 32)
            or not _integer(per_scope_limit, 1, active_limit) or not _integer(scope_interval_seconds, 0, 300)):
        raise ValueError("Invalid delivery lease or rate limit")
    token = token_hex(24)
    with store.transaction(tenant=tenant, write=True) as connection:
        connection.execute(
            """UPDATE p4_delivery_jobs
               SET status = CASE WHEN lease_manual OR attempts >= max_attempts THEN 'manual' ELSE 'queued' END,
                   next_attempt_at = lease_expires_at + make_interval(
                       secs => least(?, ? * power(2, greatest(attempts - 1, 0)))),
                   last_error = CASE WHEN lease_manual THEN 'manual_review'
                                     WHEN attempts >= max_attempts THEN 'retry_limit' ELSE 'lease_expired' END,
                   lease_token = NULL, lease_expires_at = NULL, lease_manual = false
               WHERE tenant = ? AND kind = ? AND status = 'leased' AND lease_expires_at <= clock_timestamp()""",
            (max_delay, base_seconds, tenant, kind),
        )
        active = connection.execute(
            "SELECT count(*) FROM p4_delivery_jobs WHERE tenant = ? AND kind = ? AND status = 'leased'",
            (tenant, kind),
        ).fetchone()[0]
        if active >= active_limit:
            return None
        row = connection.execute(
            """SELECT candidate.task_id, candidate.operation_id, candidate.scope
               FROM p4_delivery_jobs candidate
               WHERE candidate.tenant = ? AND candidate.kind = ?
                 AND ((NOT ? AND candidate.status = 'queued' AND candidate.attempts < candidate.max_attempts
                         AND candidate.next_attempt_at <= clock_timestamp())
                      OR (? AND candidate.status = 'manual' AND candidate.operation_id = ?))
                 AND (SELECT count(*) FROM p4_delivery_jobs running
                      WHERE running.tenant = candidate.tenant AND running.kind = candidate.kind
                        AND running.scope = candidate.scope AND running.status = 'leased') < ?
                 AND NOT EXISTS (
                     SELECT 1 FROM p4_delivery_jobs recent
                     WHERE recent.tenant = candidate.tenant AND recent.kind = candidate.kind
                       AND recent.scope = candidate.scope
                       AND recent.last_claimed_at > clock_timestamp() - make_interval(secs => ?))
               ORDER BY candidate.next_attempt_at, candidate.operation_id LIMIT 1""",
            (tenant, kind, manual, manual, manual_operation_id, per_scope_limit, scope_interval_seconds),
        ).fetchone()
        if row is None:
            return None
        claimed = connection.execute(
            """UPDATE p4_delivery_jobs
               SET status = 'leased', lease_token = ?, lease_expires_at = clock_timestamp() + make_interval(secs => ?),
                   last_claimed_at = clock_timestamp(), attempts = attempts + ?, lease_manual = ?
               WHERE tenant = ? AND operation_id = ? AND kind = ?
               RETURNING attempts, max_attempts""",
            (token, lease_seconds, 0 if manual else 1, manual, tenant, row["operation_id"], kind),
        ).fetchone()
        return Lease(tenant, row["task_id"], row["operation_id"], kind, row["scope"], token,
                     claimed["attempts"], claimed["max_attempts"], manual)


def finish_delivery(store, lease, outcome, *, base_seconds=2, max_delay=300):
    """Only the currently live lease can complete or reschedule its own job."""
    _retry_policy(base_seconds, max_delay)
    if not isinstance(lease, Lease) or outcome not in ("done", "retry", "manual"):
        raise ValueError("Expected a lease and a delivery outcome")
    delay = 0
    if outcome == "done":
        status, last_error = "completed", None
    elif outcome == "manual" or lease.manual:
        status, last_error = "manual", "manual_review"
    elif lease.attempts >= lease.max_attempts:
        status, last_error = "manual", "retry_limit"
    else:
        status, last_error = "queued", "transient"
        delay = min(max_delay, base_seconds * 2 ** (lease.attempts - 1))
    with store.transaction(tenant=lease.tenant, write=True) as connection:
        updated = connection.execute(
            """UPDATE p4_delivery_jobs
               SET status = ?, last_error = ?, next_attempt_at = clock_timestamp() + make_interval(secs => ?),
                   lease_token = NULL, lease_expires_at = NULL, lease_manual = false
               WHERE tenant = ? AND operation_id = ? AND kind = ? AND status = 'leased'
                 AND lease_token = ? AND lease_manual = ? AND lease_expires_at > clock_timestamp()""",
            (status, last_error, delay, lease.tenant, lease.operation_id, lease.kind, lease.token, lease.manual),
        )
    return status if updated.rowcount else None


def has_delivery_lease(connection, lease, tenant, task_id, operation_id, kind):
    """Check a lease's exact binding and deadline before scheduled I/O."""
    if not isinstance(lease, Lease) or (lease.tenant, lease.task_id, lease.operation_id, lease.kind) != (
        tenant, task_id, operation_id, kind
    ):
        return False
    return connection.execute(
        """SELECT 1 FROM p4_delivery_jobs
           WHERE tenant = ? AND task_id = ? AND operation_id = ? AND kind = ? AND scope = ?
             AND status = 'leased' AND lease_token = ? AND lease_manual = ? AND lease_expires_at > clock_timestamp()""",
        (tenant, task_id, operation_id, kind, lease.scope, lease.token, lease.manual),
    ).fetchone() is not None


def delivery_status(connection, tenant, operation_id, kind):
    """Return bounded scheduling metadata without exposing lease tokens."""
    _job_scope(tenant, kind)
    row = connection.execute(
        """SELECT status, attempts, max_attempts, next_attempt_at, last_error
           FROM p4_delivery_jobs WHERE tenant = ? AND operation_id = ? AND kind = ?""",
        (tenant, operation_id, kind),
    ).fetchone()
    if row is None:
        return None
    return {
        "status": row["status"], "attempts": row["attempts"], "max_attempts": row["max_attempts"],
        "next_attempt_at": row["next_attempt_at"].isoformat(), "last_error": row["last_error"],
    }


def run_delivery_batch(store, tenant, kind, handler, *, limit=10, **claim_options):
    """Run a bounded set of short jobs without holding transactions across network or disk operations."""
    if ("manual_operation_id" in claim_options or not callable(handler)
            or not _integer(limit, 1, 100)):
        raise ValueError("Expected a delivery handler and a batch limit between 1 and 100")
    results = []
    for _ in range(limit):
        lease = claim_delivery(store, tenant, kind, **claim_options)
        if lease is None:
            break
        try:
            outcome = handler(lease)
        except (OSError, ValueError, LookupError):
            outcome = "retry"
        status = finish_delivery(store, lease, outcome, base_seconds=claim_options.get("base_seconds", 2),
                                 max_delay=claim_options.get("max_delay", 300))
        results.append({"operation_id": lease.operation_id, "status": status or "lease_lost"})
    return results


class ProofUnavailable(OSError):
    """A referenced proof cannot currently be read with intact bytes."""


def _proof_scope(tenant, kind):
    if not _identifier(tenant) or kind not in _PROOFS:
        raise ValueError("Expected a tenant and a source receipt or runtime attestation kind")


def _proof_bytes(document):
    if type(document) is not dict:
        raise ValueError("Evidence must be a JSON object")
    raw = encode(document).encode("utf-8")
    if len(raw) > _MAX_PROOF_BYTES:
        raise ValueError("Evidence exceeds the archive size limit")
    return raw


def _blob_digest(raw):
    return sha256(raw).hexdigest()


class ProofStore:
    """Local content-addressed files with independent raw and redacted namespaces."""

    def __init__(self, root):
        self.root = Path(root).absolute()
        self.root.mkdir(parents=True, mode=0o700, exist_ok=True)

    @contextmanager
    def _folder(self, tenant, view, *, create=False):
        if not _identifier(tenant) or view not in _VIEWS:
            raise ValueError("Invalid proof folder")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        descriptors = []
        try:
            descriptors.append(os.open(self.root, flags))
            for item in (_blob_digest(tenant.encode("utf-8")), view):
                parent = descriptors[-1]
                if create:
                    try:
                        os.mkdir(item, mode=0o700, dir_fd=parent)
                    except FileExistsError:
                        pass
                    else:
                        os.fsync(parent)
                descriptors.append(os.open(item, flags, dir_fd=parent))
            yield descriptors[-1]
        except OSError as exc:
            if isinstance(exc, ProofUnavailable):
                raise
            raise ProofUnavailable("Evidence archive I/O failed") from None
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)

    @staticmethod
    def _read_file(folder, digest):
        name = f"{digest}.json"
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        try:
            descriptor = os.open(name, flags, dir_fd=folder)
        except OSError:
            raise ProofUnavailable("Evidence file is unavailable") from None
        with os.fdopen(descriptor, "rb") as file:
            meta = os.fstat(file.fileno())
            if not stat.S_ISREG(meta.st_mode) or meta.st_size > _MAX_PROOF_BYTES:
                raise ProofUnavailable("Evidence file is invalid")
            content = file.read(_MAX_PROOF_BYTES + 1)
        if len(content) > _MAX_PROOF_BYTES or _blob_digest(content) != digest:
            raise ProofUnavailable("Evidence file failed integrity verification")
        return content

    def read(self, tenant, view, digest):
        if type(digest) is not str or _HEX.fullmatch(digest) is None:
            raise ValueError("Expected a SHA-256 proof digest")
        with self._folder(tenant, view) as folder:
            return self._read_file(folder, digest)

    def put(self, tenant, view, raw, *, repair=False):
        if type(raw) is not bytes or len(raw) > _MAX_PROOF_BYTES:
            raise ValueError("Invalid evidence bytes")
        digest = _blob_digest(raw)
        filename = f"{digest}.json"
        temp = f".pending-{token_hex(24)}"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        with self._folder(tenant, view, create=True) as folder:
            try:
                self._read_file(folder, digest)
            except ProofUnavailable:
                pass
            else:
                return digest
            descriptor = os.open(temp, flags, 0o600, dir_fd=folder)
            try:
                with os.fdopen(descriptor, "wb") as file:
                    file.write(raw)
                    file.flush()
                    os.fsync(file.fileno())
                if repair:
                    os.replace(temp, filename, src_dir_fd=folder, dst_dir_fd=folder)
                else:
                    try:
                        os.link(temp, filename, src_dir_fd=folder, dst_dir_fd=folder, follow_symlinks=False)
                    except FileExistsError:
                        pass
                os.fsync(folder)
                self._read_file(folder, digest)
            finally:
                try:
                    os.unlink(temp, dir_fd=folder)
                except FileNotFoundError:
                    pass
        return digest


def publish_proof(store, archive, *, tenant, task_id, operation_id, kind, raw, redacted):
    """Publish already verified evidence after hashing and reading back both files."""
    _proof_scope(tenant, kind)
    if not all(map(_identifier, (task_id, operation_id))):
        raise ValueError("Invalid evidence operation")
    content, summary = _proof_bytes(raw), _proof_bytes(redacted)
    raw_digest = archive.put(tenant, "raw", content, repair=True)
    redacted_digest = archive.put(tenant, "redacted", summary, repair=True)
    with store.transaction(tenant=tenant, write=True) as connection:
        connection.execute(
            """INSERT INTO p4_proof_records (tenant, task_id, operation_id, kind, raw_digest, redacted_digest,
                                            raw_document, redacted_document)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING""",
            (tenant, task_id, operation_id, kind, raw_digest, redacted_digest,
             content.decode("utf-8"), summary.decode("utf-8")),
        )
        prior = connection.execute(
            """SELECT task_id, raw_digest, redacted_digest FROM p4_proof_records
               WHERE tenant = ? AND operation_id = ? AND kind = ?""", (tenant, operation_id, kind),
        ).fetchone()
        if prior is None or tuple(prior) != (task_id, raw_digest, redacted_digest):
            raise ValueError("Evidence operation already points to different files")
    return {"raw_digest": raw_digest, "redacted_digest": redacted_digest}


def _checked_view(tenant, kind, view):
    _proof_scope(tenant, kind)
    if view not in _VIEWS:
        raise ValueError("Invalid evidence view")


def read_proof(store, archive, tenant, operation_id, kind, *, view="redacted"):
    """Read the requested reference without silently hiding lost or damaged files."""
    _checked_view(tenant, kind, view)
    with store.transaction(tenant=tenant) as connection:
        row = connection.execute(
            f"SELECT {view}_digest FROM p4_proof_records WHERE tenant = ? AND operation_id = ? AND kind = ?",
            (tenant, operation_id, kind),
        ).fetchone()
    if row is None:
        raise LookupError("Evidence was not published")
    return json.loads(archive.read(tenant, view, row[0]))


def repair_proof(store, archive, tenant, operation_id, kind, *, view="redacted"):
    """Rebuild one referenced file from the exact canonical PostgreSQL bytes."""
    _checked_view(tenant, kind, view)
    with store.transaction(tenant=tenant) as connection:
        row = connection.execute(
            f"""SELECT {view}_digest, {view}_document FROM p4_proof_records
               WHERE tenant = ? AND operation_id = ? AND kind = ?""", (tenant, operation_id, kind),
        ).fetchone()
    if row is None:
        raise LookupError("Evidence was not published")
    document = row[1].encode("utf-8")
    if _blob_digest(document) != row[0]:
        raise ProofUnavailable("Evidence backup failed integrity verification")
    archive.put(tenant, view, document, repair=True)
    return row[0]


def deliver_attestation(store, archive, tenant, task_id, operation_id, signer, trusted_keys, *, archive_store=None):
    """Resume P3 attestation and archive its already verified envelope."""
    from .evidence import deliver_effect

    result = deliver_effect(store, tenant, operation_id, signer, trusted_keys)
    if result["status"] != "delivered":
        return "retry"
    proof = result["proof"]
    redact = {name: proof["payload"][name] for name in
              ("profile", "tenant", "task_id", "operation_id", "observation", "result_digest", "recorded_at")}
    redact["proof_digest"] = proof["digest"]
    publish_proof(store if archive_store is None else archive_store, archive, tenant=tenant, task_id=task_id,
                  operation_id=operation_id, kind="runtime_attestation", raw=proof, redacted=redact)
    return "done"
