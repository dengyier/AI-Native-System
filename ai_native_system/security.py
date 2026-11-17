"""Durable, tenant-scoped authorization for OpenWorkProof-managed actions."""

import json
from dataclasses import dataclass
from enum import StrEnum

from .fact_contracts import canonical_json


class Verdict(StrEnum):
    ALLOW = "allow"
    DENY = "deny"
    MANUAL = "manual"


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    reason: str
    authorization_digest: str | None = None

    @property
    def allowed(self):
        return self.verdict == Verdict.ALLOW


def _label(value, *, limit=512):
    return type(value) is str and bool(value.strip()) and len(value) <= limit and all(
        0x20 <= ord(character) != 0x7F for character in value
    )


def _tenant_write_lock(connection, tenant):
    from .adapters.postgres_runtime import _tenant_lock

    connection.execute("SELECT pg_advisory_xact_lock(?::bigint)", (_tenant_lock(tenant),))


class AuthorizationLedger:
    """Check grants and consume nonces using the same transaction as effect registration.

    Epoch and verifier come from trusted deployment configuration. Change the
    externally managed epoch when restoring an older snapshot, before opening
    it to runtime writers. Detached signing remains outside the ledger.
    """

    def __init__(self, epoch, verify):
        if not _label(epoch) or not callable(verify):
            raise ValueError("Configure a deployment epoch and a trusted authorization verifier")
        self.epoch = epoch
        self._verify = verify

    def admit(self, connection, tenant, task_id):
        """Admit a newly created managed task, using its creation transaction."""
        _tenant_write_lock(connection, tenant)
        connection.execute(
            """INSERT INTO owp_task_admissions (tenant, task_id, epoch)
               VALUES (?, ?, ?) ON CONFLICT DO NOTHING""",
            (tenant, task_id, self.epoch),
        )
        return self.eligible(connection, tenant, task_id)

    def eligible(self, connection, tenant, task_id):
        row = connection.execute(
            "SELECT epoch FROM owp_task_admissions WHERE tenant = ? AND task_id = ?", (tenant, task_id),
        ).fetchone()
        return row is not None and row["epoch"] == self.epoch

    @staticmethod
    def _registered(connection, tenant, operation_id):
        return connection.execute(
            "SELECT * FROM owp_authorizations WHERE tenant = ? AND operation_id = ?", (tenant, operation_id),
        ).fetchone()

    @staticmethod
    def _revoked(connection, tenant, operation_id):
        return connection.execute(
            "SELECT 1 FROM owp_revocations WHERE tenant = ? AND operation_id = ?", (tenant, operation_id),
        ).fetchone() is not None

    @staticmethod
    def _consumed(connection, tenant, operation_id):
        return connection.execute(
            """SELECT authorization_digest, request_digest, remote FROM owp_consumptions
               WHERE tenant = ? AND operation_id = ?""", (tenant, operation_id),
        ).fetchone()

    @staticmethod
    def _approved(connection, scope):
        row = connection.execute(
            """SELECT t.status, t.requester, t.approver, t.approval_hash, g.requester_context,
                      g.approver_context, g.release_digest
               FROM tasks t JOIN task_governance g ON (t.tenant, t.id) = (g.tenant, g.task_id)
               WHERE t.tenant = ? AND t.id = ?""",
            (scope["tenant"], scope["task_id"]),
        ).fetchone()
        if row is None or row["status"] not in ("ready", "reconciling") or row["approver_context"] is None:
            return False
        return (
            row["requester"] == scope["requester"]["actor"]
            and row["approver"] == scope["approver"]["actor"]
            and row["approval_hash"] == scope["approval_digest"]
            and row["release_digest"] == scope["release_digest"]
            and canonical_json(json.loads(row["requester_context"])) == canonical_json(scope["requester"])
            and canonical_json(json.loads(row["approver_context"])) == canonical_json(scope["approver"])
        )

    def _validate(self, connection, envelope, expected_scope, *, registered=None):
        try:
            claims = self._verify(envelope)
            scope = claims["scope"]
            if canonical_json(scope) != canonical_json(expected_scope):
                return Decision(Verdict.DENY, "scope_changed"), None
            if registered is not None and (
                registered["authorization_digest"] != envelope["digest"]
                or registered["request_digest"] != scope["parameters_digest"]
                or registered["nonce"] != claims["nonce"]
                or registered["epoch"] != claims["epoch"]
                or registered["task_id"] != scope["task_id"]
                or registered["issued_at"] != claims["issued_at"]
                or registered["expires_at"] != claims["expires_at"]
            ):
                return Decision(Verdict.DENY, "ledger_binding_changed"), None
            if claims["epoch"] != self.epoch or not self.eligible(connection, scope["tenant"], scope["task_id"]):
                return Decision(Verdict.DENY, "restore_epoch_changed"), None
            now = connection.database_time()
            if not claims["issued_at"] <= now < claims["expires_at"]:
                return Decision(Verdict.DENY, "authorization_outside_validity"), None
            if not self._approved(connection, scope):
                return Decision(Verdict.DENY, "approval_binding_changed"), None
        except (KeyError, TypeError, ValueError):
            return Decision(Verdict.DENY, "invalid_authorization"), None
        return Decision(Verdict.ALLOW, "authorized", envelope["digest"]), claims

    def issue(self, connection, envelope, expected_scope):
        """Register a signed approval from the trusted issuance channel."""
        tenant, operation_id = expected_scope["tenant"], expected_scope["operation_id"]
        _tenant_write_lock(connection, tenant)
        if self._revoked(connection, tenant, operation_id):
            return Decision(Verdict.DENY, "authorization_revoked")
        decision, claims = self._validate(connection, envelope, expected_scope)
        if not decision.allowed:
            return decision
        inserted = connection.execute(
            """INSERT INTO owp_authorizations
               (tenant,operation_id,task_id,epoch,nonce,authorization_digest,request_digest,issued_at,expires_at,envelope)
               VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT DO NOTHING""",
            (tenant, operation_id, expected_scope["task_id"], self.epoch, claims["nonce"],
             decision.authorization_digest, expected_scope["parameters_digest"], claims["issued_at"], claims["expires_at"],
             canonical_json(envelope)),
        )
        if inserted.rowcount:
            return decision
        previous = self._registered(connection, tenant, operation_id)
        if previous is not None and previous["envelope"] == canonical_json(envelope):
            return decision
        return Decision(Verdict.DENY, "operation_or_nonce_already_registered")

    def check(self, connection, tenant, operation_id, scope):
        """Evaluate the exact signed scope under the current trusted keys and primary database clock."""
        if (scope.get("tenant"), scope.get("operation_id")) != (tenant, operation_id):
            return Decision(Verdict.DENY, "scope_changed")
        if not self.eligible(connection, tenant, scope["task_id"]):
            return Decision(Verdict.DENY, "restore_epoch_changed")
        row = self._registered(connection, tenant, operation_id)
        if row is None:
            return Decision(Verdict.MANUAL, "authorization_required")
        if self._revoked(connection, tenant, operation_id):
            return Decision(Verdict.DENY, "authorization_revoked")
        consumption = self._consumed(connection, tenant, operation_id)
        if consumption is not None:
            verdict = Verdict.MANUAL if consumption["remote"] else Verdict.DENY
            return Decision(verdict, "lookup_only" if consumption["remote"] else "nonce_already_consumed",
                            consumption["authorization_digest"])
        try:
            envelope = json.loads(row["envelope"])
        except (TypeError, ValueError):
            return Decision(Verdict.DENY, "invalid_authorization")
        decision, _ = self._validate(connection, envelope, scope, registered=row)
        return decision

    def consume(self, connection, tenant, operation_id, scope, *, remote=False, request_digest=None):
        """Consume the nonce once. A remote consumption commits before network delivery."""
        _tenant_write_lock(connection, tenant)
        if type(remote) is not bool or remote != (scope.get("action_kind") == "write_remote"):
            return Decision(Verdict.DENY, "dispatch_mode_changed")
        expected_request = scope.get("parameters_digest")
        if expected_request is None or (request_digest is not None and request_digest != expected_request):
            return Decision(Verdict.DENY, "request_digest_changed")
        decision = self.check(connection, tenant, operation_id, scope)
        if not decision.allowed:
            return decision
        result = connection.execute(
            """INSERT INTO owp_consumptions (tenant,operation_id,nonce,authorization_digest,request_digest,remote)
               SELECT tenant,operation_id,nonce,authorization_digest,request_digest,?
               FROM owp_authorizations WHERE tenant = ? AND operation_id = ?
               ON CONFLICT DO NOTHING""",
            (remote, tenant, operation_id),
        )
        return decision if result.rowcount else Decision(Verdict.DENY, "nonce_already_consumed")

    def recover(self, connection, tenant, operation_id, request_digest):
        """Authorize looking up exactly one previously dispatched remote request."""
        consumption = self._consumed(connection, tenant, operation_id)
        if consumption is None or not consumption["remote"] or consumption["request_digest"] != request_digest:
            return Decision(Verdict.DENY, "remote_binding_missing")
        return Decision(Verdict.ALLOW, "lookup_only", consumption["authorization_digest"])

    @staticmethod
    def authorization_digest(connection, tenant, operation_id):
        """Read the digest tied to an already committed dispatch, for internal evidence."""
        row = AuthorizationLedger._consumed(connection, tenant, operation_id)
        return row["authorization_digest"] if row is not None else None

    def revoke(self, connection, tenant, operation_id, *, actor, reason):
        if not _label(actor) or not _label(reason, limit=2048):
            raise ValueError("Revocation requires an operator and a reason")
        _tenant_write_lock(connection, tenant)
        if self._registered(connection, tenant, operation_id) is None:
            return False
        result = connection.execute(
            """INSERT INTO owp_revocations (tenant,operation_id,actor,reason)
               VALUES (?,?,?,?) ON CONFLICT DO NOTHING""", (tenant, operation_id, actor, reason),
        )
        return bool(result.rowcount)
