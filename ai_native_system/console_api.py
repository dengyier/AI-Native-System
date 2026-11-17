"""Permissioned operational views over the existing application authority."""

import base64
import binascii
import json
import re
from datetime import datetime, timezone
from urllib.parse import parse_qs

from . import governance
from .policy import Policy
from .storage import audit, database, digest, encode, object_data, row_data


_EVENT_KEYS = {
    "request.accepted": (), "request.blocked": (), "release.bound": (), "tool.read": ("stage",),
    "model.started": ("stage",), "model.completed": ("elapsed_ms", "input_tokens", "output_tokens"),
    "model.failed": ("elapsed_ms",), "model.discarded": (), "handoff.received": (),
    "stage.recorded": ("stage", "status"), "approval.recorded": ("verdict",), "approval.blocked": (),
    "policy.allowed": (), "policy.blocked": (), "task.cancelled": (), "cancel.deferred": (),
    "tool.committed": (), "tool.timeout": (), "remote.prepared": (), "remote.dispatched": (),
    "remote.dispatch_skipped": (), "remote.receipt": ("remote_status",), "remote.receipt_invalid": (),
    "remote.confirmed": ("projection_state",), "remote.unknown": (), "remote.retry_authorized": (),
    "source.receipt": ("remote_status",), "handover.recorded": ("verdict",),
}
_SAFE_STATES = frozenset({"planning", "awaiting_approval", "ready", "completed", "no_action", "cancelled",
                          "rejected", "blocked", "failed", "reconciling", "reconciliation_conflict", "pending",
                          "succeeded", "not_found", "approve", "reject", "accept"})


def _cursor(task_id, position):
    return base64.urlsafe_b64encode(encode([task_id, position]).encode()).decode().rstrip("=")


def _page(query, task_id):
    values = parse_qs(query, keep_blank_values=True, strict_parsing=True, max_num_fields=2)
    if values.keys() - {"limit", "cursor"} or any(len(value) != 1 for value in values.values()):
        raise ValueError("Invalid event query")
    limit = int(values.get("limit", [50])[0])
    if not 1 <= limit <= 100:
        raise ValueError("Events limit must be 1–100")
    raw = values.get("cursor", [None])[0]
    if raw is None:
        return limit, 0
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,512}", raw):
        raise ValueError("Invalid event cursor")
    try:
        target, position = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
    except (UnicodeError, ValueError, TypeError, binascii.Error):
        raise ValueError("Invalid event cursor") from None
    if target != task_id or type(position) is not int or not 1 <= position <= 2**63 - 1 or raw != _cursor(target, position):
        raise ValueError("Invalid event cursor")
    return limit, position


def _public_event(row):
    name = row["event"]
    raw = row_data(row, "detail")["detail"]
    detail = {}
    if isinstance(raw, dict):
        for field in _EVENT_KEYS.get(name, ()):
            value = raw.get(field)
            if (type(value) is int and 0 <= value <= 2**63 - 1) or (type(value) is str and value in _SAFE_STATES):
                detail[field] = value
    timestamp = str(row["time"])
    if not re.fullmatch(r"[\dTZ:+. -]{10,40}", timestamp):
        timestamp = None
    return {"sequence": row["task_sequence"], "time": timestamp,
            "event": name if name in _EVENT_KEYS else "internal.event", "detail": detail}


class ConsoleOperations:
    def __init__(self, runtime, *, control=None, delivery=None, attestation_keys=None, embedding=None):
        self.runtime = runtime
        self.control = control
        self.delivery = delivery
        self.attestation_keys = dict(attestation_keys or {})
        self.embedding = embedding
        self.policy = Policy()

    def events(self, identity, task_id, query):
        limit, after = _page(query, task_id)
        with database(self.runtime.path, tenant=identity.tenant) as connection:
            governance.read_task(connection, identity.tenant, task_id, identity, "read")
            rows = connection.execute("""SELECT task_sequence,time,event,detail FROM events
                WHERE task_id=? AND task_sequence>? ORDER BY task_sequence LIMIT ?""",
                (task_id, after, limit + 1)).fetchall()
        events = [_public_event(row) for row in rows[:limit]]
        position = events[-1]["sequence"] if events else after
        return {"events": events, "next_cursor": _cursor(task_id, position) if position else None,
                "has_more": len(rows) > limit}

    def task(self, identity, task_id):
        result = self.runtime.inspect(identity.tenant, task_id, identity=identity)
        tenant = identity.tenant
        with database(self.runtime.path, tenant=tenant) as connection:
            task = governance.read_task(connection, tenant, task_id, identity, "read")
            # If authority advanced concurrently, discard a review belonging to the previous state.
            if task["status"] != result["status"]:
                result = {"id": task_id, "status": task["status"]}
            result.update(next_stage=task["next_stage"], deadline=task.get("graph_deadline"))
            if self.policy.permits(connection, identity, "read", "app", task["application"]):
                result["application"] = task["application"]
            operations = {"planning": ("advance", "cancel"), "awaiting_approval": ("cancel", "approve"),
                          "ready": ("advance", "cancel"), "reconciling": ("reconcile", "review"),
                          "reconciliation_conflict": ("review",)}
            result["available_actions"] = [operation for operation in operations.get(task["status"], ())
                                           if (operation != "cancel" or identity.actor == task["requester"])
                                           and (operation != "approve" or (result.get("review") and identity.service is None
                                                                          and identity.actor != task["requester"]))
                                           and self.policy.permits(connection, identity, operation, "task", task_id)]
            if self.policy.permits(connection, identity, "export", "evidence", task_id):
                result["available_actions"].append("evidence")
            if "approve" not in result["available_actions"]:
                result.pop("review", None)
            if result.get("review"):
                definition = self.runtime._definition(connection, task)
                if definition is None:
                    result.pop("review", None)
                    result["available_actions"].remove("approve")
                    return result
                reason, ground = self.runtime._ground(connection, task, definition, reviewer=identity)
                if reason or digest(ground) != task["grounding_hash"]:
                    result.pop("review", None)
                    result["available_actions"].remove("approve")
                    return result
                rule = ground.get("_owp_rule", {})
                from .owp_gate import read_scope

                resources = read_scope({**ground, "_owp_rule": {"resources": rule.get("resources", [])}})
                # The same authorization checks that built the review determine which resources appear here.
                result["review"]["scope"] = {"resources": resources, "rule_versions": rule.get("versions", {}),
                                              "parameters": {"object_id": task["object_id"],
                                                             "object_version": ground["object"]["version"],
                                                             "from_state": definition.action["from_state"],
                                                             "to_state": definition.action["to_state"]},
                                              "expires_at": task.get("graph_deadline")}
        return result

    def evidence(self, identity, task_id):
        result = self.runtime.inspect(identity.tenant, task_id, identity=identity, evidence=True)
        tenant = identity.tenant
        with database(self.runtime.path, tenant=tenant) as connection:
            task = governance.read_task(connection, tenant, task_id, identity, "read")
            self.policy.require(connection, identity, "export", "evidence", task_id)
            from .remote_execution import operation, tool_for

            current = operation(connection, task_id)
            proof = connection.execute("""SELECT authorization_digest,signed_document FROM owp_effect_evidence
                WHERE tenant=? AND operation_id=?""", (tenant, task_id)).fetchone()
            keys = self.attestation_keys.get(tenant, {})
            result["verification"] = "not_available"
            if proof:
                result["verification"] = "pending" if proof["signed_document"] is None else "recorded"
                if proof["signed_document"] and keys:
                    from .evidence import verify_effect

                    try:
                        signed = verify_effect(json.loads(proof["signed_document"]), keys)
                        if (signed["authorization_digest"] != proof["authorization_digest"]
                                or signed["operation_id"] != task_id or signed["tenant"] != tenant):
                            raise ValueError("The attestation has a different operation binding")
                        result["verification"] = "verified"
                    except (ValueError, TypeError, KeyError):
                        result["verification"] = "invalid"
            if current is not None and isinstance(current["response"], dict):
                try:
                    target = tool_for(self.runtime, current, connection, task)
                    if target.source is not None:
                        consumed = connection.execute("""SELECT authorization_digest FROM owp_consumptions
                            WHERE tenant=? AND operation_id=?""", (tenant, task_id)).fetchone()
                        if consumed is None:
                            raise ValueError("The source operation lacks its original authorization binding")
                        receipt = target.source.verify(current["response"], current["payload"], consumed["authorization_digest"])
                        result["receipt"] = {"operation_id": task_id, "status": receipt["status"],
                                             "digest": digest(current["response"]), "verification": "verified"}
                    elif current["status"] in ("succeeded", "rejected"):
                        result["receipt"] = {"operation_id": task_id, "status": current["status"],
                                             "digest": digest(current["response"]), "verification": "recorded"}
                except (ValueError, TypeError, PermissionError, KeyError):
                    result["receipt"] = {"operation_id": task_id, "verification": "unavailable"}
            if self.policy.permits(connection, identity, "review", "task", task_id):
                result["handover"] = self._assessment(connection, identity, task, current)
        return result

    def _assessment(self, connection, identity, task, operation):
        tenant, task_id = identity.tenant, task["id"]
        remote_status = operation["status"] if operation is not None else None
        pending = task["status"] == "reconciling" and remote_status in ("dispatched", "unknown", "pending", "not_found")
        fingerprint = digest((tenant, task_id, task["status"], remote_status,
                              operation["payload"]["request_hash"] if operation else None,
                              operation["attempts"] if operation else None,
                              operation["response"] if operation else None))
        row = connection.execute("""SELECT verdict,reason,recorded_at,assessment_digest FROM task_handover
            WHERE tenant=? AND task_id=? ORDER BY recorded_at DESC, assessment_digest LIMIT 1""",
            (tenant, task_id)).fetchone()
        decision = None if row is None else {"verdict": row["verdict"], "reason": row["reason"],
                                             "recorded_at": row["recorded_at"].isoformat(),
                                             "current": row["assessment_digest"] == fingerprint}
        return {"assessment_digest": fingerprint, "remote_status": remote_status,
                "decision": decision, "eligible": pending or task["status"] == "reconciliation_conflict"}

    def handover(self, identity, task_id, body=None):
        tenant = identity.tenant
        with database(self.runtime.path, tenant=tenant, write=body is not None) as connection:
            task = governance.read_task(connection, tenant, task_id, identity, "review")
            from .remote_execution import operation

            current = operation(connection, task_id)
            assessment = self._assessment(connection, identity, task, current)
            if body is None:
                return assessment
            if (set(body) != {"verdict", "assessment_digest", "reason"} or body["verdict"] not in ("accept", "reject")
                    or type(body["reason"]) is not str or not 1 <= len(body["reason"].strip()) <= 300
                    or identity.service is not None or identity.actor == task["requester"]):
                raise ValueError("An independent human decision and a reason are required")
            prior = connection.execute("""SELECT actor,verdict,reason FROM task_handover
                WHERE tenant=? AND task_id=? AND assessment_digest=?""",
                (tenant, task_id, body["assessment_digest"])).fetchone()
            values = (identity.actor, body["verdict"], body["reason"].strip())
            if prior is not None:
                if tuple(prior) != values:
                    raise ValueError("A different assessment decision is already recorded")
                return assessment
            if not assessment["eligible"] or assessment["assessment_digest"] != body["assessment_digest"]:
                raise ValueError("The current operation assessment has changed")
            connection.execute("""INSERT INTO task_handover (tenant,task_id,assessment_digest,actor,verdict,reason)
                VALUES (?,?,?,?,?,?)""", (tenant, task_id, body["assessment_digest"], *values))
            audit(connection, task_id, "handover.recorded", verdict=body["verdict"])
            return self._assessment(connection, identity, task, current)

    def reconcile(self, identity, task_id):
        tenant = identity.tenant
        task = self.runtime.reconcile(tenant, task_id, identity=identity, worker=False)
        if self.delivery is None or task.get("authorization", {}).get("reason") != "reconciliation_queued":
            return task
        from .delivery import claim_delivery, finish_delivery

        lease = claim_delivery(self.delivery, tenant, "reconcile", manual_operation_id=task_id)
        if lease is None:
            return task
        outcome = "manual"
        try:
            resolved = self.runtime.reconcile(tenant, task_id, identity=identity, worker=False, delivery_lease=lease)
            if resolved["status"] != "reconciling":
                outcome = "done"
            return resolved
        finally:
            finish_delivery(self.delivery, lease, outcome)

    def facts(self, identity, body):
        if set(body) != {"object_type", "object_id", "field"}:
            raise ValueError("Select exactly one fact field")
        from .fact_contracts import FactField, ObjectIdentity
        from .facts import Facts

        tenant = identity.tenant
        target = ObjectIdentity(tenant, body["object_type"], body["object_id"])
        field = FactField(target, body["field"])
        with database(self.runtime.path, tenant=tenant) as connection:
            self.policy.require(connection, identity, "read", "object", target.object_id)
            if field.name in ("$state", "$exists"):
                self.policy.require(connection, identity, "read", "metadata", target.object_id, field.name[1:])
            else:
                self.policy.require(connection, identity, "read", "field", target.object_id, field.name)
            item = object_data(connection, tenant, target.object_id)
            if item is None or item["type"] != target.object_type:
                raise LookupError("Fact object is unavailable")
            now = datetime.fromtimestamp(connection.database_time(), timezone.utc)
            current = Facts(self.runtime.path, tenant).read_fact(connection, field, as_of=now, known_at=now)
        deadlines = [read.fresh_until for read in current.reads if read.fresh_until is not None]
        return {"status": current.reason, "coverage": current.coverage.value, "known": current.available or current.deleted,
                "present": current.available and not current.deleted, "conflicts": len(current.conflicts),
                "fresh_until": min(deadlines).isoformat() if deadlines else None,
                **({"value": current.value} if current.available else {})}

    def release(self, identity, method, target, operation, body):
        from .releases import ReleaseSnapshot, ReleaseStore

        tenant = identity.tenant
        if method == "POST" and self.control is None:
            raise PermissionError("The release control role is unavailable")
        store = self.control if method == "POST" else self.runtime.path
        with database(store, tenant=tenant, write=method == "POST") as connection:
            if method == "POST" and target == "draft" and operation is None:
                if ("application" not in body or body.keys() - {"application", "ontology", "mapping_version",
                                                               "knowledge_strategy", "owp_profile", "policy_version",
                                                               "retrieval"}):
                    raise ValueError("Invalid release draft")
                self.policy.require(connection, identity, "manage", "app", body["application"])
                options = {key: value for key, value in body.items() if key != "application"}
                if options.get("ontology") is not None:
                    from .ontology import OntologyRelease

                    options["ontology"] = OntologyRelease.from_document(options["ontology"])
                if "retrieval" in options:
                    from .release_control import draft_retrieval_binding

                    retrieval = options["retrieval"]
                    if not isinstance(retrieval, dict) or set(retrieval) != {"index_id", "method"}:
                        raise ValueError("Invalid release retrieval declaration")
                    options["retrieval"] = draft_retrieval_binding(
                        connection, identity, retrieval["index_id"], retrieval["method"])
                snapshot = ReleaseSnapshot.capture(self.runtime.registry, body["application"], self.runtime.model,
                                                   self.runtime.tools, **options)
                return self._release_summary(ReleaseStore.draft(connection, tenant, snapshot, publisher=identity.actor), True)
            record = ReleaseStore.get(connection, tenant, target)
            if record is None:
                raise LookupError("Release unavailable")
            app = record.snapshot.application
            manage = self.policy.permits(connection, identity, "manage", "app", app)
            if method == "GET":
                if body:
                    raise ValueError("Read endpoints accept no body")
                if not manage:
                    self.policy.require(connection, identity, "read", "release", target)
                if operation is None:
                    return self._release_summary(record, manage and self.control is not None)
                if operation == "impact":
                    prior = ReleaseStore._selected(connection, tenant, app)
                    if not manage and prior is not None:
                        self.policy.require(connection, identity, "read", "release", prior)
                    assessment = ReleaseStore.impact(connection, tenant, target)
                    return {key: assessment[key] for key in ("classification", "changes", "bindings")}
                raise LookupError("Unknown release operation")
            if method != "POST" or not manage:
                raise PermissionError("Release management access denied")
            if operation == "publish" and body.keys() <= {"migration_ref"}:
                record = ReleaseStore.publish(connection, tenant, target, publisher=identity.actor,
                                              migration_ref=body.get("migration_ref"),
                                              embedding=self.embedding, identity=identity)
            elif operation == "bind-rule" and "rule_id" in body and body.keys() <= {"rule_id", "feedback_source", "feedback_stream"}:
                from .fact_gate import bind_rule

                return bind_rule(connection, tenant, target, body["rule_id"], actor=identity.actor,
                                 feedback_source=body.get("feedback_source"), feedback_stream=body.get("feedback_stream"))
            elif operation == "select" and not body:
                record = ReleaseStore.select(connection, tenant, app, target, publisher=identity.actor,
                                             embedding=self.embedding, identity=identity)
            elif operation in ("deprecate", "revoke") and not body:
                transition = ReleaseStore.deprecate if operation == "deprecate" else ReleaseStore.revoke
                record = transition(connection, tenant, target, publisher=identity.actor)
            else:
                raise ValueError("Invalid release operation")
            return self._release_summary(record, True)

    @staticmethod
    def _release_summary(record, manage=False):
        snapshot = record.snapshot
        document = snapshot.to_document()
        ontology = document["ontology"]
        return {"digest": snapshot.digest, "application": snapshot.application, "status": record.status,
                "available_actions": {
                    "draft": ["publish", "bind-rule", "revoke"], "published": ["select", "deprecate", "revoke"],
                    "deprecated": ["revoke"],
                }.get(record.status, []) if manage else [],
                "ontology": {"digest": ontology["digest"], "namespace": ontology["definition"]["namespace"],
                             "version": ontology["definition"]["version"]},
                "knowledge_strategy": document["knowledge"]["strategy"], "owp_profile": document["owp"]["profile"]}
