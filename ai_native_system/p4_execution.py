"""Validate signed source results and complete recovery without dispatching writes."""

from .delivery import enqueue_delivery, has_delivery_lease, publish_proof, deliver_attestation
from .evidence import enqueue_effect
from .fact_feedback import receipt as record_feedback
from .storage import audit, database, digest, encode, object_data, task_data


def delivery_scope(identity):
    return digest({"endpoint": identity.get("endpoint"), "launch": identity.get("launch_digest")})


def has_reconcile_lease(connection, lease, task):
    return has_delivery_lease(connection, lease, task["tenant"], task["id"], task["id"], "reconcile")


def record_source_response(connection, task, op, payload, envelope, authorization, tool, mode):
    tenant, task_id = task["tenant"], task["id"]
    try:
        receipt = tool.source.verify(envelope, payload, authorization.authorization_digest)
    except (TypeError, ValueError, KeyError):
        connection.execute("UPDATE remote_operations SET status='unknown' WHERE operation_id=?", (task_id,))
        audit(connection, task_id, "source.receipt_invalid", phase=mode)
        return task_data(connection, tenant, task_id)

    status = receipt["status"]
    connection.execute("UPDATE remote_operations SET status=?, response=? WHERE operation_id=?",
                       (status, encode(envelope), task_id))
    audit(connection, task_id, "source.receipt", remote_status=status, phase=mode,
          receipt_digest=envelope["digest"])
    if status == "not_found":
        return task_data(connection, tenant, task_id)

    if status == "rejected":
        record_feedback(connection, payload, status)
        connection.execute("UPDATE tasks SET status='failed' WHERE id=?", (task_id,))
    else:
        result = receipt["result"]["objects"]
        primary = next(item for item in result if item["id"] == payload["object_id"])
        shadow = object_data(connection, tenant, payload["object_id"])
        aligned = False
        # Legacy shadow versions are internal revision counters. Opaque native
        # versions are retained verbatim in the receipt and synchronization proof.
        if len(result) == 1 and shadow is not None:
            aligned = ((shadow["state"], shadow["version"]) ==
                       (payload["from_state"], payload["expected_version"]))
            if aligned:
                connection.execute(
                    "UPDATE objects SET state=?, version=? WHERE tenant=? AND id=?",
                    (primary["state"], payload["expected_version"] + 1, tenant, payload["object_id"]),
                )
        effects = {"objects": result, "source_receipt_digest": envelope["digest"], "projection_aligned": aligned}
        connection.execute("INSERT INTO effects VALUES (?, ?, ?, ?)",
                           (task_id, payload["action"], payload["object_id"], encode(effects)))
        record_feedback(connection, payload, status, source_version=primary["version"])
        enqueue_effect(connection, tenant=tenant, task_id=task_id, operation_id=task_id,
                       authorization_digest=authorization.authorization_digest, result=effects,
                       observation="remote_receipt_observed")
        state = "completed" if aligned else "reconciliation_conflict"
        connection.execute("UPDATE tasks SET status=? WHERE id=?", (state, task_id))
        audit(connection, task_id, "source.confirmed", projection_state=state, operation_id=task_id)
    enqueue_delivery(connection, tenant=tenant, task_id=task_id, operation_id=task_id,
                     kind="evidence", scope=delivery_scope(op["adapter_identity"]))
    return task_data(connection, tenant, task_id)


def reconcile_job(runtime, lease):
    task = runtime.reconcile(lease.tenant, lease.task_id, delivery_lease=lease)
    return "retry" if task["status"] == "reconciling" else "done"


def evidence_job(runtime, store, archive, lease, signer, keys, *, attester_store=None):
    from .remote_execution import _ledger_for, operation, tool_for

    tenant, task_id, operation_id = lease.tenant, lease.task_id, lease.operation_id
    with database(runtime.path, tenant=tenant) as connection:
        task = task_data(connection, tenant, task_id)
        op = operation(connection, task_id)
        if op is None or op["status"] not in ("succeeded", "rejected"):
            return "manual"
        tool = tool_for(runtime, op, connection, task)
        if tool.source is None:
            return "manual"
        payload = op["payload"]
        ledger = _ledger_for(runtime, connection, task, payload)
        access = ledger.recover(connection, tenant, operation_id, payload["request_hash"])
        if not access.allowed:
            return "manual"
        envelope = op["response"]
        receipt = tool.source.verify(envelope, payload, access.authorization_digest)
        if receipt["status"] != op["status"]:
            return "manual"
    redacted = {name: receipt[name] for name in (
        "profile", "source", "operation_id", "status", "recorded_at", "retain_until",
    )}
    redacted["receipt_digest"] = envelope["digest"]
    publish_proof(store, archive, tenant=tenant, task_id=task_id, operation_id=operation_id,
                  kind="source_receipt", raw=envelope, redacted=redacted)
    if receipt["status"] == "rejected":
        return "done"
    if signer is None:
        return "retry"
    return deliver_attestation(attester_store or store, archive, tenant, task_id, operation_id, signer, keys,
                               archive_store=store)
