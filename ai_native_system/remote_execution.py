"""Durable remote intent and receipt reconciliation, independent of network transport."""
from time import monotonic

from . import governance
from .storage import audit, database, digest, encode, object_data, row_data, task_data


def build_payload(task, app, action, ground):
    payload = {
        "operation_id": task["id"], "tenant": task["tenant"], "action": app["action"],
        "object_id": task["object_id"], "expected_version": ground["object"]["version"],
        "from_state": action["from_state"], "to_state": action["to_state"],
        "requester": task["requester"], "approver": task["approver"], "executor": app["executor"],
    }
    if task.get("release_digest"):
        payload["release_digest"] = task["release_digest"]
    if ground.get("_p4_source_conditions") is not None:
        payload["source_conditions"] = ground["_p4_source_conditions"]
        payload["action_instance_id"] = f"{task['id']}:action"
    payload["request_hash"] = digest(payload)
    return payload


def prepare(connection, task, app, action, tool, ground):
    payload = build_payload(task, app, action, ground)
    previous = operation(connection, task["id"])
    identity = tool.identity
    if previous is not None:
        if previous["payload"] != payload or previous["adapter_identity"] != identity:
            raise ValueError("Remote intent is already bound to another request or destination")
        return
    connection.execute(
        """INSERT INTO remote_operations
           (operation_id, tool_name, tool_version, adapter_identity, payload, status)
           VALUES (?, ?, ?, ?, ?, 'prepared')""",
        (task["id"], tool.name, tool.version, encode(identity), encode(payload)),
    )
    if task.get("release_digest"):
        from .fact_feedback import expect
        from .fact_gate import binding_for

        rule = binding_for(connection, task["tenant"], task["release_digest"])
        expect(connection, payload, ground["object"]["type"], rule)
    audit(connection, task["id"], "remote.prepared", request_hash=payload["request_hash"],
          tool=tool.name, version=tool.version)


def operation(connection, task_id):
    return row_data(connection.execute(
        "SELECT * FROM remote_operations WHERE operation_id = ?", (task_id,)
    ).fetchone(), "payload", "response", "adapter_identity")


def _bound_payload(op, task):
    payload = op["payload"]
    if ((payload.get("tenant"), payload.get("operation_id")) != (task["tenant"], task["id"])
            or payload.get("request_hash") != digest({k: v for k, v in payload.items() if k != "request_hash"})):
        raise ValueError("Stored remote payload does not match its request hash")
    return payload


def tool_for(runtime, op, connection, task):
    _bound_payload(op, task)
    tools = runtime.tools
    if governance.enabled(connection, task["tenant"]):
        from .releases import ReleaseStore
        binding = governance.binding_for(connection, task["tenant"], task["id"])
        if binding is None or binding["release_digest"] != op["payload"].get("release_digest"):
            raise ValueError("The remote operation lacks a pinned release")
        release = ReleaseStore().get(connection, task["tenant"], binding["release_digest"])
        if release is None:
            raise ValueError("Pinned release not found")
        _, tools = runtime.release_adapters.get(binding["release_digest"], (runtime.model, tools))
        release.snapshot.check_tool(tools)
        _, action, _ = release.snapshot.registry().definition(task["application"])
        pinned = tools.resolve(action)
        if (op["tool_name"], op["tool_version"]) != (pinned.name, pinned.version):
            raise ValueError("Stored remote tool is outside the pinned release")
    tool = tools.resolve({"tool": op["tool_name"], "tool_version": op["tool_version"]})
    if not tool.remote or tool.identity != op["adapter_identity"]:
        raise ValueError("Remote destination has changed")
    if (tool.source is not None) != ("source_conditions" in op["payload"]):
        raise ValueError("Remote operation uses a different source protocol")
    return tool


def adapter_for(runtime, op, connection, task):
    return tool_for(runtime, op, connection, task).handler


def _approved_action(runtime, connection, task):
    definition = runtime._definition(connection, task)
    if definition is None:
        return None
    reason, ground, reviewer = runtime._approved_ground(connection, task, definition)
    return None if reason else (definition, ground, reviewer)


def _ledger_for(runtime, connection, task, payload):
    pinned_digest = payload.get("release_digest")
    if governance.enabled(connection, task["tenant"]):
        binding = governance.binding_for(connection, task["tenant"], task["id"])
        if binding is None or binding["release_digest"] != pinned_digest:
            raise PermissionError("Stored operation no longer matches its pinned release")
    if pinned_digest is None:
        return None
    from .owp_gate import PROFILE
    from .releases import ReleaseStore

    release = ReleaseStore.get(connection, task["tenant"], pinned_digest)
    if release is None:
        raise ValueError("Pinned release not found")
    profile, _ = release.snapshot.authorization_profile()
    if profile is None:
        return None
    if profile != PROFILE or task["tenant"] not in runtime.owp_ledgers:
        raise PermissionError("No trusted OWP recovery configuration")
    return runtime.owp_ledgers[task["tenant"]]


def dispatch(runtime, tenant, task_id, identity=None, *, worker=True):
    from .graph_runtime import expire_task, expired

    send_before = None
    with database(runtime.path, write=True, tenant=tenant) as connection:
        task = governance.read_task(connection, tenant, task_id, identity, "advance", worker=worker)
        op = operation(connection, task_id)
        if task["status"] != "reconciling" or op is None or op["status"] != "prepared":
            return task
        if task.get("graph_deadline") is not None:
            send_before = monotonic() + (task["graph_deadline"] - runtime._clock(connection))
            if monotonic() >= send_before:
                return expire_task(runtime, connection, task)
        ledger = _ledger_for(runtime, connection, task, op["payload"])
        if ledger is not None and not ledger.eligible(connection, tenant, task_id):
            return {**task, "authorization": {"verdict": "manual", "reason": "restore_epoch_changed"}}
        approved = _approved_action(runtime, connection, task)
        if approved is None:
            connection.execute("UPDATE remote_operations SET status='rejected' WHERE operation_id=?", (task_id,))
            return runtime._block(connection, task, "remote_authorization_changed")
        tool = tool_for(runtime, op, connection, task)
        if expired(connection, task):
            return expire_task(runtime, connection, task)
        adapter = tool.handler
        invoke = adapter.execute
        definition, ground, reviewer = approved
        if definition.owp_profile is not None:
            from .owp_gate import scope_for

            scope = scope_for(task, definition, ground, reviewer, op["payload"])
            decision = ledger.consume(connection, tenant, task_id, scope, remote=True,
                                      request_digest=op["payload"]["request_hash"])
            if decision.verdict == "manual":
                return {**task, "authorization": {"verdict": "manual", "reason": decision.reason}}
            if not decision.allowed:
                connection.execute("UPDATE remote_operations SET status='rejected' WHERE operation_id=?", (task_id,))
                return runtime._block(connection, task, "owp_" + decision.reason)
            if tool.source is not None:
                from functools import partial
                import json
                from .delivery import enqueue_delivery
                from .p4_execution import delivery_scope

                row = connection.execute(
                    """SELECT envelope FROM owp_authorizations WHERE tenant = ? AND operation_id = ?
                       AND authorization_digest = ?""", (tenant, task_id, decision.authorization_digest),
                ).fetchone()
                invoke = partial(adapter.execute_authorized, envelope=json.loads(row[0]))
                enqueue_delivery(connection, tenant=tenant, task_id=task_id, operation_id=task_id,
                                 kind="reconcile", scope=delivery_scope(tool.identity))
        connection.execute(
            "UPDATE remote_operations SET status='dispatched', attempts=attempts+1 WHERE operation_id=?", (task_id,)
        )
        audit(connection, task_id, "remote.dispatched", request_hash=op["payload"]["request_hash"])
    return call_and_record(runtime, tenant, task_id, invoke, op["payload"], "execute", send_before=send_before)


def call_and_record(runtime, tenant, task_id, invoke, payload, mode, *, delivery_lease=None, send_before=None):
    from .remote import RemoteError
    if send_before is not None and monotonic() >= send_before:
        with database(runtime.path, write=True, tenant=tenant) as connection:
            task = task_data(connection, tenant, task_id)
            if task["status"] == "reconciling" and connection.execute(
                "UPDATE remote_operations SET status='unknown' WHERE operation_id=? AND status='dispatched'",
                (task_id,),
            ).rowcount:
                audit(connection, task_id, "remote.dispatch_skipped", reason="graph_deadline")
            return task
    try:
        response = invoke(payload)
    except (RemoteError, OSError, TimeoutError):
        with database(runtime.path, write=True, tenant=tenant) as connection:
            task = task_data(connection, tenant, task_id)
            if mode == "lookup" and "source_conditions" in payload:
                from .p4_execution import has_reconcile_lease

                if not has_reconcile_lease(connection, delivery_lease, task):
                    return task
            if task["status"] == "reconciling":
                connection.execute("UPDATE remote_operations SET status='unknown' WHERE operation_id=?", (task_id,))
                audit(connection, task_id, "remote.unknown", phase=mode)
            return task
    return record_response(runtime, tenant, task_id, response, mode,
                           expected_payload=payload, delivery_lease=delivery_lease)


def valid_response(payload, response):
    if not isinstance(response, dict):
        return False
    if any(response.get(key) != payload[key] for key in ("operation_id", "request_hash")):
        return False
    status = response.get("status")
    if status not in ("succeeded", "rejected", "pending", "not_found"):
        return False
    if status == "succeeded":
        result = response.get("result")
        return (isinstance(result, dict) and result.get("state") == payload["to_state"]
                and type(result.get("version")) is int and result["version"] == payload["expected_version"] + 1)
    return True


def record_response(runtime, tenant, task_id, response, mode, *, expected_payload=None, delivery_lease=None):
    with database(runtime.path, write=True, tenant=tenant) as connection:
        task = task_data(connection, tenant, task_id)
        if task["status"] != "reconciling":
            return task
        op = operation(connection, task_id)
        payload = _bound_payload(op, task)
        if expected_payload is not None and payload != expected_payload:
            raise PermissionError("Stored operation changed during the network request")
        if "source_conditions" in payload:
            from .p4_execution import has_reconcile_lease, record_source_response

            if mode == "lookup" and not has_reconcile_lease(connection, delivery_lease, task):
                return task
            ledger = _ledger_for(runtime, connection, task, payload)
            if ledger is None:
                raise PermissionError("Source receipt lacks its original authorization")
            authorization = ledger.recover(connection, tenant, task_id, payload["request_hash"])
            if not authorization.allowed:
                raise PermissionError("Source receipt lacks its original authorization")
            tool = tool_for(runtime, op, connection, task)
            return record_source_response(connection, task, op, payload, response, authorization, tool, mode)
        if not valid_response(payload, response):
            audit(connection, task_id, "remote.receipt_invalid", phase=mode)
            connection.execute("UPDATE remote_operations SET status='unknown' WHERE operation_id=?", (task_id,))
            return task
        ledger = _ledger_for(runtime, connection, task, payload)
        authorization = None
        if ledger is not None:
            authorization = ledger.recover(connection, tenant, task_id, payload["request_hash"])
            if not authorization.allowed:
                raise PermissionError("Remote receipt lacks its original authorization binding")
        status = response["status"]
        connection.execute(
            "UPDATE remote_operations SET status=?, response=? WHERE operation_id=?",
            (status, encode(response), task_id),
        )
        if payload.get("release_digest"):
            from .fact_feedback import receipt
            from .fact_gate import binding_for

            rule = binding_for(connection, tenant, payload["release_digest"])
            if rule is not None and rule["feedback_source"] is not None:
                receipt(connection, payload, status)
        audit(connection, task_id, "remote.receipt", remote_status=status, phase=mode)
        if status == "rejected":
            connection.execute("UPDATE tasks SET status='failed' WHERE id=?", (task_id,))
        elif status == "succeeded":
            receipt = response["result"]
            current = object_data(connection, tenant, payload["object_id"])
            aligned = current is not None and (
                (current["version"] == payload["expected_version"] and current["state"] == payload["from_state"])
                or (current["version"] == receipt["version"] and current["state"] == receipt["state"])
            )
            if aligned:
                connection.execute(
                    "UPDATE objects SET state=?, version=? WHERE tenant=? AND id=?",
                    (receipt["state"], receipt["version"], tenant, payload["object_id"]),
                )
            connection.execute(
                "INSERT INTO effects VALUES (?, ?, ?, ?)",
                (task_id, payload["action"], payload["object_id"], encode(receipt)),
            )
            if authorization is not None:
                from .evidence import enqueue_effect

                enqueue_effect(connection, tenant=tenant, task_id=task_id, operation_id=task_id,
                               authorization_digest=authorization.authorization_digest,
                               result=receipt, observation="remote_receipt_observed")
            state = "completed" if aligned else "reconciliation_conflict"
            connection.execute("UPDATE tasks SET status=? WHERE id=?", (state, task_id))
            audit(connection, task_id, "remote.confirmed", projection_state=state, operation_id=task_id)
        return task_data(connection, tenant, task_id)


def reconcile(runtime, tenant, task_id, identity=None, *, worker=True, delivery_lease=None):
    with database(runtime.path, tenant=tenant) as connection:
        task = governance.read_task(connection, tenant, task_id, identity, "reconcile", worker=worker)
        if task["status"] != "reconciling":
            return task
        op = operation(connection, task_id)
        if op is None:
            raise ValueError("Remote operation not found")
        if op["status"] == "prepared":
            return task
        if "source_conditions" in op["payload"]:
            from .p4_execution import has_reconcile_lease

            if not has_reconcile_lease(connection, delivery_lease, task):
                return {**task, "authorization": {"verdict": "manual", "reason": "reconciliation_queued"}}
        adapter = adapter_for(runtime, op, connection, task)
        ledger = _ledger_for(runtime, connection, task, op["payload"])
        if ledger is not None and not ledger.recover(
            connection, tenant, task_id, op["payload"]["request_hash"],
        ).allowed:
            raise PermissionError("Remote lookup lacks its original authorization binding")
    return call_and_record(runtime, tenant, task_id, adapter.lookup, op["payload"], "lookup",
                           delivery_lease=delivery_lease)


def retry(runtime, tenant, task_id, actor, identity=None):
    from .graph_runtime import expired

    # Query first. An absent record alone is never evidence that an old request cannot arrive.
    # The remote execute contract MUST atomically deduplicate operation_id + request_hash.
    with database(runtime.path, tenant=tenant) as connection:
        task = governance.read_task(connection, tenant, task_id, identity, "retry")
        governance.task_access(connection, task, identity, "advance")
        if identity is not None:
            governance.require_identity_match(identity, tenant, actor)
        if actor != task["requester"]:
            raise PermissionError("Only the requester can retry a remote operation")
    reconcile(runtime, tenant, task_id, identity, worker=False)
    with database(runtime.path, write=True, tenant=tenant) as connection:
        task = governance.read_task(connection, tenant, task_id, identity, "retry")
        governance.task_access(connection, task, identity, "advance")
        op = operation(connection, task_id)
        if task["status"] != "reconciling" or op is None or op["status"] != "not_found":
            return task
        if expired(connection, task):
            return {**task, "authorization": {"verdict": "manual", "reason": "graph_deadline"}}
        if _ledger_for(runtime, connection, task, op["payload"]) is not None:
            return {**task, "authorization": {"verdict": "manual", "reason": "lookup_only"}}
        if _approved_action(runtime, connection, task) is None:
            raise PermissionError("Remote retry requires current approval and permissions")
        adapter_for(runtime, op, connection, task)
        connection.execute("UPDATE remote_operations SET status='prepared' WHERE operation_id=?", (task_id,))
        audit(connection, task_id, "remote.retry_authorized", actor=actor)
    if task.get("graph_version") is not None:
        return runtime.advance(tenant, task_id, identity=identity, worker=False)
    return dispatch(runtime, tenant, task_id, identity, worker=False)
