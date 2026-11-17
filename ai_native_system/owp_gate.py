"""Bind the installed workflow and its live proofs to the enterprise OWP profile."""

from functools import partial
from pathlib import Path

from . import governance
from .registry import is_name
from .storage import digest
from .tools import transition


PROFILE = "ai-native-action/v0.1"


def enforced(connection, tenant):
    return connection.execute("SELECT 1 FROM owp_enforced_tenants WHERE tenant = ?", (tenant,)).fetchone() is not None


def enforce(connection, tenant):
    if not governance.enabled(connection, tenant):
        raise ValueError("Activate enterprise governance before requiring OWP")
    if enforced(connection, tenant):
        return
    if connection.execute(
        """SELECT 1 FROM tasks WHERE tenant = ? AND status = 'reconciling' LIMIT 1""", (tenant,),
    ).fetchone():
        raise ValueError("Reconcile pending remote operations before requiring OWP")
    connection.execute("INSERT INTO owp_enforced_tenants VALUES (?) ON CONFLICT DO NOTHING", (tenant,))


def check_profile(connection, tenant, profile, *, required=False):
    if profile is not None and profile != PROFILE:
        raise ValueError("Unsupported OWP release profile")
    if profile is None and (required or enforced(connection, tenant)):
        raise PermissionError("This tenant requires an OWP release")


def configured_ledgers(document):
    from .adapters.owp import key_id, load_public_key, verify_authorization
    from .security import AuthorizationLedger

    if not isinstance(document, dict) or not document:
        raise ValueError("Configure OWP authority trust by tenant")
    ledgers = {}
    for tenant, authority in document.items():
        if (not is_name(tenant) or not isinstance(authority, dict) or authority.keys() != {"epoch", "public_keys"}
                or not isinstance(authority["public_keys"], list) or not authority["public_keys"]):
            raise ValueError("Each authority requires a tenant, recovery epoch and public keys")
        keys = {}
        for path in authority["public_keys"]:
            key = load_public_key(Path(path).read_bytes())
            keys[key_id(key)] = key
        ledgers[tenant] = AuthorizationLedger(authority["epoch"], partial(verify_authorization, trusted_keys=keys))
    return ledgers


def read_scope(ground):
    resources = set()
    for item in (ground["object"], *ground["related"].values()):
        resource_id = item["id"]
        resources.add(("object", resource_id, None))
        resources.update(("metadata", resource_id, name) for name in ("state", "version"))
        resources.update(("field", resource_id, name) for name in item["properties"])
        resources.update(("edge", resource_id, name) for name in item["links"])
        resources.update(("object", target_id, None) for target_id in item["links"].values())
    resources.update(("document", document.get("document_id", document["id"]), None)
                     for document in ground["knowledge"])
    resources.update(tuple(entry) for entry in ground["_owp_rule"]["resources"])
    return [
        {"kind": kind, "resource_id": resource_id, "member": member}
        for kind, resource_id, member in sorted(resources, key=lambda item: (item[0], item[1], item[2] or ""))
    ]


def scope_for(task, definition, ground, approver, remote_payload=None):
    tool = definition.tools.resolve(definition.action)
    item = ground["object"]
    if tool.remote:
        if tool.source is not None and ground.get("_p4_source_conditions") is None:
            raise PermissionError("The source cannot atomically enforce all required facts")
        from .remote_execution import build_payload

        expected = build_payload({**task, "release_digest": definition.release_digest}, definition.app,
                                 definition.action, ground)
        if remote_payload is not None and remote_payload != expected:
            raise PermissionError("The pending operation does not match its current authorization scope")
        parameters = expected["request_hash"]
        destination = digest(tool.identity)
    else:
        if tool.handler is not transition or (tool.name, tool.version) != ("state.transition", "1"):
            raise PermissionError("The OWP local action requires the registered transactional state tool")
        parameters = digest({
            "tenant": task["tenant"], "type": item["type"], "id": item["id"], "version": item["version"],
            "from_state": definition.action["from_state"], "to_state": definition.action["to_state"],
        })
        destination = None
    requester = governance.bound_identity(definition.binding, "requester_context", task["tenant"], task["requester"])
    rule = ground["_owp_rule"]
    return {
        "tenant": task["tenant"], "task_id": task["id"], "operation_id": task["id"],
        "action_instance_id": f"{task['id']}:action", "release_digest": definition.release_digest,
        "ontology_digest": definition.ontology.digest, "policy_version": definition.owp_policy,
        "rule_versions": rule["versions"], "rule_proof_digest": ground["_fact_fingerprint"],
        "fact_read_set_digest": rule["read_set_digest"],
        "requester": requester.as_document(), "approver": approver.as_document(),
        "executor": definition.app["executor"], "approval_digest": task["approval_hash"],
        "action": definition.app["action"], "action_version": definition.action["version"],
        "action_kind": "write_remote" if tool.remote else "write_local",
        "targets": [{"type": item["type"], "id": item["id"]}],
        "reads": read_scope(ground),
        "writes": [{"kind": "object", "resource_id": item["id"], "member": None},
                   {"kind": "metadata", "resource_id": item["id"], "member": "state"},
                   {"kind": "metadata", "resource_id": item["id"], "member": "version"}],
        "parameters_digest": parameters,
        "tool": {"name": tool.name, "version": tool.version, "destination_digest": destination},
    }
