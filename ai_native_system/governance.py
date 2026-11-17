"""Task bindings and current authorization for opt-in governed tenants."""
import json
from dataclasses import dataclass

from .identity import IdentityContext
from .storage import encode, task_data


@dataclass(frozen=True)
class Definition:
    registry: object
    model: object
    tools: object
    app: dict
    action: dict
    binding: dict | None = None
    release_digest: str | None = None
    ontology: object | None = None
    owp_profile: str | None = None
    owp_policy: str | int | None = None


def enabled(connection, tenant):
    # Only the PostgreSQL transaction adapter exposes database_time.
    return hasattr(connection, "database_time") and connection.execute(
        "SELECT 1 FROM governed_tenants WHERE tenant = ?", (tenant,),
    ).fetchone() is not None


def activate(connection, tenant):
    from .adapters.postgres_runtime import _tenant_lock

    connection.execute("SELECT pg_catalog.pg_advisory_xact_lock(?::bigint)", (_tenant_lock(tenant),))
    if enabled(connection, tenant):
        return
    if connection.execute("""SELECT 1 FROM remote_operations op JOIN tasks task ON task.id = op.operation_id
                             WHERE task.tenant = ? AND task.status = 'reconciling' LIMIT 1""", (tenant,)).fetchone():
        raise ValueError("Reconcile legacy remote operations before activating this tenant")
    connection.execute("INSERT INTO governed_tenants VALUES (?) ON CONFLICT DO NOTHING", (tenant,))


def binding_for(connection, tenant, task_id):
    row = connection.execute(
        "SELECT * FROM task_governance WHERE tenant = ? AND task_id = ?", (tenant, task_id),
    ).fetchone()
    return {key: row[key] for key in row.keys()} if row is not None else None


def bind_task(connection, task, identity, release_digest):
    connection.execute(
        """INSERT INTO task_governance (tenant, task_id, release_digest, requester_context)
           VALUES (?, ?, ?, ?)""",
        (task["tenant"], task["id"], release_digest, encode(identity.as_document())),
    )


def bind_approval(connection, task, identity):
    connection.execute(
        "UPDATE task_governance SET approver_context = ? WHERE tenant = ? AND task_id = ?",
        (encode(identity.as_document()), task["tenant"], task["id"]),
    )


def bound_identity(binding, field, tenant, actor):
    identity = IdentityContext.from_document(json.loads(binding[field]))
    if (identity.tenant, identity.actor) != (tenant, actor):
        raise PermissionError("Task identity does not match its binding")
    return identity


def require_identity_match(identity, tenant, actor=None):
    if (
        not isinstance(identity, IdentityContext) or identity.tenant != tenant
        or (actor is not None and identity.actor != actor)
    ):
        raise PermissionError("A trusted identity for this tenant is required")


def read_task(connection, tenant, task_id, identity, operation, **options):
    task_access(connection, {"tenant": tenant, "id": task_id}, identity, operation, **options)
    return task_data(connection, tenant, task_id)


def task_access(connection, task, identity, operation, *, worker=False, active=None):
    tenant = task["tenant"]
    if active is None:
        active = enabled(connection, tenant)
    if not active and identity is None:
        return
    if active and worker and identity is None:
        return  # Internal worker. The bound authorization is rechecked at execution.
    if not active:
        raise PermissionError("Enterprise mode is required")
    require_identity_match(identity, tenant)
    from .policy import Policy
    policy = Policy()
    policy.require(connection, identity, "read", "task", task["id"])
    if operation != "read":
        policy.require(connection, identity, operation, "task", task["id"])


def require_ground(connection, policy, identities, kind, resource_id, fields=(), edges=(), *, metadata=()):
    for identity in identities:
        policy.require(connection, identity, "read", kind, resource_id)
        for field in fields:
            policy.require(connection, identity, "read", "field", resource_id, field)
        for name in metadata:
            policy.require(connection, identity, "read", "metadata", resource_id, name)
        for edge in edges:
            policy.require(connection, identity, "read", "edge", resource_id, edge)
