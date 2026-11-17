"""Authority callbacks and fair claims for tasks pinned to LangGraph."""

from . import governance
from .graph_contract import GraphSpec
from .model import ModelError
from .releases import ReleaseStore
from .storage import database


_OPEN = ("planning", "awaiting_approval", "ready", "reconciling")


class GraphUnavailable(ModelError):
    """A task's pinned graph cannot currently be driven."""


class GraphQueueFull(ModelError):
    """This tenant's graph task queue has reached its configured capacity."""


def expired(connection, task):
    deadline = task.get("graph_deadline")
    return deadline is not None and deadline <= connection.database_time()


def expire_task(runtime, connection, task):
    """Stop new work, allowing recovery of an operation that may already have executed."""
    if task["status"] not in _OPEN or not expired(connection, task):
        return task
    if task["status"] == "reconciling":
        operation = connection.execute("SELECT status, attempts FROM remote_operations WHERE operation_id = ?",
                                       (task["id"],)).fetchone()
        if operation is None or operation["status"] != "prepared":
            return task
        if operation["attempts"]:
            connection.execute("UPDATE remote_operations SET status = 'unknown' WHERE operation_id = ?", (task["id"],))
            return task
        connection.execute("UPDATE remote_operations SET status = 'cancelled' WHERE operation_id = ?", (task["id"],))
    return runtime._block(connection, task, "graph_deadline")


def require_queue_slot(connection, tenant, limit):
    count = connection.execute("""SELECT count(*) FROM tasks WHERE tenant = ? AND graph_version IS NOT NULL
        AND status IN ('planning', 'awaiting_approval', 'ready', 'reconciling')""", (tenant,)).fetchone()[0]
    if count >= limit:
        raise GraphQueueFull("Graph task queue is full for this tenant")


def advance_graph(runtime, tenant, task, simulate_timeout, identity, *, worker):
    task_id = task["id"]

    def read(connection):
        return governance.read_task(connection, tenant, task_id, identity, "advance", worker=worker)

    def observe():
        with database(runtime.path, tenant=tenant) as connection:
            current = read(connection)
            if current["status"] not in _OPEN or not expired(connection, current):
                return current
        with database(runtime.path, write=True, tenant=tenant) as connection:
            return expire_task(runtime, connection, read(connection))

    # A broken or incompatible checkpointer must not keep expired work on the queue.
    if task["status"] in _OPEN:
        task = observe()
        if task["status"] == "blocked":
            return task
    if runtime.graph_store is None:
        if task["status"] not in _OPEN:
            return task
        raise GraphUnavailable("This task requires its PostgreSQL LangGraph checkpoint worker")
    from .adapters.langgraph import LangGraphDriver
    from .adapters.langgraph_postgres import GraphStorageError

    with database(runtime.path, tenant=tenant) as connection:
        binding = governance.binding_for(connection, tenant, task_id)
        record = ReleaseStore.get(connection, tenant, binding["release_digest"]) if binding else None
        if record is None or record.snapshot.application != task["application"]:
            raise GraphUnavailable("The pinned graph release is unavailable")
        app, _, fingerprint = record.snapshot.registry().definition(task["application"])
        if app.get("graph", {}).get("version") != task["graph_version"] or fingerprint != task["definition_hash"]:
            raise GraphUnavailable("The task's graph version or definition changed")
        spec = GraphSpec.from_document(app["graph"])

    def plan(expected_stage):
        return runtime._plan(tenant, task_id, identity, worker=worker, expected_stage=expected_stage)

    def execute(expected_status):
        current = observe()
        if current["status"] != expected_status:
            return current
        return runtime._advance_native(tenant, current, simulate_timeout, identity, worker=worker)

    def check(name):
        with database(runtime.path, tenant=tenant) as connection:
            current = read(connection)
            if current["status"] != "planning" or expired(connection, current):
                return False
            definition = runtime._definition(connection, current)
            if definition is None:
                return False
            reason, ground = runtime._ground(connection, current, definition)
            if reason:
                return False
            if name == "object_grounded":
                return bool(ground["object"])
            if name == "knowledge_grounded":
                return bool(ground["knowledge"])
            if name == "relationships_grounded":
                return bool(ground["related"])
            raise GraphUnavailable("The graph asked for an unsupported read check")

    def block(reason):
        with database(runtime.path, write=True, tenant=tenant) as connection:
            current = expire_task(runtime, connection, read(connection))
            if current["status"] == "planning":
                return runtime._block(connection, current, reason)
            return current

    driver = LangGraphDriver(runtime.graph_store)
    try:
        return driver.advance(tenant, task_id, spec, release_digest=record.snapshot.digest,
                              observe=observe, plan=plan, execute=execute, check=check, block=block)
    except GraphStorageError as exc:
        raise GraphUnavailable(str(exc)) from None


def work_graph(runtime, tenants, per_tenant):
    """Offer each configured tenant one claim per round with a fixed batch bound."""
    from .adapters.langgraph import GraphVersionError

    if runtime.graph_store is None:
        raise GraphUnavailable("Configure the LangGraph checkpoint worker before polling graph tasks")
    if (not isinstance(tenants, (list, tuple)) or not 1 <= len(tenants) <= 32
            or any(type(tenant) is not str or not tenant.strip() for tenant in tenants)
            or len(set(tenants)) != len(tenants) or type(per_tenant) is not int or not 1 <= per_tenant <= 10):
        raise ValueError("Graph work requires 1–32 distinct tenants and 1–10 claims per tenant")
    results = []
    for _ in range(per_tenant):
        for tenant in tenants:
            with database(runtime.path, write=True, tenant=tenant) as connection:
                row = connection.execute("""SELECT id FROM tasks WHERE tenant = ? AND graph_version IS NOT NULL
                    AND (status IN ('planning', 'ready', 'reconciling')
                         OR (status = 'awaiting_approval' AND graph_deadline <= ?))
                    ORDER BY graph_last_claim NULLS FIRST, graph_deadline, id LIMIT 1""",
                    (tenant, connection.database_time())).fetchone()
                if row is None:
                    continue
                task_id = row["id"]
                connection.execute("UPDATE tasks SET graph_last_claim = ? WHERE tenant = ? AND id = ?",
                                   (connection.database_time(), tenant, task_id))
            try:
                status = runtime.advance(tenant, task_id)["status"]
            except GraphVersionError:
                status = "version_blocked"
            except (ModelError, TimeoutError):
                status = "retryable"
            results.append({"tenant": tenant, "id": task_id, "status": status})
    return results
