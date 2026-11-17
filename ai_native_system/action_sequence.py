"""An ordered group of independently authorized effects."""

from uuid import uuid4

from .storage import task_data


_STOPPED = {"blocked", "cancelled", "failed", "rejected", "no_action", "reconciliation_conflict"}


def _available_task(connection, tenant, task_id):
    task = task_data(connection, tenant, task_id)
    if task["status"] not in ("planning", "awaiting_approval", "ready"):
        raise ValueError("An action must be grouped before execution")
    if connection.execute("SELECT 1 FROM owp_task_admissions WHERE tenant=? AND task_id=?", (tenant, task_id)).fetchone() is None:
        raise ValueError("Every step must be an independently governed task")
    return task


def create_sequence(connection, tenant, task_ids):
    if not isinstance(task_ids, (tuple, list)) or not 2 <= len(task_ids) <= 32 or len(set(task_ids)) != len(task_ids):
        raise ValueError("Supply 2–32 distinct tasks in execution order")
    for task_id in task_ids:
        _available_task(connection, tenant, task_id)
        if connection.execute("SELECT 1 FROM p4_sequence_steps WHERE tenant=? AND task_id=?", (tenant, task_id)).fetchone():
            raise ValueError("Task is already in an action sequence")
    sequence = uuid4().hex
    connection.execute("INSERT INTO p4_sequences VALUES (?, ?)", (tenant, sequence))
    for number, task_id in enumerate(task_ids, 1):
        connection.execute("INSERT INTO p4_sequence_steps VALUES (?, ?, ?, ?)", (tenant, sequence, number, task_id))
    return sequence


def may_execute(connection, tenant, task_id):
    if not hasattr(connection, "database_time"):
        return True
    return connection.execute(
        """SELECT 1 FROM p4_sequence_steps step
           JOIN p4_sequence_steps previous
             ON (previous.tenant, previous.sequence_id) = (step.tenant, step.sequence_id)
            AND previous.position < step.position
           JOIN tasks task ON (task.tenant, task.id) = (previous.tenant, previous.task_id)
           WHERE step.tenant = ? AND step.task_id = ? AND task.status <> 'completed' LIMIT 1""",
        (tenant, task_id),
    ).fetchone() is None


def sequence_status(connection, tenant, sequence_id):
    rows = connection.execute(
        """SELECT step.position, task.id, task.status, effect.operation_id
           FROM p4_sequence_steps step JOIN tasks task ON (task.tenant, task.id) = (step.tenant, step.task_id)
           LEFT JOIN effects effect ON effect.operation_id = task.id
           WHERE step.tenant = ? AND step.sequence_id = ? ORDER BY step.position""",
        (tenant, sequence_id),
    ).fetchall()
    if not rows:
        raise LookupError("Action sequence not found")
    steps = [{"position": row[0], "task_id": row[1], "status": row[2], "effect_recorded": row[3] is not None}
             for row in rows]
    if all(step["status"] == "completed" for step in steps):
        status = "completed"
    elif any(step["status"] in _STOPPED for step in steps):
        status = "partial" if any(step["effect_recorded"] for step in steps) else "failed"
    else:
        status = "pending"
    return {"id": sequence_id, "status": status, "steps": steps}


def link_compensation(connection, tenant, original_id, compensation_id):
    if original_id == compensation_id:
        raise ValueError("Compensation requires a distinct task")
    _available_task(connection, tenant, compensation_id)
    original = task_data(connection, tenant, original_id)
    if (original["status"] not in ("completed", "reconciliation_conflict")
            or connection.execute("SELECT 1 FROM effects WHERE operation_id=?", (original_id,)).fetchone() is None):
        raise ValueError("Compensation requires an observed original effect")
    connection.execute("INSERT INTO p4_compensations VALUES (?, ?, ?)", (tenant, original_id, compensation_id))
    return {"original": original_id, "compensation": compensation_id}
