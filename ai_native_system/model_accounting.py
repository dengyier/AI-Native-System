"""Reserve and settle model spend in the tenant's PostgreSQL ledger."""

import math
import time
from dataclasses import dataclass, field
from uuid import uuid4

from .model import ModelError


_MAX_BIGINT = 2**63 - 1
_MAX_INTEGER = 2**31 - 1
_UNCERTAIN = {"timeout", "cancelled"}
_TERMINAL = {"succeeded", "failed"}
_ACTIVE = "(outcome IS NULL OR outcome IN ('timeout', 'cancelled')) AND active_until > to_timestamp(?)"
_COMPLETE_USAGE = "input_tokens IS NOT NULL AND (output_tokens IS NOT NULL OR max_output_tokens = 0)"


def _integer(value, name, *, minimum=0, maximum=_MAX_BIGINT):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer between {minimum} and {maximum}")


def _identifier(value, name):
    if type(value) is not str or not value.strip() or len(value) > 256 or "\x00" in value:
        raise ValueError(f"invalid model accounting {name}")


def _seconds(value, name):
    if type(value) not in (int, float) or not 0.001 <= value <= 86_400 or not math.isfinite(value):
        raise ValueError(f"{name} must be between 0.001 and 86400 seconds")


class ModelBudgetError(ModelError):
    """No provider request was admitted, or the permit expired before dispatch."""

    def __init__(self, reason):
        self.reason = reason
        super().__init__(f"model budget denied: {reason}")


@dataclass(frozen=True)
class ModelLimits:
    max_active: int
    max_attempts: int
    max_tokens: int
    max_cost_nanos: int
    deadline_seconds: float

    def __post_init__(self):
        _integer(self.max_active, "maximum active attempts", minimum=1, maximum=_MAX_INTEGER)
        _integer(self.max_attempts, "maximum attempts", minimum=1, maximum=_MAX_INTEGER)
        _integer(self.max_tokens, "maximum tokens", minimum=1)
        _integer(self.max_cost_nanos, "maximum cost in USD nanos")
        _seconds(self.deadline_seconds, "logical deadline")


@dataclass(frozen=True)
class ModelPrice:
    """Configured USD nanodollars per token and the price table revision."""

    version: str
    input_nanos: int
    output_nanos: int

    def __post_init__(self):
        _identifier(self.version, "price version")
        _integer(self.input_nanos, "input price in USD nanos")
        _integer(self.output_nanos, "output price in USD nanos")


@dataclass(frozen=True)
class ModelPermit:
    tenant: str
    call_id: str
    attempt_id: str
    ordinal: int
    _local_deadline: float = field(repr=False)

    def remaining_seconds(self):
        remaining = self._local_deadline - time.monotonic()
        if remaining <= 0:
            raise ModelBudgetError("deadline")
        return remaining


class ModelAccounting:
    """Use the store's tenant write lock to serialize admission and settlement.

    Tokens and USD nanos cover the tenant ledger's full lifetime. A logical
    call fixes its policy and deadline when opened. Unknown usage remains
    charged at the reservation even after the active slot is released.
    """

    def __init__(self, store):
        self.store = store

    def open_call(self, tenant, call_id, *, limits, task_id=None, purpose="generation"):
        _identifier(call_id, "call ID")
        if task_id is not None:
            _identifier(task_id, "task ID")
        if purpose not in {"generation", "embedding"}:
            raise ValueError("invalid model call purpose")
        policy = (task_id, purpose, limits.max_active, limits.max_attempts, limits.max_tokens,
                  limits.max_cost_nanos, limits.deadline_seconds)
        with self.store.transaction(tenant=tenant, write=True) as connection:
            connection.execute(
                """INSERT INTO model_calls
                   (tenant, call_id, task_id, purpose, max_active, max_attempts, max_tokens, max_cost_nanos,
                    deadline_seconds, deadline_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, clock_timestamp() + ? * interval '1 second')
                   ON CONFLICT (tenant, call_id) DO NOTHING""",
                (tenant, call_id, *policy, limits.deadline_seconds),
            )
            existing = connection.execute(
                """SELECT task_id, purpose, max_active, max_attempts, max_tokens, max_cost_nanos, deadline_seconds
                   FROM model_calls WHERE tenant = ? AND call_id = ?""",
                (tenant, call_id),
            ).fetchone()
            if tuple(existing) != policy:
                raise ValueError("model call already has a different task, purpose or policy")

    def reserve(self, tenant, call_id, *, route, provider, model, model_version,
                max_input_tokens, max_output_tokens, price, timeout_seconds, admit=None):
        for value, name in ((route, "route"), (provider, "provider"), (model, "model"), (model_version, "model version")):
            _identifier(value, name)
        _integer(max_input_tokens, "maximum input tokens", minimum=1)
        _integer(max_output_tokens, "maximum output tokens")
        _seconds(timeout_seconds, "provider timeout")
        requested_tokens = max_input_tokens + max_output_tokens
        requested_cost = max_input_tokens * price.input_nanos + max_output_tokens * price.output_nanos
        with self.store.transaction(tenant=tenant, write=True) as connection:
            call = connection.execute(
                """SELECT *, extract(epoch FROM deadline_at)::double precision AS deadline
                   FROM model_calls WHERE tenant = ? AND call_id = ?""",
                (tenant, call_id),
            ).fetchone()
            if call is None:
                raise ValueError("model call was not opened")
            budget = connection.execute(
                f"""SELECT count(*) FILTER (WHERE call_id = ?) AS attempts,
                           count(*) FILTER (WHERE {_ACTIVE}) AS active,
                           coalesce(sum(charged_tokens), 0) AS tokens,
                           coalesce(sum(charged_cost_nanos), 0) AS cost
                    FROM model_attempts WHERE tenant = ?""",
                (call_id, connection.database_time(), tenant),
            ).fetchone()
            admission_started = time.monotonic()
            admitted_seconds = admit(connection) if admit is not None else None
            local_now = time.monotonic()
            now = connection.database_time()
            window = min(timeout_seconds, call["deadline"] - now)
            if admitted_seconds is not None:
                if type(admitted_seconds) not in (int, float) or not math.isfinite(admitted_seconds):
                    raise ValueError("model admission must return a finite duration or None")
                window = min(window, admitted_seconds - (local_now - admission_started))
            for denied, reason in (
                (window < 0.001, "deadline"),
                (budget["attempts"] >= call["max_attempts"], "attempts"),
                (budget["active"] >= call["max_active"], "concurrency"),
                (budget["tokens"] + requested_tokens > call["max_tokens"], "tokens"),
                (budget["cost"] + requested_cost > call["max_cost_nanos"], "cost"),
            ):
                if denied:
                    raise ModelBudgetError(reason)
            permit = ModelPermit(tenant, call_id, uuid4().hex, budget["attempts"] + 1, local_now + window)
            # Timeout leaves a bounded quarantine of one additional request window.
            # This tracks local dispatch, not execution outside the provider's HTTP connection.
            connection.execute(
                """INSERT INTO model_attempts
                   (tenant, attempt_id, call_id, ordinal, route, provider, model, model_version,
                    price_version, input_nanos, output_nanos, max_input_tokens, max_output_tokens,
                    deadline_at, active_until)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, to_timestamp(?), to_timestamp(?))""",
                (tenant, permit.attempt_id, call_id, permit.ordinal, route, provider, model, model_version,
                 price.version, price.input_nanos, price.output_nanos, max_input_tokens, max_output_tokens,
                 now + window, now + 2 * window),
            )
        return permit

    def settle(self, permit, *, outcome, input_tokens=None, output_tokens=None,
               actual_provider=None, actual_model=None, callback=None):
        if outcome not in _UNCERTAIN | _TERMINAL:
            raise ValueError("invalid model attempt outcome")
        for value, name in ((input_tokens, "input tokens"), (output_tokens, "output tokens")):
            if value is not None:
                _integer(value, name)
        for value, name in ((actual_provider, "actual provider"), (actual_model, "actual model")):
            if value is not None:
                _identifier(value, name)
        with self.store.transaction(tenant=permit.tenant, write=True) as connection:
            keys = (permit.tenant, permit.call_id, permit.attempt_id)
            row = connection.execute(
                "SELECT * FROM model_attempts WHERE tenant = ? AND call_id = ? AND attempt_id = ?", keys,
            ).fetchone()
            if row is None:
                raise ValueError("model attempt was not reserved")
            counts = []
            for name, value in (
                ("input_tokens", input_tokens), ("output_tokens", output_tokens),
                ("actual_provider", actual_provider), ("actual_model", actual_model),
            ):
                saved = row[name]
                if saved is not None and value is not None and value != saved:
                    raise ValueError(f"conflicting settlement for {name}")
                counts.append(saved if saved is not None else value)

            previous = row["outcome"]
            if previous is not None and outcome != previous:
                if outcome in _UNCERTAIN:
                    outcome = previous
                elif previous not in _UNCERTAIN:
                    raise ValueError("conflicting model attempt outcomes")
            columns = ("outcome", "input_tokens", "output_tokens", "actual_provider", "actual_model")
            settlement = (outcome, *counts)
            changed = tuple(row[name] for name in columns) != settlement
            if changed:
                row = connection.execute(
                    """UPDATE model_attempts
                       SET outcome = ?, input_tokens = ?, output_tokens = ?, actual_provider = ?, actual_model = ?,
                           finished_at = CASE WHEN outcome IS DISTINCT FROM ? THEN clock_timestamp() ELSE finished_at END
                       WHERE tenant = ? AND call_id = ? AND attempt_id = ? RETURNING *""",
                    (*settlement, outcome, *keys),
                ).fetchone()
            result = _attempt(row, connection.database_time())
            if changed and callback is not None:
                callback(connection, result)
            return result

    def usage(self, tenant, call_id=None, *, limit=100):
        """Read a bounded page of attempts and aggregate usage across all matching attempts."""
        _integer(limit, "usage page size", minimum=1, maximum=1000)
        scope = "tenant = ?" if call_id is None else "tenant = ? AND call_id = ?"
        parameters = (tenant,) if call_id is None else (tenant, call_id)
        with self.store.transaction(tenant=tenant) as connection:
            now = connection.database_time()
            totals = connection.execute(
                f"""SELECT count(*) AS attempts, count(*) FILTER (WHERE {_ACTIVE}) AS active_attempts,
                           count(*) FILTER (WHERE NOT ({_COMPLETE_USAGE})) AS unknown_usage_attempts,
                           coalesce(sum(input_tokens), 0) AS input_tokens,
                           coalesce(sum(output_tokens), 0) AS output_tokens,
                           coalesce(sum(input_tokens::numeric * input_nanos), 0)
                           + coalesce(sum(output_tokens::numeric * output_nanos), 0) AS known_cost_nanos,
                           coalesce(sum(charged_tokens), 0) AS charged_tokens,
                           coalesce(sum(charged_cost_nanos), 0) AS charged_cost_nanos
                    FROM model_attempts WHERE {scope}""",
                (now, *parameters),
            ).fetchone()
            rows = connection.execute(
                f"""SELECT a.*, c.task_id, c.purpose FROM model_attempts a
                    JOIN model_calls c USING (tenant, call_id) WHERE {scope}
                    ORDER BY a.created_at DESC, a.attempt_id DESC LIMIT ?""",
                (*parameters, limit),
            ).fetchall()
        return {
            "attempts": [_attempt(row, now) for row in rows],
            "totals": {name: int(totals[name]) for name in totals.keys()},
        }


def _attempt(row, now):
    values = {name: row[name] for name in row.keys()}
    outcome, stop = row["outcome"], row["active_until"].timestamp()
    values["active"] = (outcome is None or outcome in _UNCERTAIN) and now < stop
    if outcome is None:
        values["outcome"] = "reserved" if now < stop else "unknown"
    for name in ("created_at", "deadline_at", "active_until", "finished_at"):
        values[name] = None if row[name] is None else row[name].isoformat()
    for name in ("charged_tokens", "charged_cost_nanos"):
        values[name] = int(row[name])
    input_tokens, output_tokens = row["input_tokens"], row["output_tokens"]
    values["actual_cost_nanos"] = None
    if input_tokens is not None and (output_tokens is not None or row["max_output_tokens"] == 0):
        values["actual_cost_nanos"] = input_tokens * row["input_nanos"] + (output_tokens or 0) * row["output_nanos"]
    values["exceeded_reservation"] = (
        (input_tokens is not None and input_tokens > row["max_input_tokens"])
        or (output_tokens is not None and output_tokens > row["max_output_tokens"])
    )
    return values
