"""Deterministic retrieval and safety evaluation bound to an immutable release."""

import math
import re
from uuid import NAMESPACE_URL, uuid5

from .governance import enabled
from .policy import Policy
from .storage import digest, encode, row_data


_DATASET_FIELDS = {"id", "relevant", "forbidden", "supports_action", "action", "effects", "block", "limits"}
_OBSERVATION_FIELDS = {"id", "retrieved", "citations", "action", "effects", "blocked", "latency_ms", "cost_nanos"}
_BLOCKS = {"contradiction", "prompt_injection", "unauthorized", "withdrawn", "unsupported"}


def _name(value):
    return type(value) is str and 1 <= len(value) <= 256 and all(char.isprintable() for char in value)


def _names(values):
    if (not isinstance(values, (list, tuple)) or len(values) > 100 or not all(map(_name, values))
            or len(set(values)) != len(values)):
        raise ValueError("Invalid evaluation reference list")
    return set(values)


def _number(value):
    return type(value) in (int, float) and 0 <= value <= 10**18 and math.isfinite(value)


def _by_id(documents, fields):
    if not isinstance(documents, (list, tuple)) or not 1 <= len(documents) <= 1000:
        raise ValueError("Expected one to 1000 evaluation records")
    index = {}
    for item in documents:
        if not isinstance(item, dict) or set(item) != fields or not _name(item["id"]) or item["id"] in index:
            raise ValueError("Invalid or duplicate evaluation record")
        index[item["id"]] = item
    return index


def evaluate(dataset, observations, *, manual=None):
    """Evaluate observed behavior. Human scores are kept apart from fixed assertions."""
    from llama_index.core.evaluation.retrieval.metrics import HitRate, MRR

    expected = _by_id(dataset, _DATASET_FIELDS)
    observed = _by_id(observations, _OBSERVATION_FIELDS)
    if expected.keys() != observed.keys():
        raise ValueError("Every evaluation case requires one observation")
    manual = {} if manual is None else manual
    if (not isinstance(manual, dict) or manual.keys() - expected.keys()
            or any(not _number(score) or score > 1 for score in manual.values())):
        raise ValueError("Manual scores must be between zero and one for known cases")
    cases = []
    for case_id in sorted(expected):
        target, actual = expected[case_id], observed[case_id]
        relevant, forbidden = _names(target["relevant"]), _names(target["forbidden"])
        support, cited = _names(target["supports_action"]), _names(actual["citations"])
        retrieved = _names(actual["retrieved"])
        blocked, wanted_blocks = _names(actual["blocked"]), _names(target["block"])
        limits = target["limits"]
        if (relevant & forbidden or not support <= relevant or (blocked | wanted_blocks) - _BLOCKS
                or any(item["action"] is not None and not _name(item["action"]) for item in (target, actual))
                or any(type(item["effects"]) is not int or not _number(item["effects"]) for item in (target, actual))
                or not isinstance(limits, dict) or limits.keys() - {"latency_ms", "cost_nanos"}
                or any(not _number(value) for value in limits.values())
                or any(actual[key] is not None and not _number(actual[key]) for key in ("latency_ms", "cost_nanos"))):
            raise ValueError("Invalid evaluation expectation or measurement")
        if target["action"] is not None and not support:
            raise ValueError("An expected action requires supporting evidence")

        measure = {"expected_ids": sorted(relevant), "retrieved_ids": actual["retrieved"]}
        metrics = {"hit_rate": HitRate().compute(**measure).score, "mrr": MRR().compute(**measure).score} if relevant and retrieved else {
            "hit_rate": 0.0 if relevant else None, "mrr": 0.0 if relevant else None,
        }
        checks = {"retrieval": relevant <= retrieved, "permission": not (retrieved | cited) & forbidden,
                  "legal_citations": cited <= retrieved,
                  "supports_action": actual["action"] is None or bool(cited & support),
                  "selected_action": actual["action"] == target["action"],
                  "effect_count": actual["effects"] == target["effects"], "blocked": wanted_blocks <= blocked}
        checks.update({key: actual[key] is not None and actual[key] <= cap for key, cap in limits.items()})
        cases.append({"id": case_id, "checks": checks, "retrieval_metrics": metrics,
                      "latency_ms": actual["latency_ms"], "cost_nanos": actual["cost_nanos"],
                      "passed": all(checks.values())})
    return {"dataset_digest": digest([expected[key] for key in sorted(expected)]),
            "observation_digest": digest([observed[key] for key in sorted(observed)]),
            "cases": cases, "passed": all(case["passed"] for case in cases), "manual_scores": manual}


def record_evaluation(store, identity, release_digest, dataset, observations, *, manual=None):
    """Bind an identical rerun to the same retained release without duplicate reports."""
    report = evaluate(dataset, observations, manual=manual)
    with store.transaction(tenant=identity.tenant, write=True) as connection:
        if not enabled(connection, identity.tenant):
            raise PermissionError("Enterprise mode is required")
        Policy().require(connection, identity, "read", "release", release_digest)
        Policy().require(connection, identity, "evaluate", "release", release_digest)
        report["release_digest"] = release_digest
        run_id = digest(report)
        connection.execute("""INSERT INTO knowledge_evaluations (tenant, release_digest, id, report)
            VALUES (?, ?, ?, ?) ON CONFLICT (tenant, id) DO NOTHING""",
            (identity.tenant, release_digest, run_id, encode(report)))
        saved = row_data(connection.execute("SELECT report FROM knowledge_evaluations WHERE tenant=? AND id=?",
                                            (identity.tenant, run_id)).fetchone(), "report")
        if saved is None or saved["report"] != report:
            raise ValueError("Evaluation record did not match its digest")
    return {"run_id": run_id, **report}


def publish_scores(client, report, traces):
    """Export only numeric scores to explicitly linked Langfuse traces."""
    pending = []
    for case in report["cases"]:
        trace_id = traces.get(case["id"])
        if trace_id is None:
            continue
        if type(trace_id) is not str or not re.fullmatch(r"[0-9a-f]{32}", trace_id) or int(trace_id, 16) == 0:
            raise ValueError("Invalid Langfuse trace ID")
        metrics = {"deterministic_pass": float(case["passed"]), **case["retrieval_metrics"]}
        if case["id"] in report["manual_scores"]:
            metrics["manual_review"] = report["manual_scores"][case["id"]]
        for metric, value in metrics.items():
            if value is not None:
                score_id = str(uuid5(NAMESPACE_URL, encode((report["run_id"], trace_id, case["id"], metric))))
                pending.append({"name": "ai_native." + metric, "value": value, "trace_id": trace_id, "score_id": score_id,
                                "data_type": "NUMERIC", "metadata": {"release_digest": report["release_digest"]}})
    for item in pending:
        client.create_score(**item)
    return len(pending)
