"""Attach a deterministic fact prerequisite to a draft application release."""

from .registry import is_name
from .releases import ReleaseStore
from .storage import row_data


def binding_for(connection, tenant, release_digest):
    return row_data(connection.execute(
        """SELECT rule_name, feedback_source, feedback_stream FROM fact_rule_bindings
           WHERE tenant = ? AND release_digest = ?""",
        (tenant, release_digest),
    ).fetchone())


def bind_rule(connection, tenant, release_digest, rule_name, *, actor, feedback_source=None, feedback_stream=None):
    if not all(map(is_name, (actor, rule_name))):
        raise ValueError("Supply a rule name and operator")
    if (feedback_source is not None or feedback_stream is not None) and not all(
        map(is_name, (feedback_source, feedback_stream))
    ):
        raise ValueError("A feedback source requires both source and stream")
    prior = binding_for(connection, tenant, release_digest)
    expected = {"rule_name": rule_name, "feedback_source": feedback_source, "feedback_stream": feedback_stream}
    if prior is not None:
        if prior != expected:
            raise ValueError("The release already has a different fact rule binding")
        return prior
    record = ReleaseStore.get(connection, tenant, release_digest)
    if record is None or record.status != "draft":
        raise ValueError("Bind the rule while the release is a draft")
    snapshot = record.snapshot
    _, action, _ = snapshot.registry().definition(snapshot.application)
    rule = snapshot.ontology().to_document()["rules"].get(rule_name)
    if rule is None or rule["object_type"] != action["object_type"]:
        raise ValueError("Rule and action must target the same ontology type")
    destination = snapshot.to_document()["tool"]["destination"]
    if feedback_source is not None:
        if destination is None:
            raise ValueError("Source feedback requires a remote tool")
        source_binding = destination.get("source_binding")
        if source_binding is not None and feedback_source != source_binding["source"]:
            raise ValueError("Feedback must come from the conditional write authority")
    connection.execute(
        """INSERT INTO fact_rule_bindings
           (tenant, release_digest, rule_name, feedback_source, feedback_stream, bound_by)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (tenant, release_digest, rule_name, feedback_source, feedback_stream, actor),
    )
    return expected


def assess(connection, store, ontology, tenant, object_type, object_id, binding, *, observed_at=None):
    from .fact_contracts import ObjectIdentity
    from .facts import Facts
    from .rules import RuleEvaluator

    subject = ObjectIdentity(tenant, object_type, object_id)
    return RuleEvaluator(Facts(store, tenant)).evaluate(connection, ontology, binding["rule_name"], subject,
                                                       known_at=observed_at)
