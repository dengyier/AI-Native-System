"""Compare authorized remote intents with source observations and receipts."""
from .fact_contracts import ChangeKind
from .storage import encode, row_data


def expect(connection, payload, target_type, binding):
    """Anchor a remote intent to the source that can confirm its state change."""
    if binding is None or binding["feedback_source"] is None:
        return
    connection.execute(
        """INSERT INTO fact_feedback_expectations
           (tenant, operation_id, source, stream, object_type, object_id, expected_state, request_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING""",
        (payload["tenant"], payload["operation_id"], binding["feedback_source"], binding["feedback_stream"],
         target_type, payload["object_id"], payload["to_state"], payload["request_hash"]),
    )


def observe(connection, event, stream, target):
    """Record source evidence without creating effects or invoking tools."""
    if event.operation_id is None:
        return
    expected = connection.execute(
        """SELECT * FROM fact_feedback_expectations
           WHERE tenant = ? AND operation_id = ? AND source = ? AND stream = ?""",
        (event.identity.tenant, event.operation_id, event.identity.source, stream),
    ).fetchone()
    if expected is None:
        return
    if event.kind == ChangeKind.UPSERT and "state" not in event.payload:
        return
    state = event.payload["state"] if event.kind == ChangeKind.UPSERT else None
    match = (target.object_type, target.object_id, state) == (
        expected["object_type"], expected["object_id"], expected["expected_state"],
    )
    version = encode(event.version.token) if event.version is not None else None
    connection.execute(
        """INSERT INTO fact_feedback_observations (tenant, operation_id, source, event_id, matches, source_version_token)
           VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING""",
        (event.identity.tenant, event.operation_id, event.identity.source, event.event_id, match, version),
    )


def receipt(connection, payload, status, *, source_version=None):
    if status not in ("succeeded", "rejected"):
        return
    if source_version is not None:
        connection.execute(
            """UPDATE fact_feedback_expectations SET receipt_status = ?, expected_source_version = ?
               WHERE tenant = ? AND operation_id = ? AND request_hash = ? AND receipt_status IS NULL""",
            (status, encode(source_version), payload["tenant"], payload["operation_id"], payload["request_hash"]),
        )
        return
    connection.execute(
        """UPDATE fact_feedback_expectations SET receipt_status = ?
           WHERE tenant = ? AND operation_id = ? AND request_hash = ? AND receipt_status IS NULL""",
        (status, payload["tenant"], payload["operation_id"], payload["request_hash"]),
    )


def status(connection, tenant, operation_id):
    row = row_data(connection.execute(
        """SELECT expectation.receipt_status,
                  bool_and(observation.matches AND (expectation.expected_source_version IS NULL
                      OR observation.source_version_token IS NOT DISTINCT FROM expectation.expected_source_version))
                      AS observations_agree,
                  count(observation.event_id) AS observations
           FROM fact_feedback_expectations expectation
           LEFT JOIN fact_feedback_observations observation USING (tenant, operation_id)
           WHERE expectation.tenant = ? AND expectation.operation_id = ?
           GROUP BY expectation.receipt_status""",
        (tenant, operation_id),
    ).fetchone())
    if row is None:
        return None
    if row["observations"] and (not row["observations_agree"] or row["receipt_status"] == "rejected"):
        return "conflict"
    if row["receipt_status"] == "rejected":
        return "rejected"
    if row["receipt_status"] == "succeeded" and row["observations"]:
        return "matched"
    if row["receipt_status"] == "succeeded":
        return "waiting_source"
    if row["observations"]:
        return "waiting_receipt"
    return "waiting_both"
