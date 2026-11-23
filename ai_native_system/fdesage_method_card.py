"""Map one source-declared closed FDE intent snapshot into existing AINS APIs.

The declared stream is the card and its current immutable intent payload only.
It is not a CDC feed, source-wide coverage or a guarantee of current permission.
"""

import re
from dataclasses import dataclass
from datetime import datetime, timezone

from .fact_contracts import ChangeKind, Coverage, SnapshotBoundary, SourceCursor, SourceEvent, SourceIdentity, SourceVersion
from .fdesage_source import SOURCE, TENANT
from .registry import Registry
from .storage import digest


APPLICATION = "fde-method-card-verification"
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}")
_DIGEST = re.compile(r"[0-9a-f]{64}")
_UTC = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z")


@dataclass(frozen=True)
class IntentSnapshot:
    boundary: SnapshotBoundary
    events: tuple[SourceEvent, ...]
    position: int


def _integer(value):
    return type(value) is int and 1 <= value <= 9007199254740991


def _capture(intent):
    if (type(intent) is not dict or intent.get("namespace") != TENANT
            or intent.get("recordProfile") != "fde-method-card-submission/1"
            or type(intent.get("payloadVersion")) is not int or intent["payloadVersion"] != 1
            or type(intent.get("id")) is not str or _UUID.fullmatch(intent["id"]) is None
            or not _integer(intent.get("cardId")) or not _integer(intent.get("cardRevision"))
            or not _integer(intent.get("expiresAt")) or type(intent.get("cardKey")) is not str or not intent["cardKey"]
            or type(intent.get("sourceEpoch")) is not str or not intent["sourceEpoch"]
            or not all(type(intent.get(name)) is str and _DIGEST.fullmatch(intent[name]) is not None
                       for name in ("contentDigest", "submissionDigest"))):
        raise ValueError("Expected a source-declared immutable FDE method-card intent")
    if intent.get("nativeVersion") != f"revision:{intent['cardRevision']}:sha256:{intent['contentDigest']}":
        raise ValueError("Source card revision and content digest disagree")
    source = intent.get("sourceSnapshot")
    if (type(source) is not dict or source.keys() != {
            "profile", "stream", "snapshotRevision", "bookmark", "coverage", "capturedAt", "records"}
            or source["profile"] != "fdesage-method-card-intent-snapshot/1"
            or source["stream"] != "method-card-review:" + str(intent["cardId"])
            or type(source["snapshotRevision"]) is not int or source["snapshotRevision"] != intent["cardRevision"]
            or source["bookmark"] != intent["submissionDigest"] or source["coverage"] != "selected_records"):
        raise ValueError("No complete source-declared scope for this closed intent snapshot")
    expected = [
        {"recordType": "method_cards", "recordId": str(intent["cardId"]), "nativeVersion": intent["nativeVersion"],
         "sequence": intent["cardRevision"], "state": "draft"},
        {"recordType": "method_card_submissions", "recordId": intent["id"], "nativeVersion": intent["submissionDigest"],
         "sequence": 1, "state": "recorded"},
    ]
    if (type(source["records"]) is not list or source["records"] != expected
            or any(type(record.get("sequence")) is not int for record in source["records"])):
        raise ValueError("Closed intent snapshot must contain all and only the two declared native records")
    try:
        if type(source["capturedAt"]) is not str or _UTC.fullmatch(source["capturedAt"]) is None:
            raise ValueError()
        captured_at = datetime.fromisoformat(source["capturedAt"].replace("Z", "+00:00"))
        if captured_at.timestamp() >= intent["expiresAt"]:
            raise ValueError()
    except (ValueError, OverflowError):
        raise ValueError("Use the original source UTC capture time before intent expiry") from None
    return source, captured_at


def intent_snapshot(intent):
    source, captured_at = _capture(intent)
    submission_id = "method-card-submission:" + intent["id"]
    cursor = SourceCursor(TENANT, SOURCE, source["stream"], intent["sourceEpoch"], source["bookmark"])
    boundary = SnapshotBoundary(TENANT, SOURCE, source["bookmark"], intent["sourceEpoch"], captured_at,
                                captured_at, Coverage.COMPLETE, cursor)
    events = []
    for index, record in enumerate(source["records"]):
        identity = SourceIdentity(TENANT, SOURCE, record["recordType"], record["recordId"])
        version = SourceVersion(identity, intent["sourceEpoch"], record["nativeVersion"], record["sequence"])
        if index == 0:
            payload = {
                "state": "draft", "properties": {"label": intent["cardKey"], "content_digest": intent["contentDigest"]},
                "relations": [{"type": "method_card.submission", "id": "submission", "target_type": "fdesage_method_submission",
                               "target_id": submission_id, "properties": {}}],
            }
        else:
            payload = {"state": "recorded", "properties": {"submission_digest": intent["submissionDigest"]}, "relations": []}
        event_id = "fde-intent-record:" + digest({"snapshot": source["bookmark"], "record": record})
        events.append(SourceEvent(event_id, identity, ChangeKind.UPSERT, datetime.now(timezone.utc), payload,
                                  version, cursor, captured_at))
    return IntentSnapshot(boundary, tuple(events), source["snapshotRevision"])


def intent_registry(intent, *, reviewer_actor):
    """Declare the one real action; the separately trusted operator chooses the human reviewer."""
    _capture(intent)
    requester = intent.get("requester")
    if (type(requester) is not dict or type(requester.get("actor")) is not str or not requester["actor"]
            or type(reviewer_actor) is not str or not reviewer_actor or reviewer_actor == requester["actor"]
            or reviewer_actor == "fde-method-executor" or requester["actor"] == "fde-method-executor"):
        raise ValueError("Configure an independent requester, human reviewer and executor")
    card_id, submission_id = "method-card:" + str(intent["cardId"]), "method-card-submission:" + intent["id"]
    return Registry({
        "applications": {APPLICATION: {
            "id": APPLICATION, "version": "1", "action": "verify_method_card", "executor": "fde-method-executor",
            "agents": [{"id": "method-card-review-planner", "instructions":
                        "依据固定版本内容摘要和已记录申请提出审核建议；人工批准由后续独立评审完成。"}],
            "knowledge": ["fde-method-card-policy"],
        }},
        "actions": {"verify_method_card": {
            "version": "1", "description": "对本次申请的指定版本草稿，取得独立人工批准后由源端条件执行。",
            "object_type": "method_card", "from_state": "draft", "to_state": "verified",
            "requires_properties": {},
            "requires_link_states": {"submission": "recorded"},
            "request_role": "request", "approval_role": "approve", "execute_role": "execute",
            "tool": "method-card.verify", "tool_version": "1",
        }},
        "types": {
            "method_card": {"states": ["draft", "verified"], "fields": {"label": "string", "content_digest": "string"},
                            "links": {"submission": "fdesage_method_submission"}},
            "fdesage_method_submission": {"states": ["recorded"], "fields": {"submission_digest": "string"}, "links": {}},
        },
        "seed": {
            "actors": [{"tenant": TENANT, "id": actor, "roles": [role]} for actor, role in (
                (requester["actor"], "request"), (reviewer_actor, "approve"), ("fde-method-executor", "execute"))],
            "objects": [
                {"tenant": TENANT, "id": card_id, "type": "method_card", "state": "draft", "version": intent["cardRevision"],
                 "properties": {"label": intent["cardKey"], "content_digest": intent["contentDigest"]},
                 "links": {"submission": submission_id}},
                {"tenant": TENANT, "id": submission_id, "type": "fdesage_method_submission", "state": "recorded", "version": 1,
                 "properties": {"submission_digest": intent["submissionDigest"]}, "links": {}},
            ],
            "knowledge": [{"tenant": TENANT, "id": "fde-method-card-policy", "version": 1, "text":
                           "仅允许本次固定内容摘要对应的草稿；申请记录不代表人工批准。实际执行仍由FDE源端核对当前权限、撤销、期限及版本。"}],
        },
    })
