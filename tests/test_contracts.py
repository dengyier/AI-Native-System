import unittest
from pathlib import Path

from ai_native_system.contracts import (
    AcceptanceStatus, ActionDefinition, ActionKind, ActionReceipt, ActionRequest, AffectedObject,
    AttemptRef, EffectStatus, EvidenceStatus, LegacyOperationRef, OperationRef, OperationStatus,
    TaskProgress, TaskRef,
)
from ai_native_system.fact_contracts import CollectionRead, FactReadSet, ObjectIdentity, SourceIdentity, SourceVersion
from ai_native_system.registry import Registry
from ai_native_system.remote import HttpRemote
from ai_native_system.storage import digest
from ai_native_system.tools import ToolRegistry


class ActionContractTests(unittest.TestCase):
    def setUp(self):
        self.task = TaskRef("tenant-a", "operator", "task-1", "workspace/2")
        self.operation = OperationRef(self.task, "step-1", "operation-1")
        self.target = ObjectIdentity("tenant-a", "document", "doc-1")

    def test_query_and_generation_can_omit_target_but_saved_artifacts_have_scope(self):
        read = ActionDefinition("search", 1, ActionKind.READ, parameters={"query": {"type": "string"}})
        generate = ActionDefinition("summarize", 1, ActionKind.GENERATE, artifact_scope="drafts")
        self.assertIsNone(ActionRequest(self.operation, read, {"query": "会议"}).to_document()["target"])
        self.assertEqual(ActionRequest(self.operation, generate, {}, artifact_scope="drafts").artifact_scope, "drafts")
        with self.assertRaisesRegex(ValueError, "outside the declared scope"):
            ActionRequest(self.operation, generate, {}, artifact_scope="published")
        with self.assertRaisesRegex(ValueError, "Only generation"):
            ActionDefinition("search", 1, "read", artifact_scope="drafts")

    def test_action_schema_checks_arguments_tool_mode_and_target(self):
        with self.assertRaisesRegex(ValueError, "Task requires"):
            TaskRef("tenant-a", ActionKind.READ, "task-1", "workspace/2")
        with self.assertRaisesRegex(ValueError, "requires a destination"):
            ActionDefinition("rename", 1, "write_remote", "document", tool="update", tool_version="1")
        with self.assertRaisesRegex(ValueError, "cannot declare business writes"):
            ActionDefinition("read", 1, "read", "document", write_fields=("title",))
        update = ActionDefinition.from_document("rename", {
            "version": 2, "kind": "write_local", "target_type": "document", "tool": "update", "tool_version": "1",
            "parameters": {"title": {"type": "string"}, "priority": {"type": "integer", "required": False}},
            "write_fields": ["title"],
        })
        with self.assertRaisesRegex(ValueError, "requires a target"):
            ActionRequest(self.operation, update, {"title": "Q2 plan"})
        for invalid in ({}, {"title": None}, {"title": "Q2", "priority": True}, {"title": "Q2", "admin": True}):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                ActionRequest(self.operation, update, invalid, self.target)
        with self.assertRaisesRegex(ValueError, "outside the declared scope"):
            ActionRequest(self.operation, update, {"title": "Q2"}, ObjectIdentity("tenant-b", "document", "doc-1"))
        self.assertEqual(ActionDefinition.from_document("rename", update.to_document()), update)

    def test_retries_bind_one_operation_and_changed_membership_changes_digest(self):
        definition = ActionDefinition("search", 1, "read", parameters={"query": {"type": "string"}})
        scope = {"source": "doc-1", "relation": "attachments"}
        original = FactReadSet("tenant-a", collections=(CollectionRead("tenant-a", "relationship", scope, 1, ("one",)),))
        changed = FactReadSet("tenant-a", collections=(CollectionRead("tenant-a", "relationship", scope, 2, ("one", "two")),))
        arguments = {"query": "允许"}
        request = ActionRequest(self.operation, definition, arguments, read_set=original)
        first = AttemptRef(self.operation, "attempt-1", "trace-1")
        second = AttemptRef(self.operation, "attempt-2", "trace-2")
        self.assertNotEqual(first, second)
        original_digest = request.request_digest
        arguments["query"] = "tampered"
        self.assertEqual(request.request_digest, original_digest)
        self.assertEqual(ActionRequest(second.operation, definition, {"query": "允许"}, read_set=original).request_digest,
                         original_digest)
        self.assertNotEqual(ActionRequest(second.operation, definition, {"query": "允许"}, read_set=changed).request_digest,
                            original_digest)
        with self.assertRaisesRegex(ValueError, "Read set tenant"):
            ActionRequest(self.operation, definition, {"query": "允许"}, read_set=FactReadSet("tenant-b"))

    def test_evidence_and_human_acceptance_cannot_restart_successful_or_unknown_effect(self):
        self.assertTrue(OperationStatus(TaskProgress.READY).eligible_for_initial_dispatch)
        for effect in (EffectStatus.SUCCEEDED, EffectStatus.UNKNOWN, EffectStatus.PARTIAL):
            for evidence in (EvidenceStatus.PENDING, EvidenceStatus.INVALID, EvidenceStatus.VERIFIED):
                status = OperationStatus(TaskProgress.READY, effect, evidence, AcceptanceStatus.REJECTED)
                self.assertFalse(status.eligible_for_initial_dispatch)
        self.assertFalse(OperationStatus(TaskProgress.CANCELLED).eligible_for_initial_dispatch)

    def test_receipt_binds_operation_and_opaque_source_version(self):
        definition = ActionDefinition("submit", 1, "write_remote", "document", tool="write", tool_version="1",
                                      destination="vault", result={"reference": {"type": "string"}})
        request = ActionRequest(self.operation, definition, {}, self.target)
        version = SourceVersion(SourceIdentity("tenant-a", "vault", "document", "source-1"), "epoch-1", 'W/"c21b"')
        receipt = ActionReceipt(self.operation, request.request_digest, "succeeded", "vault", {"reference": "a1"},
                                (AffectedObject(self.target, source_version=version),))
        receipt.validate_for(request)
        self.assertEqual(receipt.affected[0].source_version.token, 'W/"c21b"')
        with self.assertRaisesRegex(ValueError, "does not belong"):
            receipt.validate_for(ActionRequest(OperationRef(self.task, "step-2", "operation-2"), definition, {}, self.target))
        with self.assertRaisesRegex(ValueError, "Only confirmed outcomes"):
            ActionReceipt(self.operation, request.request_digest, "pending", "vault", affected=(AffectedObject(self.target),))

    def test_receipt_cannot_assert_write_effects_outside_digest_bound_targets(self):
        other = ObjectIdentity("tenant-a", "document", "doc-2")
        write = ActionDefinition("update", 1, "write_local", "document", tool="update", tool_version="1")
        single = ActionRequest(self.operation, write, {}, self.target)
        multiple = ActionRequest(self.operation, write, {}, self.target, additional_targets=(other,))
        self.assertNotEqual(single.request_digest, multiple.request_digest)
        ActionReceipt(self.operation, multiple.request_digest, "partial", "local",
                      affected=(AffectedObject(other),)).validate_for(multiple)
        read = ActionRequest(self.operation, ActionDefinition("get", 1, "read", "document"), {}, self.target)
        for request, effect in ((single, other), (read, self.target)):
            with self.subTest(kind=request.definition.kind), self.assertRaisesRegex(ValueError, "outside.*write targets"):
                ActionReceipt(self.operation, request.request_digest, "succeeded", "local",
                              affected=(AffectedObject(effect),)).validate_for(request)

    def test_legacy_request_and_application_hashes_are_unchanged(self):
        payload = {"operation_id": "legacy-task-id", "tenant": "tenant-a", "object_id": "文档", "expected_version": 7}
        payload["request_hash"] = digest(payload)
        reference = LegacyOperationRef.from_payload(payload)
        self.assertEqual((reference.operation_id, reference.request_hash), ("legacy-task-id", payload["request_hash"]))
        with self.assertRaisesRegex(ValueError, "does not match"):
            LegacyOperationRef.from_payload({**payload, "expected_version": 8})
        registry = Registry.load(Path(__file__).resolve().parents[1] / "fixtures" / "conformance.json")
        tools = ToolRegistry()
        action_name = registry.applications["single"]["action"]
        contract = registry.action_contract(action_name, tools)
        self.assertEqual(contract.kind, ActionKind.WRITE_LOCAL)
        self.assertIn(action_name, registry.ontology().to_document()["rules"])
        tools.register_remote("partner", "1", HttpRemote("https://test.invalid/base"))
        registry.actions[action_name].update(tool="partner", tool_version="1")
        remote = registry.action_contract(action_name, tools)
        self.assertEqual(remote.kind, ActionKind.WRITE_REMOTE)
        self.assertIn("https://test.invalid/base", remote.destination)
        del registry.actions[action_name]["tool"]
        del registry.actions[action_name]["tool_version"]
        self.assertEqual(registry.definition("single")[2], "739e05368423307ddc6c62fa25c3849f8690fa51ed438f99c5b68305bdb6b443")
        self.assertEqual(registry.definition("collaboration")[2], "1f82b16bf1130aed04a1dc75c774fd3fd951105a248c1f4017e862ef733dddb8")


if __name__ == "__main__":
    unittest.main()
