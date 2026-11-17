import json
import unittest
from pathlib import Path

from ai_native_system.gateway import ModelGateway, configured_gateway
from ai_native_system.model import DemoModel, OpenAICompatibleModel
from ai_native_system.registry import Registry
from ai_native_system.releases import ReleaseError, ReleaseSnapshot
from ai_native_system.remote import MCPRemote
from ai_native_system.tools import ToolRegistry


FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "conformance.json"


def registry_document():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class ReleaseSnapshotTests(unittest.TestCase):
    def test_existing_definition_remains_executable_and_snapshot_is_immutable(self):
        registry = Registry(registry_document())
        snapshot = ReleaseSnapshot.capture(registry, "collaboration", DemoModel(), ToolRegistry())
        expected = registry.definition("collaboration")
        registry.applications["collaboration"]["agents"][0]["instructions"] = "new instructions"
        exported = snapshot.to_document()
        exported["definition"]["applications"].clear()
        exported["ontology"].clear()

        self.assertEqual(snapshot.registry().definition("collaboration")[1], expected[1])
        self.assertEqual(snapshot.registry().definition("collaboration")[2], expected[2])
        self.assertNotEqual(snapshot.definition_hash, registry.definition("collaboration")[2])
        self.assertEqual(snapshot, ReleaseSnapshot.from_document(snapshot.to_document()))
        self.assertEqual(snapshot.to_document()["knowledge"]["references"], ["artifact-policy"])

    def test_gateway_and_remote_config_verify_destinations_and_allow_credential_rotation(self):
        definition = registry_document()
        definition["actions"]["verify_asset"].update(tool="remote", tool_version="1")
        registry = Registry(definition)

        def adapters(key, *, model_endpoint="https://model.example/v1", tool_endpoint="https://tool.example/mcp",
                     fallback_enabled=True):
            gateway = ModelGateway(default="primary", max_context_bytes=4096)
            gateway.register("primary", OpenAICompatibleModel(model_endpoint, "model-v2", key),
                             version="3", fallback="spare")
            gateway.register("spare", DemoModel(), enabled=fallback_enabled)
            tools = ToolRegistry()
            tools.register_remote("remote", "1", MCPRemote(tool_endpoint, "execute", "lookup", token=key))
            return gateway, tools

        snapshot = ReleaseSnapshot.capture(registry, "single", *adapters("credential-one"))
        document = snapshot.to_document()
        self.assertNotIn("credential-one", json.dumps(document))
        binding = document["models"]["stages"][0]
        self.assertEqual((binding["route"], binding["version"], binding["fallback"]["route"]), ("primary", "3", "spare"))
        self.assertEqual(document["tool"]["destination"]["lookup_tool"], "lookup")
        snapshot.check_adapters(*adapters("credential-two"))
        self.assertEqual(snapshot, ReleaseSnapshot.capture(registry, "single", *adapters("credential-two")))
        _, matching_tools = adapters("credential-two", fallback_enabled=False)
        snapshot.check_tool(matching_tools)
        for change in ({"model_endpoint": "https://other.example/v1"},
                       {"tool_endpoint": "https://other.example/mcp"}, {"fallback_enabled": False}):
            with self.subTest(change=change), self.assertRaises(ReleaseError):
                snapshot.check_adapters(*adapters("credential-two", **change))

    def test_snapshot_rejects_inconsistent_immutable_metadata(self):
        snapshot = ReleaseSnapshot.capture(Registry(registry_document()), "single", DemoModel(), ToolRegistry())
        for key, value in (("definition_hash", "0" * 64), ("ontology", {}), ("action", {}),
                           ("knowledge", {"references": [], "strategy": "current-by-id-v1"})):
            with self.subTest(key=key), self.assertRaises(ReleaseError):
                ReleaseSnapshot.from_document({**snapshot.to_document(), key: value})

    def test_retrieval_binding_is_immutable_without_changing_legacy_fingerprints(self):
        args = Registry(registry_document()), "collaboration", DemoModel(), ToolRegistry()
        legacy = ReleaseSnapshot.capture(*args)
        self.assertIsNone(legacy.retrieval_binding())
        self.assertEqual(legacy.digest, "ce690567da4463d0e55036509e2f7cbfd183e029c2e8cc4b90cf3c1d03497e27")

        binding = {"index_id": "production-v1", "method": "hybrid", "binding_digest": "a" * 64}
        pinned = ReleaseSnapshot.capture(*args, retrieval=binding)
        self.assertNotEqual(pinned.digest, legacy.digest)
        self.assertEqual(pinned, ReleaseSnapshot.from_document(pinned.to_document()))
        exported = pinned.retrieval_binding()
        self.assertEqual(exported, binding)
        exported["method"] = "exact"
        self.assertEqual(pinned.retrieval_binding(), binding)
        for invalid in ({**binding, "binding_digest": "invalid"}, {**binding, "index_id": "bad\nindex"},
                        {**binding, "method": "other"}, {**binding, "extra": True}):
            with self.subTest(invalid=invalid), self.assertRaises(ReleaseError):
                ReleaseSnapshot.capture(*args, retrieval=invalid)

    def test_archived_litellm_identity_stays_readable_but_cannot_substitute_current_adapter(self):
        example = FIXTURE.with_name("models-p5.json")
        gateway = configured_gateway(json.loads(example.read_text(encoding="utf-8")))
        tools = ToolRegistry()
        snapshot = ReleaseSnapshot.capture(Registry(registry_document()), "single", gateway, tools)
        document = snapshot.to_document()
        transport = document["models"]["stages"][0]["adapter"]["transport"]
        transport.update(backend="litellm-1.0.0", system_prompt_sha256="a" * 64)
        archive = ReleaseSnapshot.from_document(document)
        archive.check_tool(tools)
        with self.assertRaisesRegex(ReleaseError, "model binding changed"):
            archive.check_adapters(gateway, tools)
