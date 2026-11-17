"""Validate graph release identity and reject unbounded or executable settings."""

import unittest

from ai_native_system.gateway import ModelGateway
from ai_native_system.graph_contract import GraphSpec
from ai_native_system.model import DemoModel, OpenAICompatibleModel
from ai_native_system.registry import Registry
from ai_native_system.releases import ReleaseError, ReleaseSnapshot
from ai_native_system.tools import ToolRegistry

from test_releases import registry_document


class GraphContractTests(unittest.TestCase):
    def test_legacy_registry_and_release_identity_are_stable(self):
        registry = Registry(registry_document())
        snapshot = ReleaseSnapshot.capture(registry, "single", DemoModel(), ToolRegistry())
        self.assertEqual(registry.definition("single")[2],
                         "739e05368423307ddc6c62fa25c3849f8690fa51ed438f99c5b68305bdb6b443")
        self.assertEqual(snapshot.digest, "b97ba69f2fe4d3ddc6b4e953a6fb18e1f29829a53ed1f5722b7b13cdabedb768")
        self.assertNotIn("graph", snapshot.registry().applications["single"])

    def test_graph_options_are_frozen_with_the_selected_release(self):
        document = registry_document()
        original_hash = Registry(document).definition("collaboration")[2]
        graph = {"version": "workflow.1", "deadline_seconds": 90,
                 "checks": ["object_grounded", "relationships_grounded"],
                 "on_check_failure": "retry", "max_rounds": 3}
        document["applications"]["collaboration"]["graph"] = graph
        registry = Registry(document)
        snapshot = ReleaseSnapshot.capture(registry, "collaboration", DemoModel(), ToolRegistry())
        self.assertNotEqual(snapshot.definition_hash, original_hash)
        self.assertEqual(ReleaseSnapshot.from_document(snapshot.to_document()), snapshot)
        self.assertEqual(GraphSpec.from_document(snapshot.registry().applications["collaboration"]["graph"]),
                         GraphSpec("workflow.1", 90, ("object_grounded", "relationships_grounded"), "retry", 3))

        graph["version"] = "workflow.2"
        updated = ReleaseSnapshot.capture(registry, "collaboration", DemoModel(), ToolRegistry())
        self.assertNotEqual(updated.digest, snapshot.digest)
        document = snapshot.to_document()
        document["definition"]["applications"]["collaboration"]["graph"]["version"] = "tampered"
        with self.assertRaisesRegex(ReleaseError, "fingerprint"):
            ReleaseSnapshot.from_document(document)

    def test_graph_defaults_are_bounded(self):
        default = GraphSpec.from_document({"version": "workflow.1"})
        self.assertEqual(default, GraphSpec("workflow.1", 120, (), "block", 1))
        self.assertEqual(default, GraphSpec.from_document(default.to_document()))

    def test_unsafe_or_inconsistent_graph_documents_are_rejected(self):
        invalid_fields = (
            {"version": ""}, {"version": "?"}, {"version": True}, {"version": "x" * 65},
            {"deadline_seconds": True}, {"deadline_seconds": 0}, {"deadline_seconds": 86_401},
            {"checks": "object_grounded"}, {"checks": [{}]}, {"checks": ["arbitrary_sql"]},
            {"checks": ["object_grounded", "object_grounded"]}, {"on_check_failure": "execute"},
            {"on_check_failure": "retry"}, {"on_check_failure": "retry", "max_rounds": 2},
            {"max_rounds": 5}, {"max_rounds": 2}, {"max_rounds": True},
            {"nodes": ["write"]}, {"tools": ["anything"]}, {"edges": [["start", "loop"]]},
        )
        for fields in invalid_fields:
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                document = registry_document()
                document["applications"]["single"]["graph"] = {"version": "workflow.1", **fields}
                Registry(document)

    def test_graph_agent_instructions_cannot_declare_executable_tools(self):
        document = registry_document()
        app = document["applications"]["single"]
        app["graph"] = {"version": "workflow.1"}
        app["agents"][0]["tools"] = ["arbitrary-tool"]
        with self.assertRaisesRegex(ValueError, "agents can only declare"):
            Registry(document)
        app["agents"] = [{"id": f"agent-{index}", "instructions": "check"} for index in range(17)]
        with self.assertRaisesRegex(ValueError, "too many agents"):
            Registry(document)

    def test_graph_release_cannot_send_to_unmanaged_network_models(self):
        model = OpenAICompatibleModel("https://models.example/v1", "unmanaged")
        document = registry_document()
        tools = ToolRegistry()
        ReleaseSnapshot.capture(Registry(document), "single", model, tools)
        document["applications"]["single"]["graph"] = {"version": "workflow.1"}
        registry = Registry(document)
        with self.assertRaisesRegex(ReleaseError, "require a managed LiteLLM route"):
            ReleaseSnapshot.capture(registry, "single", model, tools)

        gateway = ModelGateway(default="demo")
        gateway.register("demo", DemoModel(), fallback="unmanaged")
        gateway.register("unmanaged", model)
        with self.assertRaisesRegex(ReleaseError, "require a managed LiteLLM route"):
            ReleaseSnapshot.capture(registry, "single", gateway, tools)
