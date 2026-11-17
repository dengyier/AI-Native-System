import json
import unittest

from ai_native_system.gateway import ModelGateway
from ai_native_system.model import ModelError, Proposal


class StubModel:
    def __init__(self, model, *, error=None):
        self.model = model
        self.error = error
        self.received = []

    def propose(self, context):
        self.received.append(context)
        if self.error:
            raise self.error
        return Proposal(None, "No action", (), provider="test-provider", model=self.model)


class ModelGatewayTests(unittest.TestCase):
    def test_agent_route_overrides_default_and_preserves_provider_identity(self):
        default = StubModel("default-model")
        specialist = StubModel("specialist-model")
        gateway = ModelGateway(default="general")
        gateway.register("general", default, version="v3", tags=["quick"])
        gateway.register("specialist", specialist, version="v1", tags=["review"])

        default_context = {"agent": {"id": "general-agent"}}
        specialist_context = {"agent": {"id": "review-agent", "model": "specialist"}}
        self.assertEqual(gateway.propose(default_context).model, "default-model")
        result = gateway.propose(specialist_context)
        self.assertEqual((result.provider, result.model), ("test-provider", "specialist-model"))
        self.assertEqual(default.received, [default_context])
        self.assertEqual(specialist.received, [specialist_context])
        self.assertEqual(gateway.list_models(), [
            {"name": "general", "version": "v3", "tags": ["quick"], "enabled": True, "fallback": None},
            {"name": "specialist", "version": "v1", "tags": ["review"], "enabled": True, "fallback": None},
        ])

    def test_unknown_or_disabled_routes_never_use_default_or_fallback(self):
        default = StubModel("default-model")
        disabled = StubModel("disabled-model")
        gateway = ModelGateway(default="general")
        gateway.register("general", default)
        gateway.register("disabled", disabled, enabled=False, fallback="general")

        for name in ("missing", "disabled", None, ["general"]):
            with self.subTest(name=name):
                with self.assertRaises(ModelError):
                    gateway.propose({"agent": {"model": name}})
        self.assertEqual(default.received, [])
        self.assertEqual(disabled.received, [])
        self.assertFalse(gateway.list_models()[0]["enabled"])

    def test_only_explicit_fallback_receives_failed_primary_request(self):
        bad = StubModel("unavailable", error=ModelError("private provider body"))
        alternate = StubModel("alternate-model")
        gateway = ModelGateway(default="general")
        gateway.register("general", bad, fallback="alternate")
        gateway.register("alternate", alternate)
        context = {"agent": {"id": "planner"}}

        result = gateway.propose(context)
        self.assertEqual((result.provider, result.model), ("test-provider", "alternate-model"))
        self.assertEqual(bad.received, [context])
        self.assertEqual(alternate.received, [context])

    def test_provider_failures_are_sanitized_and_fallback_is_one_hop(self):
        bad = StubModel("unavailable", error=ModelError("private primary body"))
        alternate = StubModel("broken-fallback", error=ModelError("private fallback body"))
        third = StubModel("third-model")
        gateway = ModelGateway(default="general")
        gateway.register("general", bad, fallback="alternate")
        gateway.register("alternate", alternate, fallback="third")
        gateway.register("third", third)

        with self.assertRaisesRegex(ModelError, "^model route and fallback failed$") as caught:
            gateway.propose({})
        self.assertTrue(caught.exception.__suppress_context__)
        self.assertEqual(third.received, [])

        standalone = ModelGateway(default="standalone")
        standalone.register("standalone", bad)
        with self.assertRaisesRegex(ModelError, "^model route failed$"):
            standalone.propose({})

    def test_disabled_fallback_never_receives_context(self):
        primary = StubModel("primary", error=ModelError("private primary body"))
        alternate = StubModel("disabled")
        gateway = ModelGateway(default="primary")
        gateway.register("primary", primary, fallback="alternate")
        gateway.register("alternate", alternate, enabled=False)

        with self.assertRaisesRegex(ModelError, "^model fallback is unavailable$"):
            gateway.propose({})
        self.assertEqual(alternate.received, [])

    def test_context_budget_counts_utf8_bytes_before_provider_call(self):
        context = {"agent": {"id": "评审"}}
        byte_count = len(json.dumps(context, ensure_ascii=False).encode("utf-8"))
        model = StubModel("test-model")
        gateway = ModelGateway(default="general", max_context_bytes=byte_count)
        gateway.register("general", model)

        self.assertEqual(gateway.propose(context).model, "test-model")
        oversized = {"agent": {"id": "评审人"}}
        with self.assertRaisesRegex(ModelError, "^model context exceeds the byte limit$"):
            gateway.propose(oversized)
        self.assertEqual(model.received, [context])


if __name__ == "__main__":
    unittest.main()
