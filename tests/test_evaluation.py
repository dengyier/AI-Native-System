import unittest
from importlib.util import find_spec
from unittest.mock import Mock

from ai_native_system.evaluation import evaluate, publish_scores


def expectations(case_id="supported", **updates):
    return {"id": case_id, "relevant": ["same-policy", "supporting"], "forbidden": ["outside-scope"],
            "supports_action": ["supporting"], "action": "allowed-action", "effects": 1,
            "block": [], "limits": {"latency_ms": 500, "cost_nanos": 500}, **updates}


def observation(case_id="supported", **updates):
    return {"id": case_id, "retrieved": ["related", "same-policy", "supporting"], "citations": ["supporting"],
            "action": "allowed-action", "effects": 1, "blocked": [], "latency_ms": 100, "cost_nanos": 100, **updates}


@unittest.skipUnless(find_spec("llama_index"), "Install the locked LlamaIndex integration")
class KnowledgeEvaluationTests(unittest.TestCase):
    def test_ranked_retrieval_and_independent_human_scores(self):
        report = evaluate([expectations()], [observation()], manual={"supported": 0.25})
        self.assertEqual(report["cases"][0]["retrieval_metrics"], {"hit_rate": 1.0, "mrr": 0.5})
        self.assertTrue(report["passed"])
        self.assertEqual(report["manual_scores"], {"supported": 0.25})

    def test_valid_citation_that_does_not_support_action_fails(self):
        result = evaluate([expectations()], [observation(citations=["same-policy"])])["cases"][0]
        self.assertTrue(result["checks"]["legal_citations"])
        self.assertFalse(result["checks"]["supports_action"])
        self.assertFalse(result["passed"])

    def test_permission_injection_contradiction_idempotence_latency_and_cost(self):
        expected = expectations(action=None, effects=0, block=["prompt_injection", "contradiction"])
        measured = observation(action=None, effects=0, blocked=["prompt_injection", "contradiction"])
        self.assertTrue(evaluate([expected], [measured])["passed"])
        cases = (
            ({"retrieved": ["same-policy", "supporting", "outside-scope"]}, "permission"),
            ({"blocked": ["prompt_injection"]}, "blocked"),
            ({"effects": 2}, "effect_count"), ({"latency_ms": 501}, "latency_ms"),
            ({"cost_nanos": None}, "cost_nanos"),
        )
        for change, assertion in cases:
            with self.subTest(assertion=assertion):
                measured_bad = {**measured, **change}
                report = evaluate([expected], [measured_bad])
                self.assertFalse(report["cases"][0]["checks"][assertion])
                self.assertFalse(report["passed"])

    def test_langfuse_emits_only_repeatable_numeric_scores(self):
        report = {**evaluate([expectations()], [observation()], manual={"supported": 0.5}),
                  "release_digest": "a" * 64, "run_id": "b" * 64}
        client = Mock()
        self.assertEqual(publish_scores(client, report, {"supported": "c" * 32}), 4)
        first = client.create_score.call_args_list[:]
        publish_scores(client, report, {"supported": "c" * 32})
        self.assertEqual(first, client.create_score.call_args_list[4:])
        for call in first:
            self.assertEqual(call.kwargs["metadata"], {"release_digest": "a" * 64})
            self.assertEqual(call.kwargs["data_type"], "NUMERIC")
