"""Exercise the model ledger against PostgreSQL and a limited runtime role."""

import os
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

from ai_native_system.adapters.postgres_runtime import PostgresRuntimeStore
from ai_native_system.model_accounting import ModelAccounting, ModelBudgetError, ModelLimits, ModelPrice

from p2b_support import restricted_role


TEST_DSN = os.environ.get("AI_NATIVE_P5_TEST_DSN")
GRANTS = [
    "SELECT ON ai_native.governed_tenants, ai_native.fact_rule_bindings, ai_native.owp_enforced_tenants, ai_native.p4_sequence_steps",
    "SELECT, INSERT ON ai_native.model_calls, ai_native.model_attempts",
    "UPDATE (outcome, input_tokens, output_tokens, actual_provider, actual_model, finished_at) ON ai_native.model_attempts",
]


@unittest.skipUnless(TEST_DSN, "Requires a disposable PostgreSQL P5 database")
class ModelAccountingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = cls.enterClassContext(PostgresRuntimeStore(restricted_role(GRANTS, TEST_DSN)))
        cls.accounting = ModelAccounting(cls.store)
        cls.price = ModelPrice("price-v1", 2, 5)

    def setUp(self):
        self.tenant = "p5-" + uuid4().hex

    def open_call(self, call_id="call", *, max_active=2, max_attempts=2, max_tokens=100, max_cost_nanos=80):
        limits = ModelLimits(max_active, max_attempts, max_tokens, max_cost_nanos, 60)
        self.accounting.open_call(self.tenant, call_id, limits=limits)
        return limits

    def reserve(self, call_id="call", *, timeout_seconds=5, admit=None):
        return self.accounting.reserve(
            self.tenant, call_id, route="route", provider="provider", model="model", model_version="model-v1",
            max_input_tokens=10, max_output_tokens=4, price=self.price, timeout_seconds=timeout_seconds, admit=admit,
        )

    def test_attempts_charge_actual_or_reserve_and_settle_once(self):
        limits = self.open_call()
        self.accounting.open_call(self.tenant, "call", limits=limits)
        first = self.reserve()
        self.assertGreater(first.remaining_seconds(), 0)
        self.assertLessEqual(first.remaining_seconds(), 5)
        self.accounting.settle(first, outcome="failed", input_tokens=4, actual_provider="actual")
        second = self.reserve()
        for _ in range(2):
            self.accounting.settle(second, outcome="succeeded", input_tokens=6, output_tokens=2, actual_model="actual-v2")
        with self.assertRaises(ValueError):
            self.accounting.settle(second, outcome="succeeded", input_tokens=7, output_tokens=2)
        with self.assertRaisesRegex(ModelBudgetError, "attempts"):
            self.reserve()
        usage = self.accounting.usage(self.tenant, "call")
        totals = usage["totals"]
        self.assertEqual(totals["attempts"], 2)
        self.assertEqual(totals["input_tokens"], 10)
        self.assertEqual(totals["output_tokens"], 2)
        self.assertEqual(totals["charged_tokens"], 16)
        self.assertEqual(totals["charged_cost_nanos"], 50)
        self.assertEqual(totals["unknown_usage_attempts"], 1)
        self.assertEqual(usage["attempts"][1]["outcome"], "failed")
        self.assertIsNone(usage["attempts"][1]["actual_cost_nanos"])
        self.assertEqual(usage["attempts"][0]["actual_cost_nanos"], 22)
        self.assertEqual(usage["attempts"][0]["actual_model"], "actual-v2")
        self.assertEqual(usage["attempts"][0]["price_version"], "price-v1")
        other = self.accounting.usage(self.tenant + "-other", "call")
        self.assertEqual(other["attempts"], [])
        self.assertEqual(other["totals"]["attempts"], 0)

    def test_concurrent_calls_reserve_one_shared_tenant_slot(self):
        for call_id in ("one", "two"):
            self.open_call(call_id, max_active=1)

        def attempt(call_id):
            try:
                return self.reserve(call_id)
            except ModelBudgetError as error:
                return error.reason

        with ThreadPoolExecutor(max_workers=2) as pool:
            admitted = list(pool.map(attempt, ("one", "two")))
        self.assertEqual(admitted.count("concurrency"), 1)
        permit = next(result for result in admitted if result != "concurrency")
        self.accounting.settle(permit, outcome="timeout")
        self.assertEqual(self.accounting.usage(self.tenant)["totals"]["active_attempts"], 1)
        self.accounting.settle(permit, outcome="failed", input_tokens=3, output_tokens=0)
        self.assertEqual(self.accounting.usage(self.tenant)["totals"]["active_attempts"], 0)
        self.assertEqual(self.reserve("two" if permit.call_id == "one" else "one").ordinal, 1)

    def test_expired_worker_keeps_unknown_spend_and_late_usage_can_exceed_reserve(self):
        self.open_call(max_cost_nanos=40, max_active=1)
        permit = self.reserve(timeout_seconds=0.05)
        stop = time.monotonic() + 2
        while self.accounting.usage(self.tenant)["totals"]["active_attempts"]:
            self.assertLess(time.monotonic(), stop)
            time.sleep(0.01)
        usage = self.accounting.usage(self.tenant)
        self.assertEqual(usage["attempts"][0]["outcome"], "unknown")
        self.assertEqual(usage["totals"]["charged_cost_nanos"], 40)
        with self.assertRaisesRegex(ModelBudgetError, "cost"):
            self.reserve()
        self.accounting.settle(permit, outcome="succeeded", input_tokens=100, output_tokens=0)
        usage = self.accounting.usage(self.tenant)
        self.assertEqual(usage["attempts"][0]["actual_cost_nanos"], 200)
        self.assertTrue(usage["attempts"][0]["exceeded_reservation"])
        self.assertEqual(usage["totals"]["charged_cost_nanos"], 200)

    def test_active_admission_can_refuse_or_clip_and_settlement_is_atomic(self):
        self.open_call()
        with self.assertRaisesRegex(ModelBudgetError, "deadline"):
            self.reserve(admit=lambda connection: 0)
        self.assertEqual(self.accounting.usage(self.tenant)["totals"]["attempts"], 0)

        def authorize(connection):
            self.assertEqual(connection.execute("SELECT current_setting('ai_native.tenant')").fetchone()[0], self.tenant)
            return 0.5

        permit = self.reserve(admit=authorize)
        self.assertGreater(permit.remaining_seconds(), 0)
        self.assertLess(permit.remaining_seconds(), 0.5)

        def reject_observation(connection, row):
            self.assertEqual(row["actual_cost_nanos"], 4)
            raise RuntimeError("queue not ready")

        with self.assertRaisesRegex(RuntimeError, "queue not ready"):
            self.accounting.settle(permit, outcome="succeeded", input_tokens=2, output_tokens=0,
                                   callback=reject_observation)
        self.assertEqual(self.accounting.usage(self.tenant)["totals"]["charged_cost_nanos"], 40)
        observed = []
        for _ in range(2):
            self.accounting.settle(permit, outcome="succeeded", input_tokens=2, output_tokens=0,
                                   callback=lambda connection, row: observed.append(row))
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0]["attempt_id"], permit.attempt_id)
        self.assertEqual(self.accounting.usage(self.tenant)["totals"]["charged_cost_nanos"], 4)
