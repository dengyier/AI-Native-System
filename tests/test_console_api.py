"""Exercise P8 views with real PostgreSQL, HTTP, and independent approval."""

import json
import os
import socket
import subprocess
import threading
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import urlopen

from ai_native_system.adapters.owp import key_id
from ai_native_system.api import make_server
from ai_native_system.applications import ApplicationCatalog
from ai_native_system.client import APIError, Client
from ai_native_system.evidence import deliver_effect, sign_effect
from ai_native_system.releases import ReleaseStore

from p2b_support import restricted_role
from test_security_entry import SecureWorkflowFixture


DSN = os.environ.get("AI_NATIVE_P8_TEST_DSN")


class _FixtureIdentity:
    def __init__(self, tokens):
        self.tokens = tokens

    def authenticate(self, bearer):
        if bearer not in self.tokens:
            raise PermissionError("Unknown fixture credential")
        return self.tokens[bearer]


@unittest.skipUnless(DSN, "Use verify_p8.py against PostgreSQL")
class ConsoleAPITests(SecureWorkflowFixture, unittest.TestCase):
    test_dsn = DSN
    runtime_grants = SecureWorkflowFixture.runtime_grants + ("INSERT ON ai_native.task_handover",)

    def setUp(self):
        super().setUp()
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        self.attestation_key = Ed25519PrivateKey.generate()
        public = self.attestation_key.public_key()
        self.attestation = {key_id(public): public}
        self.tokens = {actor: "console-test-credential-for-" + actor for actor in self.identity}
        identity = _FixtureIdentity({token: self.identity[actor] for actor, token in self.tokens.items()})
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.grant(connection, "requester", "read", "app", "single")
            self.grant(connection, "reviewer", "manage", "app", "single")
        self.catalog = ApplicationCatalog(self.runtime, None, {"applications": [
            {"id": "controlled-action", "application": "single", "kind": "action", "label": "受控校验"},
        ]})
        run = self.catalog.run

        def run_with_operator_grants(*args):
            result = run(*args)
            self.grant_task_roles(result["id"])
            return result

        self.enterContext(patch.object(self.catalog, "run", side_effect=run_with_operator_grants))
        self.server = self.enterContext(make_server(self.runtime, {}, port=0, enterprise_identity=identity,
                                                   catalog=self.catalog, console=True, control_store=self.control,
                                                   attestation_keys={self.tenant: self.attestation}))
        running = threading.Thread(target=self.server.serve_forever, daemon=True)
        running.start()
        self.addCleanup(running.join, 2)
        self.addCleanup(self.server.shutdown)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        self.requester, self.reviewer = (Client(self.url, self.tokens[actor]) for actor in ("requester", "reviewer"))

    def grant_task_roles(self, task_id):
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            for actor, action, kind in (("requester", "read", "task"), ("requester", "advance", "task"),
                                        ("requester", "reconcile", "task"), ("requester", "cancel", "task"),
                                        ("requester", "export", "evidence"), ("reviewer", "read", "task"),
                                        ("reviewer", "approve", "task"), ("reviewer", "review", "task")):
                self.grant(connection, actor, action, kind, task_id)

    def submit_task(self, request="p8"):
        result = self.requester.run_application("controlled-action", {
            "object_id": "asset-1", "expected_version": 1, "request_key": request, "release_digest": self.release,
        })
        return result["id"]

    def approval(self, task_id):
        self.assertEqual(self.requester.advance(task_id)["status"], "awaiting_approval")
        self.assertNotIn("review", self.requester.task(task_id))
        review = self.reviewer.task(task_id)["review"]
        self.assertEqual(review["scope"]["parameters"]["object_version"], 1)
        self.assertIn({"kind": "field", "resource_id": "asset-1", "member": "checksum_ok"}, review["scope"]["resources"])
        return review["proposal_digest"]

    def attest(self, task_id):
        attester_dsn = restricted_role(("SELECT ON ai_native.owp_effect_evidence",
                                       "UPDATE (signed_document, delivered_at, attempts, last_error) ON ai_native.owp_effect_evidence"), DSN)
        with self.store_type(attester_dsn) as store:
            deliver_effect(store, self.tenant, task_id, lambda body: sign_effect(body, self.attestation_key), self.attestation)

    def test_sdk_replayed_approval_retains_one_effect_and_historical_read_after_release_revoke(self):
        task_id = self.submit_task()
        self.assertEqual(self.submit_task(), task_id)
        fingerprint = self.approval(task_id)
        with self.assertRaises(APIError) as stale:
            self.reviewer.approve(task_id, "0" * 64)
        self.assertEqual(stale.exception.status, 400)
        writer = self.server.RequestHandlerClass.write_json

        def drop_approved_reply(handler, status, result):
            if handler.path.endswith("/decision") and status == 200 and result.get("status") == "ready":
                handler.close_connection = True
                handler.connection.shutdown(socket.SHUT_RDWR)
                return
            writer(handler, status, result)

        with patch.object(self.server.RequestHandlerClass, "write_json", drop_approved_reply):
            with self.assertRaises(APIError) as lost:
                self.reviewer.approve(task_id, fingerprint)
            self.assertTrue(lost.exception.outcome_unknown)
        self.assertEqual(self.reviewer.approve(task_id, fingerprint)["status"], "ready")
        with self.assertRaises(APIError):
            self.reviewer.reject(task_id, fingerprint)
        self.authorize(task_id)
        self.assertEqual(self.requester.advance(task_id)["status"], "completed")
        self.assertEqual(self.counts(), (1, 1, 1))
        pending = self.requester.export_evidence(task_id)
        self.assertEqual(pending["verification"], "pending")
        self.assertEqual(pending["receipt"]["operation_id"], task_id)
        self.attest(task_id)
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            ReleaseStore.revoke(connection, self.tenant, self.release, publisher="operator")
        self.runtime.registry.applications.pop("single")
        self.assertEqual(self.requester.task(task_id)["status"], "completed")
        verified = self.requester.export_evidence(task_id)
        self.assertEqual(verified["verification"], "verified")
        self.assertNotIn("signature", json.dumps(verified))

    def test_events_late_commit_retains_all_pages_and_redacts_legacy_fields(self):
        import psycopg

        task_id = self.submit_task()
        with psycopg.connect(DSN) as late, psycopg.connect(DSN) as early:
            late_id, = late.execute("SELECT nextval(pg_get_serial_sequence('ai_native.events', 'id'))").fetchone()
            early.execute("INSERT INTO ai_native.events(task_id,event,detail) VALUES (%s,'tool.committed',%s)",
                          (task_id, json.dumps({"receipt_secret": "forbidden-secret"})))
            early.commit()
            first = self.requester.events(task_id, limit=100)
            self.assertFalse(first["has_more"])
            late.execute("INSERT INTO ai_native.events(id,task_id,event,detail) VALUES (%s,%s,%s,%s)",
                         (late_id, task_id, "private.fixture_name", json.dumps({"text": "forbidden-secret"})))
            late.commit()
        second = self.requester.events(task_id, limit=1, cursor=first["next_cursor"])
        self.assertEqual(second["events"][0]["sequence"], first["events"][-1]["sequence"] + 1)
        self.assertEqual(second["events"][0]["event"], "internal.event")
        self.assertNotIn("forbidden-secret", json.dumps([first, second]))
        empty = self.requester.events(task_id, cursor=second["next_cursor"])
        self.assertEqual((empty["events"], empty["next_cursor"]), ([], second["next_cursor"]))
        second_task = self.submit_task("other-events-task")
        with self.assertRaises(APIError):
            self.requester.events(second_task, cursor=second["next_cursor"])

    def test_handover_keeps_unknown_effect_distinct_until_lookup(self):
        task_id = self.submit_task()
        self.reviewer.approve(task_id, self.approval(task_id))
        self.authorize(task_id)
        self.remote.drop_after_commit = True
        self.assertEqual(self.requester.advance(task_id)["status"], "reconciling")
        with self.assertRaises(APIError):
            self.requester.handover(task_id)
        handover = self.reviewer.handover(task_id)
        self.assertTrue(handover["eligible"])
        current = handover["assessment_digest"]
        accepted = self.reviewer.decide_handover(task_id, "accept", current, "Accept operational escalation")
        self.assertEqual(accepted["decision"]["verdict"], "accept")
        self.assertEqual(accepted, self.reviewer.decide_handover(task_id, "accept", current, "Accept operational escalation"))
        with self.assertRaises(APIError):
            self.reviewer.decide_handover(task_id, "reject", current, "Conflicting decision")
        self.assertEqual(self.counts(), (0, 1, 0))
        self.assertEqual(self.requester.reconcile(task_id)["status"], "completed")
        self.assertFalse(self.reviewer.handover(task_id)["decision"]["current"])
        self.assertEqual(self.counts(), (1, 1, 1))

    def test_release_and_fact_interfaces_use_current_grants(self):
        self.assertEqual(self.requester.fact_status("asset", "asset-1", "checksum_ok")["value"], True)
        with self.assertRaises(APIError):
            self.requester.fact_status("asset", "asset-stale", "checksum_ok")
        with self.assertRaises(APIError):
            self.requester.draft_release("single")
        draft = self.reviewer.draft_release("single", policy_version="console-v2", owp_profile=self.owp_profile)
        self.assertEqual(draft["status"], "draft")
        self.assertIn("publish", draft["available_actions"])
        self.assertIn("classification", self.reviewer.release_impact(draft["digest"]))
        self.reviewer.bind_rule(draft["digest"], "verify_asset", feedback_source="inventory", feedback_stream="main")
        self.assertEqual(self.reviewer.change_release(draft["digest"], "publish")["status"], "published")
        self.assertEqual(self.reviewer.change_release(draft["digest"], "select")["digest"], draft["digest"])
        self.assertEqual(self.reviewer.release(draft["digest"])["status"], "published")

    def test_console_assets_without_credentials_and_api_requires_bearer(self):
        with urlopen(self.url + "/console/", timeout=3) as response:
            self.assertEqual(response.headers["Cache-Control"], "no-store")
            self.assertIn("script-src 'self'", response.headers["Content-Security-Policy"])
            self.assertIn(b"connect-form", response.read())
        with self.assertRaises(HTTPError) as response:
            urlopen(self.url + "/v1/applications", timeout=3)
        self.assertEqual(response.exception.code, 403)

    @unittest.skipUnless(os.environ.get("AI_NATIVE_P8_BROWSER") == "1", "Use verify_p8.py --browser")
    def test_browser_real_submission_approver_decision_and_recovery(self):
        root = Path(__file__).resolve().parents[1]
        environment = {**os.environ, "P8_BROWSER_URL": self.url, "P8_REQUESTER_TOKEN": self.tokens["requester"],
                       "P8_REVIEWER_TOKEN": self.tokens["reviewer"]}
        def browser(phase, **extra):
            result = subprocess.check_output(("node", "tests/p8_browser.mjs"), cwd=root, timeout=55, text=True,
                                             env={**environment, "P8_BROWSER_PHASE": phase, **extra})
            return json.loads(result)
        approved = browser("approve")
        self.assertEqual(approved["status"], "ready")
        self.authorize(approved["id"])
        final = browser("complete", P8_BROWSER_TASK_ID=approved["id"])
        self.assertEqual(final["status"], "completed")
        self.assertEqual(self.counts(), (1, 1, 1))
