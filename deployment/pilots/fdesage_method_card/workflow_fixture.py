"""Isolated acceptance harness; its synthetic approval is never a production approver.

Use a fresh, loopback-only PostgreSQL *_test database for each captured intent.
The caller supplies the real FDE intent and official MCP source configuration.
"""

import secrets
import time
from contextlib import ExitStack
from pathlib import Path
from uuid import uuid4

from ai_native_system.adapters.owp import key_id, load_private_key, sign_authorization, verify_authorization
from ai_native_system.adapters.postgres import migrate_postgres
from ai_native_system.adapters.postgres_runtime import PostgresRuntimeStore
from ai_native_system.fact_contracts import FactField, FieldAuthority, IdentityMapping, ObjectIdentity
from ai_native_system.fact_gate import assess, bind_rule
from ai_native_system.facts import Facts
from ai_native_system.fdesage_method_card import APPLICATION, intent_registry, intent_snapshot
from ai_native_system.fdesage_source import SOURCE, TENANT
from ai_native_system.governance import activate
from ai_native_system.identity import IdentityContext
from ai_native_system.model import DemoModel
from ai_native_system.gateway import ModelGateway
from ai_native_system.owp_gate import PROFILE, enforce
from ai_native_system.policy import Policy, tool_resource_id
from ai_native_system.releases import ReleaseSnapshot, ReleaseStore
from ai_native_system.runtime import Runtime
from ai_native_system.security import AuthorizationLedger
from ai_native_system.sync import FactSync
from ai_native_system.storage import encode
from ai_native_system.tools import configured_tools


_GRANTS = {
    "runtime": (
        "SELECT ON ALL TABLES IN SCHEMA ai_native", "USAGE ON ALL SEQUENCES IN SCHEMA ai_native",
        "INSERT ON ai_native.principals, ai_native.objects, ai_native.knowledge, ai_native.knowledge_history, ai_native.events, ai_native.task_governance, ai_native.fact_feedback_expectations",
        "INSERT, UPDATE ON ai_native.tasks, ai_native.steps, ai_native.remote_operations, ai_native.effects",
        "INSERT, UPDATE, DELETE ON ai_native.execution_claims", "UPDATE (state, version) ON ai_native.objects",
        "UPDATE (approver_context) ON ai_native.task_governance", "UPDATE (receipt_status, expected_source_version) ON ai_native.fact_feedback_expectations",
        "INSERT ON ai_native.owp_task_admissions, ai_native.owp_consumptions, ai_native.owp_effect_evidence, ai_native.p4_delivery_jobs",
    ),
    "control": (
        "SELECT ON ALL TABLES IN SCHEMA ai_native",
        "INSERT ON ai_native.governed_tenants, ai_native.resource_grants, ai_native.application_releases, ai_native.application_release_lifecycle, ai_native.application_release_selections, ai_native.identity_mappings, ai_native.fact_authorities, ai_native.fact_rule_bindings, ai_native.fact_invalidation_outbox, ai_native.owp_revocations, ai_native.owp_enforced_tenants",
        "INSERT, UPDATE, DELETE ON ai_native.fact_projections", "DELETE ON ai_native.resource_grants",
        "UPDATE (status, changed_at, changed_by, migration_ref) ON ai_native.application_release_lifecycle",
        "UPDATE (digest, changed_at, changed_by) ON ai_native.application_release_selections",
    ),
    "source": (
        "SELECT ON ALL TABLES IN SCHEMA ai_native",
        "INSERT ON ai_native.source_events, ai_native.source_sync_snapshots, ai_native.source_sync_progress, ai_native.source_sync_conflicts, ai_native.fact_assertions, ai_native.fact_observations, ai_native.fact_invalidation_outbox, ai_native.fact_feedback_observations",
        "INSERT, UPDATE ON ai_native.source_sync_streams, ai_native.source_sync_records, ai_native.source_cursors, ai_native.source_sync_deliveries",
        "INSERT, UPDATE, DELETE ON ai_native.fact_projections",
    ),
    "issuer": ("SELECT ON ALL TABLES IN SCHEMA ai_native", "INSERT ON ai_native.owp_authorizations"),
    "attester": ("SELECT ON ai_native.owp_effect_evidence",
                 "UPDATE (signed_document, delivered_at, attempts, last_error) ON ai_native.owp_effect_evidence"),
    "projection": ("SELECT ON ALL TABLES IN SCHEMA ai_native", "INSERT ON ai_native.objects",
                   "UPDATE (state,version,properties,links) ON ai_native.objects"),
    "delivery": ("SELECT ON ai_native.p4_delivery_jobs, ai_native.p4_proof_records",
                 "UPDATE (status,attempts,next_attempt_at,last_claimed_at,lease_token,lease_expires_at,last_error,lease_manual) ON ai_native.p4_delivery_jobs"),
}


def _restricted_role(dsn, grants):
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo

    role, password = "fde_method_" + secrets.token_hex(6), secrets.token_urlsafe(24)
    with psycopg.connect(dsn) as admin:
        identifier = sql.Identifier(role)
        admin.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(identifier, sql.Literal(password)))
        admin.execute(sql.SQL("GRANT USAGE ON SCHEMA ai_native TO {}").format(identifier))
        admin.execute(sql.SQL("GRANT SELECT ON ai_native.schema_migrations TO {}").format(identifier))
        for grant in grants:
            admin.execute(sql.SQL("GRANT " + grant + " TO {}").format(identifier))
    return make_conninfo(dsn, user=role, password=password)


class MethodWorkflowFixture:
    """Real AINS release/facts/runtime/ledger; only the advisory model and human are synthetic."""

    def __init__(self, dsn, intent, *, reviewer_actor, tools_document, authority_private_key_file):
        from psycopg.conninfo import conninfo_to_dict

        address = conninfo_to_dict(dsn)
        if address.get("host") != "127.0.0.1" or not address.get("dbname", "").endswith("_test"):
            raise ValueError("Use an explicit loopback PostgreSQL *_test database for this harness")
        if intent["requester"].get("service") is not None:
            raise ValueError("The isolated fixture requires a separately configured direct human requester")
        self.dsn, self.intent, self.reviewer_actor = dsn, intent, reviewer_actor
        self.tools_document, self.authority_key_file = tools_document, authority_private_key_file
        self.stack = ExitStack()

    def __enter__(self):
        try:
            return self._initialize()
        except BaseException:
            self.stack.close()
            raise

    def __exit__(self, *arguments):
        return self.stack.__exit__(*arguments)

    def _initialize(self):
        migrate_postgres(self.dsn)
        self.role_dsns = {name: _restricted_role(self.dsn, grants) for name, grants in _GRANTS.items()}
        stores = {name: self.stack.enter_context(PostgresRuntimeStore(dsn)) for name, dsn in self.role_dsns.items()}
        self.store, self.control, self.source_store, self.issuer, self.attester = (
            stores[name] for name in ("runtime", "control", "source", "issuer", "attester"))
        self.projection = stores["projection"]
        self.delivery = stores["delivery"]
        self.registry = intent_registry(self.intent, reviewer_actor=self.reviewer_actor)
        self.capture = intent_snapshot(self.intent)
        self.card_id = "method-card:" + str(self.intent["cardId"])
        self.submission_id = "method-card-submission:" + self.intent["id"]
        self.private_key = load_private_key(Path(self.authority_key_file).read_bytes())
        public = self.private_key.public_key()
        self.trusted_keys = {key_id(public): public}
        self.ledger = AuthorizationLedger(self.intent["sourceEpoch"],
                                          lambda envelope: verify_authorization(envelope, self.trusted_keys))
        self.tools = configured_tools(self.tools_document)
        self.model = ModelGateway(default="synthetic-acceptance", max_context_bytes=65536)
        self.model.register("synthetic-acceptance", DemoModel())
        self.runtime = Runtime(self.store, self.registry, self.model, self.tools, owp_ledgers={TENANT: self.ledger})
        self.runtime.initialize()
        self.facts = Facts(self.source_store, TENANT)
        self.release = ReleaseSnapshot.capture(self.registry, APPLICATION, self.model, self.tools, owp_profile=PROFILE,
                                                policy_version="fde-method-card-policy/1")
        with self.control.transaction(tenant=TENANT, write=True) as connection:
            for event in self.capture.events:
                primary = event.identity.source_type == "method_cards"
                subject = ObjectIdentity(TENANT, "method_card" if primary else "fdesage_method_submission",
                                         self.card_id if primary else self.submission_id)
                self.facts.bind_mapping(connection, IdentityMapping(event.identity, subject, 1, event.occurred_at),
                                        actor="isolated-fixture-operator", reason="Source-declared two-record native scope")
                names = ("$exists", "$state", "label", "content_digest", "method_card.submission") if primary else (
                    "$exists", "$state", "submission_digest")
                for name in names:
                    self.facts.set_authority(connection, FieldAuthority(FactField(subject, name), (SOURCE,), 1),
                                             actor="isolated-fixture-operator", reason="FDE owns this declared native record")
            ReleaseStore.draft(connection, TENANT, self.release, publisher="isolated-fixture-operator")
            bind_rule(connection, TENANT, self.release.digest, "verify_method_card", actor="isolated-fixture-operator")
            ReleaseStore.publish(connection, TENANT, self.release.digest, publisher="isolated-fixture-operator")
            ReleaseStore.select(connection, TENANT, APPLICATION, self.release.digest, publisher="isolated-fixture-operator")
            activate(connection, TENANT)
            enforce(connection, TENANT)
        sync = FactSync(self.source_store, TENANT, SOURCE, self.capture.boundary.resume_cursor.stream, self.facts)
        imported = sync.snapshot(self.capture.boundary, self.capture.events, position=self.capture.position)
        if imported.status != "applied":
            raise AssertionError("The actual source-declared closed snapshot was not imported: " + str(imported))
        self.source_snapshot_result = imported.status
        with self.control.transaction(tenant=TENANT, write=True) as connection:
            evaluation = assess(connection, self.source_store, self.release.ontology(), TENANT, "method_card", self.card_id,
                                {"rule_name": "verify_method_card"})
            if evaluation.status != "satisfied":
                raise AssertionError("The actual captured facts do not establish the rule: " + repr(evaluation))
            policy = Policy()
            requester, reviewer, executor = self.intent["requester"]["actor"], self.reviewer_actor, "fde-method-executor"
            self.identities = {actor: IdentityContext(TENANT, actor) for actor in (requester, reviewer)}
            policy.grant(connection, TENANT, requester, "submit", "app", APPLICATION)
            policy.grant(connection, TENANT, requester, "read", "release", self.release.digest)
            policy.grant(connection, TENANT, executor, "execute", "action", "verify_method_card")
            tool = self.tools.resolve(self.registry.actions["verify_method_card"])
            policy.grant(connection, TENANT, executor, "execute", "tool", tool_resource_id(tool.name, tool.version))
            policy.grant(connection, TENANT, executor, "write", "object", self.card_id)
            for member in ("state", "version"):
                policy.grant(connection, TENANT, executor, "write", "metadata", self.card_id, member)
            for actor in (requester, reviewer, executor):
                for kind, resource_id, member in evaluation.resources:
                    policy.grant(connection, TENANT, actor, "read", kind, resource_id, member)
                policy.grant(connection, TENANT, actor, "read", "document", "fde-method-card-policy")
                policy.grant(connection, TENANT, actor, "read", "edge", self.card_id, "submission")
                for item in self.registry.seed["objects"]:
                    policy.grant(connection, TENANT, actor, "read", "object", item["id"])
                    for member in ("state", "version"):
                        policy.grant(connection, TENANT, actor, "read", "metadata", item["id"], member)
                    for member in item["properties"]:
                        policy.grant(connection, TENANT, actor, "read", "field", item["id"], member)
        return self

    def import_next_intent(self, intent):
        """Import a newer native pointer revision, preserving old tasks' pinned releases."""
        capture = intent_snapshot(intent)
        registry = intent_registry(intent, reviewer_actor=self.reviewer_actor)
        if (intent["cardId"] != self.intent["cardId"] or intent["sourceEpoch"] != self.intent["sourceEpoch"]
                or intent["requester"] != self.intent["requester"] or intent["id"] == self.intent["id"]
                or intent["cardRevision"] <= self.intent["cardRevision"]):
            raise ValueError("This fixture expects a later intent pointer for the same card and identities")
        submission_id = "method-card-submission:" + intent["id"]
        with self.control.transaction(tenant=TENANT, write=True) as connection:
            event = capture.events[1]
            subject = ObjectIdentity(TENANT, "fdesage_method_submission", submission_id)
            self.facts.bind_mapping(connection, IdentityMapping(event.identity, subject, 1, event.occurred_at),
                                    actor="isolated-fixture-operator", reason="A new versioned native intent pointer")
            for name in ("$exists", "$state", "submission_digest"):
                self.facts.set_authority(connection, FieldAuthority(FactField(subject, name), (SOURCE,), 1),
                                         actor="isolated-fixture-operator", reason="FDE owns the selected immutable payload")
        sync = FactSync(self.source_store, TENANT, SOURCE, capture.boundary.resume_cursor.stream, self.facts)
        imported = sync.snapshot(capture.boundary, capture.events, position=capture.position,
                                 predecessor=self.capture.boundary.resume_cursor)
        if imported.status != "applied":
            raise AssertionError("The newer native intent snapshot was not imported: " + repr(imported))
        with self.projection.transaction(tenant=TENANT, write=True) as connection:
            for item in registry.seed["objects"]:
                connection.execute(
                    """INSERT INTO objects (tenant,id,type,state,version,properties,links) VALUES (?,?,?,?,?,?,?)
                       ON CONFLICT (tenant,id) DO UPDATE SET state=EXCLUDED.state,version=EXCLUDED.version,
                         properties=EXCLUDED.properties,links=EXCLUDED.links""",
                    (TENANT, item["id"], item["type"], item["state"], item["version"], encode(item["properties"]),
                     encode(item["links"])),
                )
        release = ReleaseSnapshot.capture(registry, APPLICATION, self.model, self.tools, owp_profile=PROFILE,
                                            policy_version="fde-method-card-policy/1")
        if release.digest != self.release.digest:
            raise AssertionError("New intent data must not change the installed policy or executable release")
        with self.control.transaction(tenant=TENANT, write=True) as connection:
            evaluation = assess(connection, self.source_store, release.ontology(), TENANT, "method_card", self.card_id,
                                {"rule_name": "verify_method_card"})
            if evaluation.status != "satisfied":
                raise AssertionError("New intent does not establish its exact source rule")
            policy = Policy()
            for actor in (intent["requester"]["actor"], self.reviewer_actor, "fde-method-executor"):
                for kind, resource_id, member in evaluation.resources:
                    policy.grant(connection, TENANT, actor, "read", kind, resource_id, member)
                policy.grant(connection, TENANT, actor, "read", "object", submission_id)
                for member in ("state", "version"):
                    policy.grant(connection, TENANT, actor, "read", "metadata", submission_id, member)
                policy.grant(connection, TENANT, actor, "read", "field", submission_id, "submission_digest")
            policy.grant(connection, TENANT, intent["requester"]["actor"], "read", "release", release.digest)
        self.intent, self.capture, self.registry, self.release = intent, capture, registry, release
        self.runtime.registry = registry
        self.submission_id = submission_id
        return imported

    def plan(self):
        requester = self.intent["requester"]["actor"]
        task = self.runtime.submit(TENANT, APPLICATION, self.card_id, requester, "acceptance:" + uuid4().hex,
                                   identity=self.identities[requester])
        self.task_id = task["id"]
        with self.control.transaction(tenant=TENANT, write=True) as connection:
            policy = Policy()
            for actor in (requester, self.reviewer_actor):
                policy.grant(connection, TENANT, actor, "read", "task", self.task_id)
            policy.grant(connection, TENANT, self.reviewer_actor, "approve", "task", self.task_id)
        task = self.runtime.advance(TENANT, self.task_id)
        if task["status"] != "awaiting_approval":
            raise AssertionError("The governed task did not wait for independent approval: " + repr(task))
        return self.runtime.inspect(TENANT, self.task_id, identity=self.identities[self.reviewer_actor])["review"]

    def decide(self, decision="approve", *, proposal_digest=None):
        review = self.runtime.inspect(TENANT, self.task_id, identity=self.identities[self.reviewer_actor])["review"]
        return self.runtime.decide(TENANT, self.task_id, self.reviewer_actor, decision,
                                   identity=self.identities[self.reviewer_actor],
                                   proposal_digest=proposal_digest or review["proposal_digest"])

    def authorize(self, *, expires_in=120):
        with self.store.transaction(tenant=TENANT) as connection:
            request = self.runtime.authorization_request(connection, TENANT, self.task_id)
        now = int(time.time())
        envelope = sign_authorization({**request, "nonce": uuid4().hex, "issued_at": now - 1,
                                       "expires_at": now + expires_in}, self.private_key)
        with self.issuer.transaction(tenant=TENANT, write=True) as connection:
            current = self.runtime.authorization_request(connection, TENANT, self.task_id)
            decision = self.ledger.issue(connection, envelope, current["scope"])
            if not decision.allowed:
                raise AssertionError("The exact governed authorization was not registered: " + repr(decision))
        return envelope

    def operation(self):
        from ai_native_system.remote_execution import operation

        with self.store.transaction(tenant=TENANT) as connection:
            return operation(connection, self.task_id)

    def reconcile(self):
        from functools import partial
        from ai_native_system.delivery import run_delivery_batch
        from ai_native_system.p4_execution import reconcile_job

        jobs = run_delivery_batch(self.delivery, TENANT, "reconcile", partial(reconcile_job, self.runtime), limit=1)
        return self.runtime.advance(TENANT, self.task_id), jobs

    def counts(self):
        with self.store.transaction(tenant=TENANT) as connection:
            return {name: connection.execute(f"SELECT count(*) FROM {name}").fetchone()[0] for name in (
                "tasks", "effects", "owp_authorizations", "owp_consumptions", "owp_effect_evidence", "remote_operations",
                "source_events", "source_sync_snapshots", "source_cursors")}
