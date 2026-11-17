import unittest
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

from ai_native_system.fact_contracts import (
    ChangeKind, CollectionKind, CollectionRead, Coverage, EvidenceRevocation, FactField, FactRead, FieldAuthority,
    IdentityMapping,
    ObjectIdentity, ReadKind, SourceCursor, SourceEvent, SourceIdentity, SourceVersion,
)
from ai_native_system.ontology import OntologyRelease
from ai_native_system.rules import RuleEvaluator, RuleStatus
from p2b_support import TEST_DSN, restricted_role


NOW = datetime(2026, 11, 17, 8, tzinfo=timezone.utc)
SAMPLE = ObjectIdentity("test", "sample", "sample-1")
BATCH = ObjectIdentity("test", "batch", "batch-1")
OTHER_BATCH = ObjectIdentity("test", "batch", "batch-2")


def release():
    return OntologyRelease.from_document({
        "namespace": "sample-check", "version": 1,
        "types": {
            "sample": {"states": ["prepared", "archived"], "properties": {
                "mass": {"type": "decimal", "unit": "g", "precision": 6, "scale": 2},
                "description": {"type": "string", "nullable": True, "required": False},
                "batch_start": {"type": "datetime", "required": False},
            }},
            "batch": {"states": ["open", "closed"], "properties": {}},
        },
        "relations": {"belongs_to": {
            "source_type": "sample", "target_type": "batch", "direction": "directed",
            "targets_per_source": {"min": 0, "max": None},
            "sources_per_target": {"min": 0, "max": None},
        }},
        "rules": {
            "positive": {"version": 7, "object_type": "sample", "conditions": [
                {"property": "mass", "operator": "gt", "value": {"value": "9.99", "unit": "g"}},
                {"state": "prepared"},
            ]},
            "ready": {"version": 1, "object_type": "sample", "depends_on": ["positive"], "conditions": [
                {"relation": "belongs_to", "target_state": "open", "quantifier": "all"},
            ]},
            "any_open": {"version": 1, "object_type": "sample", "conditions": [
                {"relation": "belongs_to", "target_state": "open", "quantifier": "any"},
            ]},
            "explicit_null": {"version": 1, "object_type": "sample", "conditions": [
                {"property": "description", "operator": "eq", "value": None},
            ]},
            "time_match": {"version": 1, "object_type": "sample", "conditions": [
                {"property": "batch_start", "operator": "eq", "value": "2026-11-17T08:00:00Z"},
            ]},
        },
    })


class Observations:
    def __init__(self):
        self.facts = {}
        self.relation = None
        self.source_cursor = SourceCursor("test", "inventory", "primary", "e1", "30")

    def put(self, subject, name, value, *, revision=1, available=True, fresh_until=NOW + timedelta(minutes=5)):
        field = FactField(subject, name)
        proof = FactRead("test", ReadKind.ASSERTION, f"{subject.object_id}/{name}", revision, fresh_until=fresh_until)
        self.facts[field] = SimpleNamespace(value=value, available=available, reads=(proof,), source_cursors=())

    def links(self, *members, revision=1, coverage=Coverage.COMPLETE, available=True):
        collection = CollectionRead("test", CollectionKind.RELATIONSHIP, {"source": SAMPLE.object_id, "type": "belongs_to"},
                                    revision, tuple(item.object_id for item in members), coverage)
        self.relation = SimpleNamespace(collection=collection, available=available, reads=(),
                                        source_cursors=(self.source_cursor,))

    def read_fact(self, connection, field, *, as_of, known_at):
        value = self.facts.get(field)
        if value is None:
            return SimpleNamespace(available=False, reads=(), source_cursors=())
        available = value.available and known_at < value.reads[0].fresh_until
        return SimpleNamespace(value=value.value, available=available, reads=value.reads, source_cursors=value.source_cursors)

    def read_relation(self, connection, subject, relation, *, as_of, known_at, target_type, max_members):
        if (subject, relation, target_type) != (SAMPLE, "belongs_to", "batch"):
            raise AssertionError("Unanticipated relation scope")
        return self.relation


class RuleEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.ontology = release()
        self.reader = Observations()
        for subject in (SAMPLE, BATCH, OTHER_BATCH):
            self.reader.put(subject, "$exists", True)
        self.reader.put(SAMPLE, "$state", "prepared")
        self.reader.put(SAMPLE, "mass", {"value": "10.00", "unit": "g"})
        self.reader.put(BATCH, "$state", "open")
        self.reader.put(OTHER_BATCH, "$state", "closed")
        self.reader.links(BATCH)
        self.connection = SimpleNamespace(database_time=lambda: NOW.timestamp())
        self.evaluator = RuleEvaluator(self.reader)

    def evaluate(self, name="ready", now=NOW):
        return self.evaluator.evaluate(self.connection, self.ontology, name, SAMPLE, as_of=now, known_at=now)

    def test_typed_decimal_comparison_versions_and_complete_reads(self):
        approval = self.evaluate()
        self.assertEqual(approval.status, RuleStatus.SATISFIED)
        self.assertEqual(dict(approval.versions), {"positive": 7, "ready": 1})
        self.assertEqual(approval.ontology_digest, self.ontology.digest)
        self.assertIn("sample-1/mass", [fact.resource_id for fact in approval.read_set.reads])
        self.assertIn("batch-1/$state", [fact.resource_id for fact in approval.read_set.reads])
        self.assertEqual(approval.read_set.collections[0].member_ids, ("batch-1",))
        self.assertEqual(approval.read_set.source_cursors, (self.reader.source_cursor,))
        self.assertTrue(self.evaluator.is_current(self.connection, self.ontology, approval))
        self.reader.put(SAMPLE, "mass", {"value": "9.98", "unit": "g"}, revision=2)
        self.assertEqual(self.evaluate().status, RuleStatus.NOT_SATISFIED)
        self.assertFalse(self.evaluator.is_current(self.connection, self.ontology, approval))

    def test_stale_missing_invalid_and_partial_are_insufficient(self):
        self.reader.links(BATCH, coverage=Coverage.PARTIAL)
        self.assertEqual(self.evaluate("any_open").status, RuleStatus.INSUFFICIENT)
        self.reader.links(BATCH)
        self.reader.put(BATCH, "$state", "open", fresh_until=NOW)
        self.assertEqual(self.evaluate().status, RuleStatus.INSUFFICIENT)
        self.reader.put(SAMPLE, "mass", {"value": "100.00", "unit": "kg"})
        self.assertEqual(self.evaluate("positive").status, RuleStatus.INSUFFICIENT)
        self.assertEqual(self.evaluate("explicit_null").status, RuleStatus.INSUFFICIENT)

    def test_explicit_null_and_equivalent_timezone_values(self):
        self.reader.put(SAMPLE, "description", None)
        self.reader.put(SAMPLE, "batch_start", "2026-11-17T16:00:00+08:00")
        self.assertEqual(self.evaluate("explicit_null").status, RuleStatus.SATISFIED)
        self.assertEqual(self.evaluate("time_match").status, RuleStatus.SATISFIED)

    def test_membership_and_revision_changes_invalidate_even_if_predicate_still_holds(self):
        approval = self.evaluate("any_open")
        self.reader.links(BATCH, OTHER_BATCH, revision=2)
        self.assertEqual(self.evaluate("any_open").status, RuleStatus.SATISFIED)
        self.assertFalse(self.evaluator.is_current(self.connection, self.ontology, approval))
        approval = self.evaluate("any_open")
        self.reader.links(BATCH, revision=3)
        self.assertFalse(self.evaluator.is_current(self.connection, self.ontology, approval))
        self.reader.links(BATCH, revision=4)
        self.assertNotEqual(approval.fingerprint, self.evaluate("any_open").fingerprint)

    def test_tombstone_does_not_reuse_old_state_and_all_is_nonvacuous(self):
        self.reader.put(BATCH, "$exists", False, revision=2)
        self.assertEqual(self.evaluate("any_open").status, RuleStatus.INSUFFICIENT)
        self.reader.links(revision=2)
        self.assertEqual(self.evaluate("any_open").status, RuleStatus.NOT_SATISFIED)
        self.assertEqual(self.evaluate().status, RuleStatus.NOT_SATISFIED)

    def test_binding_pins_assertion_versions_and_rechecks_freshness(self):
        approval = self.evaluate()
        self.assertEqual(approval.fingerprint, self.evaluate(now=NOW + timedelta(seconds=2)).fingerprint)
        current = SimpleNamespace(database_time=lambda: (NOW + timedelta(minutes=5)).timestamp())
        self.assertFalse(self.evaluator.is_current(current, self.ontology, approval))
        self.reader.put(BATCH, "$state", "open", revision=2)
        self.assertFalse(self.evaluator.is_current(self.connection, self.ontology, approval))
        altered = self.ontology.to_document()
        altered["rules"]["ready"]["version"] = 2
        self.assertFalse(self.evaluator.is_current(self.connection, OntologyRelease.from_document(altered), approval))

    def test_no_runtime_code_and_bounded_membership(self):
        forged = self.ontology.to_document()
        forged["rules"]["ready"]["conditions"] = [{"code": "raise Exception"}]
        with self.assertRaises(ValueError):
            OntologyRelease.from_document(forged)
        members = tuple(replace(BATCH, object_id=f"batch-{index}") for index in range(201))
        self.reader.links(*members)
        self.assertEqual(self.evaluate("any_open").status, RuleStatus.INSUFFICIENT)


@unittest.skipUnless(TEST_DSN, "Run deployment/local-postgres/verify_p2b.py --only rules")
class PostgreSQLRuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from ai_native_system.adapters.postgres import migrate_postgres

        migrate_postgres(TEST_DSN)

    def setUp(self):
        from uuid import uuid4

        from ai_native_system.adapters.postgres_runtime import PostgresRuntimeStore
        from ai_native_system.facts import Facts

        self.tenant = "rule-" + uuid4().hex[:10]
        self.sample = replace(SAMPLE, tenant=self.tenant)
        self.batch = replace(BATCH, tenant=self.tenant)
        self.other_batch = replace(OTHER_BATCH, tenant=self.tenant)
        self.ontology = release()
        writer = restricted_role((
            "SELECT, INSERT ON ai_native.identity_mappings, ai_native.fact_authorities, "
            "ai_native.fact_assertions, ai_native.fact_observations, ai_native.fact_invalidation_outbox",
            "SELECT, INSERT, UPDATE, DELETE ON ai_native.fact_projections",
            "SELECT, INSERT ON ai_native.source_sync_progress",
            "SELECT, INSERT ON ai_native.principals, ai_native.resource_grants",
        ))
        reader = restricted_role((
            "SELECT ON ai_native.identity_mappings, ai_native.fact_authorities, ai_native.fact_assertions, "
            "ai_native.fact_observations, ai_native.fact_invalidation_outbox, ai_native.fact_projections, "
            "ai_native.source_sync_progress",
        ))
        self.writer = self.enterContext(PostgresRuntimeStore(writer, max_connections=1))
        self.reader = self.enterContext(PostgresRuntimeStore(reader, max_connections=1))
        self.facts = Facts(self.writer, self.tenant)
        self.evaluator = RuleEvaluator(Facts(self.reader, self.tenant))
        self.catalog, self.process = "inventory", "process"
        self.snapshot()

    def source(self, subject):
        name = self.catalog if subject.object_type == "sample" else self.process
        return SourceIdentity(self.tenant, name, subject.object_type, f"source-{subject.object_id}")

    def sample_values(self, *targets):
        return {
            ("$state", None): "prepared",
            ("mass", None): {"value": "10.00", "unit": "g"},
            **{
                ("belongs_to", f"edge-{target.object_id}"): {
                    "target_id": target.object_id, "target_type": target.object_type, "properties": {},
                }
                for target in targets
            },
        }

    def write_observation(self, connection, subject, sequence, changes):
        identity = self.source(subject)
        time = connection.execute("SELECT clock_timestamp()").fetchone()[0]
        version = SourceVersion(identity, "epoch-1", f"revision-{sequence}", sequence)
        event = SourceEvent(f"{subject.object_id}-{sequence}", identity,
                            ChangeKind.DELETE if changes is None else ChangeKind.UPSERT, time,
                            None if changes is None else {"fixture": True}, version=version, occurred_at=time)
        self.facts.write_source(connection, event, stream="primary", changes=changes, observed_at=time)

    def record_progress(self, connection, source, revision, *, status="ready", freshness=timedelta(minutes=5)):
        now = connection.execute("SELECT clock_timestamp()").fetchone()[0]
        coverage = "complete" if status == "ready" else "unknown"
        connection.execute(
            """INSERT INTO source_sync_progress
                (tenant,source,stream,epoch,position,token,snapshot_id,status,coverage,updated_at,fresh_until,revision)
               VALUES (?,?,'primary','epoch-1',?,?,'snapshot-1',?,?,?,?,?)""",
            (self.tenant, source, revision, f"cursor-{revision}", status, coverage, now, now + freshness, revision),
        )

    def snapshot(self):
        with self.writer.transaction(tenant=self.tenant, write=True) as connection:
            for source in (self.catalog, self.process):
                self.record_progress(connection, source, 1)
            for subject in (self.sample, self.batch, self.other_batch):
                native = self.source(subject)
                instant = connection.execute("SELECT clock_timestamp()").fetchone()[0]
                self.facts.bind_mapping(connection, IdentityMapping(native, subject, 1, instant),
                                        actor="operator", reason="bind test source record")
                names = ("$exists", "$state", "mass", "belongs_to") if subject == self.sample else ("$exists", "$state")
                for name in names:
                    definition = FieldAuthority(FactField(subject, name), (native.source,), 1)
                    self.facts.set_authority(connection, definition, actor="operator", reason="set authoritative source")
            self.write_observation(connection, self.batch, 1, {("$state", None): "open"})
            self.write_observation(connection, self.other_batch, 1, {("$state", None): "open"})
            self.write_observation(connection, self.sample, 1, self.sample_values(self.batch))

    def evaluate(self, rule="ready"):
        with self.reader.transaction(tenant=self.tenant) as connection:
            return self.evaluator.evaluate(connection, self.ontology, rule, self.sample)

    def assert_current(self, previous, expected):
        with self.reader.transaction(tenant=self.tenant) as connection:
            self.assertEqual(self.evaluator.is_current(connection, self.ontology, previous), expected)

    def test_relation_member_add_and_remove_change_live_rule_proof(self):
        prior = self.evaluate()
        self.assertEqual(prior.status, RuleStatus.SATISFIED)
        self.assertEqual({cursor.source for cursor in prior.read_set.source_cursors}, {self.catalog, self.process})
        self.assertEqual(prior.read_set.collections[0].member_ids, (self.batch.object_id,))
        self.assert_current(prior, True)
        with self.writer.transaction(tenant=self.tenant, write=True) as connection:
            self.write_observation(connection, self.sample, 2, self.sample_values(self.batch, self.other_batch))
        next_proof = self.evaluate()
        self.assertEqual(next_proof.status, RuleStatus.SATISFIED)
        self.assertEqual(next_proof.read_set.collections[0].member_ids,
                         (self.batch.object_id, self.other_batch.object_id))
        self.assert_current(prior, False)
        with self.writer.transaction(tenant=self.tenant, write=True) as connection:
            self.write_observation(connection, self.sample, 3, self.sample_values(self.batch))
        self.assertEqual(self.evaluate().status, RuleStatus.SATISFIED)
        self.assert_current(next_proof, False)
        self.assert_current(prior, False)

    def test_blocked_stream_freshness_and_deleted_subject_fail_closed(self):
        prior = self.evaluate()
        self.assertEqual(prior.status, RuleStatus.SATISFIED)
        with self.writer.transaction(tenant=self.tenant, write=True) as connection:
            self.record_progress(connection, self.process, 2, status="blocked")
        self.assertEqual(self.evaluate().status, RuleStatus.INSUFFICIENT)
        self.assert_current(prior, False)
        with self.reader.transaction(tenant=self.tenant) as connection:
            historical = self.evaluator.evaluate(connection, self.ontology, "ready", self.sample,
                                                 as_of=prior.read_set.as_of, known_at=prior.read_set.as_of)
        self.assertEqual(historical.fingerprint, prior.fingerprint)
        with self.writer.transaction(tenant=self.tenant, write=True) as connection:
            self.record_progress(connection, self.process, 3, freshness=timedelta())
        self.assertEqual(self.evaluate().status, RuleStatus.INSUFFICIENT)
        with self.writer.transaction(tenant=self.tenant, write=True) as connection:
            self.record_progress(connection, self.process, 4, freshness=timedelta(minutes=1))
        self.assertEqual(self.evaluate().status, RuleStatus.SATISFIED)
        with self.writer.transaction(tenant=self.tenant, write=True) as connection:
            self.write_observation(connection, self.sample, 2, None)
        self.assertEqual(self.evaluate().status, RuleStatus.INSUFFICIENT)
        self.assert_current(prior, False)

    def test_changing_target_type_cannot_turn_same_id_into_a_valid_edge(self):
        prior = self.evaluate()
        self.assertEqual(prior.status, RuleStatus.SATISFIED)
        wrong_type = replace(self.batch, object_type="unrelated")
        with self.writer.transaction(tenant=self.tenant, write=True) as connection:
            native = self.source(wrong_type)
            now = connection.execute("SELECT clock_timestamp()").fetchone()[0]
            self.facts.bind_mapping(connection, IdentityMapping(native, wrong_type, 1, now),
                                    actor="operator", reason="map different canonical type with same ID")
            self.facts.set_authority(connection, FieldAuthority(FactField(wrong_type, "$exists"), (native.source,), 1),
                                     actor="operator", reason="set authoritative source")
            self.write_observation(connection, wrong_type, 1, {("$state", None): "open"})
            self.write_observation(connection, self.sample, 2, self.sample_values(wrong_type))
        self.assertEqual(self.evaluate().status, RuleStatus.INSUFFICIENT)
        self.assert_current(prior, False)

    def test_revoked_evidence_invalidates_a_satisfied_rule(self):
        from ai_native_system.identity import IdentityContext
        from ai_native_system.policy import Policy

        previous = self.evaluate()
        self.assertEqual(previous.status, RuleStatus.SATISFIED)
        proof = next(read for read in previous.read_set.reads if read.kind == ReadKind.EVIDENCE)
        operator = IdentityContext(self.tenant, "reviewer")
        with self.writer.transaction(tenant=self.tenant, write=True) as connection:
            connection.execute("INSERT INTO principals (tenant,id,roles,active) VALUES (?,?,'[]',1)",
                               (self.tenant, operator.actor))
            Policy().grant(connection, self.tenant, operator.actor, "revoke", "evidence", proof.resource_id)
            now = connection.execute("SELECT clock_timestamp()").fetchone()[0]
            self.facts.revoke_evidence(connection, EvidenceRevocation(
                "withdraw-1", self.tenant, proof.resource_id, proof.revision, now, "invalid source evidence",
            ), operator)
        self.assertEqual(self.evaluate().status, RuleStatus.INSUFFICIENT)
        self.assert_current(previous, False)
