"""Exercise the authoritative business query and bound-rule preview on PostgreSQL."""

import unittest
from datetime import timedelta
from unittest.mock import patch

from ai_native_system.api import ApplicationAPI
from ai_native_system.fact_contracts import (
    ChangeKind, Coverage, FactField, FieldAuthority, IdentityMapping, ObjectIdentity, SnapshotBoundary,
    SourceEvent, SourceIdentity, SourceVersion,
)
from ai_native_system.fact_gate import bind_rule
from ai_native_system.identity import IdentityContext, create_delegation, revoke_delegation
from ai_native_system.ontology import OntologyRelease
from ai_native_system.policy import Policy, tool_resource_id
from ai_native_system.releases import ReleaseSnapshot, ReleaseStore
from ai_native_system.storage import encode
from p2b_support import TEST_DSN
from test_p2b_workflow import FactWorkflowFixture


class _FixtureIdentity:
    def __init__(self, tokens):
        self.tokens = tokens

    def authenticate(self, bearer):
        return self.tokens[bearer]


@unittest.skipUnless(TEST_DSN, "Use verify_p2b.py --only authoritative against PostgreSQL")
class AuthoritativeQueryTests(FactWorkflowFixture, unittest.TestCase):
    control_grants = (
        "DELETE ON ai_native.resource_grants",
        "INSERT ON ai_native.enterprise_delegations, ai_native.enterprise_delegation_scopes",
        "UPDATE (revoked_at) ON ai_native.enterprise_delegations",
    )

    def setUp(self):
        super().setUp()
        self.api = ApplicationAPI(self.runtime, {}, enterprise_identity=_FixtureIdentity(self.identity))
        tool = self.runtime.tools.resolve(self.registry.actions["verify_asset"])
        self.tool_id = tool_resource_id(tool.name, tool.version)
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.grant(connection, "requester", "read", "app", "single")
            self.grant(connection, "requester", "read", "action", "verify_asset")
            self.grant(connection, "requester", "preview", "action", "verify_asset")
            self.facts.set_authority(connection, FieldAuthority(FactField(self.object, "label"), ("inventory",), 1),
                                     actor="operator", reason="Inventory owns the label")

    def query(self, *, authoritative=None, token="requester", **options):
        body = {"application": "single", "object_type": "asset", "object_id": self.object.object_id, **options}
        if authoritative is not None:
            body["authoritative"] = authoritative
        return self.api.dispatch("POST", "/v1/query", token, body)

    def preview_read_scopes(self):
        return (
            ("read", "app", "single", None),
            ("read", "release", self.release, None),
            ("read", "object", self.object.object_id, None),
            ("read", "metadata", self.object.object_id, "state"),
            ("read", "field", self.object.object_id, "checksum_ok"),
            ("read", "action", "verify_asset", None),
        )

    def test_selected_release_resolves_authoritative_values_without_execution(self):
        legacy = self.query()["objects"][0]
        self.assertEqual(legacy["properties"]["label"], "Source fixture")
        with patch.object(self.runtime.model, "propose", side_effect=AssertionError("A query must not invoke a model")):
            result = self.query(authoritative={"fields": ["label", "checksum_ok", "$state"], "preview": True})
        self.assertEqual(result["release_digest"], self.release)
        self.assertEqual(result["object"], {"id": self.object.object_id, "type": self.object.object_type})
        self.assertEqual(
            {name: (entry["status"], entry["value"]) for name, entry in result["facts"].items()},
            {"label": ("available", "Current inventory label"), "checksum_ok": ("available", True),
             "$state": ("available", "pending")},
        )
        preview = result["preview"]
        self.assertEqual(preview["status"], "satisfied")
        self.assertEqual(preview["effect"], {"field": "$state", "value": "verified"})
        self.assertIn({"rule": "verify_asset", "field": "checksum_ok", "status": "satisfied"}, preview["conditions"])
        with self.store.transaction(tenant=self.tenant) as connection:
            for table in ("tasks", "model_calls", "remote_operations", "owp_authorizations", "owp_consumptions", "effects"):
                with self.subTest(table=table):
                    self.assertEqual(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0], 0)
        self.assertEqual(self.remote.calls, [])

    def test_preview_only_identity_cannot_submit_or_discover_executable_action(self):
        self.identity["guest"] = IdentityContext(self.tenant, "guest")
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            for scope in self.preview_read_scopes():
                self.grant(connection, "guest", *scope)
            self.grant(connection, "guest", "preview", "action", "verify_asset")

        options = {"preview": True}
        self.assertEqual(self.query(token="guest", authoritative=options)["preview"]["status"], "satisfied")
        self.assertEqual(self.query(token="guest", discover_actions=True)["objects"][0]["actions"], [])
        with self.assertRaises(PermissionError):
            self.api.dispatch("POST", "/v1/tasks", "guest", {
                "application": "single", "object_id": self.object.object_id, "request_key": "preview-only",
            })
        with self.store.transaction(tenant=self.tenant) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM tasks").fetchone()[0], 0)
        self.assertEqual(self.remote.calls, [])

    def test_preview_requires_delegated_scope_and_both_principal_grants(self):
        read = self.preview_read_scopes()
        preview_scope = ("preview", "action", "verify_asset", None)
        now = self.now()
        self.identity["scoped"] = IdentityContext(self.tenant, "requester", "worker", "bound-preview")
        self.identity["unscoped"] = IdentityContext(self.tenant, "requester", "worker", "read-without-preview")
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            for scope in read:
                self.grant(connection, "worker", *scope)
            create_delegation(connection, self.identity["scoped"], (*read, preview_scope),
                              starts_at=now - timedelta(seconds=5), expires_at=now + timedelta(minutes=5))
            create_delegation(connection, self.identity["unscoped"], read,
                              starts_at=now - timedelta(seconds=5), expires_at=now + timedelta(minutes=5))

        options = {"preview": True}
        hidden = {"status": "not_displayable"}
        self.assertEqual(self.query(token="scoped", authoritative=options)["preview"], hidden)
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.grant(connection, "worker", *preview_scope)
        self.assertEqual(self.query(token="unscoped", authoritative=options)["preview"], hidden)
        self.assertEqual(self.query(token="scoped", authoritative=options)["preview"]["status"], "satisfied")
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.assertTrue(revoke_delegation(connection, self.tenant, self.identity["scoped"].delegation_id))
        with self.assertRaises(PermissionError):
            self.query(token="scoped", authoritative=options)

    def test_live_preview_does_not_reuse_an_approval_from_an_earlier_fact_version(self):
        options = {"fields": ["checksum_ok"], "preview": True}
        self.assertEqual(self.query(authoritative=options)["preview"]["status"], "satisfied")
        task_id = self.approved()

        self.deliver("quality", self.quality(True))
        fresh = self.query(authoritative=options)
        self.assertEqual(fresh["preview"]["status"], "satisfied")
        self.assertIs(fresh["facts"]["checksum_ok"]["value"], True)
        self.assertEqual(self.runtime.advance(self.tenant, task_id)["status"], "blocked")
        self.assertEqual(self.remote.calls, [])

        updated = self.event("quality", 3, self.quality(False))
        self.assertEqual(self.sync["quality"].apply(updated, position=3, predecessor=self.cursor("quality", 2)).status,
                         "applied")
        new = self.query(authoritative=options)
        self.assertEqual(new["preview"]["status"], "not_satisfied")
        self.assertIs(new["facts"]["checksum_ok"]["value"], False)
        self.assertIs(self.query()["objects"][0]["properties"]["checksum_ok"], True)

    def test_manual_rule_cutover_changes_the_preview_with_unchanged_facts(self):
        options = {"fields": ["checksum_ok"], "preview": True}
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            old = ReleaseStore.get(connection, self.tenant, self.release).snapshot
            definition = old.ontology().to_document()
            definition["version"] = "p9-cutover-v2"
            rule = definition["rules"]["verify_asset"]
            prior_version = rule["version"]
            rule["version"] = "p9-cutover-v2"
            condition = next(item for item in rule["conditions"] if item.get("property") == "checksum_ok")
            condition["value"] = False
            new = ReleaseSnapshot.capture(self.registry, "single", self.runtime.model, self.runtime.tools,
                                          ontology=OntologyRelease.from_document(definition))
            ReleaseStore.draft(connection, self.tenant, new, publisher="operator")
            bind_rule(connection, self.tenant, new.digest, "verify_asset", actor="operator",
                      feedback_source="inventory", feedback_stream="main")
            self.grant(connection, "requester", "read", "release", new.digest)
            with self.assertRaises(ValueError):
                ReleaseStore.resolve(connection, self.tenant, "single", new.digest)

        before = self.query(authoritative=options)
        self.assertEqual(before["release_digest"], self.release)
        self.assertEqual(before["preview"]["rule_versions"], {"verify_asset": prior_version})
        self.assertEqual(before["preview"]["status"], "satisfied")

        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            ReleaseStore.publish(connection, self.tenant, new.digest, publisher="operator",
                                 migration_ref="p9-manual-rule-cutover")
            ReleaseStore.select(connection, self.tenant, "single", new.digest, publisher="operator")
            ReleaseStore.deprecate(connection, self.tenant, self.release, publisher="operator")
            with self.assertRaises(ValueError):
                ReleaseStore.resolve(connection, self.tenant, "single", self.release)

        after = self.query(authoritative=options)
        self.assertEqual(after["release_digest"], new.digest)
        self.assertEqual(after["facts"], before["facts"])
        self.assertEqual(after["preview"]["rule_versions"], {"verify_asset": "p9-cutover-v2"})
        self.assertEqual(after["preview"]["status"], "not_satisfied")
        with self.store.transaction(tenant=self.tenant) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM tasks").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT count(*) FROM remote_operations").fetchone()[0], 0)
        self.assertEqual(self.remote.calls, [])

    def test_unavailable_and_withdrawn_facts_do_not_fall_back_to_legacy_values(self):
        options = {"fields": ["checksum_ok"], "preview": True}
        quality = self.sources["quality"]
        now = self.now()
        deleted = SourceEvent("quality-delete", quality, ChangeKind.DELETE, now,
                              version=SourceVersion(quality, "e1", "deleted-v2", 2),
                              cursor=self.cursor("quality", 2), occurred_at=now)
        self.assertEqual(self.sync["quality"].apply(deleted, position=2, predecessor=self.cursor("quality", 1)).status,
                         "applied")
        result = self.query(authoritative=options)
        self.assertEqual(result["facts"]["checksum_ok"]["status"], "withdrawn")
        self.assertNotIn("value", result["facts"]["checksum_ok"])
        self.assertEqual(result["preview"]["status"], "insufficient")

        self.assertEqual(self.sync["inventory"].invalidate(self.cursor("inventory", 1)).status, "blocked")
        label = self.query(authoritative={"fields": ["label"]})["facts"]["label"]
        self.assertEqual(label["status"], "unavailable")
        self.assertNotIn("value", label)

    def test_proven_root_deletion_hides_other_sources_and_legacy_object(self):
        options = {"fields": ["checksum_ok"], "preview": True}
        self.assertIs(self.query(authoritative=options)["facts"]["checksum_ok"]["value"], True)
        inventory = self.sources["inventory"]
        now = self.now()
        deleted = SourceEvent("inventory-delete", inventory, ChangeKind.DELETE, now,
                              version=SourceVersion(inventory, "e1", "deleted-v2", 2),
                              cursor=self.cursor("inventory", 2), occurred_at=now)
        self.assertEqual(self.sync["inventory"].apply(deleted, position=2, predecessor=self.cursor("inventory", 1)).status,
                         "applied")
        self.assertEqual(self.query()["objects"][0]["id"], self.object.object_id)
        with self.store.transaction(tenant=self.tenant) as connection:
            observed_at = self.now()
            quality = self.facts.read_fact(connection, FactField(self.object, "checksum_ok"),
                                           as_of=observed_at, known_at=observed_at)
        self.assertTrue(quality.available)
        self.assertIs(quality.value, True)

        with self.assertRaises((PermissionError, LookupError)) as absent:
            self.query(authoritative=options, object_id="unknown-asset")
        with self.assertRaises(type(absent.exception)) as deleted_error:
            self.query(authoritative=options)
        self.assertEqual(str(deleted_error.exception), str(absent.exception))

    def test_field_and_action_permissions_are_rechecked(self):
        options = {"fields": ["label", "checksum_ok"], "preview": True}
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            Policy().revoke(connection, self.tenant, "requester", "read", "field", self.object.object_id, "checksum_ok")
        hidden = self.query(authoritative=options)
        self.assertEqual(set(hidden["facts"]), {"label"})
        self.assertEqual(hidden["preview"], {"status": "not_displayable"})

        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.grant(connection, "requester", "read", "field", self.object.object_id, "checksum_ok")
            Policy().revoke(connection, self.tenant, "requester", "preview", "action", "verify_asset")
            self.grant(connection, "requester", "execute", "tool", self.tool_id)
        unavailable = self.query(authoritative=options)
        self.assertEqual(set(unavailable["facts"]), {"label", "checksum_ok"})
        self.assertEqual(unavailable["preview"], hidden["preview"])
        self.assertEqual(self.query(discover_actions=True)["objects"][0]["actions"], ["verify_asset"])

        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.grant(connection, "requester", "preview", "action", "verify_asset")
            Policy().revoke(connection, self.tenant, "requester", "read", "action", "verify_asset")
        self.assertEqual(self.query(authoritative=options)["preview"], hidden["preview"])

    def test_provenance_requires_a_separate_grant_and_omits_native_identifiers(self):
        options = {"fields": ["label", "checksum_ok"]}
        ordinary = self.query(authoritative=options)["facts"]
        for result in ordinary.values():
            self.assertNotIn("provenance", result)
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.grant(connection, "requester", "read", "provenance", self.object.object_id, "checksum_ok")
        facts = self.query(authoritative=options)["facts"]
        self.assertNotIn("provenance", facts["label"])
        provenance = facts["checksum_ok"]["provenance"]
        self.assertEqual(provenance["coverage"], "complete")
        self.assertEqual(provenance["sources"], [{"source": "quality", "version": "v1"}])
        self.assertIsNotNone(provenance["fresh_until"])
        self.assertNotIn("quality-ref", encode(facts))
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            Policy().revoke(connection, self.tenant, "requester", "read", "field", self.object.object_id, "checksum_ok")
        self.assertNotIn("checksum_ok", self.query(authoritative=options)["facts"])

    def test_hidden_and_missing_roots_use_the_same_denial_and_scope_is_bounded(self):
        options = {"fields": ["checksum_ok"], "preview": True}
        errors = []
        for object_id in ("asset-stale", "unknown-asset"):
            with self.assertRaises((PermissionError, LookupError)) as raised:
                self.query(authoritative=options, object_id=object_id)
            errors.append((type(raised.exception), str(raised.exception)))
        self.assertEqual(errors[0], errors[1])

        invalid = (
            {"application": None}, {"object_type": None}, {"object_id": None}, {"limit": 1},
            {"follow": ["source"]}, {"filters": {"checksum_ok": True}}, {"count": True},
            {"authoritative": {"fields": ["label", "label"]}},
            {"authoritative": {"preview": 1}}, {"authoritative": {"rule": "verify_asset"}},
        )
        for override in invalid:
            with self.subTest(override=override), self.assertRaises(ValueError):
                self.query(**{"authoritative": options, **override})
        with self.assertRaises(ValueError):
            self.query(authoritative={"fields": [f"field-{number}" for number in range(201)]})

    def _select_guarded_release(self):
        targets = ("asset-stale", "asset-linked")
        relation = "asset.guard"
        document = self.registry.ontology(namespace="p9-authoritative-query").to_document()
        document["relations"][relation] = {
            "source_type": "asset", "target_type": "asset", "direction": "directed",
            "targets_per_source": {"min": 0, "max": None}, "sources_per_target": {"min": 0, "max": None},
        }
        document["rules"]["verify_asset"]["conditions"].append(
            {"relation": relation, "target_state": "verified", "quantifier": "all"},
        )
        snapshot = ReleaseSnapshot.capture(self.registry, "single", self.runtime.model, self.runtime.tools,
                                           ontology=OntologyRelease.from_document(document))
        with self.store.transaction(tenant=self.tenant, write=True) as connection:
            connection.execute("""INSERT INTO objects (tenant, id, type, state, version, properties, links)
                                  VALUES (?, ?, 'asset', 'verified', 1, ?, '{}')""",
                               (self.tenant, targets[1], encode({"label": "Second guard", "checksum_ok": True})))

        records = []
        cutoff = self.now()
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.grant(connection, "requester", "read", "edge", self.object.object_id, relation)
            self.facts.set_authority(connection, FieldAuthority(FactField(self.object, relation), ("inventory",), 1),
                                     actor="operator", reason="Inventory owns the relationship")
            for object_id in targets:
                target = ObjectIdentity(self.tenant, "asset", object_id)
                native = SourceIdentity(self.tenant, "inventory", "record", f"{object_id}-source")
                self.facts.bind_mapping(connection, IdentityMapping(native, target, 1, self.now()),
                                        actor="operator", reason="Guard identity verified")
                for field in ("$exists", "$state"):
                    self.facts.set_authority(connection, FieldAuthority(FactField(target, field), ("inventory",), 1),
                                             actor="operator", reason="Inventory owns guard state")
                self.grant(connection, "requester", "read", "object", object_id)
                self.grant(connection, "requester", "read", "metadata", object_id, "state")
                records.append(SourceEvent(f"inventory-{object_id}", native, ChangeKind.UPSERT, cutoff,
                                           self.inventory("verified"), SourceVersion(native, "e1", "v1", 1),
                                           occurred_at=cutoff))
            ReleaseStore.draft(connection, self.tenant, snapshot, publisher="operator")
            bind_rule(connection, self.tenant, snapshot.digest, "verify_asset", actor="operator",
                      feedback_source="inventory", feedback_stream="main")
            ReleaseStore.publish(connection, self.tenant, snapshot.digest, publisher="operator",
                                 migration_ref="p9-authoritative-guards")
            ReleaseStore.select(connection, self.tenant, "single", snapshot.digest, publisher="operator")
            self.grant(connection, "requester", "read", "release", snapshot.digest)

        payload = self.inventory("pending")
        payload["relations"] = [
            {"type": relation, "id": f"link-{object_id}", "target_type": "asset", "target_id": object_id,
             "properties": {}}
            for object_id in targets
        ]
        records.append(self.event("inventory", 2, payload))
        boundary = SnapshotBoundary(self.tenant, "inventory", "guarded-snapshot", "e1", cutoff, self.now(),
                                    Coverage.COMPLETE, self.cursor("inventory", 2))
        self.assertEqual(self.sync["inventory"].snapshot(boundary, records, position=2,
                                                         predecessor=self.cursor("inventory", 1)).status, "applied")
        return snapshot.digest, relation, targets

    def test_relationship_previews_do_not_compute_on_the_visible_subset(self):
        release, relation, targets = self._select_guarded_release()
        options = {"relation": relation, "preview": True}
        visible = self.query(authoritative=options)
        self.assertEqual(visible["release_digest"], release)
        self.assertEqual(visible["relation"]["scope"], "authorized_subset")
        self.assertCountEqual(visible["relation"]["members"], [{"id": name, "type": "asset"} for name in targets])
        self.assertNotIn("coverage", visible["relation"])
        self.assertEqual(visible["preview"]["status"], "satisfied")

        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.grant(connection, "requester", "read", "provenance", self.object.object_id, relation)
        self.assertEqual(self.query(authoritative=options)["relation"]["coverage"], "complete")

        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            Policy().revoke(connection, self.tenant, "requester", "read", "object", targets[1])
        hidden = self.query(authoritative=options)
        self.assertEqual(hidden["relation"]["members"], [{"id": targets[0], "type": "asset"}])
        self.assertEqual(hidden["relation"]["scope"], "authorized_subset")
        self.assertEqual(hidden["preview"], {"status": "not_displayable"})

        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            Policy().revoke(connection, self.tenant, "requester", "read", "edge", self.object.object_id, relation)
        self.assertNotIn("relation", self.query(authoritative=options))

    def test_hidden_target_changes_do_not_affect_visible_relationship_coverage(self):
        _, relation, (visible_target, hidden_target) = self._select_guarded_release()
        options = {"relation": relation, "preview": True}
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.grant(connection, "requester", "read", "provenance", self.object.object_id, relation)
            Policy().revoke(connection, self.tenant, "requester", "read", "object", hidden_target)
        baseline = self.query(authoritative=options)
        self.assertEqual(baseline["relation"]["members"], [{"id": visible_target, "type": "asset"}])
        self.assertEqual(baseline["relation"]["coverage"], "complete")
        self.assertEqual(baseline["preview"], {"status": "not_displayable"})

        native = SourceIdentity(self.tenant, "inventory", "record", f"{hidden_target}-source")
        now = self.now()
        removed = SourceEvent("hidden-target-deleted", native, ChangeKind.DELETE, now,
                              version=SourceVersion(native, "e1", "deleted-v2", 2),
                              cursor=self.cursor("inventory", 3), occurred_at=now)
        self.assertEqual(self.sync["inventory"].apply(removed, position=3, predecessor=self.cursor("inventory", 2)).status,
                         "applied")
        self.assertEqual(self.query(authoritative=options), baseline)

        existence = FactField(ObjectIdentity(self.tenant, "asset", hidden_target), "$exists")
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.facts.set_authority(connection, FieldAuthority(existence, ("quality",), 2), expected=1,
                                     actor="operator", reason="Hidden target authority has no snapshot")
        self.assertEqual(self.query(authoritative=options), baseline)
