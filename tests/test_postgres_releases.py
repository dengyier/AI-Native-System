import argparse
import os
import secrets
import unittest

from ai_native_system.model import DemoModel
from ai_native_system.ontology import OntologyRelease
from ai_native_system.registry import Registry
from ai_native_system.release_control import add_release_arguments, run_release_control
from ai_native_system.releases import ReleaseError, ReleaseSnapshot, ReleaseStore
from ai_native_system.tools import ToolRegistry

from test_releases import registry_document


DSN = os.environ.get("AI_NATIVE_PG_RELEASE_TEST_DSN")
TABLES = ("application_releases", "application_release_lifecycle", "application_release_selections")


@unittest.skipUnless(DSN, "Run deployment/local-postgres/verify_p2a.py --only releases")
class PostgresReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import make_conninfo

        from ai_native_system.adapters.postgres import migrate_postgres
        from ai_native_system.adapters.postgres_runtime import PostgresRuntimeStore

        owner = "p2a_release_owner"
        catalog = "p2a_release_catalog"
        runtime = "p2a_release_reader"
        role_dsns = {}
        with psycopg.connect(DSN) as admin:
            for role in (owner, catalog, runtime):
                password = secrets.token_urlsafe(24)
                admin.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(sql.Identifier(role), sql.Literal(password)))
                role_dsns[role] = make_conninfo(DSN, user=role, password=password)
            admin.execute("CREATE SCHEMA ai_native AUTHORIZATION p2a_release_owner")
        cls.owner_dsn = role_dsns[owner]
        cls.reader_dsn = role_dsns[runtime]
        migrate_postgres(cls.owner_dsn)
        with psycopg.connect(cls.owner_dsn) as connection:
            connection.execute("GRANT USAGE ON SCHEMA ai_native TO p2a_release_catalog, p2a_release_reader")
            connection.execute("""
                GRANT SELECT ON ai_native.schema_migrations, ai_native.application_releases,
                    ai_native.application_release_lifecycle, ai_native.application_release_selections
                TO p2a_release_catalog, p2a_release_reader
            """)
            connection.execute("GRANT SELECT ON ai_native.application_release_selection_history TO p2a_release_reader")
            connection.execute("""
                GRANT SELECT ON ai_native.task_governance TO p2a_release_catalog;
                GRANT INSERT (tenant, digest, document, created_by)
                    ON ai_native.application_releases TO p2a_release_catalog;
                GRANT INSERT (tenant, digest, changed_by), UPDATE (status, changed_by, changed_at, migration_ref)
                    ON ai_native.application_release_lifecycle TO p2a_release_catalog;
                GRANT INSERT (tenant, application, digest, changed_by), UPDATE (digest, changed_by, changed_at)
                    ON ai_native.application_release_selections TO p2a_release_catalog
            """)
        cls.catalog = cls.enterClassContext(PostgresRuntimeStore(role_dsns[catalog], max_connections=1))
        cls.reader = cls.enterClassContext(PostgresRuntimeStore(cls.reader_dsn, max_connections=1))

    @staticmethod
    def snapshot(application="single", *, change_schema=False, instructions=None, ontology=None):
        definition = registry_document()
        if instructions is not None:
            definition["applications"][application]["agents"][0]["instructions"] = instructions
        if change_schema:
            definition["types"]["asset"]["fields"]["new_property"] = "boolean"
            definition["seed"]["objects"] = []
        return ReleaseSnapshot.capture(Registry(definition), application, DemoModel(), ToolRegistry(), ontology=ontology)

    def test_publish_select_rollback_and_retained_history(self):
        import psycopg

        tenant = "lifecycle"
        original = self.snapshot()
        update = self.snapshot(instructions="updated prompt")
        with self.catalog.transaction(write=True, tenant=tenant) as tx:
            created = ReleaseStore.draft(tx, tenant, original, publisher="author")
            self.assertEqual((created.status, created.created_by), ("draft", "author"))
            self.assertIsNone(ReleaseStore.resolve(tx, tenant, "single"))
            with self.assertRaises(ReleaseError):
                ReleaseStore.resolve(tx, tenant, "single", original.digest)
            ReleaseStore.publish(tx, tenant, original.digest, publisher="publisher")
            ReleaseStore.select(tx, tenant, "single", original.digest, publisher="publisher")
            ReleaseStore.draft(tx, tenant, update, publisher="author")
            self.assertEqual(ReleaseStore.impact(tx, tenant, update.digest)["classification"], "compatible")
            ReleaseStore.publish(tx, tenant, update.digest, publisher="publisher")
            ReleaseStore.select(tx, tenant, "single", update.digest, publisher="publisher")
            self.assertEqual(ReleaseStore.resolve(tx, tenant, "single").snapshot, update)
            self.assertEqual(ReleaseStore.pinned(tx, tenant, original.digest).snapshot, original)
            ReleaseStore.select(tx, tenant, "single", original.digest, publisher="rollback-admin")
            ReleaseStore.select(tx, tenant, "single", original.digest, publisher="retry-admin")
            self.assertEqual(ReleaseStore.resolve(tx, tenant, "single").snapshot, original)
            ReleaseStore.deprecate(tx, tenant, original.digest, publisher="publisher")
            self.assertEqual(ReleaseStore.pinned(tx, tenant, original.digest).status, "deprecated")
            with self.assertRaises(ReleaseError):
                ReleaseStore.resolve(tx, tenant, "single")
            with self.assertRaises(ReleaseError):
                ReleaseStore.select(tx, tenant, "single", original.digest, publisher="publisher")
            ReleaseStore.revoke(tx, tenant, original.digest, publisher="operator")
            with self.assertRaises(ReleaseError):
                ReleaseStore.pinned(tx, tenant, original.digest)
            history = ReleaseStore.get(tx, tenant, original.digest)
            self.assertEqual((history.snapshot, history.status, history.created_by, history.changed_by),
                             (original, "revoked", "author", "operator"))
        statement = """SELECT previous_digest, digest, changed_by FROM application_release_selection_history
                       WHERE tenant=? AND application='single' ORDER BY id"""
        with self.reader.transaction(tenant=tenant) as tx:
            self.assertEqual([tuple(row) for row in tx.execute(statement, (tenant,)).fetchall()], [
                (None, original.digest, "publisher"), (original.digest, update.digest, "publisher"),
                (update.digest, original.digest, "rollback-admin"),
            ])
        with self.reader.transaction(tenant="other-audit-tenant") as tx:
            self.assertEqual(tx.execute(statement, (tenant,)).fetchall(), [])
        with self.assertRaisesRegex(psycopg.errors.CheckViolation, "Release records are immutable"):
            with psycopg.connect(self.owner_dsn) as owner:
                owner.execute("DELETE FROM ai_native.application_release_selection_history WHERE tenant=%s", (tenant,))

    def test_breaking_change_reports_dependents_and_preserves_migration_reference(self):
        import psycopg

        tenant = "compatibility"
        baseline = self.snapshot()
        collaboration = self.snapshot("collaboration")
        candidate = self.snapshot(change_schema=True)
        with self.catalog.transaction(write=True, tenant=tenant) as tx:
            for snapshot in (baseline, collaboration):
                ReleaseStore.draft(tx, tenant, snapshot, publisher="publisher")
                ReleaseStore.publish(tx, tenant, snapshot.digest, publisher="publisher")
                ReleaseStore.select(tx, tenant, snapshot.application, snapshot.digest, publisher="publisher")
        with psycopg.connect(self.owner_dsn) as owner:
            owner.execute(
                """INSERT INTO ai_native.tasks (id, tenant, application, object_id, requester, request_key,
                                                definition_hash, status)
                   VALUES ('pinned-release-test', %s, 'single', 'object', 'actor', 'key', %s, 'planning')""",
                (tenant, baseline.definition_hash),
            )
            owner.execute(
                """INSERT INTO ai_native.task_governance (tenant, task_id, release_digest, requester_context)
                   VALUES (%s, 'pinned-release-test', %s, '{}')""",
                (tenant, baseline.digest),
            )
        with self.catalog.transaction(write=True, tenant=tenant) as tx:
            ReleaseStore.draft(tx, tenant, candidate, publisher="publisher")
            impact = ReleaseStore.impact(tx, tenant, candidate.digest)
            self.assertEqual(impact["classification"], "breaking")
            self.assertEqual(impact["changes"]["types"]["changed"], ["asset"])
            self.assertEqual(impact["data"], ["asset"])
            self.assertEqual(impact["index_scopes"], ["asset"])
            self.assertEqual(impact["applications"], ["collaboration", "single"])
            self.assertEqual(impact["pinned_tasks"], {baseline.digest: 1})
            self.assertTrue(impact["migration"])
            with self.assertRaisesRegex(ReleaseError, "migration reference"):
                ReleaseStore.publish(tx, tenant, candidate.digest, publisher="publisher")
            published = ReleaseStore.publish(tx, tenant, candidate.digest, publisher="publisher", migration_ref="migration-001")
            self.assertEqual(published.migration_ref, "migration-001")
            revoked = ReleaseStore.revoke(tx, tenant, candidate.digest, publisher="publisher")
            self.assertEqual(revoked.migration_ref, "migration-001")

        version = baseline.to_document()["ontology"]["definition"]["version"]
        conflicting = candidate.to_document()["ontology"]["definition"]
        conflicting["version"] = version
        invalid = self.snapshot(change_schema=True, ontology=OntologyRelease.from_document(conflicting))
        with self.catalog.transaction(write=True, tenant=tenant) as tx, self.assertRaisesRegex(ReleaseError, "version"):
            ReleaseStore.draft(tx, tenant, invalid, publisher="publisher")

    def test_new_required_ontology_relationship_impacts_existing_objects(self):
        tenant = "required-relationship"
        baseline = self.snapshot()
        updated = baseline.to_document()["ontology"]["definition"]
        updated["version"] = "with-required-reference"
        updated["relations"]["mandatory_reference"] = {
            "source_type": "asset", "target_type": "artifact", "direction": "directed",
            "targets_per_source": {"min": 1, "max": 1}, "sources_per_target": {"min": 0, "max": None},
        }
        candidate = self.snapshot(ontology=OntologyRelease.from_document(updated))
        with self.catalog.transaction(write=True, tenant=tenant) as tx:
            ReleaseStore.draft(tx, tenant, baseline, publisher="publisher")
            ReleaseStore.publish(tx, tenant, baseline.digest, publisher="publisher")
            ReleaseStore.select(tx, tenant, "single", baseline.digest, publisher="publisher")
            ReleaseStore.draft(tx, tenant, candidate, publisher="publisher")
            impact = ReleaseStore.impact(tx, tenant, candidate.digest)
            self.assertEqual(impact["classification"], "breaking")
            self.assertEqual(impact["changes"]["relations"]["added"], ["mandatory_reference"])

    def test_rls_reader_grants_and_immutable_database_guards(self):
        import psycopg

        tenant = "release-boundary"
        original = self.snapshot()
        with self.catalog.transaction(write=True, tenant=tenant) as tx:
            ReleaseStore.draft(tx, tenant, original, publisher="author")
            ReleaseStore.publish(tx, tenant, original.digest, publisher="operator")
            ReleaseStore.select(tx, tenant, "single", original.digest, publisher="operator")

        with self.reader.transaction(tenant=tenant) as tx:
            self.assertEqual(ReleaseStore.resolve(tx, tenant, "single").snapshot, original)
        for scope in ("wrong-tenant", None):
            with self.reader.transaction(tenant=scope) as tx:
                for table in TABLES:
                    self.assertEqual(tx.execute(f"SELECT count(*) FROM {table}").fetchone()[0], 0)
        with self.catalog.transaction(write=True, tenant="wrong-tenant") as tx, self.assertRaises(psycopg.errors.InsufficientPrivilege):
            ReleaseStore.draft(tx, tenant, original, publisher="forged")
        with self.reader.transaction(write=True, tenant=tenant) as tx, self.assertRaises(psycopg.errors.InsufficientPrivilege):
            ReleaseStore.revoke(tx, tenant, original.digest, publisher="forged")

        invalid_mutations = (
            "UPDATE ai_native.application_releases SET created_by = 'forged'",
            "DELETE FROM ai_native.application_releases",
            "UPDATE ai_native.application_release_lifecycle SET status = 'draft'",
            "DELETE FROM ai_native.application_release_lifecycle",
            "DELETE FROM ai_native.application_release_selections",
            "TRUNCATE ai_native.application_release_selections",
        )
        for mutation in invalid_mutations:
            with self.subTest(mutation=mutation), psycopg.connect(self.owner_dsn) as owner:
                with self.assertRaises(psycopg.errors.CheckViolation), owner.transaction():
                    owner.execute(mutation)
            with self.reader.transaction(tenant=tenant) as tx:
                self.assertEqual(ReleaseStore.resolve(tx, tenant, "single").snapshot, original)

    def test_operator_can_validate_show_publish_and_select_a_release(self):
        parser = argparse.ArgumentParser()
        parser.add_argument("--tenant", default="controls")
        commands = parser.add_subparsers(dest="command", required=True)
        add_release_arguments(commands)

        def release(*arguments):
            options = parser.parse_args(["release", *arguments])
            write = options.release_command not in ("show", "impact")
            with self.catalog.transaction(write=write, tenant=options.tenant) as tx:
                return run_release_control(tx, options, Registry(registry_document()), DemoModel())

        draft = release("draft", "single", "--actor", "author", "--mapping-version", "mapping-2")
        digest = draft["digest"]
        self.assertEqual(release("show", digest)["snapshot"]["mapping_version"], "mapping-2")
        published = release("publish", digest, "--actor", "manager")
        self.assertEqual((published["status"], published["changed_by"]), ("published", "manager"))
        self.assertEqual(published["impact"]["classification"], "initial")
        self.assertEqual(release("select", "single", digest, "--actor", "manager")["digest"], digest)
