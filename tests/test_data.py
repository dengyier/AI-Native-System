import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from ai_native_system.data import DataService
from ai_native_system.model import DemoModel
from ai_native_system.registry import Registry
from ai_native_system.runtime import Runtime
from ai_native_system.storage import database, encode, initialize, object_data


FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "conformance.json"
ADMIN = "data-test-admin"
READER = "data-test-reader"


class DataTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.path = Path(directory.name) / "data.sqlite"
        self.registry = Registry.load(FIXTURE)
        initialize(self.path, self.registry.seed)
        with database(self.path, write=True) as connection:
            connection.executemany(
                "INSERT INTO principals (tenant, id, roles) VALUES (?, ?, ?)",
                [
                    ("local", ADMIN, encode(["data_admin"])),
                    ("local", READER, encode(["knowledge_read"])),
                    ("other", ADMIN, encode(["data_admin"])),
                ],
            )
        self.service = DataService(self.path, self.registry)

    @staticmethod
    def new_artifact(source="asset-1"):
        return {
            "id": "data-test-artifact", "type": "artifact", "state": "draft",
            "properties": {"label": "Data test", "revision": 1}, "links": {"source": source},
        }

    def test_roles_are_active_and_tenant_scoped(self):
        with self.assertRaises(PermissionError):
            self.service.put_object("local", READER, self.new_artifact())
        with self.assertRaises(PermissionError):
            self.service.put_knowledge("local", READER, "test-policy", "A rule")
        with self.assertRaises(PermissionError):
            self.service.search_knowledge("local", "guest", "policy")
        self.assertEqual(self.service.search_knowledge("local", READER, "asset-policy")[0]["version"], 1)
        self.assertEqual(self.service.search_knowledge("other", ADMIN, "asset-policy"), [])
        with database(self.path, write=True) as connection:
            connection.execute("UPDATE principals SET active = 0 WHERE tenant = 'local' AND id = ?", (ADMIN,))
        with self.assertRaises(PermissionError):
            self.service.search_knowledge("local", ADMIN, "policy")

    def test_object_validation_and_optimistic_revision(self):
        for invalid in [
            self.new_artifact("asset-2"),
            self.new_artifact("artifact-1"),
            dict(self.new_artifact(), tenant="other"),
            dict(self.new_artifact(), properties={"label": "invalid", "revision": True}),
        ]:
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.service.put_object("local", ADMIN, invalid)
        saved = self.service.put_object("local", ADMIN, self.new_artifact())
        self.assertEqual((saved["tenant"], saved["version"]), ("local", 1))
        with self.assertRaises(ValueError):
            self.service.put_object("local", ADMIN, self.new_artifact())
        updated = self.service.put_object("local", ADMIN, dict(saved, state="published"), expected_version=1)
        self.assertEqual((updated["state"], updated["version"]), ("published", 2))
        with self.assertRaises(ValueError):
            self.service.put_object("local", ADMIN, saved, expected_version=1)
        with database(self.path) as connection:
            self.assertEqual(object_data(connection, "local", saved["id"]), updated)

    def test_same_object_revision_allows_only_one_concurrent_update(self):
        saved = self.service.put_object("local", ADMIN, self.new_artifact())

        def write(label):
            try:
                result = self.service.put_object(
                    "local", ADMIN, dict(saved, properties={"label": label, "revision": 1}), expected_version=1,
                )
            except ValueError:
                return None
            return result["version"]

        with ThreadPoolExecutor(max_workers=2) as executor:
            outcomes = list(executor.map(write, ["first", "second"]))
        self.assertCountEqual(outcomes, [2, None])

    def test_search_returns_latest_version_and_historical_evidence_is_preserved(self):
        first = self.service.put_knowledge("local", ADMIN, "qa-literacy", "Review CASEFOLD and 50% literal.")
        self.assertEqual(first["version"], 1)
        self.assertEqual(self.service.search_knowledge("local", READER, "casefold"), [first])
        self.assertEqual(self.service.search_knowledge("local", READER, "%"), [first])
        self.service.put_knowledge("other", ADMIN, "qa-literacy", "Review casefold for other tenant.")
        second = self.service.put_knowledge("local", ADMIN, "qa-literacy", "Revised CASEFOLD note.", expected_version=1)
        with self.assertRaises(ValueError):
            self.service.put_knowledge("local", ADMIN, "qa-literacy", "This would lose an update.", expected_version=1)
        self.assertEqual(second["version"], 2)
        self.assertEqual(self.service.search_knowledge("local", READER, "casefold", limit=1), [second])
        self.assertEqual(self.service.search_knowledge("local", READER, "%"), [])
        self.assertEqual(self.service.search_knowledge("local", READER, "other tenant"), [])
        with database(self.path) as connection:
            versions = connection.execute(
                "SELECT version, text FROM knowledge_history WHERE tenant = 'local' AND id = 'qa-literacy' ORDER BY version"
            ).fetchall()
        self.assertEqual([tuple(row) for row in versions], [(1, first["text"]), (2, second["text"])])
        for limit in (0, 51, True):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                self.service.search_knowledge("local", READER, "casefold", limit)

    def test_revising_existing_knowledge_invalidates_approval(self):
        runtime = Runtime(self.path, self.registry, DemoModel())
        task = runtime.submit("local", "single", "asset-1", "requester", "data-test")
        self.assertEqual(runtime.advance("local", task["id"])["status"], "awaiting_approval")
        self.assertEqual(runtime.decide("local", task["id"], "reviewer", "approve")["status"], "ready")
        original = self.service.search_knowledge("local", READER, "asset-policy")[0]
        self.service.put_knowledge("local", ADMIN, "asset-policy", "A new policy applies.", expected_version=1)
        self.assertEqual(runtime.advance("local", task["id"])["status"], "blocked")
        self.assertEqual(runtime.inspect("local", task["id"])["effects"], [])
        with database(self.path) as connection:
            history = connection.execute(
                "SELECT text FROM knowledge_history WHERE tenant = 'local' AND id = 'asset-policy' AND version = 1"
            ).fetchone()
        self.assertEqual(history["text"], original["text"])
