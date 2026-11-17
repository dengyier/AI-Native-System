"""Perform a local backup and recovery cutover with live policy fencing."""

import json
import os
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic
from unittest.mock import patch
from uuid import uuid4

import test_p7_workflow as p7

from ai_native_system.knowledge import KnowledgeRetrieval, citation_fragment
from ai_native_system.knowledge_ingest import KnowledgeIngestion
from ai_native_system.memory import MemoryStore
from ai_native_system.model_accounting import ModelLimits
from ai_native_system.model_service import EmbeddingService
from ai_native_system.runtime import Runtime
from ai_native_system.storage import task_data


DSN = os.environ.get("AI_NATIVE_P9_TEST_DSN")
CONTAINER = os.environ.get("AI_NATIVE_P9_TEST_CONTAINER")


class DeploymentRecoveryTests(p7.KnowledgeWorkflowTests):
    test_dsn = DSN
    __unittest_skip__ = not (DSN and CONTAINER)
    __unittest_skip_why__ = "Use verify_p9.py for the disposable PostgreSQL restore drill"

    @classmethod
    def setUpClass(cls):
        with patch.object(p7, "DSN", DSN):
            super().setUpClass()

    def test_restore_earlier_backup_replays_withdrawal_and_fences_old_approval(self):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import conninfo_to_dict, make_conninfo

        citation = self.cite()
        memory = MemoryStore(self.store)
        memory.remember(self.reader, "cross_task", "team", citation, ttl_seconds=300)
        task = self.approved_citation(citation, "p9-restore")
        self.authorize(task)
        with self.control.transaction(tenant=self.tenant, write=True) as connection:
            self.grant(connection, self.reader.actor, "delete", "document", citation.document_id)

        config = conninfo_to_dict(DSN)
        started = monotonic()
        archive = subprocess.check_output(
            ["docker", "exec", CONTAINER, "pg_dump", "-U", config["user"], "-d", config["dbname"],
             "--format=custom", "--schema=ai_native"], timeout=30,
        )
        dump_ms = round((monotonic() - started) * 1000)
        outside = Path(self.enterContext(TemporaryDirectory())) / "withdrawals.json"
        tombstone = self.ingestion.retire_document(self.reader, citation.document_id,
                                                  expected_version=citation.document_version, delete=True)
        outside.write_text(json.dumps(tombstone), encoding="utf-8")
        self.assertEqual(memory.recall(self.reader, "cross_task", "team"), [])

        restored_name = "p9_restore_" + uuid4().hex[:12]
        with psycopg.connect(DSN, autocommit=True) as admin:
            admin.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(restored_name)))
        started = monotonic()
        try:
            subprocess.run(
                ["docker", "exec", "-i", CONTAINER, "pg_restore", "-U", config["user"], "-d", restored_name,
                 "--single-transaction", "--exit-on-error", "--no-owner"], input=archive, timeout=30, check=True,
            )
            restore_ms = round((monotonic() - started) * 1000)
            with (self.store_type(make_conninfo(self.runtime_dsn, dbname=restored_name)) as restored,
                  self.store_type(make_conninfo(self.knowledge_dsn, dbname=restored_name)) as writer):
                epoch = self.ledger_at("p9-restored-" + uuid4().hex)
                # Inspect restored state via restricted roles before constructing a reader.
                with restored.transaction(tenant=self.tenant) as connection:
                    self.assertEqual(task_data(connection, self.tenant, task)["status"], "ready")
                    self.assertTrue(self.ledger.eligible(connection, self.tenant, task))
                    self.assertFalse(epoch.eligible(connection, self.tenant, task))
                    self.assertEqual(connection.execute("SELECT count(*) FROM knowledge_vector_chunks").fetchone()[0], 1)
                    self.assertEqual(connection.execute("SELECT count(*) FROM knowledge_memories").fetchone()[0], 1)

                reapply = KnowledgeIngestion(writer, None)
                saved = json.loads(outside.read_text(encoding="utf-8"))
                started = monotonic()
                self.assertEqual(reapply.reapply_tombstone(self.reader, saved), saved)
                replay_ms = round((monotonic() - started) * 1000)
                self.assertEqual(reapply.reapply_tombstone(self.reader, saved), saved)

                limits = ModelLimits(**self.config["limits"])
                retrieval = KnowledgeRetrieval(restored, EmbeddingService(restored, self.config, limits))
                self.assertEqual(retrieval.search(self.reader, "恢复后的校验资料", limit=1).hits, ())
                self.assertEqual(MemoryStore(restored).recall(self.reader, "cross_task", "team"), [])
                with restored.transaction(tenant=self.tenant) as connection:
                    with self.assertRaises(PermissionError):
                        citation_fragment(connection, self.reader, citation)
                    for table in ("knowledge", "knowledge_history", "knowledge_vector_chunks"):
                        predicate = "id" if table in ("knowledge", "knowledge_history") else "document_id"
                        count, = connection.execute(f"SELECT count(*) FROM {table} WHERE {predicate}=?",
                                                    (citation.document_id,)).fetchone()
                        self.assertEqual(count, 0)
                runtime = Runtime(restored, self.registry, self.runtime.model, self.runtime.tools,
                                  owp_ledgers={self.tenant: epoch})
                self.assertEqual(runtime.advance(self.tenant, task)["status"], "blocked")
                with restored.transaction(tenant=self.tenant) as connection:
                    self.assertEqual(tuple(connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                                           for table in ("effects", "owp_consumptions", "owp_effect_evidence")),
                                     (0, 0, 0))
                self.assertEqual(self.counts(), (0, 0, 0))
            print(f"P9 local recovery sample: {len(archive)} bytes, dump {dump_ms} ms, restore {restore_ms} ms, "
                  f"withdrawal replay {replay_ms} ms", flush=True)
        finally:
            with psycopg.connect(DSN, autocommit=True) as admin:
                admin.execute(sql.SQL("DROP DATABASE {} WITH (FORCE)").format(sql.Identifier(restored_name)))


def load_tests(loader, _suite, _pattern):
    names = (name for name, item in vars(DeploymentRecoveryTests).items()
             if name.startswith(loader.testMethodPrefix) and callable(item))
    return unittest.TestSuite(DeploymentRecoveryTests(name) for name in sorted(names))
