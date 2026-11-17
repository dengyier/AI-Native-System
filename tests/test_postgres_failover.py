"""The P9 disposable physical-cluster rehearsal, including concurrent Runtime recovery."""

import json
import multiprocessing
import os
import subprocess
import time
import unittest

import psycopg
from cryptography.hazmat.primitives import serialization
from psycopg.conninfo import conninfo_to_dict, make_conninfo
from psycopg_pool import PoolTimeout

from ai_native_system.adapters.langgraph_postgres import PostgresGraphStore
from ai_native_system.adapters.owp import key_id, verify_authorization
from ai_native_system.adapters.postgres_runtime import PostgresRuntimeStore
from ai_native_system.gateway import ModelGateway
from ai_native_system.model import DemoModel
from ai_native_system.model_accounting import ModelAccounting, ModelBudgetError, ModelLimits, ModelPrice
from ai_native_system.registry import Registry
from ai_native_system.remote import HttpRemote
from ai_native_system.runtime import Runtime
from ai_native_system.security import AuthorizationLedger
from ai_native_system.tools import ToolRegistry

import test_graph_runtime
from test_p2b_workflow import FIXTURE
from test_security_entry import SecureWorkflowFixture


PRIMARY_DSN = os.environ.get("AI_NATIVE_P9_HA_PRIMARY_DSN")
STANDBY_DSN = os.environ.get("AI_NATIVE_P9_HA_STANDBY_DSN")
PRIMARY_CONTAINER = os.environ.get("AI_NATIVE_P9_HA_PRIMARY_CONTAINER")
BACKEND = "SELECT inet_server_addr()::text, pg_is_in_recovery(), current_setting('synchronous_commit')"


def writable_endpoints(dsn):
    primary = conninfo_to_dict(PRIMARY_DSN)
    standby = conninfo_to_dict(STANDBY_DSN)
    return make_conninfo(dsn, host=f"{primary['host']},{standby['host']}",
                         hostaddr=f"{primary['hostaddr']},{standby['hostaddr']}",
                         port=f"{primary['port']},{standby['port']}", connect_timeout=2,
                         target_session_attrs="read-write")


def wait_for_read(probe, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            result = probe()
            if result:
                return result
        except (psycopg.OperationalError, psycopg.InterfaceError, PoolTimeout):
            pass
        time.sleep(0.05)
    raise TimeoutError("The PostgreSQL readiness read did not succeed")


def backend(store):
    with store.transaction() as connection:
        return tuple(connection.execute(BACKEND).fetchone())


def ledger_for(public_pem):
    key = serialization.load_pem_public_key(public_pem)
    return AuthorizationLedger("deployment-1", lambda envelope: verify_authorization(envelope, {key_id(key): key}))


def public_key(fixture):
    return fixture.private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def runtime_replica(runtime_dsn, graph_dsn, local_task, remote_task, remote_endpoint, model_call, proceed, reports):
    model = ModelGateway(default="default", max_context_bytes=65536)
    model.register("default", DemoModel())
    tools = ToolRegistry()
    tools.register_remote("remote.verify", "1", HttpRemote(remote_endpoint))
    remote_tenant, remote_id, remote_key = remote_task
    local_tenant, local_id, local_key = local_task
    ledgers = {local_tenant: ledger_for(local_key), remote_tenant: ledger_for(remote_key)}
    with PostgresRuntimeStore(runtime_dsn, max_connections=1, timeout=2) as store:
        with PostgresGraphStore(graph_dsn) as checkpoints:
            runtime = Runtime(store, Registry.load(FIXTURE), model, tools, owp_ledgers=ledgers, graph_store=checkpoints)
            reports.put(("warm", os.getpid(), backend(store)))
            if not proceed.wait(30):
                raise TimeoutError("The failover signal was not received")
            started = time.monotonic()
            new_backend = wait_for_read(lambda: backend(store))
            ready_after = time.monotonic() - started
            local = runtime.advance(local_tenant, local_id)["status"]
            remote = runtime.reconcile(remote_tenant, remote_id)["status"]
            try:
                ModelAccounting(store).reserve(
                    local_tenant, model_call, route="default", provider="fixture", model="fixture", model_version="1",
                    max_input_tokens=8, max_output_tokens=4, price=ModelPrice("test", 1, 1), timeout_seconds=60,
                )
                budget = "reserved"
            except ModelBudgetError as error:
                budget = error.reason
            reports.put(("resumed", os.getpid(), new_backend, local, remote, ready_after, budget))


def stop_workers(workers):
    for worker in workers:
        worker.join(1)
        if worker.is_alive():
            worker.terminate()
            worker.join(5)
        if not worker.is_alive():
            worker.close()


@unittest.skipUnless(PRIMARY_DSN and STANDBY_DSN and PRIMARY_CONTAINER,
                     "Run verify_p9_ha.py to rehearse physical PostgreSQL failover")
class PostgresFailoverTests(unittest.TestCase):
    def test_runtime_replicas_resume_graph_and_reconcile_remote_write_after_fenced_promotion(self):
        class RemoteWorkflow(SecureWorkflowFixture, unittest.TestCase):
            test_dsn = PRIMARY_DSN

        class GraphWorkflow(test_graph_runtime.GraphRuntimeTests):
            test_dsn = PRIMARY_DSN

        remote, graph = RemoteWorkflow(), GraphWorkflow()
        for fixture in (remote, graph):
            fixture.setUpClass()
            self.addCleanup(fixture.doCleanups)
            fixture.setUp()

        remote_id = remote.approved("remote-before-failover")
        remote.authorize(remote_id)
        remote.remote.drop_after_commit = True
        self.assertEqual(remote.runtime.advance(remote.tenant, remote_id)["status"], "reconciling")
        self.assertEqual(remote.counts(), (0, 1, 0))
        receipt, = remote.remote.operation_states()
        self.assertEqual(receipt["status"], "succeeded")

        graph_id = graph.submit_task("local-after-failover")
        review = graph.plan_to_approval(graph_id)
        graph.approve(graph_id, review)
        graph.authorize(graph_id)
        checkpoint = graph.persisted_checkpoint(graph_id)
        self.assertEqual(checkpoint.checkpoint["channel_values"]["status"], "awaiting_approval")
        self.assertEqual(graph.counts(), (0, 0, 0))
        model_calls = ("replica-model-1", "replica-model-2")
        accounting = ModelAccounting(graph.store)
        for call_id in model_calls:
            accounting.open_call(graph.tenant, call_id, limits=ModelLimits(1, 1, 100, 100, 120))

        context = multiprocessing.get_context("spawn")
        reports = context.Queue()
        self.addCleanup(reports.close)
        proceed = context.Event()
        workers = []
        self.addCleanup(stop_workers, workers)
        runtime_dsn = writable_endpoints(graph.runtime_dsn)
        graph_dsn = writable_endpoints(graph.checkpoint_dsn)
        for call_id in model_calls:
            worker = context.Process(target=runtime_replica, args=(
                runtime_dsn, graph_dsn, (graph.tenant, graph_id, public_key(graph)),
                (remote.tenant, remote_id, public_key(remote)), remote.remote.endpoint, call_id, proceed, reports,
            ))
            worker.start()
            workers.append(worker)

        with psycopg.connect(PRIMARY_DSN, autocommit=True) as primary, psycopg.connect(STANDBY_DSN, autocommit=True) as standby:
            primary_backend = primary.execute(BACKEND).fetchone()
            standby_backend = standby.execute(BACKEND).fetchone()
            self.assertEqual(primary_backend[1:], (False, "remote_apply"))
            self.assertTrue(standby_backend[1])
            self.assertNotEqual(primary_backend[0], standby_backend[0])
            warm = [reports.get(timeout=15) for _ in workers]
            self.assertEqual({item[0] for item in warm}, {"warm"})
            self.assertEqual({item[1] for item in warm}, {worker.pid for worker in workers})
            self.assertEqual({item[2] for item in warm}, {primary_backend})
            fence_lsn, = primary.execute("SELECT pg_current_wal_flush_lsn()").fetchone()
            wait_for_read(lambda: standby.execute("SELECT pg_last_wal_replay_lsn() >= %s::pg_lsn", (fence_lsn,)).fetchone()[0])

            project = subprocess.check_output([
                "docker", "inspect", "-f", '{{index .Config.Labels "com.docker.compose.project"}}', PRIMARY_CONTAINER,
            ], text=True, timeout=10).strip()
            self.assertTrue(project.startswith("ai-native-p9-ha-"))
            address = subprocess.check_output(["docker", "port", PRIMARY_CONTAINER, "5432/tcp"],
                                              text=True, timeout=10).strip()
            primary_endpoint = conninfo_to_dict(PRIMARY_DSN)
            self.assertEqual(address, f"127.0.0.1:{primary_endpoint['port']}")
            # Deliberately leave one real runtime transaction open through the crash.
            with self.assertRaises(psycopg.OperationalError):
                with remote.store.transaction(tenant=remote.tenant, write=True) as transaction:
                    transaction.execute("INSERT INTO events (task_id, event, detail) VALUES (?, ?, ?)",
                                        (remote_id, "uncommitted_p9_probe", "{}"))
                    started = time.monotonic()
                    subprocess.run(["docker", "kill", "--signal", "KILL", PRIMARY_CONTAINER],
                                   check=True, capture_output=True, timeout=10)
                    running = subprocess.check_output(["docker", "inspect", "-f", "{{.State.Running}}", PRIMARY_CONTAINER],
                                                      text=True, timeout=10).strip()
                    self.assertEqual(running, "false")
            # The failover DSN must reject the remaining server until promotion.
            with self.assertRaisesRegex(psycopg.OperationalError, "session is read-only"):
                with psycopg.connect(runtime_dsn):
                    self.fail("A read-write client connected while no primary was available")
            self.assertEqual(standby.execute("SELECT pg_promote(wait_seconds=>15)").fetchone(), (True,))
            self.assertFalse(standby.execute("SELECT pg_is_in_recovery()").fetchone()[0])
            cutover = time.monotonic() - started
            proceed.set()

        resumed = [reports.get(timeout=25) for _ in workers]
        self.assertEqual({item[0] for item in resumed}, {"resumed"})
        self.assertEqual({item[1] for item in resumed}, {worker.pid for worker in workers})
        self.assertEqual({item[2][:2] for item in resumed}, {(standby_backend[0], False)})
        self.assertIn("completed", {item[3] for item in resumed})
        self.assertIn("completed", {item[4] for item in resumed})
        self.assertCountEqual([item[6] for item in resumed], ["reserved", "concurrency"])
        for worker in workers:
            worker.join(5)
            self.assertEqual(worker.exitcode, 0)

        with PostgresRuntimeStore(runtime_dsn) as store:
            remote.store = graph.store = store
            self.assertEqual(remote.counts(), (1, 1, 1))
            self.assertEqual(graph.counts(), (1, 1, 1))
            with store.transaction(tenant=remote.tenant) as connection:
                self.assertEqual(connection.execute(
                    "SELECT count(*) FROM events WHERE task_id=? AND event='uncommitted_p9_probe'", (remote_id,),
                ).fetchone()[0], 0)
                response, attempts = connection.execute(
                    "SELECT response, attempts FROM remote_operations WHERE operation_id=?", (receipt["operation_id"],),
                ).fetchone()
                self.assertEqual(json.loads(response), receipt)
                self.assertEqual(attempts, 1)
            with store.transaction(tenant=graph.tenant) as connection:
                self.assertEqual(connection.execute("SELECT status FROM tasks WHERE id=?", (graph_id,)).fetchone()[0], "completed")
            usage = ModelAccounting(store).usage(graph.tenant)["totals"]
            self.assertEqual(usage["active_attempts"], 1)
            self.assertEqual(usage["charged_tokens"], 12)

        calls = remote.remote.calls
        self.assertEqual([path for path, _ in calls].count("/execute"), 1)
        self.assertIn("/lookup", [path for path, _ in calls])
        self.assertEqual({payload["operation_id"] for _, payload in calls}, {receipt["operation_id"]})
        self.assertEqual(remote.remote.operation_states(), [receipt])
        print(f"P9 local failover: replayed through {fence_lsn}; fence-to-promotion {cutover:.2f}s; "
              f"warmed pools recovered in {max(item[5] for item in resumed):.2f}s after promotion", flush=True)
