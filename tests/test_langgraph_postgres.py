"""Exercise the official checkpoint adapter with separate PostgreSQL roles."""

import os
import secrets
import unittest
from typing import TypedDict

from ai_native_system.adapters.langgraph_postgres import GraphStorageError, PostgresGraphStore, setup_graph_postgres


DSN = os.environ.get("AI_NATIVE_P6_TEST_DSN")


def graph_role(dsn, *, grants=True):
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo

    username, password = f"p6_checkpoint_{secrets.token_hex(6)}", secrets.token_urlsafe(24)
    role = sql.Identifier(username)
    with psycopg.connect(dsn) as owner:
        owner.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(role, sql.Literal(password)))
        if grants:
            owner.execute(sql.SQL("GRANT USAGE ON SCHEMA ai_native_graph TO {}").format(role))
            owner.execute(sql.SQL("GRANT SELECT ON ai_native_graph.checkpoint_migrations TO {}").format(role))
            owner.execute(
                sql.SQL("""GRANT SELECT, INSERT, UPDATE ON ai_native_graph.checkpoints,
                    ai_native_graph.checkpoint_blobs, ai_native_graph.checkpoint_writes TO {}""").format(role),
            )
    return make_conninfo(dsn, user=username, password=password)


class ExampleState(TypedDict):
    result: str


def example_graph(checkpointer):
    from langgraph.graph import END, START, StateGraph
    from langgraph.types import interrupt

    def review(state):
        decision = interrupt({"requested": state["result"]})
        return {"result": decision}

    builder = StateGraph(ExampleState)
    builder.add_node("review", review)
    builder.add_edge(START, "review")
    builder.add_edge("review", END)
    return builder.compile(checkpointer=checkpointer)


@unittest.skipUnless(DSN, "Run the P6 PostgreSQL verification runner")
class LangGraphPostgresTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.head = setup_graph_postgres(DSN)
        cls.runtime_dsn = graph_role(DSN)

    def new_thread(self):
        thread = secrets.token_hex(32)
        return thread, {"configurable": {"thread_id": thread}}

    def test_explicit_migration_and_restricted_runtime(self):
        from psycopg.errors import InsufficientPrivilege

        self.assertEqual(setup_graph_postgres(DSN), self.head)
        with self.assertRaisesRegex(GraphStorageError, "separate least-privilege"):
            with PostgresGraphStore(DSN):
                self.fail("Owner was allowed as runtime")
        with self.assertRaisesRegex(GraphStorageError, "unavailable to the runtime role"):
            with PostgresGraphStore(graph_role(DSN, grants=False)):
                self.fail("Ungrantable runtime connected successfully")
        thread, _ = self.new_thread()
        with PostgresGraphStore(self.runtime_dsn) as store, store.claim(thread) as saver:
            self.assertEqual(store.check_ready(), self.head)
            for statement in ("CREATE TABLE ai_native_graph.forbidden (id int)",
                              "INSERT INTO ai_native_graph.checkpoint_migrations VALUES (99999)",
                              "TRUNCATE ai_native_graph.checkpoints"):
                with self.subTest(statement=statement), self.assertRaises(InsufficientPrivilege):
                    saver.conn.execute(statement)

    def test_precreated_schema_can_be_migrated_by_its_non_superuser_owner(self):
        import psycopg
        from psycopg import sql
        from psycopg.conninfo import conninfo_to_dict, make_conninfo

        database_name = "p6_checkpoint_owner_" + secrets.token_hex(6)
        database = sql.Identifier(database_name)
        with psycopg.connect(DSN, autocommit=True) as bootstrap:
            bootstrap.execute(sql.SQL("CREATE DATABASE {}").format(database))
        admin_dsn = make_conninfo(DSN, dbname=database_name)
        try:
            owner_dsn = graph_role(admin_dsn, grants=False)
            owner = sql.Identifier(conninfo_to_dict(owner_dsn)["user"])
            with psycopg.connect(admin_dsn) as admin:
                admin.execute(sql.SQL("CREATE SCHEMA ai_native_graph AUTHORIZATION {}").format(owner))
            self.assertEqual(setup_graph_postgres(owner_dsn), self.head)
            thread, _ = self.new_thread()
            with PostgresGraphStore(graph_role(admin_dsn)) as store, store.claim(thread) as saver:
                self.assertIsNotNone(saver)
        finally:
            with psycopg.connect(DSN, autocommit=True) as bootstrap:
                bootstrap.execute(sql.SQL("DROP DATABASE {}").format(database))

    def test_interrupt_survives_restart_and_database_limits_thread_scope(self):
        from langgraph.types import Command
        from psycopg.errors import InsufficientPrivilege

        thread, config = self.new_thread()
        other, other_config = self.new_thread()
        with PostgresGraphStore(self.runtime_dsn) as store, store.claim(thread) as saver:
            graph = example_graph(saver)
            output = graph.invoke({"result": "pending"}, config=config, durability="sync")
            self.assertEqual(output["__interrupt__"][0].value, {"requested": "pending"})

        with PostgresGraphStore(self.runtime_dsn) as reopened:
            with reopened.claim(other) as saver:
                self.assertIsNone(saver.get_tuple(config))
                with self.assertRaises(InsufficientPrivilege):
                    saver.conn.execute("""INSERT INTO ai_native_graph.checkpoint_blobs
                       (thread_id, checkpoint_ns, channel, version, type) VALUES (%s, '', 'x', '0', 'empty')""",
                       (thread,),
                    )
                example_graph(saver).invoke({"result": "other"}, config=other_config, durability="sync")
            with reopened.claim(thread) as saver:
                entries = saver.conn.execute("SELECT DISTINCT thread_id FROM ai_native_graph.checkpoints").fetchall()
                self.assertEqual(entries, [(thread,)])
                graph = example_graph(saver)
                self.assertEqual(graph.get_state(config).interrupts[0].value, {"requested": "pending"})
                finished = graph.invoke(Command(resume="approved elsewhere"), config=config, durability="sync")
                self.assertEqual(finished["result"], "approved elsewhere")
                self.assertFalse(graph.get_state(config).next)

    def test_claims_serialize_one_thread_across_sessions_without_blocking_others(self):
        thread, _ = self.new_thread()
        other, _ = self.new_thread()
        with PostgresGraphStore(self.runtime_dsn) as first, PostgresGraphStore(self.runtime_dsn) as second:
            with first.claim(thread) as winner:
                self.assertIsNotNone(winner)
                with second.claim(thread) as duplicate, second.claim(other) as different:
                    self.assertIsNone(duplicate)
                    self.assertIsNotNone(different)
            with second.claim(thread) as released:
                self.assertIsNotNone(released)

    def test_no_pickle_fallback_and_bounded_session_capacity(self):
        import pickle

        thread, _ = self.new_thread()
        other, _ = self.new_thread()
        with PostgresGraphStore(self.runtime_dsn, max_connections=1, timeout=0.01) as store:
            with store.claim(thread) as saver:
                with self.assertRaisesRegex(NotImplementedError, "serialization type"):
                    saver.serde.loads_typed(("pickle", pickle.dumps({"untrusted": True})))
                with self.assertRaisesRegex(GraphStorageError, "capacity exhausted"):
                    with store.claim(other):
                        self.fail("Checkpoint capacity unexpectedly exceeded")
