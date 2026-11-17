"""An explicitly migrated, thread-scoped PostgreSQL checkpointer for LangGraph."""

from contextlib import contextmanager
from hashlib import sha256
from importlib.metadata import PackageNotFoundError, version
from math import ceil, isfinite
from threading import BoundedSemaphore


SCHEMA = "ai_native_graph"
CHECKPOINT_TABLES = ("checkpoints", "checkpoint_blobs", "checkpoint_writes")
_SCHEMA_LOCK = (0x41494E, 0x47524150)
_SDK_VERSION = "3.2.1"


class GraphStorageError(ValueError):
    """Checkpoint storage could not safely provide the requested graph session."""


def _sdk():
    try:
        if version("langgraph-checkpoint-postgres") != _SDK_VERSION:
            raise GraphStorageError(f"Install LangGraph PostgreSQL checkpoint {_SDK_VERSION} from the lock file")
        from langgraph.checkpoint.postgres import PostgresSaver
        from langgraph.checkpoint.serde.jsonplus import JsonPlusSerializer
    except (ImportError, PackageNotFoundError):
        raise GraphStorageError("Install the locked LangGraph and PostgreSQL dependencies") from None
    return PostgresSaver, JsonPlusSerializer(pickle_fallback=False, allowed_msgpack_modules=())


@contextmanager
def _connect(dsn, *, timeout, statement_timeout, setup=False):
    import psycopg

    connection = None
    try:
        connection = psycopg.connect(dsn, autocommit=True, prepare_threshold=0,
                                     connect_timeout=max(2, ceil(timeout)), target_session_attrs="read-write")
        connection.execute("SET search_path TO ai_native_graph, pg_catalog, pg_temp" if setup else
                           "SET search_path TO pg_catalog, ai_native_graph, pg_temp")
        connection.execute("""SELECT pg_catalog.set_config('lock_timeout', %s, false),
                                     pg_catalog.set_config('statement_timeout', %s, false)""",
                           (f"{int(timeout * 1000)}ms", f"{int(statement_timeout * 1000)}ms"))
    except psycopg.Error:
        if connection is not None:
            connection.close()
        raise GraphStorageError("Failed to open a LangGraph checkpoint connection") from None
    with connection:
        yield connection


def _revisions(connection):
    return tuple(row[0] for row in connection.execute("SELECT v FROM ai_native_graph.checkpoint_migrations ORDER BY v"))


def setup_graph_postgres(dsn):
    """Run the locked official SDK's migrations and provision checkpoint row security."""
    if type(dsn) is not str or not dsn.strip():
        raise GraphStorageError("An explicit LangGraph migration DSN is required")
    saver_type, serde = _sdk()
    import psycopg
    from psycopg import sql

    with _connect(dsn, timeout=5, statement_timeout=60, setup=True) as connection:
        try:
            connection.execute("SELECT pg_catalog.pg_advisory_lock(%s, %s)", _SCHEMA_LOCK)
            if connection.execute("SELECT to_regnamespace('ai_native_graph')").fetchone()[0] is None:
                connection.execute("CREATE SCHEMA ai_native_graph")
            expected = tuple(range(len(saver_type.MIGRATIONS)))
            if connection.execute("SELECT to_regclass('ai_native_graph.checkpoint_migrations')").fetchone()[0] is not None:
                applied = _revisions(connection)
                if applied != expected[:len(applied)]:
                    raise GraphStorageError("LangGraph checkpoint migrations are unknown or out of order")
            # The SDK has CREATE INDEX CONCURRENTLY revisions, so setup uses autocommit.
            saver_type(connection, serde=serde).setup()
            with connection.transaction():
                for table_name in CHECKPOINT_TABLES:
                    table = sql.Identifier(SCHEMA, table_name)
                    connection.execute(sql.SQL("ALTER TABLE {} ENABLE ROW LEVEL SECURITY").format(table))
                    connection.execute(sql.SQL("ALTER TABLE {} FORCE ROW LEVEL SECURITY").format(table))
                    connection.execute(sql.SQL("DROP POLICY IF EXISTS graph_thread ON {}").format(table))
                    connection.execute(sql.SQL("""CREATE POLICY graph_thread ON {}
                        USING (thread_id = NULLIF(pg_catalog.current_setting('ai_native_graph.thread_id', true), ''))
                    """).format(table))
            return expected[-1]
        except psycopg.Error:
            raise GraphStorageError("LangGraph checkpoint setup failed; use the separate schema owner") from None


class PostgresGraphStore:
    """Bind each official checkpointer to an exclusive, row-scoped graph session.

    A direct PostgreSQL session holds the advisory lock while the graph is
    examined and advanced. Backend disconnect and normal exit release the lock.
    The framework must authorize tasks before claiming their derived thread IDs.
    """

    def __init__(self, dsn, *, max_connections=4, timeout=5, statement_timeout=15):
        if type(dsn) is not str or not dsn.strip():
            raise GraphStorageError("An explicit LangGraph runtime DSN is required")
        if type(max_connections) is not int or max_connections < 1:
            raise ValueError("LangGraph connection capacity must be a positive integer")
        for seconds in (timeout, statement_timeout):
            if type(seconds) not in (int, float) or not isfinite(seconds) or not 0.001 <= seconds <= 120:
                raise ValueError("LangGraph database timeouts must be between one millisecond and 120 seconds")
        self._dsn = dsn
        self._timeout = timeout
        self._statement_timeout = statement_timeout
        self._slots = BoundedSemaphore(max_connections)
        self._ready = False

    def __enter__(self):
        self._saver_type, self._serde = _sdk()
        self.check_ready()
        self._ready = True
        return self

    def __exit__(self, *exc):
        self._ready = False

    def _connect(self):
        return _connect(self._dsn, timeout=self._timeout, statement_timeout=self._statement_timeout)

    def check_ready(self):
        """Validate migrations, grants and mandatory table isolation without running DDL."""
        import psycopg

        saver_type, _ = _sdk()
        with self._connect() as connection:
            try:
                with connection.transaction():
                    connection.execute("SELECT pg_catalog.pg_advisory_xact_lock_shared(%s, %s)", _SCHEMA_LOCK)
                    expected = tuple(range(len(saver_type.MIGRATIONS)))
                    if _revisions(connection) != expected:
                        raise GraphStorageError("Run the explicit LangGraph checkpoint migration")
                    tables = connection.execute("""SELECT c.oid, c.relrowsecurity AND c.relforcerowsecurity,
                               (SELECT count(*) = 1 AND bool_and(p.polname = 'graph_thread')
                                FROM pg_catalog.pg_policy p WHERE p.polrelid = c.oid),
                               has_table_privilege(current_user, c.oid, 'SELECT')
                                   AND has_table_privilege(current_user, c.oid, 'INSERT')
                                   AND has_table_privilege(current_user, c.oid, 'UPDATE')
                        FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
                        WHERE n.nspname = 'ai_native_graph' AND c.relname = ANY(%s)""",
                        (list(CHECKPOINT_TABLES),),
                    ).fetchall()
                    if len(tables) != len(CHECKPOINT_TABLES) or not all(all(row[1:]) for row in tables):
                        raise GraphStorageError("LangGraph checkpoint isolation or runtime grants are incomplete")
                    unsafe_role = connection.execute("""SELECT EXISTS (
                        SELECT 1 FROM pg_catalog.pg_roles r
                        WHERE (r.rolname IN (current_user, session_user) OR pg_has_role(session_user, r.oid, 'SET'))
                          AND (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole
                            OR has_schema_privilege(r.oid, 'ai_native_graph', 'CREATE')
                            OR has_table_privilege(r.oid, 'ai_native_graph.checkpoint_migrations',
                                                   'INSERT, UPDATE, DELETE, TRUNCATE')
                            OR EXISTS (SELECT 1 FROM pg_catalog.pg_class c WHERE c.oid = ANY(%s::oid[])
                                AND (pg_has_role(r.oid, c.relowner, 'USAGE')
                                     OR has_table_privilege(r.oid, c.oid, 'DELETE, TRUNCATE'))))
                    )""", ([row[0] for row in tables],)).fetchone()[0]
                    if unsafe_role:
                        raise GraphStorageError("Use a separate least-privilege LangGraph checkpoint runtime role")
            except psycopg.Error:
                raise GraphStorageError("LangGraph checkpoint schema is unavailable to the runtime role") from None
        return expected[-1]

    @contextmanager
    def claim(self, thread_id):
        """Yield a scoped official PostgresSaver, or None for an already claimed thread."""
        import psycopg

        if type(thread_id) is not str or not thread_id or len(thread_id) > 256 or not thread_id.isascii() or not all(
            32 < ord(char) < 127 for char in thread_id
        ):
            raise ValueError("A stable printable LangGraph thread ID is required")
        if not self._ready:
            raise GraphStorageError("Open the LangGraph checkpoint store before claiming a thread")
        if not self._slots.acquire(timeout=self._timeout):
            raise GraphStorageError("LangGraph checkpoint connection capacity exhausted")
        material = f"ai_native/graph/thread/{thread_id}".encode("ascii")
        key = int.from_bytes(sha256(material).digest()[:8], "big", signed=True)
        try:
            with self._connect() as connection:
                try:
                    if not connection.execute("SELECT pg_catalog.pg_try_advisory_lock_shared(%s, %s)",
                                              _SCHEMA_LOCK).fetchone()[0]:
                        raise GraphStorageError("LangGraph checkpoint maintenance is in progress")
                    acquired = connection.execute("SELECT pg_catalog.pg_try_advisory_lock(%s::bigint)",
                                                  (key,)).fetchone()[0]
                    if acquired:
                        connection.execute("SELECT pg_catalog.set_config('ai_native_graph.thread_id', %s, false)",
                                           (thread_id,))
                except psycopg.Error:
                    raise GraphStorageError("Failed to claim the LangGraph checkpoint thread") from None
                yield self._saver_type(connection, serde=self._serde) if acquired else None
        finally:
            self._slots.release()
