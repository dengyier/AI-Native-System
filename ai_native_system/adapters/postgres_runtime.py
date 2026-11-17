"""Explicit PostgreSQL storage for the existing governed runtime."""

import math
from contextlib import contextmanager
from hashlib import sha256

from psycopg_pool import ConnectionPool

from ..storage import seed_rows
from .postgres import SCHEMA_LOCK, MigrationError, require_compatible_schema


class _Row:
    """Provide the name, position and iteration access used by sqlite3.Row."""

    def __init__(self, columns, values):
        self._columns = columns
        self._values = values

    def keys(self):
        return self._columns.keys()

    def __getitem__(self, key):
        return self._values[self._columns[key] if isinstance(key, str) else key]

    def __iter__(self):
        return iter(self._values)

    def __len__(self):
        return len(self._values)


def _row_factory(cursor):
    columns = {column.name: index for index, column in enumerate(cursor.description or ())}
    return lambda values: _Row(columns, values)


def _bind(statement, size):
    # Shared SQL uses positional ? markers and binds all input as parameters.
    if statement.count("?") != size:
        raise ValueError("Expected one ? placeholder per PostgreSQL runtime SQL parameter")
    return statement.replace("%", "%%").replace("?", "%s")


class _Transaction:
    def __init__(self, connection):
        self._connection = connection

    def execute(self, statement, parameters=()):
        if not parameters:
            return self._connection.execute(statement)
        return self._connection.execute(_bind(statement, len(parameters)), parameters)

    def executemany(self, statement, rows):
        with self._connection.cursor() as cursor:
            cursor.executemany(_bind(statement, statement.count("?")), rows)

    @contextmanager
    def scan(self, statement, parameters):
        with self._connection.cursor(name="ai_native_scan") as cursor:
            cursor.execute(_bind(statement, len(parameters)), parameters)
            yield cursor

    def database_time(self):
        return self._connection.execute("SELECT extract(epoch FROM clock_timestamp())::double precision").fetchone()[0]


def _tenant_lock(tenant):
    # PostgreSQL's one-bigint lock namespace is disjoint from the two-int schema lock.
    material = f"ai_native/runtime/{tenant}".encode("utf-8")
    return int.from_bytes(sha256(material).digest()[:8], "big", signed=True)


class PostgresRuntimeStore:
    """Use a dedicated runtime DSN and explicit migrations before entering the store.

    The tenant lock serializes framework writes, including trusted SQL tools.
    Other writers must follow the same lock protocol. Only the trusted runtime
    sets the transaction tenant used by the database's row security policies.
    """

    def __init__(self, dsn, *, max_connections=4, timeout=5, statement_timeout=15):
        if type(dsn) is not str or not dsn.strip():
            raise ValueError("An explicit PostgreSQL runtime DSN is required")
        if type(max_connections) is not int or max_connections < 1:
            raise ValueError("PostgreSQL pool size must be a positive integer")
        for seconds in (timeout, statement_timeout):
            if type(seconds) not in (int, float) or not math.isfinite(seconds) or seconds < 0.001:
                raise ValueError("PostgreSQL timeouts must be at least one millisecond")
        self._timeout = timeout
        self._settings = (f"{int(timeout * 1000)}ms", f"{int(statement_timeout * 1000)}ms")
        self._pool = ConnectionPool(
            dsn, open=False, min_size=1, max_size=max_connections, timeout=timeout,
            kwargs={"autocommit": True, "row_factory": _row_factory,
                    "connect_timeout": max(2, math.ceil(timeout)), "target_session_attrs": "read-write"},
        )

    def __enter__(self):
        try:
            self._pool.open(wait=True, timeout=self._timeout)
            self.check_ready()
        except BaseException:
            self._pool.close()
            raise
        return self

    def __exit__(self, *exc):
        self._pool.close()

    def check_ready(self):
        """Check migration compatibility and reject a DDL-capable runtime login."""
        with self._connection(write=False) as connection:
            revision = require_compatible_schema(connection)
            unsafe_role = connection.execute("""SELECT EXISTS (
                SELECT 1 FROM pg_roles r
                WHERE (r.rolname IN (current_user, session_user) OR pg_has_role(session_user, r.oid, 'SET'))
                  AND (r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR has_schema_privilege(r.oid, 'ai_native', 'CREATE')
                    OR EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                               WHERE n.nspname = 'ai_native'
                                 AND (pg_has_role(r.oid, c.relowner, 'USAGE')
                                      OR (c.relkind IN ('r', 'p') AND has_table_privilege(r.oid, c.oid, 'TRUNCATE'))))
                    OR has_table_privilege(r.oid, 'ai_native.schema_migrations', 'INSERT, UPDATE, DELETE, TRUNCATE')
                    OR has_table_privilege(r.oid, 'ai_native.sqlite_imports', 'INSERT, UPDATE, DELETE, TRUNCATE'))
                )""").fetchone()[0]
            if unsafe_role:
                raise MigrationError("Use a separate runtime role without owner, bypass, DDL or import privileges")
            return revision

    def check_governance_role(self):
        """Keep identity, policy and publication controls outside the task runtime role."""
        with self._connection(write=False) as connection:
            invalid = connection.execute("""SELECT EXISTS (
                SELECT 1 FROM pg_roles r CROSS JOIN pg_class c
                JOIN pg_namespace n ON c.relnamespace = n.oid
                WHERE n.nspname = 'ai_native'
                  AND (r.rolname IN (current_user, session_user) OR pg_has_role(session_user, r.oid, 'SET'))
                  AND (
                    (c.relname IN ('governed_tenants', 'enterprise_delegations', 'enterprise_delegation_scopes',
                                   'resource_grants', 'application_releases', 'application_release_lifecycle',
                                   'application_release_selections', 'fact_rule_bindings',
                                   'fact_authorities', 'fact_observations', 'source_sync_streams', 'source_sync_progress',
                                   'source_sync_snapshots', 'source_sync_deliveries', 'source_sync_conflicts',
                                   'source_sync_records', 'fact_feedback_observations',
                                   'identity_mappings', 'fact_assertions', 'fact_projections',
                                   'source_events', 'source_cursors', 'fact_invalidation_outbox',
                                   'owp_authorizations', 'owp_revocations', 'owp_enforced_tenants',
                                   'p4_sequences', 'p4_sequence_steps', 'p4_compensations', 'p4_proof_records')
                       AND (has_any_column_privilege(r.oid, c.oid, 'INSERT, UPDATE, REFERENCES')
                            OR has_table_privilege(r.oid, c.oid, 'DELETE')))
                    OR (c.relname IN ('owp_task_admissions', 'owp_consumptions', 'owp_effect_evidence', 'p4_delivery_jobs')
                       AND (has_any_column_privilege(r.oid, c.oid, 'UPDATE, REFERENCES')
                            OR has_table_privilege(r.oid, c.oid, 'DELETE')))
                    OR (c.relname = 'task_governance'
                       AND (has_table_privilege(r.oid, c.oid, 'DELETE')
                            OR EXISTS (SELECT 1 FROM pg_attribute a
                                       WHERE a.attrelid = c.oid AND a.attnum > 0 AND a.attname <> 'approver_context'
                                         AND has_column_privilege(r.oid, c.oid, a.attnum, 'UPDATE'))))
                  )
            )""").fetchone()[0]
            if invalid:
                raise MigrationError("Use a separate operator role for enterprise governance writes")
            if not connection.execute(
                """SELECT has_table_privilege(current_user, 'ai_native.governed_tenants', 'SELECT')
                       AND has_table_privilege(current_user, 'ai_native.fact_rule_bindings', 'SELECT')
                       AND has_table_privilege(current_user, 'ai_native.owp_enforced_tenants', 'SELECT')
                       AND has_table_privilege(current_user, 'ai_native.p4_sequence_steps', 'SELECT')""",
            ).fetchone()[0]:
                raise MigrationError("Grant runtime SELECT on governed_tenants, fact_rule_bindings, owp_enforced_tenants and p4_sequence_steps")

    @contextmanager
    def _connection(self, *, write, exclusive=False, tenant=None):
        with self._pool.connection() as connection, connection.transaction():
            if write:
                connection.execute("SET TRANSACTION ISOLATION LEVEL READ COMMITTED")
            else:
                connection.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            connection.execute("SET LOCAL search_path TO pg_catalog, ai_native, pg_temp")
            connection.execute("""SELECT set_config('lock_timeout', %s, true),
                                         set_config('statement_timeout', %s, true),
                                         set_config('idle_in_transaction_session_timeout', %s, true),
                                         set_config('ai_native.tenant', %s, true)""",
                               (self._settings[0], self._settings[1], self._settings[1], tenant or ""))
            if exclusive:
                connection.execute("SELECT pg_advisory_xact_lock(%s, %s)", SCHEMA_LOCK)
            else:
                connection.execute("SELECT pg_advisory_xact_lock_shared(%s, %s)", SCHEMA_LOCK)
            if write and tenant is not None:
                connection.execute("SELECT pg_advisory_xact_lock(%s::bigint)", (_tenant_lock(tenant),))
            yield connection

    @contextmanager
    def transaction(self, *, write=False, tenant=None):
        if (write or tenant is not None) and (type(tenant) is not str or not tenant.strip()):
            raise ValueError("PostgreSQL runtime requires a valid transaction tenant")
        with self._connection(write=write, tenant=tenant) as connection:
            require_compatible_schema(connection)
            yield _Transaction(connection)

    def initialize(self, seed):
        """Seed reference data atomically, without running migrations."""
        with self._connection(write=True, exclusive=True) as connection:
            require_compatible_schema(connection)
            collections = {section: seed[section] for section in ("actors", "objects", "knowledge")}
            tenants = sorted({row["tenant"] for rows in collections.values() for row in rows})
            for tenant in tenants:
                connection.execute("SELECT set_config('ai_native.tenant', %s, true)", (tenant,))
                seed_rows(_Transaction(connection), {
                    section: [row for row in rows if row["tenant"] == tenant] for section, rows in collections.items()
                })
