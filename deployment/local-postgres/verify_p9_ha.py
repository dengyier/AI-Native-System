"""Exercise physical PostgreSQL replication and fenced promotion in a disposable cluster."""

import ipaddress
import os
import secrets
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path

import psycopg
from psycopg import sql
from psycopg.conninfo import make_conninfo

from verify import disposable_postgres


STANDBY_COMMAND = """
install -d -m 0700 -o postgres -g postgres "$PGDATA"
install -m 0600 -o postgres -g postgres /dev/null /tmp/p9-replication.pgpass
printf 'postgres:5432:replication:p9_repl:%s\\n' "$AI_NATIVE_P9_REPLICATION_PASSWORD" > /tmp/p9-replication.pgpass
unset AI_NATIVE_P9_REPLICATION_PASSWORD
gosu postgres pg_basebackup -D "$PGDATA" -R -X stream -w --checkpoint=fast -d \
  'host=postgres port=5432 user=p9_repl application_name=p9_standby passfile=/tmp/p9-replication.pgpass connect_timeout=5'
exec gosu postgres postgres -D "$PGDATA" -c listen_addresses=0.0.0.0
"""


def docker_output(*args):
    return subprocess.check_output(["docker", *args], text=True, timeout=15).strip()


def wait_for(description, probe, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if probe():
                return
        except psycopg.OperationalError:
            pass
        time.sleep(0.1)
    raise RuntimeError(f"Timed out waiting for {description}")


def connect(dsn):
    return psycopg.connect(dsn, autocommit=True)


def query(dsn, statement):
    with connect(dsn) as connection:
        return connection.execute(statement).fetchone()


@contextmanager
def standby(prefix, primary, primary_dsn):
    network = docker_output("inspect", "-f", "{{range $name, $net := .NetworkSettings.Networks}}{{$name}}{{end}}", primary)
    if not network.startswith(f"{prefix}-") or not network.endswith("_default"):
        raise RuntimeError("Expected the primary to be on its disposable Compose network")
    subnet = ipaddress.ip_network(docker_output("network", "inspect", "-f", "{{(index .IPAM.Config 0).Subnet}}", network))
    replication_password = secrets.token_urlsafe(24)
    with connect(primary_dsn) as connection:
        connection.execute(sql.SQL("CREATE ROLE p9_repl WITH LOGIN REPLICATION NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD {}").format(
            sql.Literal(replication_password),
        ))
        subprocess.run(["docker", "exec", "-i", primary, "sh", "-ec", 'cat >> "$PGDATA/pg_hba.conf"'],
                       input=f"\nhost replication p9_repl {subnet} scram-sha-256\n", text=True, check=True, timeout=15)
        connection.execute("SELECT pg_reload_conf()")

    image_id = docker_output("inspect", "-f", "{{.Image}}", primary)
    replica = f"{prefix}-standby"
    subprocess.run(["docker", "run", "-d", "--name", replica, "--network", network, "--restart=no",
                    "--tmpfs", "/var/lib/postgresql", "-p", "127.0.0.1::5432", "--env", "AI_NATIVE_P9_REPLICATION_PASSWORD",
                    "--entrypoint", "/bin/sh", image_id, "-ec", STANDBY_COMMAND],
                   env={**os.environ, "AI_NATIVE_P9_REPLICATION_PASSWORD": replication_password}, check=True, timeout=30)
    try:
        host, _, port = docker_output("port", replica, "5432/tcp").rpartition(":")
        if host != "127.0.0.1":
            raise RuntimeError("Expected a loopback standby port")
        replica_dsn = make_conninfo(primary_dsn, port=port)
        try:
            wait_for("the physical standby to stream WAL", lambda: query(
                replica_dsn, "SELECT pg_is_in_recovery() AND EXISTS (SELECT 1 FROM pg_stat_wal_receiver WHERE status='streaming')",
            ) == (True,))
        except RuntimeError:
            subprocess.run(["docker", "logs", "--tail", "20", replica], check=True, timeout=15)
            raise

        # Apply these only after base backup so the promoted node can accept
        # writes while it is the sole database server in this rehearsal.
        with connect(primary_dsn) as connection:
            connection.execute("ALTER SYSTEM SET synchronous_standby_names='FIRST 1 (p9_standby)'")
            connection.execute("ALTER SYSTEM SET synchronous_commit='remote_apply'")
            connection.execute("SELECT pg_reload_conf()")
        wait_for("the synchronous standby to acknowledge replay", lambda: query(
            primary_dsn, "SELECT sync_state FROM pg_stat_replication WHERE application_name='p9_standby' AND state='streaming'",
        ) == ("sync",))
        if query(primary_dsn, "SHOW synchronous_commit") != ("remote_apply",):
            raise RuntimeError("The primary must wait for standby replay before acknowledging writes")
        identifier_sql = "SELECT system_identifier FROM pg_control_system()"
        if query(primary_dsn, identifier_sql) != query(replica_dsn, identifier_sql):
            raise RuntimeError("Primary and standby must share the physical cluster identifier")
        yield replica_dsn
    finally:
        subprocess.run(["docker", "rm", "-f", replica], check=True, timeout=15)


def main():
    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root))
    from ai_native_system.adapters.postgres import migrate_postgres

    prefix = "ai-native-p9-ha-" + secrets.token_hex(4)
    with disposable_postgres(prefix) as (port, password):
        dsn = make_conninfo(host="127.0.0.1", hostaddr="127.0.0.1", port=port, dbname="ai_native_p0",
                            user="p0_admin", password=password, connect_timeout=2)
        with connect(dsn) as connection:
            connection.execute("CREATE SCHEMA IF NOT EXISTS ai_native")
            version, extension = connection.execute(
                "SELECT current_setting('server_version'), extversion FROM pg_extension WHERE extname='vector'",
            ).fetchone()
        revision = migrate_postgres(dsn)
        primary, = docker_output("ps", "--filter", f"name={prefix}-", "--filter",
                                 "label=com.docker.compose.service=postgres", "-q").split()
        with standby(prefix, primary, dsn) as replica_dsn:
            print(f"P9 HA PostgreSQL {version}, pgvector {extension}, migration {revision}, synchronous remote_apply", flush=True)
            subprocess.run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-p",
                            "test_postgres_failover.py", "-v"], cwd=root, check=True, timeout=180,
                           env={**os.environ, "AI_NATIVE_P9_HA_PRIMARY_DSN": dsn,
                                "AI_NATIVE_P9_HA_STANDBY_DSN": replica_dsn, "AI_NATIVE_P9_HA_PRIMARY_CONTAINER": primary})


if __name__ == "__main__":
    main()
