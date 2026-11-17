"""Restricted PostgreSQL test roles within the disposable P2b database."""

import os
import secrets


TEST_DSN = os.environ.get("AI_NATIVE_P2B_TEST_DSN")


def restricted_role(grants, dsn=TEST_DSN):
    """Create a fresh login with the statements' explicitly listed privileges."""
    import psycopg
    from psycopg import sql
    from psycopg.conninfo import make_conninfo

    role, password = f"p2b_{secrets.token_hex(6)}", secrets.token_urlsafe(24)
    with psycopg.connect(dsn) as admin:
        identifier = sql.Identifier(role)
        admin.execute(sql.SQL("CREATE ROLE {} LOGIN PASSWORD {}").format(identifier, sql.Literal(password)))
        admin.execute(sql.SQL("GRANT USAGE ON SCHEMA ai_native TO {}").format(identifier))
        admin.execute(sql.SQL("GRANT SELECT ON ai_native.schema_migrations TO {}").format(identifier))
        for clause in grants:
            admin.execute(sql.SQL("GRANT " + clause + " TO {}").format(identifier))
    return make_conninfo(dsn, user=role, password=password)
