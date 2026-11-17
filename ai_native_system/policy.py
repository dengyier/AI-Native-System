"""Exact tenant-scoped resource grants for enterprise principals."""

from .identity import IdentityError, _name, delegation_scopes, require_identity
from .storage import object_data


def tool_resource_id(name, version):
    """Bind grants to an unambiguous tool name and version."""
    return "@".join(part.replace("%", "%25").replace("@", "%40") for part in (name, version))


def _validate_scope(operation, kind, resource_id, member):
    if not all(map(_name, (operation, kind, resource_id))) or (member is not None and not _name(member)):
        raise ValueError("Invalid resource scope")


class Policy:
    """Both principals and the persisted delegation must allow a delegated request."""

    def permits(self, connection, identity, operation, kind, resource_id, member=None):
        _validate_scope(operation, kind, resource_id, member)
        try:
            require_identity(connection, identity, scope=(operation, kind, resource_id, member))
        except IdentityError:
            return False
        return self._granted(connection, identity, operation, kind, resource_id, member)

    def require(self, connection, identity, operation, kind, resource_id, member=None):
        if not self.permits(connection, identity, operation, kind, resource_id, member):
            raise PermissionError("Resource access denied")

    @staticmethod
    def _granted(connection, identity, operation, kind, resource_id, member):
        principal_rows = connection.execute(
            """SELECT count(*) FROM resource_grants
               WHERE tenant = ? AND principal = ANY(?)
                 AND operation = ? AND kind = ? AND resource_id = ? AND member = ?""",
            (identity.tenant, list(identity.principals), operation, kind, resource_id, member or ""),
        ).fetchone()
        return principal_rows[0] == len(identity.principals)

    @staticmethod
    def _members(connection, identity, scopes, kind, resource_id, members):
        candidates = [member for member in members
                      if _name(member) and (scopes is None or ("read", kind, resource_id, member) in scopes)]
        if not candidates:
            return ()
        rows = connection.execute(
            """SELECT member FROM resource_grants
               WHERE tenant = ? AND principal = ANY(?) AND operation = 'read'
                 AND kind = ? AND resource_id = ? AND member = ANY(?)
               GROUP BY member HAVING count(*) = ? ORDER BY member""",
            (identity.tenant, list(identity.principals), kind, resource_id, candidates, len(identity.principals)),
        )
        return tuple(row[0] for row in rows)

    def project_object(self, connection, identity, object_row, target_lookup=None):
        self.require(connection, identity, "read", "object", object_row["id"])
        if object_row["tenant"] != identity.tenant:
            raise PermissionError("Resource access denied")
        scopes = delegation_scopes(connection, identity)
        resource_id, properties, links = object_row["id"], object_row["properties"], object_row["links"]
        fields = self._members(connection, identity, scopes, "field", resource_id, properties)
        metadata = self._members(connection, identity, scopes, "metadata", resource_id, ("state", "version"))
        edges = self._members(connection, identity, scopes, "edge", resource_id, links)
        projected = {
            "tenant": identity.tenant, "id": resource_id, "type": object_row["type"],
            "properties": {key: properties[key] for key in fields}, "links": {},
            **{key: object_row[key] for key in metadata},
        }
        for key in edges:
            target_id = links[key]
            if not _name(target_id) or not self.permits(connection, identity, "read", "object", target_id):
                continue
            target = (target_lookup(target_id) if target_lookup is not None else
                      object_data(connection, identity.tenant, target_id))
            if target is not None and target["tenant"] == identity.tenant and target["id"] == target_id:
                projected["links"][key] = target_id
        return projected

    @staticmethod
    def _change(connection, tenant, principal, operation, kind, resource_id, member, statement):
        from .adapters.postgres_runtime import _tenant_lock

        if not all(map(_name, (tenant, principal))):
            raise ValueError("Invalid grant principal")
        _validate_scope(operation, kind, resource_id, member)
        connection.execute("SELECT pg_catalog.pg_advisory_xact_lock(?::bigint)", (_tenant_lock(tenant),))
        return connection.execute(statement, (tenant, principal, operation, kind, resource_id, member or "")).rowcount > 0

    def grant(self, connection, tenant, principal, operation, kind, resource_id, member=None):
        """Provision via a trusted transaction with INSERT privileges."""
        return self._change(
            connection, tenant, principal, operation, kind, resource_id, member,
            """INSERT INTO resource_grants (tenant, principal, operation, kind, resource_id, member)
               VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING""",
        )

    def revoke(self, connection, tenant, principal, operation, kind, resource_id, member=None):
        """Revoke via a trusted transaction with DELETE privileges."""
        return self._change(
            connection, tenant, principal, operation, kind, resource_id, member,
            """DELETE FROM resource_grants WHERE tenant=? AND principal=? AND operation=?
               AND kind=? AND resource_id=? AND member=?""",
        )
