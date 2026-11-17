"""Bounded, permission-filtered PostgreSQL reads over the existing ontology projection."""

import time
from contextlib import nullcontext

from .identity import IdentityContext, IdentityError, _name, delegation_scopes
from .policy import Policy, tool_resource_id
from .registry import field_matches
from .storage import database, encode, object_data, row_data


MAX_RESULTS = 100
MAX_CANDIDATES = 200
MAX_FILTERS = 8
MAX_DEPTH = 3
MAX_RESPONSE_BYTES = 256 * 1024
QUERY_SECONDS = 3


def limit_query_transaction(connection):
    """Preserve tighter database limits and bound the complete PG read when supported."""
    connection.execute("""SELECT pg_catalog.set_config(name,
        LEAST(COALESCE(NULLIF(setting::integer, 0), ?), ?)::text || 'ms', true)
        FROM pg_catalog.pg_settings WHERE name IN ('statement_timeout', 'transaction_timeout')""",
        (QUERY_SECONDS * 1000, QUERY_SECONDS * 1000))


class SemanticQuery:
    def __init__(self, store, registry, policy=None, *, ontology=None):
        self.store = store
        self.policy = Policy() if policy is None else policy
        self.ontology = registry.ontology() if ontology is None else ontology
        self._types = {kind: shape for kind, shape in self.ontology.to_document()["types"].items()
                       if kind in registry.types}
        self._links = {name: schema["links"] for name, schema in registry.types.items()}
        self._actions = {
            name: tuple(sorted((action_id, self._tool_id(action)) for action_id, action in registry.actions.items()
                               if action["object_type"] == name))
            for name in self._types
        }

    @staticmethod
    def _tool_id(action):
        return tool_resource_id(action.get("tool", "state.transition"), action.get("tool_version", "1"))

    @staticmethod
    def _validate(object_type, object_id, filters, limit, follow, count, discover_actions, explain):
        if object_type is not None and not _name(object_type):
            raise ValueError("Invalid query object type")
        if object_id is not None and not _name(object_id):
            raise ValueError("Invalid query object ID")
        if type(limit) is not int or not 1 <= limit <= MAX_RESULTS:
            raise ValueError(f"Query limit must be 1 through {MAX_RESULTS}")
        if (not isinstance(follow, (list, tuple)) or len(follow) > MAX_DEPTH
                or not all(map(_name, follow))):
            raise ValueError(f"Specify at most {MAX_DEPTH} relationship steps")
        if not all(type(option) is bool for option in (count, discover_actions, explain)) or (count and object_type is None):
            raise ValueError("Query options are boolean and counting requires an object type")
        if not isinstance(filters, dict) or len(filters) > MAX_FILTERS:
            raise ValueError(f"Specify at most {MAX_FILTERS} property equality filters")
        for member, expected in filters.items():
            if (not _name(member) or (isinstance(expected, str) and len(expected) > 4096)
                    or (type(expected) is int and expected.bit_length() > 4096)
                    or not (type(expected) in (str, bool) or field_matches(expected, "number"))):
                raise ValueError("Invalid query property filter")

    def _candidates(self, connection, identity, scopes, object_type, object_id, cap):
        # Bound authorized candidates before materializing facts. Invisible
        # rows cannot displace a visible result or change an overflow response.
        if object_type is not None and object_type not in self._types:
            return ()
        statement = """SELECT o.* FROM objects o
            JOIN (
                SELECT resource_id FROM resource_grants
                WHERE tenant=? AND principal=ANY(?) AND operation='read' AND kind='object' AND member=''"""
        parameters = [identity.tenant, list(identity.principals)]
        if scopes is not None:
            delegated_ids = sorted(resource_id for operation, kind, resource_id, member in scopes
                                   if (operation, kind, member) == ("read", "object", None))
            if not delegated_ids:
                return ()
            statement += " AND resource_id=ANY(?)"
            parameters.append(delegated_ids)
        statement += """ GROUP BY resource_id HAVING count(*)=?
            ) allowed ON allowed.resource_id=o.id WHERE o.tenant=?"""
        parameters.extend((len(identity.principals), identity.tenant))
        if object_type is not None:
            statement += " AND o.type=?"
            parameters.append(object_type)
        else:
            statement += " AND o.type=ANY(?)"
            parameters.append(list(self._types))
        if object_id is not None:
            statement += " AND o.id=?"
            parameters.append(object_id)
        statement += " ORDER BY o.id LIMIT ?"
        parameters.append(cap)
        return connection.execute(statement, parameters).fetchall()

    def _project(self, connection, identity, row):
        schema = self._types[row["type"]]
        links = self._links[row["type"]]
        row = {**row, "properties": {key: value for key, value in row["properties"].items()
                                     if key in schema["properties"]},
               "links": {key: value for key, value in row["links"].items() if key in links}}
        return self.policy.project_object(connection, identity, row)

    def _related(self, connection, identity, projected, follow, check_deadline):
        related = []
        visited = {projected["id"]}
        current = projected
        for link in follow:
            check_deadline()
            target_id = current["links"].get(link)
            if target_id is None or target_id in visited:
                break
            target = object_data(connection, identity.tenant, target_id)
            if target is None or target["type"] != self._links[current["type"]][link]:
                break
            current = self._project(connection, identity, target)
            related.append(current)
            visited.add(target_id)
        return related

    def _discover(self, connection, identity, projected, check_deadline):
        discovered = []
        for action_id, tool_id in self._actions[projected["type"]]:
            check_deadline()
            if (self.policy.permits(connection, identity, "read", "action", action_id)
                    and self.policy.permits(connection, identity, "execute", "tool", tool_id)):
                discovered.append(action_id)
        return discovered

    def query(self, identity, *, object_type=None, object_id=None, filters=None, limit=20, follow=(), count=False,
              discover_actions=False, explain=False, connection=None):
        """Return an authorized subset. Equality filters use visible properties."""
        if not isinstance(identity, IdentityContext):
            raise IdentityError("Trusted identity required")
        filters = {} if filters is None else filters
        self._validate(object_type, object_id, filters, limit, follow, count, discover_actions, explain)
        deadline = time.monotonic() + QUERY_SECONDS

        def check_deadline():
            if time.monotonic() >= deadline:
                raise ValueError("Query exceeded its time limit")

        objects = []
        transaction = (database(self.store, tenant=identity.tenant) if connection is None else nullcontext(connection))
        with transaction as connection:
            check_deadline()
            limit_query_transaction(connection)
            scopes = delegation_scopes(connection, identity)
            if count:
                self.policy.require(connection, identity, "aggregate", "type", object_type)
            cap = MAX_CANDIDATES + 1 if filters or count else limit
            candidates = self._candidates(connection, identity, scopes, object_type, object_id, cap)
            if len(candidates) > MAX_CANDIDATES:
                raise ValueError("Query exceeds the authorized candidate limit; narrow its scope")

            size, visible_count = 0, 0
            for candidate in candidates:
                check_deadline()
                row = row_data(candidate, "properties", "links")
                projected = self._project(connection, identity, row)
                fields = self._types[row["type"]]["properties"]
                props = projected["properties"]
                if not all(name in props and name in fields and field_matches(expected, fields[name]["type"])
                           and props[name] == expected for name, expected in filters.items()):
                    continue
                visible_count += 1
                if len(objects) == limit:
                    continue
                if follow:
                    projected["related"] = self._related(connection, identity, projected, follow, check_deadline)
                if discover_actions:
                    projected["actions"] = self._discover(connection, identity, projected, check_deadline)
                size += len(encode(projected).encode("utf-8"))
                if size > MAX_RESPONSE_BYTES:
                    raise ValueError("Query response exceeds its size limit")
                objects.append(projected)
            check_deadline()

        result = {"objects": objects}
        if count:
            result["visible_count"] = visible_count
        if explain:
            result["explanation"] = {
                "scope": "authorized-subset",
                "filters": "projected-fields", "action_discovery": "declarations-only",
            }
        if len(encode(result).encode("utf-8")) > MAX_RESPONSE_BYTES:
            raise ValueError("Query response exceeds its size limit")
        return result
