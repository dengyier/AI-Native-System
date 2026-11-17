"""Tenant-scoped maintenance of the reference store's facts and knowledge."""

from .governance import enabled
from .registry import Registry, is_name
from .storage import RuntimeStore, database, encode, object_data, row_data


OBJECT_FIELDS = {"id", "type", "state", "properties", "links"}
KNOWLEDGE_HISTORY = """
CREATE TABLE IF NOT EXISTS knowledge_history (
    tenant TEXT NOT NULL,
    id TEXT NOT NULL,
    version INTEGER NOT NULL,
    text TEXT NOT NULL,
    PRIMARY KEY (tenant, id, version)
)
"""


def require_role(connection, tenant, actor, roles):
    if enabled(connection, tenant):
        raise PermissionError("Legacy data commands are unavailable for governed tenants")
    principal = row_data(connection.execute(
        "SELECT roles FROM principals WHERE tenant = ? AND id = ? AND active = 1",
        (tenant, actor),
    ).fetchone(), "roles")
    if principal is None or not roles.intersection(principal["roles"]):
        raise PermissionError("This principal has no permission for this data operation")


def next_version(current, expected_version):
    if expected_version is not None and (type(expected_version) is not int or expected_version < 1):
        raise ValueError("Expected version must be a positive integer")
    current_version = current["version"] if current is not None else None
    if expected_version != current_version:
        raise ValueError("Data version conflict")
    return 1 if current_version is None else current_version + 1


def evidence(row):
    return {**row, "source": "local_knowledge"}


class DataService:
    def __init__(self, path, registry: Registry):
        self.path = path
        self.registry = registry
        self._external_store = isinstance(path, RuntimeStore)

    def put_object(self, tenant, actor, obj, expected_version=None):
        """Create or replace an object's data under optimistic version control."""
        if (not isinstance(obj, dict) or not OBJECT_FIELDS <= obj.keys()
                or obj.keys() - OBJECT_FIELDS - {"tenant", "version"}):
            raise ValueError("Expected object ID, type, state, properties and links")
        if obj.get("tenant", tenant) != tenant or not is_name(obj["id"]):
            raise ValueError("Object ID or tenant does not match the request")
        if "version" in obj and (type(obj["version"]) is not int or obj["version"] != (expected_version or 1)):
            raise ValueError("Object version does not match the submitted revision")

        with database(self.path, write=True, tenant=tenant) as connection:
            require_role(connection, tenant, actor, {"data_admin"})
            current = object_data(connection, tenant, obj["id"])
            version = next_version(current, expected_version)
            record = {**obj, "tenant": tenant, "version": version}
            self.registry.validate_object(record)
            if current is not None and current["type"] != record["type"]:
                raise ValueError("An existing object's type cannot change")

            relations = self.registry.types[record["type"]]["links"]
            for name, target in record["links"].items():
                related = record if target == record["id"] else object_data(connection, tenant, target)
                if related is None or related["type"] != relations[name]:
                    raise ValueError(f"Link {name!r} does not resolve to its declared type in this tenant")

            connection.execute(
                """INSERT INTO objects (tenant, id, type, state, version, properties, links)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT (tenant, id) DO UPDATE SET
                   state = excluded.state, version = excluded.version,
                   properties = excluded.properties, links = excluded.links""",
                (tenant, record["id"], record["type"], record["state"], version,
                 encode(record["properties"]), encode(record["links"])),
            )
            return record

    def put_knowledge(self, tenant, actor, id, text, expected_version=None):
        """Write a new current revision and retain superseded source text."""
        if not is_name(id) or not is_name(text):
            raise ValueError("Knowledge ID and text are required")
        with database(self.path, write=True, tenant=tenant) as connection:
            require_role(connection, tenant, actor, {"data_admin"})
            current = connection.execute(
                "SELECT version, text FROM knowledge WHERE tenant = ? AND id = ?", (tenant, id),
            ).fetchone()
            version = next_version(current, expected_version)
            if not self._external_store:
                connection.execute(KNOWLEDGE_HISTORY)
            if current is not None:
                connection.execute(
                    """INSERT INTO knowledge_history (tenant, id, version, text) VALUES (?, ?, ?, ?)
                       ON CONFLICT (tenant, id, version) DO NOTHING""",
                    (tenant, id, current["version"], current["text"]),
                )
            connection.execute(
                "INSERT INTO knowledge_history (tenant, id, version, text) VALUES (?, ?, ?, ?)",
                (tenant, id, version, text),
            )
            connection.execute(
                """INSERT INTO knowledge (tenant, id, version, text) VALUES (?, ?, ?, ?)
                   ON CONFLICT (tenant, id) DO UPDATE SET version = excluded.version, text = excluded.text""",
                (tenant, id, version, text),
            )
            return evidence({"tenant": tenant, "id": id, "version": version, "text": text})

    def search_knowledge(self, tenant, actor, query, limit=10):
        """Find current knowledge using a literal, case-insensitive substring."""
        if not isinstance(query, str) or not 1 <= len(query.strip()) <= 200:
            raise ValueError("Query must contain 1–200 characters")
        if type(limit) is not int or not 1 <= limit <= 50:
            raise ValueError("Search limit must be between 1 and 50")
        term = query.strip().casefold()
        with database(self.path, tenant=tenant) as connection:
            require_role(connection, tenant, actor, {"data_admin", "knowledge_read"})
            if self._external_store:
                # Keep the legacy Python Unicode casefold semantics across stores.
                with connection.scan(
                    'SELECT tenant, id, version, text FROM knowledge WHERE tenant = ? ORDER BY id COLLATE "C"',
                    (tenant,),
                ) as rows:
                    matches = []
                    for row in rows:
                        if term in row["id"].casefold() or term in row["text"].casefold():
                            matches.append(evidence(dict(row)))
                            if len(matches) == limit:
                                break
                    return matches
            connection.create_function("casefold", 1, str.casefold, deterministic=True)
            rows = connection.execute(
                """SELECT tenant, id, version, text FROM knowledge WHERE tenant = ?
                   AND (instr(casefold(id), ?) > 0 OR instr(casefold(text), ?) > 0)
                   ORDER BY id LIMIT ?""",
                (tenant, term, term, limit),
            )
            return [evidence(dict(row)) for row in rows]
