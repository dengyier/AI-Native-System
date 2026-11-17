"""Validate registered domain declarations and fingerprint executable releases."""

import hashlib
import json
import math
from pathlib import Path

from .graph_contract import GraphSpec, MAX_GRAPH_AGENTS


FIELD_TYPES = {"string", "integer", "boolean", "number"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def is_name(value):
    return isinstance(value, str) and bool(value.strip())


def is_version(value):
    return (type(value) is int and value > 0) or is_name(value)


def field_matches(value, expected):
    if expected == "number":
        return type(value) is int or (type(value) is float and math.isfinite(value))
    return type(value) is {"string": str, "integer": int, "boolean": bool}[expected]


def unique_keys(pairs):
    document = {}
    for key, value in pairs:
        require(key not in document, f"Duplicate JSON key {key!r}")
        document[key] = value
    return document


class Registry:
    def __init__(self, document):
        require(isinstance(document, dict), "Registry must be a JSON object")
        for section in ("applications", "actions", "types", "seed"):
            require(isinstance(document.get(section), dict), f"Registry requires a {section} object")
        self.applications = document["applications"]
        self.actions = document["actions"]
        self.types = document["types"]
        self.seed = document["seed"]
        self._validate_types()
        for action_id in self.actions:
            self._action(action_id)
        for application_id in self.applications:
            self.definition(application_id)
        self._validate_seed()

    @classmethod
    def load(cls, path):
        document = json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=unique_keys)
        return cls(document)

    def _validate_types(self):
        for name, schema in self.types.items():
            require(is_name(name) and isinstance(schema, dict), f"Invalid type {name!r}")
            states = schema.get("states")
            fields = schema.get("fields")
            links = schema.get("links")
            require(isinstance(states, list) and states and all(map(is_name, states))
                    and len(states) == len(set(states)), f"Invalid states for type {name!r}")
            require(isinstance(fields, dict) and all(
                is_name(key) and is_name(kind) and kind in FIELD_TYPES for key, kind in fields.items()
            ), f"Invalid fields for type {name!r}")
            require(isinstance(links, dict) and all(
                is_name(key) and is_name(target) and target in self.types for key, target in links.items()
            ), f"Invalid link declaration for type {name!r}")

    def _action(self, action_id):
        require(is_name(action_id) and action_id in self.actions, f"Unknown action {action_id!r}")
        action = self.actions[action_id]
        require(isinstance(action, dict) and is_version(action.get("version")), f"Invalid action {action_id!r}")
        type_name = action.get("object_type")
        require(is_name(type_name) and type_name in self.types, f"Unknown object type for action {action_id!r}")
        schema = self.types[type_name]
        states = schema["states"]
        require(action.get("from_state") in states and action.get("to_state") in states
                and action["from_state"] != action["to_state"], f"Invalid state transition for action {action_id!r}")
        for role in ("request_role", "approval_role", "execute_role"):
            require(is_name(action.get(role)), f"Action {action_id!r} requires {role}")
        properties = action.get("requires_properties", {})
        require(isinstance(properties, dict) and all(
            key in schema["fields"] and field_matches(value, schema["fields"][key])
            for key, value in properties.items()
        ), f"Invalid property preconditions for action {action_id!r}")
        links = action.get("requires_link_states", {})
        require(isinstance(links, dict) and all(
            key in schema["links"] and value in self.types[schema["links"][key]]["states"]
            for key, value in links.items()
        ), f"Invalid relationship preconditions for action {action_id!r}")
        for field in ("tool", "tool_version"):
            require(field not in action or is_name(action[field]), f"Invalid {field}")
        return action

    def definition(self, application_id):
        require(is_name(application_id) and application_id in self.applications,
                f"Unknown application {application_id!r}")
        app = self.applications[application_id]
        require(isinstance(app, dict) and is_version(app.get("version"))
                and app.get("id", application_id) == application_id, f"Invalid application {application_id!r}")
        action = self._action(app.get("action"))
        require(is_name(app.get("executor")), f"Application {application_id!r} requires an executor")
        for field, default, maximum in (("max_model_calls", 12, 1000), ("lease_seconds", 60, 3600)):
            value = app.get(field, default)
            require(type(value) is int and 1 <= value <= maximum, f"Invalid {field}")
        agents = app.get("agents")
        require(isinstance(agents, list) and len(agents) >= 1 and all(
            isinstance(agent, dict) and is_name(agent.get("id")) and is_name(agent.get("instructions"))
            for agent in agents
        ), f"Application {application_id!r} requires ordered agent stages")
        require(all("model" not in agent or is_name(agent["model"]) for agent in agents),
                "Agent model routes must be nonempty names")
        require(len({agent["id"] for agent in agents}) == len(agents), f"Duplicate agent in {application_id!r}")
        if "graph" in app:
            GraphSpec.from_document(app["graph"])
            require(len(agents) <= MAX_GRAPH_AGENTS, "Application graph has too many agents")
            require(all(not (agent.keys() - {"id", "instructions", "model"}) for agent in agents),
                    "Application graph agents can only declare their ID, instructions and model")
        knowledge = app.get("knowledge")
        require(isinstance(knowledge, list) and all(map(is_name, knowledge)) and len(set(knowledge)) == len(knowledge),
                f"Invalid knowledge references for application {application_id!r}")

        # Follow type links with a visited set because domain graphs may be cyclic.
        schemas = {}
        pending = [action["object_type"]]
        while pending:
            type_name = pending.pop()
            if type_name not in schemas:
                schema = self.types[type_name]
                schemas[type_name] = schema
                pending.extend(schema["links"].values())
        declaration = {"application_id": application_id, "application": app, "action": action, "schemas": schemas}
        canonical = json.dumps(declaration, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
        return app, action, hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def action_contract(self, action_id, tools):
        """Project a legacy action without changing its executable definition or hash."""
        from .contracts import ActionDefinition
        from .fact_contracts import canonical_json

        action = self._action(action_id)
        tool = tools.resolve(action)
        target = canonical_json(tool.handler.identity) if tool.remote else None
        return ActionDefinition.from_legacy(action_id, action, remote=tool.remote, destination=target)

    def ontology(self, *, namespace="legacy-registry", version=1):
        """Project a legacy configuration into a separate ontology release."""
        from .ontology import OntologyRelease

        relations = {}
        relation_ids = {}
        for source, schema in self.types.items():
            for link, target in schema["links"].items():
                name = ".".join(part.replace("%", "%25").replace(".", "%2E") for part in (source, link))
                relation_ids[source, link] = name
                relations[name] = {
                    "source_type": source, "target_type": target, "direction": "directed",
                    "targets_per_source": {"min": 1, "max": 1},
                    "sources_per_target": {"min": 0, "max": None},
                }
        rules = {}
        for name in self.actions:
            action = self._action(name)
            source = action["object_type"]
            rules[name] = {"version": action["version"], "object_type": source, "conditions": [
                {"state": action["from_state"]},
                *({"property": key, "operator": "eq", "value": value}
                  for key, value in sorted(action.get("requires_properties", {}).items())),
                *({"relation": relation_ids[source, key], "target_state": value}
                  for key, value in sorted(action.get("requires_link_states", {}).items())),
            ]}
        return OntologyRelease.from_document({
            "namespace": namespace, "version": version, "rules": rules, "relations": relations,
            "types": {name: {"states": schema["states"], "properties": {
                key: {"type": kind} for key, kind in schema["fields"].items()
            }} for name, schema in self.types.items()},
        })

    def validate_object(self, obj):
        require(isinstance(obj, dict) and is_name(obj.get("tenant")) and is_name(obj.get("id")),
                "An object requires a tenant and ID")
        type_name = obj.get("type")
        require(is_name(type_name) and type_name in self.types, f"Unknown object type {type_name!r}")
        schema = self.types[type_name]
        require(obj.get("state") in schema["states"], f"Invalid state for type {type_name!r}")
        require(type(obj.get("version")) is int and obj["version"] > 0, "Object version must be a positive integer")

        properties = obj.get("properties")
        fields = schema["fields"]
        require(isinstance(properties, dict) and properties.keys() == fields.keys(),
                f"Properties must match fields for type {type_name!r}")
        for key, expected in fields.items():
            require(field_matches(properties[key], expected), f"Property {key!r} must be {expected}")

        # The store resolves target IDs within the source object's tenant.
        links = obj.get("links")
        require(isinstance(links, dict) and links.keys() == schema["links"].keys() and all(map(is_name, links.values())),
                f"Link IDs must match the link declaration for type {type_name!r}")

    def _validate_seed(self):
        indexes = {}
        for collection in ("actors", "objects", "knowledge"):
            rows = self.seed.get(collection)
            require(isinstance(rows, list), f"Seed requires a {collection} list")
            items = {}
            for row in rows:
                require(isinstance(row, dict) and is_name(row.get("tenant")) and is_name(row.get("id")),
                        f"Invalid row in seed {collection}")
                key = (row["tenant"], row["id"])
                require(key not in items, f"Duplicate row {key!r} in seed {collection}")
                items[key] = row
            indexes[collection] = items

        for actor in indexes["actors"].values():
            roles = actor.get("roles")
            require(isinstance(roles, list) and all(map(is_name, roles)) and len(roles) == len(set(roles)),
                    f"Invalid roles for seeded actor {actor['id']!r}")
        for knowledge in indexes["knowledge"].values():
            version = knowledge.get("version")
            require(type(version) is int and version > 0 and is_name(knowledge.get("text")),
                    f"Invalid seeded knowledge {knowledge['id']!r}")
        objects = indexes["objects"]
        for obj in objects.values():
            self.validate_object(obj)
        for obj in objects.values():
            for relation, target_id in obj["links"].items():
                target = objects.get((obj["tenant"], target_id))
                require(target is not None and target["type"] == self.types[obj["type"]]["links"][relation],
                        f"Invalid seeded link {relation!r} on {obj['id']!r}")
