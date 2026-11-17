"""Immutable application releases and their independently managed lifecycle."""

import json
import math
import re
from dataclasses import dataclass
from hashlib import sha256
from urllib.parse import urlsplit

from .contracts import ActionDefinition
from .fact_contracts import canonical_json, freeze_json, json_data
from .gateway import ModelGateway
from .identity import _name
from .model import DemoModel, OpenAICompatibleModel, _SYSTEM_PROMPT
from .model_policy import GenerationPolicy
from .ontology import OntologyRelease
from .registry import Registry, is_name, is_version


class ReleaseError(ValueError):
    """Release input, lifecycle or adapter binding is invalid."""


_FORMAT = 1
_KNOWLEDGE_STRATEGY = "current-by-id-v1"
AUTHORIZED_FRAGMENTS = "authorized-fragments-v1"
RETRIEVAL_METHODS = ("exact", "hnsw", "hybrid")
_BASE_POLICY_VERSION = "legacy-runtime-v1"
_LIVE = ("published", "deprecated")
_TRANSITIONS = {
    "draft": ("published", "revoked"),
    "published": ("deprecated", "revoked"),
    "deprecated": ("revoked",),
    "revoked": (),
}


def _require(condition, message):
    if not condition:
        raise ReleaseError(message)


def _keys(document, required, optional=()):
    return isinstance(document, dict) and set(required) <= document.keys() <= {*required, *optional}


def _legacy_definition(registry, application):
    app, action, fingerprint = registry.definition(application)
    types = {}
    pending = [action["object_type"]]
    while pending:
        kind = pending.pop()
        if kind not in types:
            types[kind] = registry.types[kind]
            pending.extend(types[kind]["links"].values())
    definition = {"applications": {application: app}, "actions": {app["action"]: action}, "types": types}
    return definition, fingerprint


def _legacy_registry(document, application):
    _require(_keys(document, ("applications", "actions", "types")), "Invalid release registry")
    registry = Registry({**document, "seed": {"actors": [], "objects": [], "knowledge": []}})
    app, action, _ = registry.definition(application)
    definition, _ = _legacy_definition(registry, application)
    _require(document == definition, "Release registry contains unrelated definitions")
    _require(_keys(app, ("version", "executor", "action", "agents", "knowledge"),
                   ("id", "max_model_calls", "lease_seconds", "graph")), "Unsupported application release fields")
    _require(all(_keys(stage, ("id", "instructions"), ("model",)) for stage in app["agents"]),
             "Unsupported agent release fields")
    _require(_keys(action, ("version", "object_type", "from_state", "to_state", "request_role",
                           "approval_role", "execute_role"), ("description", "requires_properties",
                           "requires_link_states", "tool", "tool_version")),
             "Unsupported legacy action release fields")
    _require(all(_keys(schema, ("states", "fields", "links")) for schema in registry.types.values()),
             "Unsupported legacy type release fields")
    return registry


def _endpoint(value):
    try:
        url = urlsplit(value)
        port = url.port
    except (AttributeError, TypeError, ValueError):
        raise ReleaseError("Invalid release endpoint") from None
    loopback = url.hostname in {"localhost", "127.0.0.1", "::1"}
    _require(is_name(value) and value.isascii() and all(0x21 <= ord(char) <= 0x7E for char in value)
             and not any(char in value for char in ("?", "#", "\\"))
             and bool(url.hostname) and url.username is None and port != 0
             and (url.scheme == "https" or (url.scheme == "http" and loopback)),
             "A release endpoint needs HTTPS or loopback HTTP without credentials, query, or fragment")


def _adapter(model):
    if type(model) is DemoModel:
        return {"kind": "demo"}
    if type(model) is OpenAICompatibleModel:
        return {"kind": "openai-compatible", "endpoint": model.endpoint, "model": model.model,
                "system_prompt": _SYSTEM_PROMPT, "timeout": model.timeout}
    raise ReleaseError("Model adapter does not have a supported release identity")


def _models(model, app):
    if not isinstance(model, ModelGateway):
        return {"gateway": False, "context_limit": None, "stages": [
            {"id": stage["id"], "route": None, "adapter": _adapter(model), "version": "1", "fallback": None}
            for stage in app["agents"]
        ]}

    def route_binding(name):
        route = model._routes.get(name)
        _require(route is not None and route.enabled, "Release model route is missing or disabled")
        adapter = _adapter(route.adapter) if route.policy is None else {
            "kind": "litellm", "transport": route.adapter.manifest, "policy": route.policy.document(),
        }
        return route, {"route": name, "version": route.version, "adapter": adapter}

    stages = []
    for stage in app["agents"]:
        route, binding = route_binding(stage.get("model", model.default))
        fallback = None
        if route.fallback is not None:
            secondary, fallback = route_binding(route.fallback)
            _require(model.compatible_fallback(route, secondary), "Release fallback data policy is incompatible")
        stages.append({"id": stage["id"], **binding, "fallback": fallback})
    return {"gateway": True, "context_limit": model.max_context_bytes, "stages": stages}


def _validate_binding(binding, gateway, *, graph=False):
    _require(is_name(binding["version"]) and (is_name(binding["route"]) if gateway else binding["route"] is None),
             "Invalid release model route")
    adapter = binding["adapter"]
    if adapter == {"kind": "demo"}:
        return
    if isinstance(adapter, dict) and adapter.get("kind") == "litellm":
        from .adapters.litellm import LiteLLMModel

        _require(gateway and _keys(adapter, ("kind", "transport", "policy")), "Invalid LiteLLM release binding")
        try:
            route = GenerationPolicy.from_document(adapter["policy"])
            transport = adapter["transport"]
            _require(isinstance(transport, dict)
                     and isinstance(transport.get("backend"), str)
                     and re.fullmatch(r"litellm-[0-9]+\.[0-9]+\.[0-9]+", transport["backend"]) is not None
                     and isinstance(transport.get("system_prompt_sha256"), str)
                     and re.fullmatch(r"[0-9a-f]{64}", transport["system_prompt_sha256"]) is not None,
                     "Invalid archived model identity")
            rebuilt = LiteLLMModel(
                transport["base_url"], transport["model"], timeout=transport["timeout"],
                provider=transport["provider"], api_key_env=transport["api_key_env"],
                allow_providers=transport["allowed_providers"], max_output_tokens=transport["max_output_tokens"],
            )
            canonical = {**rebuilt.manifest, "backend": transport["backend"],
                         "system_prompt_sha256": transport["system_prompt_sha256"]}
            _require(route.document() == adapter["policy"] and canonical == transport,
                     "Noncanonical LiteLLM release binding")
        except (KeyError, TypeError, ValueError, RuntimeError):
            raise ReleaseError("Invalid LiteLLM release binding") from None
        return
    _require(not graph, "Graph stages require a managed LiteLLM route or a local demo model")
    _require(_keys(adapter, ("kind", "endpoint", "model", "system_prompt", "timeout"))
             and adapter["kind"] == "openai-compatible"
             and is_name(adapter["model"]) and is_name(adapter["system_prompt"]),
             "Invalid release model adapter")
    timeout = adapter["timeout"]
    _require(type(timeout) in (int, float) and 0 < timeout < math.inf, "Invalid release model timeout")
    _endpoint(adapter["endpoint"])


def _validate_models(models, app):
    _require(_keys(models, ("gateway", "context_limit", "stages")) and type(models["gateway"]) is bool,
             "Invalid release model configuration")
    gateway, limit, stages = models["gateway"], models["context_limit"], models["stages"]
    _require(limit is None or (gateway and type(limit) is int and limit > 0), "Invalid release model context limit")
    _require(isinstance(stages, list) and len(stages) == len(app["agents"]), "Invalid release model stages")
    for configured, stage in zip(app["agents"], stages):
        _require(_keys(stage, ("id", "route", "version", "adapter", "fallback"))
                 and stage["id"] == configured["id"], "Release model stage does not match its application")
        _validate_binding(stage, gateway, graph="graph" in app)
        if gateway and "model" in configured:
            _require(stage["route"] == configured["model"], "Release model route does not match its stage")
        fallback = stage["fallback"]
        if fallback is not None:
            _require(gateway and _keys(fallback, ("route", "version", "adapter"))
                     and fallback["route"] != stage["route"], "Invalid release model fallback")
            _validate_binding(fallback, gateway=True, graph="graph" in app)
            adapters = (stage["adapter"], fallback["adapter"])
            if any(item["kind"] == "litellm" for item in adapters):
                _require(all(item["kind"] == "litellm" for item in adapters)
                         and adapters[0]["policy"]["data"] == adapters[1]["policy"]["data"],
                         "Release fallback data policy is incompatible")


def _validate_destination(destination):
    if destination is None:
        return
    _require(isinstance(destination, dict), "Invalid release tool destination")
    kind = destination.get("type")
    if kind in ("mcp-sdk-http", "mcp-sdk-stdio"):
        from .p4_tools import valid_schema_digest, valid_source_identity

        address = "endpoint" if kind == "mcp-sdk-http" else "launch_digest"
        _require(_keys(destination, ("type", address, "execute_tool", "lookup_tool", "execute_schema_digest",
                                     "lookup_schema_digest"), ("profile", "source_binding"))
                 and all(is_name(destination[key]) for key in ("execute_tool", "lookup_tool"))
                 and all(valid_schema_digest(destination[key]) for key in ("execute_schema_digest", "lookup_schema_digest")),
                 "Invalid MCP SDK destination")
        if kind == "mcp-sdk-http":
            _endpoint(destination["endpoint"])
        else:
            _require(valid_schema_digest(destination["launch_digest"]), "Invalid MCP stdio launch digest")
        if "profile" in destination or "source_binding" in destination:
            _require(destination.get("profile") == "source-write/v1"
                     and valid_source_identity(destination.get("source_binding")), "Invalid source write binding")
        return
    if kind == "mcp":
        _require(_keys(destination, ("type", "endpoint", "execute_tool", "lookup_tool"))
                 and is_name(destination["execute_tool"]) and is_name(destination["lookup_tool"]),
                 "Invalid release MCP destination")
    else:
        _require(kind == "http" and _keys(destination, ("type", "endpoint")), "Invalid release HTTP destination")
    _endpoint(destination["endpoint"])


def _tool(tools, action):
    tool = tools.resolve(action)
    destination = tool.identity
    _require(not tool.remote or destination is not None, "Remote tool requires a release destination")
    _validate_destination(destination)
    return {"name": tool.name, "version": tool.version, "destination": destination}


def _action_contract(app, action, tool):
    destination = tool["destination"]
    return ActionDefinition.from_legacy(
        app["action"], action, remote=destination is not None,
        destination=canonical_json(destination) if destination is not None else None,
    ).to_document()


@dataclass(frozen=True, init=False)
class ReleaseSnapshot:
    """Canonical executable definition and credential-free dependency bindings."""

    _document: object
    digest: str

    def __init__(self, document):
        try:
            document = json_data(document)
            self._validate(document)
        except (ValueError, KeyError, TypeError) as error:
            if isinstance(error, ReleaseError):
                raise
            raise ReleaseError("Invalid release definition") from error
        digest = sha256(canonical_json(document).encode("utf-8")).hexdigest()
        object.__setattr__(self, "_document", freeze_json(document))
        object.__setattr__(self, "digest", digest)

    @classmethod
    def capture(cls, registry, application, model, tools, *, ontology=None, mapping_version=None,
                knowledge_strategy=None, policy_version=None, owp_profile=None, retrieval=None):
        try:
            definition, fingerprint = _legacy_definition(registry, application)
            app, action, _ = registry.definition(application)
            if ontology is None:
                projection = registry.ontology()
                ontology = registry.ontology(version=projection.digest)
            _require(isinstance(ontology, OntologyRelease), "Expected a validated ontology release")
            tool = _tool(tools, action)
            knowledge = {"references": app["knowledge"],
                         "strategy": _KNOWLEDGE_STRATEGY if knowledge_strategy is None else knowledge_strategy}
            if retrieval is not None:
                knowledge["retrieval"] = retrieval
            return cls({
                "format": _FORMAT, "application": application, "definition_hash": fingerprint,
                "definition": definition, "ontology": {"digest": ontology.digest, "definition": ontology.to_document()},
                "action": _action_contract(app, action, tool), "mapping_version": mapping_version,
                "models": _models(model, app), "tool": tool,
                "knowledge": knowledge,
                "owp": {"profile": owp_profile,
                        "policy_version": _BASE_POLICY_VERSION if policy_version is None else policy_version},
            })
        except ValueError as error:
            if isinstance(error, ReleaseError):
                raise
            raise ReleaseError("Invalid release dependencies") from error

    @classmethod
    def from_document(cls, document):
        return cls(document)

    @staticmethod
    def _validate(document):
        _require(_keys(document, ("format", "application", "definition_hash", "definition", "ontology", "action",
                                 "mapping_version", "models", "tool", "knowledge", "owp"))
                 and type(document["format"]) is int and document["format"] == _FORMAT,
                 "Unsupported release document")
        application = document["application"]
        registry = _legacy_registry(document["definition"], application)
        app, action, fingerprint = registry.definition(application)
        _require(fingerprint == document["definition_hash"], "Release definition fingerprint does not match")

        ontology = document["ontology"]
        _require(_keys(ontology, ("digest", "definition")), "Invalid release ontology reference")
        ontology_definition = OntologyRelease.from_document(ontology["definition"])
        _require(ontology_definition.digest == ontology["digest"] and ontology_definition.to_document() == ontology["definition"],
                 "Release ontology fingerprint does not match")
        _require(action["object_type"] in ontology["definition"]["types"], "Release ontology lacks the action type")
        _require(document["mapping_version"] is None or is_version(document["mapping_version"]), "Invalid mapping version")

        tool = document["tool"]
        _require(_keys(tool, ("name", "version", "destination"))
                 and tool["name"] == action.get("tool", "state.transition")
                 and tool["version"] == action.get("tool_version", "1"), "Release tool does not match its action")
        _validate_destination(tool["destination"])
        _require(_action_contract(app, action, tool) == document["action"], "Release action schema does not match")
        _validate_models(document["models"], app)

        knowledge = document["knowledge"]
        _require(_keys(knowledge, ("references", "strategy"), ("retrieval",)) and knowledge["references"] == app["knowledge"]
                 and knowledge["strategy"] in (_KNOWLEDGE_STRATEGY, AUTHORIZED_FRAGMENTS)
                 and (knowledge["strategy"] != AUTHORIZED_FRAGMENTS or bool(app["knowledge"])),
                 "Unsupported release knowledge strategy or references")
        if "retrieval" in knowledge:
            binding = knowledge["retrieval"]
            _require(bool(app["knowledge"]) and _keys(binding, ("index_id", "method", "binding_digest"))
                     and _name(binding["index_id"]) and binding["method"] in RETRIEVAL_METHODS
                     and isinstance(binding["binding_digest"], str)
                     and re.fullmatch(r"[0-9a-f]{64}", binding["binding_digest"]),
                     "Invalid release retrieval binding")
        owp = document["owp"]
        _require(_keys(owp, ("profile", "policy_version")) and (owp["profile"] is None or is_name(owp["profile"]))
                 and is_version(owp["policy_version"]), "Invalid release OpenWorkProof references")
        destination = tool["destination"]
        if destination and destination.get("source_binding") is not None:
            from .owp_gate import PROFILE

            _require(owp["profile"] == PROFILE, "Conditional source writes require OpenWorkProof")

    @property
    def application(self):
        return self._document["application"]

    @property
    def definition_hash(self):
        return self._document["definition_hash"]

    def to_document(self):
        return json_data(self._document)

    def registry(self):
        return _legacy_registry(json_data(self._document["definition"]), self.application)

    def ontology(self):
        return OntologyRelease.from_document(json_data(self._document["ontology"]["definition"]))

    def authorization_profile(self):
        return self._document["owp"]["profile"], self._document["owp"]["policy_version"]

    def retrieval_binding(self):
        return json_data(self._document["knowledge"].get("retrieval"))

    @property
    def uses_knowledge_citations(self):
        return self._document["knowledge"]["strategy"] == AUTHORIZED_FRAGMENTS

    def check_adapters(self, model, tools):
        """Require the original enabled route/fallback and tool destination. Credentials may rotate."""
        app = self._document["definition"]["applications"][self.application]
        _require(_models(model, app) == json_data(self._document["models"]), "Release model binding changed")
        self.check_tool(tools)

    def check_tool(self, tools):
        """Check the original destination without requiring a model for historical receipt lookup."""
        definition = self._document["definition"]
        action = definition["actions"][definition["applications"][self.application]["action"]]
        try:
            _require(_tool(tools, action) == json_data(self._document["tool"]), "Release tool binding changed")
        except ValueError as error:
            if isinstance(error, ReleaseError):
                raise
            raise ReleaseError("Release tool adapter is unavailable") from error


@dataclass(frozen=True)
class ReleaseRecord:
    snapshot: ReleaseSnapshot
    status: str
    created_by: str
    changed_by: str
    migration_ref: str | None


def _validate_scope(tenant, value):
    _require(is_name(tenant) and is_name(value), "Release scope requires tenant and identifier")


def _change_set(before, after):
    return {
        "added": sorted(after.keys() - before.keys()),
        "removed": sorted(before.keys() - after.keys()),
        "changed": sorted(key for key in before.keys() & after.keys() if before[key] != after[key]),
    }


class ReleaseStore:
    """Release operations on a PostgreSQL runtime transaction scoped to the tenant.

    Provide an authorized publisher and a write transaction for mutations.
    The transaction's tenant lock serializes release changes with task writes.
    """

    @staticmethod
    def get(connection, tenant_id, digest):
        _validate_scope(tenant_id, digest)
        row = connection.execute(
            """SELECT release.document, release.created_by, lifecycle.status, lifecycle.changed_by,
                      lifecycle.migration_ref
               FROM application_releases release
               JOIN application_release_lifecycle lifecycle USING (tenant, digest)
               WHERE release.tenant = ? AND release.digest = ?""",
            (tenant_id, digest),
        ).fetchone()
        if row is None:
            return None
        snapshot = ReleaseSnapshot.from_document(json.loads(row["document"]))
        _require(snapshot.digest == digest, "Stored release fingerprint does not match its document")
        return ReleaseRecord(snapshot, row["status"], row["created_by"], row["changed_by"], row["migration_ref"])

    @staticmethod
    def _selected(connection, tenant_id, application):
        row = connection.execute(
            "SELECT digest FROM application_release_selections WHERE tenant = ? AND application = ?",
            (tenant_id, application),
        ).fetchone()
        return row["digest"] if row is not None else None

    @classmethod
    def resolve(cls, connection, tenant_id, application, digest=None):
        """Choose an explicitly requested or selected release for a new task."""
        _validate_scope(tenant_id, application)
        if digest is None:
            digest = cls._selected(connection, tenant_id, application)
            if digest is None:
                return None
        record = cls.get(connection, tenant_id, digest)
        _require(record is not None and record.snapshot.application == application,
                 "Release is unavailable for this application")
        _require(record.status == "published", "Release is unavailable for new tasks")
        return record

    @classmethod
    def pinned(cls, connection, tenant_id, digest):
        """Read a task's pinned release for live work. Historical reads use get()."""
        record = cls.get(connection, tenant_id, digest)
        _require(record is not None and record.status in _LIVE, "Pinned release is unavailable for execution")
        return record

    @classmethod
    def draft(cls, connection, tenant_id, snapshot, *, publisher):
        _validate_scope(tenant_id, publisher)
        _require(isinstance(snapshot, ReleaseSnapshot), "A draft requires a validated release snapshot")
        ontology = snapshot.to_document()["ontology"]
        definition = ontology["definition"]
        conflicting_version = connection.execute(
            """SELECT 1 FROM application_releases
               WHERE tenant = ? AND ontology_namespace = ? AND ontology_version = (?::jsonb)::text
                 AND ontology_digest <> ? LIMIT 1""",
            (tenant_id, definition["namespace"], canonical_json(definition["version"]), ontology["digest"]),
        ).fetchone()
        _require(conflicting_version is None, "Ontology namespace and version already describe a different definition")
        inserted = connection.execute(
            """INSERT INTO application_releases (tenant, digest, document, created_by)
               VALUES (?, ?, ?, ?) ON CONFLICT (tenant, digest) DO NOTHING""",
            (tenant_id, snapshot.digest, canonical_json(snapshot.to_document()), publisher),
        )
        if inserted.rowcount:
            connection.execute(
                "INSERT INTO application_release_lifecycle (tenant, digest, changed_by) VALUES (?, ?, ?)",
                (tenant_id, snapshot.digest, publisher),
            )
        return cls.get(connection, tenant_id, snapshot.digest)

    @classmethod
    def _transition(cls, connection, tenant_id, digest, status, publisher, migration_ref=None):
        _validate_scope(tenant_id, publisher)
        record = cls.get(connection, tenant_id, digest)
        _require(record is not None, "Release is unavailable")
        if record.status == status:
            return record
        _require(status in _TRANSITIONS[record.status], "Release lifecycle transition is invalid")
        changed = connection.execute(
            """UPDATE application_release_lifecycle
               SET status = ?, changed_by = ?, changed_at = clock_timestamp(),
                   migration_ref = coalesce(?, migration_ref)
               WHERE tenant = ? AND digest = ? AND status = ?""",
            (status, publisher, migration_ref, tenant_id, digest, record.status),
        )
        _require(changed.rowcount == 1, "Release lifecycle changed during the transition")
        return cls.get(connection, tenant_id, digest)

    @classmethod
    def publish(cls, connection, tenant_id, digest, *, publisher, migration_ref=None, embedding=None, identity=None):
        _require(migration_ref is None or is_name(migration_ref), "Invalid release migration reference")
        record = cls.get(connection, tenant_id, digest)
        _require(record is not None, "Release is unavailable")
        if record.status == "draft":
            from .owp_gate import PROFILE
            from .release_retrieval import require_ready

            require_ready(connection, tenant_id, record.snapshot, publisher=publisher,
                          embedding=embedding, identity=identity)

            if record.snapshot.authorization_profile()[0] == PROFILE:
                from .fact_gate import binding_for

                _require(binding_for(connection, tenant_id, digest) is not None,
                         "An OWP release requires a bound fact rule")
            if cls.impact(connection, tenant_id, digest)["classification"] == "breaking":
                _require(migration_ref is not None, "Breaking release requires a migration reference")
        return cls._transition(connection, tenant_id, digest, "published", publisher, migration_ref)

    @classmethod
    def deprecate(cls, connection, tenant_id, digest, *, publisher):
        return cls._transition(connection, tenant_id, digest, "deprecated", publisher)

    @classmethod
    def revoke(cls, connection, tenant_id, digest, *, publisher):
        return cls._transition(connection, tenant_id, digest, "revoked", publisher)

    @classmethod
    def select(cls, connection, tenant_id, application, digest, *, publisher, embedding=None, identity=None):
        """Move the active pointer, including rollback to an old published release."""
        _validate_scope(tenant_id, publisher)
        _require(is_name(digest), "A selection requires a release digest")
        record = cls.resolve(connection, tenant_id, application, digest)
        from .release_retrieval import require_ready

        require_ready(connection, tenant_id, record.snapshot, publisher=publisher,
                      embedding=embedding, identity=identity)
        connection.execute(
            """INSERT INTO application_release_selections (tenant, application, digest, changed_by)
               VALUES (?, ?, ?, ?)
               ON CONFLICT (tenant, application) DO UPDATE
               SET digest = excluded.digest, changed_by = excluded.changed_by, changed_at = clock_timestamp()
               WHERE application_release_selections.digest <> excluded.digest""",
            (tenant_id, application, digest, publisher),
        )
        return record

    @classmethod
    def impact(cls, connection, tenant_id, digest):
        """Compare a draft against the selected version and enumerate dependent release scopes."""
        target = cls.get(connection, tenant_id, digest)
        _require(target is not None, "Release is unavailable")
        new = target.snapshot.to_document()
        application = target.snapshot.application
        selected = cls._selected(connection, tenant_id, application)
        previous = cls.get(connection, tenant_id, selected) if selected is not None else None
        old = previous.snapshot.to_document() if previous is not None else {}
        old_ontology = old.get("ontology", {}).get("definition", {})
        new_ontology = new["ontology"]["definition"]
        changes = {
            group: _change_set(old_ontology.get(group, {}), new_ontology.get(group, {}))
            for group in ("types", "relations", "rules", "actions", "events")
        }
        changes["executable_actions"] = _change_set(old.get("definition", {}).get("actions", {}),
                                                     new["definition"]["actions"])
        bindings = [key for key in ("models", "tool", "knowledge", "owp", "mapping_version")
                    if old.get(key) != new[key]]
        legacy_types_changed = bool(old and old["definition"]["types"] != new["definition"]["types"])
        old_types = old_ontology.get("types", {})
        added_relations = (new_ontology["relations"][name] for name in changes["relations"]["added"])
        required_edges_added = any(
            (relation["source_type"] in old_types and relation["targets_per_source"]["min"] > 0)
            or (relation["target_type"] in old_types and relation["sources_per_target"]["min"] > 0)
            for relation in added_relations
        )
        breaking = bool(previous) and (
            any(group["changed"] or group["removed"] for group in changes.values())
            or legacy_types_changed or required_edges_added or "tool" in bindings or "mapping_version" in bindings
            or old["knowledge"]["strategy"] != new["knowledge"]["strategy"]
            or old_ontology["namespace"] != new_ontology["namespace"]
        )
        affected_applications = {application}
        if previous is not None and old["ontology"]["digest"] != new["ontology"]["digest"]:
            related = connection.execute(
                """SELECT release.application FROM application_releases release
                   JOIN application_release_selections selected USING (tenant, application, digest)
                   WHERE release.tenant = ? AND release.ontology_digest = ? ORDER BY release.application""",
                (tenant_id, old["ontology"]["digest"]),
            ).fetchall()
            affected_applications.update(row["application"] for row in related)
        data = sorted({name for group in ("types", "relations") for names in changes[group].values() for name in names})
        migration = []
        if breaking and (data or legacy_types_changed):
            migration.append("validate and transform affected object and relationship data and rebuild derived indexes")
        if breaking and (changes["rules"]["changed"] or changes["rules"]["removed"]
                         or changes["actions"]["changed"] or changes["actions"]["removed"]
                         or changes["executable_actions"]["changed"] or changes["executable_actions"]["removed"]):
            migration.append("validate dependent rules and actions against migrated data before selecting the release")
        if breaking and "mapping_version" in bindings:
            migration.append("reconcile source identity mappings and revalidate dependent facts")
        if breaking and "tool" in bindings:
            migration.append("validate the tool migration and keep prior receipt lookup available for pinned work")
        if breaking and not migration:
            migration.append("validate consumers against the replacement ontology namespace before selection")
        pinned_tasks = {
            row["release_digest"]: row["tasks"]
            for row in connection.execute(
                """SELECT release_digest, count(*) AS tasks FROM task_governance
                   WHERE tenant = ? AND release_digest IN (?, ?) GROUP BY release_digest""",
                (tenant_id, selected, digest),
            ).fetchall()
        }
        return {
            "release": digest, "previous_release": selected,
            "classification": ("initial" if previous is None else "breaking" if breaking else "compatible"),
            "changes": changes, "bindings": bindings, "data": data, "index_scopes": data,
            "applications": sorted(affected_applications), "migration": migration, "pinned_tasks": pinned_tasks,
        }
