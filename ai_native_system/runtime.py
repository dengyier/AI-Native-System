from hashlib import sha256
from pathlib import Path
from time import monotonic, time
from uuid import uuid4

from . import governance
from .gateway import ModelGateway
from .graph_contract import GraphSpec
from .identity import IdentityContext
from .model import Model, ModelError
from .registry import Registry
from .tools import ToolRegistry
from .storage import REMOTE_SCHEMA, RuntimeStore, audit, database, digest, encode, initialize, object_data, row_data, task_data, task_row


def permitted(connection, tenant, principal_id, role):
    principal = row_data(connection.execute(
        "SELECT roles FROM principals WHERE tenant = ? AND id = ? AND active = 1",
        (tenant, principal_id),
    ).fetchone(), "roles")
    return principal is not None and role in principal["roles"]


def business_view(item):
    return {key: value for key, value in item.items() if key != "tenant"}


def set_status(connection, task_id, status):
    connection.execute("UPDATE tasks SET status = ? WHERE id = ?", (status, task_id))


def proposal_scope(task, app, action, ground, tool=None):
    scope = {
        "action": app["action"], "definition_hash": task["definition_hash"],
        "grounding_hash": digest(ground), "tenant": task["tenant"],
        "object_id": task["object_id"], "object_version": ground["object"]["version"],
        "from_state": action["from_state"], "to_state": action["to_state"],
    }
    if task.get("release_digest"):
        scope["release_digest"] = task["release_digest"]
    if tool is not None and tool.remote:
        scope["remote_identity"] = tool.identity
    return scope


def matches_scope(proposal, expected):
    return isinstance(proposal, dict) and all(proposal.get(key) == value for key, value in expected.items())


class Runtime:
    """Durable orchestration for versioned declarative applications."""

    def __init__(self, path, registry: Registry, model: Model, tools=None, *, release_adapters=None, owp_ledgers=None,
                 graph_store=None, graph_queue_limit=100):
        self.path = path
        self.registry = registry
        self.model = model
        self.tools = tools or ToolRegistry()
        self.release_adapters = dict(release_adapters or {})
        self.owp_ledgers = dict(owp_ledgers or {})
        self._external_store = isinstance(path, RuntimeStore)
        if graph_store is not None and not self._external_store:
            raise ValueError("LangGraph tasks require a PostgreSQL runtime")
        if type(graph_queue_limit) is not int or not 1 <= graph_queue_limit <= 1000:
            raise ValueError("Graph task queue limit must be 1–1000")
        self.graph_store = graph_store
        self.graph_queue_limit = graph_queue_limit
        if hasattr(path, "check_governance_role"):
            path.check_governance_role()
        # Additive migration for databases created by the first release.
        if not self._external_store and Path(path).is_file():
            with database(path, write=True) as connection:
                connection.execute(REMOTE_SCHEMA)
                connection.execute("""CREATE TABLE IF NOT EXISTS execution_claims (
                    task_id TEXT PRIMARY KEY REFERENCES tasks(id), token TEXT NOT NULL, expires REAL NOT NULL
                )""")

    def initialize(self):
        initialize(self.path, self.registry.seed)

    def _clock(self, connection):
        return connection.database_time() if self._external_store else time()

    def submit(self, tenant, application, object_id, requester, request_key, *, identity=None, release_digest=None,
               knowledge_citations=None, expected_object_version=None):
        if not isinstance(request_key, str) or not 1 <= len(request_key) <= 200:
            raise ValueError("Request key must contain 1–200 characters")
        if expected_object_version is not None and (
            type(expected_object_version) is not int or not 1 <= expected_object_version <= 2**31 - 1
        ):
            raise ValueError("Expected object version must be a positive integer")
        if knowledge_citations is not None:
            from .knowledge import Citation

            if not isinstance(knowledge_citations, (tuple, list)) or not 1 <= len(knowledge_citations) <= 10:
                raise ValueError("A task accepts one to ten knowledge citations")
            citations = [Citation.from_document(item).to_document() for item in knowledge_citations]
            if len({digest(item) for item in citations}) != len(citations):
                raise ValueError("Duplicate knowledge citation")
        else:
            citations = None
        ledger = None
        with database(self.path, write=True, tenant=tenant) as connection:
            active = governance.enabled(connection, tenant)
            if active:
                from .policy import Policy
                governance.require_identity_match(identity, tenant, requester)
                Policy().require(connection, identity, "submit", "app", application)
            elif (identity is not None or release_digest is not None or citations is not None
                  or expected_object_version is not None or tenant in self.owp_ledgers):
                raise PermissionError("Enterprise mode is required")
            else:
                app, action, definition_hash = self.registry.definition(application)
            prior = connection.execute(
                """SELECT * FROM tasks WHERE tenant = ? AND requester = ? AND request_key = ?""",
                (tenant, requester, request_key),
            ).fetchone()
            if prior is not None:
                prior = task_row(prior)
                if (prior["object_id"] != object_id or prior["application"] != application
                        or prior.get("knowledge_citations") != citations
                        or prior.get("expected_object_version") != expected_object_version):
                    raise ValueError("Request key already bound to a different payload")
                if active:
                    binding = governance.binding_for(connection, tenant, prior["id"])
                    if not binding or (release_digest is not None and release_digest != binding["release_digest"]):
                        raise ValueError("Request key already bound to a different release")
                    bound = governance.bound_identity(binding, "requester_context", tenant, requester)
                    if (bound.service, bound.delegation_id) != (identity.service, identity.delegation_id):
                        raise PermissionError("Request key belongs to a different delegation")
                    Policy().require(connection, identity, "read", "release", binding["release_digest"])
                    Policy().require(connection, identity, "read", "object", object_id)
                return prior
            if active:
                from .releases import ReleaseStore
                if release_digest is not None:
                    Policy().require(connection, identity, "read", "release", release_digest)
                record = ReleaseStore().resolve(connection, tenant, application, release_digest)
                if record is None:
                    raise ValueError("Application has no selected release")
                from .owp_gate import check_profile

                snapshot = record.snapshot
                if snapshot.uses_knowledge_citations != (citations is not None):
                    raise ValueError("Knowledge citations must match the selected release strategy")
                profile, _ = snapshot.authorization_profile()
                check_profile(connection, tenant, profile, required=tenant in self.owp_ledgers)
                if profile is not None:
                    ledger = self.owp_ledgers.get(tenant)
                    if ledger is None:
                        raise PermissionError("Configure the tenant's trusted OWP authority")
                release_digest = snapshot.digest
                Policy().require(connection, identity, "read", "release", release_digest)
                Policy().require(connection, identity, "read", "object", object_id)
                model, tools = self.release_adapters.get(release_digest, (self.model, self.tools))
                snapshot.check_adapters(model, tools)
                app, action, definition_hash = snapshot.registry().definition(application)
            authorized = permitted(connection, tenant, requester, action["request_role"])
            item = object_data(connection, tenant, object_id) if authorized else None
            if expected_object_version is not None and (item is None or item["version"] != expected_object_version):
                raise ValueError("Object no longer matches the requested version")
            accepted = item is not None and item["type"] == action["object_type"]
            task_id = uuid4().hex
            columns = ("id", "tenant", "application", "object_id", "requester", "request_key", "definition_hash", "status")
            values = (task_id, tenant, application, object_id, requester, request_key, definition_hash,
                      "planning" if accepted else "blocked")
            if expected_object_version is not None:
                columns += ("expected_object_version",)
                values += (expected_object_version,)
            if citations is not None:
                if not accepted or any(item["document_id"] not in app["knowledge"] for item in citations):
                    raise PermissionError("Knowledge evidence is outside the authorized task scope")
                columns += ("knowledge_citations",)
                values += (encode(citations),)
            if "graph" in app:
                from .graph_runtime import GraphUnavailable, require_queue_slot

                if not active or self.graph_store is None:
                    raise GraphUnavailable("A graph release requires enterprise PostgreSQL and its checkpoint store")
                spec = GraphSpec.from_document(app["graph"])
                if accepted:
                    require_queue_slot(connection, tenant, self.graph_queue_limit)
                columns += ("graph_version", "graph_deadline")
                values += (spec.version, self._clock(connection) + spec.deadline_seconds)
            connection.execute(f"INSERT INTO tasks ({', '.join(columns)}) VALUES ({', '.join('?' for _ in values)})",
                               values)
            task = task_data(connection, tenant, task_id)
            if active:
                governance.bind_task(connection, task, identity, release_digest)
                if ledger is not None:
                    ledger.admit(connection, tenant, task_id)
                if accepted:
                    definition = self._definition(connection, task)
                    reason = "resource_permission" if definition is None else self._ground(connection, task, definition)[0]
                    if reason == "resource_permission" or (citations is not None and reason in (
                        "knowledge_unavailable", "knowledge_citation_unavailable",
                    )):
                        raise PermissionError("Task scope is not authorized")
                audit(connection, task_id, "release.bound", release_digest=release_digest)
            audit(
                connection, task_id, "request.accepted" if accepted else "request.blocked",
                application=application, object_id=object_id, requester=requester,
            )
            return task_data(connection, tenant, task_id)

    def advance(self, tenant, task_id, simulate_timeout=None, *, identity=None, worker=True):
        with database(self.path, tenant=tenant) as connection:
            task = governance.read_task(connection, tenant, task_id, identity, "advance", worker=worker)
        if task.get("graph_version") is not None:
            from .graph_runtime import advance_graph

            return advance_graph(self, tenant, task, simulate_timeout, identity, worker=worker)
        return self._advance_native(tenant, task, simulate_timeout, identity, worker=worker)

    def _advance_native(self, tenant, task, simulate_timeout, identity, *, worker):
        task_id = task["id"]
        if task["status"] == "planning":
            return self._plan(tenant, task_id, identity, worker=worker)
        if task["status"] == "reconciling":
            with database(self.path, tenant=tenant) as connection:
                op = connection.execute("SELECT status FROM remote_operations WHERE operation_id=?", (task_id,)).fetchone()
            if op is not None and op["status"] == "prepared":
                return self._dispatch_remote(tenant, task_id, identity, worker=worker)
            return self.reconcile(tenant, task_id, identity=identity, worker=worker)
        if task["status"] != "ready":
            return task
        try:
            completed, wrote = self._execute(tenant, task_id, simulate_timeout, identity, worker=worker)
            if completed["status"] == "reconciling":
                return self._dispatch_remote(tenant, task_id, identity, worker=worker)
            if wrote and simulate_timeout == "after-commit":
                raise TimeoutError("Write committed before the response was lost")
            return completed
        except TimeoutError:
            with database(self.path, write=True, tenant=tenant) as connection:
                audit(connection, task_id, "tool.timeout", phase=simulate_timeout)
            raise

    def _definition(self, connection, task):
        registry, model, tools = self.registry, self.model, self.tools
        binding = release_digest = ontology = profile = policy = None
        try:
            active = governance.enabled(connection, task["tenant"])
            if not active and task["tenant"] in self.owp_ledgers:
                return None
            if active:
                from .releases import ReleaseStore
                binding = governance.binding_for(connection, task["tenant"], task["id"])
                if binding is None:
                    return None
                release_digest = binding["release_digest"]
                record = ReleaseStore().pinned(connection, task["tenant"], release_digest)
                if record is None or record.snapshot.application != task["application"]:
                    return None
                if record.snapshot.uses_knowledge_citations != (task.get("knowledge_citations") is not None):
                    return None
                model, tools = self.release_adapters.get(release_digest, (model, tools))
                record.snapshot.check_adapters(model, tools)
                from .owp_gate import check_profile

                registry = record.snapshot.registry()
                ontology = record.snapshot.ontology()
                profile, policy = record.snapshot.authorization_profile()
                check_profile(connection, task["tenant"], profile, required=task["tenant"] in self.owp_ledgers)
                if profile is not None:
                    ledger = self.owp_ledgers.get(task["tenant"])
                    if ledger is None or not ledger.eligible(connection, task["tenant"], task["id"]):
                        return None
            app, action, version = registry.definition(task["application"])
        except (ValueError, PermissionError):
            return None
        if (version != task["definition_hash"]
                or app.get("graph", {}).get("version") != task.get("graph_version")):
            return None
        return governance.Definition(registry, model, tools, app, action, binding, release_digest, ontology,
                                     profile, policy)

    def _ground(self, connection, task, definition, *, reviewer=None):
        try:
            return self._authorized_ground(connection, task, definition, reviewer)
        except PermissionError:
            return "resource_permission", None

    def _authorized_ground(self, connection, task, definition, reviewer):
        tenant = task["tenant"]
        app, action, registry = definition.app, definition.action, definition.registry
        identities = ()
        if definition.binding is not None:
            from .policy import Policy, tool_resource_id
            policy = Policy()
            requester = governance.bound_identity(definition.binding, "requester_context", tenant, task["requester"])
            executor = IdentityContext(tenant, app["executor"], service=app["executor"])
            tool = definition.tools.resolve(action)
            policy.require(connection, requester, "submit", "app", task["application"])
            policy.require(connection, requester, "read", "release", definition.release_digest)
            policy.require(connection, executor, "execute", "action", app["action"])
            policy.require(connection, executor, "execute", "tool", tool_resource_id(tool.name, tool.version))
            policy.require(connection, executor, "write", "object", task["object_id"])
            policy.require(connection, executor, "write", "metadata", task["object_id"], "state")
            if definition.owp_profile is not None:
                policy.require(connection, executor, "write", "metadata", task["object_id"], "version")
            identities = (requester, executor) + ((reviewer,) if reviewer is not None else ())
            governance.require_ground(connection, policy, identities, "object", task["object_id"])
        if not permitted(connection, tenant, task["requester"], action["request_role"]):
            return "requester_permission", None
        if not permitted(connection, tenant, app["executor"], action["execute_role"]):
            return "executor_permission", None
        item = object_data(connection, tenant, task["object_id"])
        if item is None or item["type"] != action["object_type"]:
            return "object_state", None
        if task.get("expected_object_version") not in (None, item["version"]):
            return "object_version_changed", None
        if identities:
            governance.require_ground(connection, policy, identities, "object", item["id"],
                                      item["properties"], item["links"], metadata=("state", "version"))
        if item["state"] != action["from_state"]:
            return "object_state", None
        try:
            registry.validate_object(item)
            if definition.ontology is not None:
                definition.ontology.validate_object({key: value for key, value in item.items() if key != "links"})
            links = {}
            for name, expected in registry.types[item["type"]]["links"].items():
                if identities:
                    governance.require_ground(connection, policy, identities, "object", item["links"][name])
                related = object_data(connection, tenant, item["links"][name])
                if related is None or related["type"] != expected:
                    return "object_link", None
                registry.validate_object(related)
                if definition.ontology is not None:
                    definition.ontology.validate_object({key: value for key, value in related.items() if key != "links"})
                if identities:
                    governance.require_ground(connection, policy, identities, "object", related["id"],
                                              related["properties"], related["links"], metadata=("state", "version"))
                    for target_id in related["links"].values():
                        governance.require_ground(connection, policy, identities, "object", target_id)
                links[name] = business_view(related)
        except ValueError:
            return "ontology_validation", None
        if any(item["properties"][key] != value for key, value in action.get("requires_properties", {}).items()):
            return "property_precondition", None
        if any(links[key]["state"] != value for key, value in action.get("requires_link_states", {}).items()):
            return "relationship_precondition", None
        documents = []
        if task.get("knowledge_citations") is not None:
            from .knowledge import Citation, citation_fragment

            if not identities:
                return "resource_permission", None
            for reference in task["knowledge_citations"]:
                citation = Citation.from_document(reference)
                if citation.document_id not in app["knowledge"]:
                    return "resource_permission", None
                governance.require_ground(connection, policy, identities, "document", citation.document_id)
                try:
                    governance.require_ground(connection, policy, identities[1:], "knowledge-index", citation.index_version)
                    fragment = citation_fragment(connection, identities[0], citation)
                except PermissionError:
                    return "knowledge_citation_unavailable", None
                documents.append(fragment)
        else:
            for document_id in app["knowledge"]:
                if identities:
                    governance.require_ground(connection, policy, identities, "document", document_id)
                document = connection.execute(
                    "SELECT id, version, text FROM knowledge WHERE tenant = ? AND id = ?",
                    (tenant, document_id),
                ).fetchone()
                if document is None:
                    return "knowledge_unavailable", None
                if identities and connection.execute(
                    "SELECT knowledge_revision_revoked(?, ?)", (document_id, document["version"]),
                ).fetchone()[0]:
                    return "knowledge_unavailable", None
                documents.append(dict(document))
        ground = {"object": business_view(item), "related": links, "knowledge": documents}
        if definition.release_digest is not None:
            from .fact_gate import assess, binding_for

            rule = binding_for(connection, tenant, definition.release_digest)
            if rule is None:
                if definition.owp_profile is not None:
                    return "owp_rule_required", None
            else:
                evaluation = assess(connection, self.path, definition.ontology, tenant, item["type"], item["id"], rule)
                if definition.owp_profile is not None:
                    from .fact_contracts import canonical_json

                    for identity in identities:
                        for kind, resource_id, member in evaluation.resources:
                            policy.require(connection, identity, "read", kind, resource_id, member)
                    read_set = evaluation.read_set.as_payload()
                    read_set.pop("as_of")
                    ground["_owp_rule"] = {
                        "versions": dict(evaluation.versions),
                        "read_set_digest": sha256(canonical_json(read_set).encode("utf-8")).hexdigest(),
                        "resources": [list(resource) for resource in evaluation.resources],
                    }
                if evaluation.status != "satisfied":
                    return "fact_rule_" + evaluation.status, None
                ground["_fact_fingerprint"] = evaluation.fingerprint
                if identities and tool.source is not None:
                    if rule["feedback_source"] not in (None, tool.source.source):
                        return "source_feedback_binding_changed", None
                    from .facts import Facts
                    from .p4_tools import source_conditions

                    ground["_p4_source_conditions"] = source_conditions(
                        connection, Facts(self.path, tenant), evaluation, ground, tool.source.source, definition,
                    )
        return None, ground

    def _plan(self, tenant, task_id, identity=None, *, worker=True, expected_stage=None):
        from .graph_runtime import expired

        attempt_id = uuid4().hex
        with database(self.path, write=True, tenant=tenant) as connection:
            task = governance.read_task(connection, tenant, task_id, identity, "advance", worker=worker)
            if task["status"] != "planning" or (expected_stage is not None and task["next_stage"] != expected_stage):
                return task
            if expired(connection, task):
                return self._block(connection, task, "graph_deadline")
            definition = self._definition(connection, task)
            if definition is None:
                return self._block(connection, task, "definition_changed")
            app, action = definition.app, definition.action
            try:
                definition.tools.resolve(action)
            except ValueError:
                return self._block(connection, task, "unregistered_tool")
            lease = connection.execute("SELECT * FROM execution_claims WHERE task_id = ?", (task_id,)).fetchone()
            if lease is not None and lease["expires"] > self._clock(connection):
                return task
            attempts = connection.execute(
                "SELECT count(*) FROM events WHERE task_id = ? AND event = 'model.started'", (task_id,)
            ).fetchone()[0]
            if attempts >= app.get("max_model_calls", 12):
                return self._block(connection, task, "model_call_budget")
            expires = self._clock(connection) + app.get("lease_seconds", 60)
            if task.get("graph_deadline") is not None:
                expires = min(expires, task["graph_deadline"])
            connection.execute(
                """INSERT INTO execution_claims (task_id, token, expires) VALUES (?, ?, ?)
                   ON CONFLICT (task_id) DO UPDATE SET token = excluded.token, expires = excluded.expires""",
                (task_id, attempt_id, expires),
            )
            reason, ground = self._ground(connection, task, definition)
            if reason:
                return self._block(connection, task, reason)
            ground_hash = digest(ground)
            if task["grounding_hash"] and task["grounding_hash"] != ground_hash:
                return self._block(connection, task, "stale_handoff_context")
            index = task["next_stage"]
            agent = app["agents"][index]
            previous = connection.execute(
                "SELECT agent_id, proposal FROM steps WHERE task_id = ? AND stage = ?",
                (task_id, index - 1),
            ).fetchone()
            handoff = row_data(previous, "proposal")
            audit(
                connection, task_id, "tool.read", stage=index, tool="ontology.lookup",
                object_id=ground["object"]["id"], object_version=ground["object"]["version"],
                linked_versions={name: item["version"] for name, item in ground["related"].items()},
                knowledge=[{"id": doc["id"], "version": doc["version"]} for doc in ground["knowledge"]],
            )
            if handoff:
                audit(connection, task_id, "handoff.received", source=handoff["agent_id"], target=agent["id"])
            audit(connection, task_id, "model.started", attempt_id=attempt_id, stage=index, agent=agent["id"])
        # Provider calls run outside the transaction. A later checkpoint validates the same facts.
        started = monotonic()
        try:
            context = {
                **self._visible_ground(ground),
                "scenario": task["application"], "agent": agent, "handoff": handoff,
                "allowed_actions": [{
                    "name": app["action"],
                    "description": action.get("description", app["action"]),
                }],
            }
            if isinstance(definition.model, ModelGateway):
                def managed_call(name, route, projected):
                    from .model_service import ModelAdmissionError, ModelCall
                    from .policy import Policy

                    def admit(connection):
                        live = task_data(connection, tenant, task_id)
                        lease = connection.execute("SELECT * FROM execution_claims WHERE task_id = ?",
                                                   (task_id,)).fetchone()
                        if live["status"] != "planning" or lease is None or lease["token"] != attempt_id:
                            raise ModelAdmissionError("Model call lost its task claim")
                        current = self._definition(connection, live)
                        if current is None:
                            raise ModelAdmissionError("Model call release is unavailable")
                        reason, fresh = self._ground(connection, live, current)
                        if reason or digest(fresh) != ground_hash:
                            raise ModelAdmissionError("Model call grounding or permissions changed")
                        if current.binding is not None:
                            requester = governance.bound_identity(current.binding, "requester_context", tenant,
                                                                 task["requester"])
                            executor = IdentityContext(tenant, app["executor"], service=app["executor"])
                            policy = Policy()
                            if not all(policy.permits(connection, user, "use", "model", name)
                                       for user in (requester, executor)):
                                raise ModelAdmissionError("Model route access denied")
                        return lease["expires"] - self._clock(connection)

                    call = ModelCall(self.path, tenant, attempt_id, getattr(self.model, "limits", None),
                                     purpose="generation", task_id=task_id, action_id=app["action"])
                    return call.invoke(
                        name, route.version, route.adapter, route.policy.accounting,
                        lambda remaining: route.adapter.propose(projected, timeout_seconds=remaining),
                        max_output_tokens=route.adapter.manifest["max_output_tokens"], admit=admit,
                    )

                result = definition.model.propose(context, managed_call=managed_call)
            else:
                result = definition.model.propose(context)
        except Exception as exc:
            with database(self.path, write=True, tenant=tenant) as connection:
                connection.execute("DELETE FROM execution_claims WHERE task_id = ? AND token = ?",
                                   (task_id, attempt_id))
                audit(
                    connection, task_id, "model.failed", attempt_id=attempt_id,
                    elapsed_ms=round((monotonic() - started) * 1000),
                    **({"budget": exc.reason} if isinstance(exc, ModelError) and
                       getattr(exc, "reason", None) in ("deadline", "attempts", "concurrency", "tokens", "cost") else {}),
                )
            raise
        with database(self.path, write=True, tenant=tenant) as connection:
            task = task_data(connection, tenant, task_id)
            if task["status"] == "planning" and expired(connection, task):
                audit(connection, task_id, "model.discarded", attempt_id=attempt_id, reason="graph_deadline")
                return self._block(connection, task, "graph_deadline")
            lease = connection.execute("SELECT * FROM execution_claims WHERE task_id = ?", (task_id,)).fetchone()
            if lease is None or lease["token"] != attempt_id or lease["expires"] <= self._clock(connection):
                audit(connection, task_id, "model.discarded", attempt_id=attempt_id, reason="lease_lost")
                return task
            connection.execute("DELETE FROM execution_claims WHERE task_id = ? AND token = ?",
                               (task_id, attempt_id))
            audit(
                connection, task_id, "model.completed", attempt_id=attempt_id,
                agent=agent["id"], provider=result.provider, model=result.model,
                input_tokens=result.input_tokens, output_tokens=result.output_tokens,
                elapsed_ms=round((monotonic() - started) * 1000),
            )
            if task["status"] != "planning" or task["next_stage"] != index:
                return task
            definition = self._definition(connection, task)
            if definition is None:
                return self._block(connection, task, "definition_changed")
            reason, current = self._ground(connection, task, definition)
            if reason or digest(current) != ground_hash:
                return self._block(connection, task, reason or "stale_context")
            offered_evidence = {doc["id"] for doc in current["knowledge"]}
            if (
                result.action not in (None, app["action"])
                or not isinstance(result.rationale, str) or not 1 <= len(result.rationale.strip()) <= 600
                or not isinstance(result.evidence_ids, (list, tuple)) or len(result.evidence_ids) > 10
                or any(not isinstance(item, str) or item not in offered_evidence for item in result.evidence_ids)
                or len(set(result.evidence_ids)) != len(result.evidence_ids)
                or (result.action and offered_evidence and not result.evidence_ids)
            ):
                return self._block(connection, task, "invalid_proposal")
            proposal = {
                "action": result.action, "rationale": result.rationale,
                "evidence_ids": list(result.evidence_ids),
            }
            connection.execute(
                "INSERT INTO steps VALUES (?, ?, ?, ?)",
                (task_id, index, agent["id"], encode(proposal)),
            )
            next_stage = index + 1
            final_stage = next_stage == len(app["agents"])
            status = "planning"
            if result.action is None:
                status = "no_action"
            elif final_stage:
                status = "awaiting_approval"
                proposal.update(self._proposal_scope(task, definition, ground))
            connection.execute(
                """UPDATE tasks SET status = ?, next_stage = ?, grounding_hash = ?, proposal = ?
                   WHERE id = ?""",
                (status, next_stage, ground_hash,
                 encode(proposal) if status == "awaiting_approval" else None, task_id),
            )
            audit(connection, task_id, "stage.recorded", agent=agent["id"], stage=index, status=status)
            return task_data(connection, tenant, task_id)

    @staticmethod
    def _visible_ground(ground):
        return {key: ground[key] for key in ("object", "related", "knowledge")}

    def _proposal_scope(self, task, definition, ground):
        return proposal_scope({**task, "release_digest": definition.release_digest},
                              definition.app, definition.action, ground, definition.tools.resolve(definition.action))

    def _approved(self, connection, task, definition):
        if (
            task["approval_hash"] != digest(task["proposal"])
            or task["approver"] == task["requester"]
            or not permitted(connection, task["tenant"], task["approver"], definition.action["approval_role"])
        ):
            return False, None
        if definition.binding is None:
            return True, None
        try:
            approver = governance.bound_identity(definition.binding, "approver_context", task["tenant"], task["approver"])
            governance.task_access(connection, task, approver, "approve", active=True)
        except (PermissionError, TypeError, ValueError):
            return False, None
        return True, approver

    def decide(self, tenant, task_id, approver, verdict, *, identity=None, proposal_digest=None):
        from .graph_runtime import expired

        if verdict not in ("approve", "reject"):
            raise ValueError("Decision must be approve or reject")
        with database(self.path, write=True, tenant=tenant) as connection:
            active = governance.enabled(connection, tenant)
            task = governance.read_task(connection, tenant, task_id, identity, "approve", active=active)
            if active:
                governance.require_identity_match(identity, tenant, approver)
                if identity.service is not None:
                    raise PermissionError("Approval requires an independent human account")
                if not task["proposal"] or proposal_digest != digest(task["proposal"]):
                    raise ValueError("The proposal digest has changed")
                prior = connection.execute(
                    "SELECT detail FROM events WHERE task_id = ? AND event = 'approval.recorded'", (task_id,),
                ).fetchone()
                if prior is not None:
                    detail = row_data(prior, "detail")["detail"]
                    if detail["approver"] == approver and detail["verdict"] == verdict:
                        return task
                    raise ValueError("A different decision was already recorded")
            if task["status"] != "awaiting_approval":
                raise ValueError("Task is not awaiting approval")
            if expired(connection, task):
                return self._block(connection, task, "graph_deadline")
            definition = self._definition(connection, task)
            if definition is None:
                return self._block(connection, task, "definition_changed")
            app, action = definition.app, definition.action
            if approver != task["requester"] and permitted(connection, tenant, approver, action["approval_role"]):
                reason, ground = self._ground(connection, task, definition, reviewer=identity)
                if active and reason == "resource_permission":
                    raise PermissionError("Proposal scope is outside the approver's grants")
                if verdict == "approve":
                    if reason or digest(ground) != task["grounding_hash"]:
                        return self._block(connection, task, reason or "stale_context")
                    if not matches_scope(task["proposal"], self._proposal_scope(task, definition, ground)):
                        return self._block(connection, task, "proposal_scope")
                proposal_hash = digest(task["proposal"])
                connection.execute(
                    "UPDATE tasks SET status = ?, approver = ?, approval_hash = ? WHERE id = ?",
                    ("ready" if verdict == "approve" else "rejected", approver, proposal_hash, task_id),
                )
                if active:
                    governance.bind_approval(connection, task, identity)
                audit(connection, task_id, "approval.recorded", approver=approver, verdict=verdict,
                      proposal_hash=proposal_hash)
                return task_data(connection, tenant, task_id)
            audit(connection, task_id, "approval.blocked", approver=approver)
        raise PermissionError("An authorized independent approver is required")

    def _approved_ground(self, connection, task, definition):
        approved, reviewer = self._approved(connection, task, definition)
        if not approved:
            return "approval_invalid", None, None
        reason, ground = self._ground(connection, task, definition, reviewer=reviewer)
        if reason or digest(ground) != task["grounding_hash"]:
            return reason or "stale_context", None, None
        if not matches_scope(task["proposal"], self._proposal_scope(task, definition, ground)):
            return "proposal_scope", None, None
        return None, ground, reviewer

    def authorization_request(self, connection, tenant, task_id):
        """Prepare an exact signing request for a trusted control transaction."""
        from .owp_gate import PROFILE, scope_for
        from .graph_runtime import expired

        task = task_data(connection, tenant, task_id)
        definition = self._definition(connection, task)
        ledger = self.owp_ledgers.get(tenant)
        if (task["status"] != "ready" or definition is None or definition.owp_profile != PROFILE
                or ledger is None or expired(connection, task)):
            raise PermissionError("No eligible OWP task and recovery epoch")
        reason, ground, reviewer = self._approved_ground(connection, task, definition)
        if reason:
            raise PermissionError("The current task requires a new approval")
        return {"profile": PROFILE, "epoch": ledger.epoch, "scope": scope_for(task, definition, ground, reviewer)}

    def _execute(self, tenant, task_id, simulate_timeout, identity=None, *, worker=True):
        from .graph_runtime import expired

        with database(self.path, write=True, tenant=tenant) as connection:
            task = governance.read_task(connection, tenant, task_id, identity, "advance", worker=worker)
            if task["status"] != "ready":
                return task, False
            if expired(connection, task):
                return self._block(connection, task, "graph_deadline"), False
            from .action_sequence import may_execute

            if not may_execute(connection, tenant, task_id):
                return {**task, "authorization": {"verdict": "manual", "reason": "prior_action_incomplete"}}, False
            definition = self._definition(connection, task)
            if definition is None:
                return self._block(connection, task, "definition_changed"), False
            app, action = definition.app, definition.action
            reason, ground, reviewer = self._approved_ground(connection, task, definition)
            if reason:
                return self._block(connection, task, reason), False
            if expired(connection, task):
                return self._block(connection, task, "graph_deadline"), False
            item = ground["object"]
            tool = definition.tools.resolve(action)
            if tool.source is not None:
                if definition.owp_profile is None:
                    return self._block(connection, task, "source_write_requires_owp"), False
                if ground.get("_p4_source_conditions") is None:
                    return {**task, "authorization": {"verdict": "manual", "reason": "source_guards_unavailable"}}, False
            authorization = None
            if definition.owp_profile is not None:
                from .owp_gate import scope_for

                ledger = self.owp_ledgers.get(tenant)
                if ledger is None:
                    return self._block(connection, task, "owp_trust_unavailable"), False
                try:
                    scope = scope_for(task, definition, ground, reviewer)
                except PermissionError:
                    return self._block(connection, task, "owp_scope"), False
                authorization = (ledger.check if tool.remote else ledger.consume)(connection, tenant, task_id, scope)
                if authorization.verdict == "manual":
                    return {**task, "authorization": {"verdict": "manual", "reason": authorization.reason}}, False
                if not authorization.allowed:
                    return self._block(connection, task, "owp_" + authorization.reason), False
            audit(connection, task_id, "policy.allowed", requester=task["requester"],
                  approver=task["approver"], executor=app["executor"], action=app["action"])
            if tool.remote:
                from .remote_execution import prepare
                prepare(connection, {**task, "release_digest": definition.release_digest}, app, action, tool, ground)
                set_status(connection, task_id, "reconciling")
                return task_data(connection, tenant, task_id), False
            receipt = tool.handler(connection, task, action, ground)
            if not isinstance(receipt, dict):
                raise ValueError("Tool must return a JSON object receipt")
            encode(receipt)
            connection.execute(
                "INSERT INTO effects VALUES (?, ?, ?, ?)",
                (task_id, app["action"], item["id"], encode(receipt)),
            )
            if authorization is not None:
                from .evidence import enqueue_effect

                enqueue_effect(connection, tenant=tenant, task_id=task_id, operation_id=task_id,
                               authorization_digest=authorization.authorization_digest,
                               result=receipt, observation="local_transaction")
            audit(connection, task_id, "tool.committed", action=app["action"], operation_id=task_id, **receipt)
            set_status(connection, task_id, "completed")
            if simulate_timeout == "before-commit":
                raise TimeoutError("Write timed out before commit")
            return task_data(connection, tenant, task_id), True

    def cancel(self, tenant, task_id, actor, *, identity=None):
        with database(self.path, write=True, tenant=tenant) as connection:
            task = governance.read_task(connection, tenant, task_id, identity, "cancel")
            if identity is not None:
                governance.require_identity_match(identity, tenant, actor)
            principal = connection.execute(
                "SELECT active FROM principals WHERE tenant = ? AND id = ?", (tenant, actor)
            ).fetchone()
            if actor != task["requester"] or principal is None or not principal["active"]:
                raise PermissionError("Only the active requester can cancel")
            if task["status"] == "reconciling":
                op = connection.execute(
                    "SELECT status FROM remote_operations WHERE operation_id=?", (task_id,)
                ).fetchone()
                if op is not None and op["status"] == "prepared":
                    connection.execute("UPDATE remote_operations SET status='cancelled' WHERE operation_id=?", (task_id,))
                    set_status(connection, task_id, "cancelled")
                    audit(connection, task_id, "task.cancelled", actor=actor)
                else:
                    audit(connection, task_id, "cancel.deferred", reason="remote_outcome_unknown", actor=actor)
            if task["status"] in ("planning", "awaiting_approval", "ready"):
                set_status(connection, task_id, "cancelled")
                connection.execute("DELETE FROM execution_claims WHERE task_id = ?", (task_id,))
                audit(connection, task_id, "task.cancelled", actor=actor)
            return task_data(connection, tenant, task_id)

    def work(self, tenant, limit=20):
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("Worker limit must be 1–100")
        with database(self.path, tenant=tenant) as connection:
            if self._external_store:
                statement = """SELECT t.id FROM tasks t LEFT JOIN legacy_task_order legacy ON legacy.task_id = t.id
                    WHERE t.tenant = ? AND t.status IN ('planning', 'ready', 'reconciling')
                      AND (? OR t.graph_version IS NULL)
                    ORDER BY legacy.row_id NULLS LAST,
                        (SELECT min(e.id) FROM events e WHERE e.task_id = t.id), t.id LIMIT ?"""
                parameters = (tenant, self.graph_store is not None, limit)
            else:
                statement = """SELECT id FROM tasks WHERE tenant = ? AND status IN ('planning', 'ready', 'reconciling')
                    ORDER BY rowid LIMIT ?"""
                parameters = (tenant, limit)
            tasks = connection.execute(statement, parameters).fetchall()
        results = []
        for row in tasks:
            try:
                result = self.advance(tenant, row["id"])
                results.append({"id": row["id"], "status": result["status"]})
            except ModelError:
                results.append({"id": row["id"], "status": "retryable"})
        return results

    def work_graph(self, tenants, per_tenant=1):
        from .graph_runtime import work_graph

        return work_graph(self, tenants, per_tenant)

    def metrics(self, tenant):
        with database(self.path, tenant=tenant) as connection:
            states = dict(connection.execute(
                "SELECT status, count(*) FROM tasks WHERE tenant = ? GROUP BY status", (tenant,)
            ).fetchall())
            events = connection.execute(
                """SELECT e.detail FROM events e JOIN tasks t ON e.task_id = t.id
                   WHERE t.tenant = ? AND e.event = 'model.completed'""", (tenant,)
            )
            calls = [row_data(row, "detail")["detail"] for row in events]
            expired_claims = connection.execute(
                """SELECT count(*) FROM execution_claims c JOIN tasks t ON c.task_id = t.id
                   WHERE t.tenant = ? AND c.expires <= ?""", (tenant, self._clock(connection)),
            ).fetchone()[0]
            oldest_reconciliation = connection.execute(
                """SELECT min(e.time) FROM events e JOIN tasks t ON e.task_id = t.id
                   WHERE t.tenant = ? AND t.status = 'reconciling' AND e.event = 'remote.prepared'""", (tenant,),
            ).fetchone()[0]
            return {
                "tasks_by_status": states, "model_calls_completed": len(calls),
                "model_elapsed_ms": sum(c["elapsed_ms"] for c in calls),
                "reported_input_tokens": sum(c["input_tokens"] or 0 for c in calls),
                "reported_output_tokens": sum(c["output_tokens"] or 0 for c in calls),
                "calls_without_usage": sum(c["input_tokens"] is None or c["output_tokens"] is None for c in calls),
                "expired_execution_claims": expired_claims,
                "reconciling_tasks": states.get("reconciling", 0),
                "oldest_reconciliation_at": oldest_reconciliation,
            }

    def _dispatch_remote(self, tenant, task_id, identity=None, *, worker=True):
        from .remote_execution import dispatch
        return dispatch(self, tenant, task_id, identity, worker=worker)

    def reconcile(self, tenant, task_id, *, identity=None, worker=True, delivery_lease=None):
        from .remote_execution import reconcile
        return reconcile(self, tenant, task_id, identity, worker=worker, delivery_lease=delivery_lease)

    def retry_remote(self, tenant, task_id, actor, *, identity=None):
        from .remote_execution import retry
        return retry(self, tenant, task_id, actor, identity)

    def _block(self, connection, task, reason):
        connection.execute("DELETE FROM execution_claims WHERE task_id = ?", (task["id"],))
        set_status(connection, task["id"], "blocked")
        audit(connection, task["id"], "policy.blocked", reason=reason)
        return task_data(connection, task["tenant"], task["id"])

    def inspect(self, tenant, task_id, *, identity=None, evidence=False):
        with database(self.path, tenant=tenant) as connection:
            active = governance.enabled(connection, tenant)
            task = governance.read_task(connection, tenant, task_id, identity, "read", active=active)
            if active:
                from .policy import Policy
                policy = Policy()
                result = {"id": task_id, "status": task["status"]}
                binding = governance.binding_for(connection, tenant, task_id)
                if binding and policy.permits(connection, identity, "read", "release", binding["release_digest"]):
                    result["release_digest"] = binding["release_digest"]
                if evidence:
                    policy.require(connection, identity, "export", "evidence", task_id)
                    if task["proposal"]:
                        result["proposal_digest"] = digest(task["proposal"])
                    result["effect_recorded"] = connection.execute(
                        "SELECT 1 FROM effects WHERE operation_id = ?", (task_id,),
                    ).fetchone() is not None
                    if binding:
                        from .releases import ReleaseStore
                        release = ReleaseStore.get(connection, tenant, binding["release_digest"])
                        if release is not None and release.snapshot.authorization_profile()[0] is not None:
                            from .evidence import evidence_status

                            result["owp_evidence"] = evidence_status(connection, tenant, task_id)
                        from .fact_feedback import status
                        from .fact_gate import binding_for

                        rule = binding_for(connection, tenant, binding["release_digest"])
                        if rule is not None and rule["feedback_source"] is not None:
                            result["source_feedback"] = status(connection, tenant, task_id)
                if not evidence and task["status"] == "awaiting_approval" and policy.permits(connection, identity, "approve", "task", task_id):
                    definition = self._definition(connection, task)
                    if definition is not None:
                        reason, ground = self._ground(connection, task, definition, reviewer=identity)
                        if reason is None and digest(ground) == task["grounding_hash"]:
                            result["review"] = {"proposal": task["proposal"], "proposal_digest": digest(task["proposal"]),
                                                "grounding": self._visible_ground(ground)}
                return result
            return {
                "task": task,
                "steps": [row_data(row, "proposal") for row in connection.execute(
                    "SELECT stage, agent_id, proposal FROM steps WHERE task_id = ? ORDER BY stage", (task_id,)
                )],
                "events": [row_data(row, "detail") for row in connection.execute(
                    "SELECT * FROM events WHERE task_id = ? ORDER BY id", (task_id,)
                )],
                "operations": [row_data(row, "payload", "response", "adapter_identity") for row in connection.execute(
                    "SELECT * FROM remote_operations WHERE operation_id = ?", (task_id,)
                )],
                "effects": [row_data(row, "receipt") for row in connection.execute(
                    "SELECT * FROM effects WHERE operation_id = ?", (task_id,)
                )],
            }
