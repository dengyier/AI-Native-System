"""Published, permission-bound reference applications on the shared runtime."""

import json
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from . import governance
from .gateway import ModelGateway
from .identity import IdentityContext, require_identity
from .knowledge import citation_fragment
from .model import DemoModel, ModelError
from .model_service import ModelCall
from .owp_gate import PROFILE
from .policy import Policy
from .registry import unique_keys
from .releases import ReleaseError, ReleaseStore
from .storage import database


_KINDS = {"question", "artifact", "action"}


def _identifier(value):
    return (type(value) is str and 1 <= len(value) <= 80 and value.isascii() and
            all(char.isalnum() or char in "._-" for char in value))


@dataclass(frozen=True)
class ApplicationSpec:
    id: str
    application: str
    label: str
    kind: str
    retrieval_method: str = "exact"

    @classmethod
    def parse(cls, document):
        if (not isinstance(document, dict) or set(document) - {"retrieval_method"} != {"id", "application", "label", "kind"}
               or not all(_identifier(document[key]) for key in ("id", "application"))
               or type(document["kind"]) is not str or document["kind"] not in _KINDS
               or type(document["label"]) is not str or not document["label"].strip()
               or len(document["label"]) > 80 or not document["label"].isprintable()):
            raise ValueError("Invalid application declaration")
        if "retrieval_method" in document:
            method = document["retrieval_method"]
            if document["kind"] == "action" or type(method) is not str or method not in ("exact", "hnsw", "hybrid"):
                raise ValueError("Application retrieval_method requires a question or artifact and a supported method")
        return cls(**document)

    @property
    def operation(self):
        return "submit" if self.kind == "action" else "run"


class ApplicationCatalog:
    """Select a published app and pass its fixed scope to shared services."""

    def __init__(self, runtime, retrieval, document):
        if (not isinstance(document, dict) or set(document) != {"applications"}
                or not isinstance(document["applications"], list) or not 1 <= len(document["applications"]) <= 32):
            raise ValueError("Application catalog requires one to 32 declarations")
        entries = [ApplicationSpec.parse(item) for item in document["applications"]]
        self.applications = {item.id: item for item in entries}
        if len(self.applications) != len(entries):
            raise ValueError("Application catalog IDs must be distinct")
        self.runtime = runtime
        self.retrieval = retrieval
        self.policy = Policy()

    @classmethod
    def load(cls, runtime, retrieval, path):
        with Path(path).open("rb") as source:
            payload = source.read(128_001)
        if len(payload) > 128_000:
            raise ValueError("Application catalog exceeds the file limit")
        return cls(runtime, retrieval, json.loads(payload, object_pairs_hook=unique_keys))

    @staticmethod
    def _check_identity(connection, identity):
        require_identity(connection, identity)
        if not governance.enabled(connection, identity.tenant):
            raise PermissionError("Applications require a governed tenant")

    def _release(self, connection, identity, spec, release_digest=None):
        self._check_identity(connection, identity)
        for operation in ("read", spec.operation):
            self.policy.require(connection, identity, operation, "app", spec.application)
        if release_digest is not None:
            self.policy.require(connection, identity, "read", "release", release_digest)
        if spec.kind == "action" and release_digest is not None:
            # Runtime checks a prior request before it resolves permission to start new work.
            record = ReleaseStore.get(connection, identity.tenant, release_digest)
        else:
            record = ReleaseStore.resolve(connection, identity.tenant, spec.application, release_digest)
        if record is None or record.snapshot.application != spec.application:
            raise LookupError("Published application is unavailable")
        snapshot = record.snapshot
        self.policy.require(connection, identity, "read", "release", snapshot.digest)
        if spec.kind == "action" and snapshot.authorization_profile()[0] != PROFILE:
            raise PermissionError("The controlled application requires OpenWorkProof")
        return snapshot

    def list(self, identity):
        if not isinstance(identity, IdentityContext):
            raise PermissionError("Applications require a trusted identity")
        available = []
        with database(self.runtime.path, tenant=identity.tenant) as connection:
            self._check_identity(connection, identity)
            for spec in self.applications.values():
                try:
                    snapshot = self._release(connection, identity, spec)
                except (PermissionError, LookupError, ReleaseError):
                    continue
                app, _, _ = snapshot.registry().definition(spec.application)
                docs = [doc for doc in app["knowledge"] if self.policy.permits(connection, identity, "read", "document", doc)]
                available.append({"id": spec.id, "label": spec.label, "kind": spec.kind,
                                  "application": spec.application, "release_digest": snapshot.digest,
                                  "uses_knowledge_citations": snapshot.uses_knowledge_citations, "documents": docs})
        return {"applications": available}

    def run(self, identity, app_id, payload):
        if not isinstance(identity, IdentityContext):
            raise PermissionError("Applications require a trusted identity")
        if not _identifier(app_id) or app_id not in self.applications:
            raise LookupError("Published application is unavailable")
        if not isinstance(payload, dict):
            raise ValueError("Application input must be an object")
        spec = self.applications[app_id]
        release_digest = payload.get("release_digest")
        if release_digest is not None and (type(release_digest) is not str or len(release_digest) != 64
                                           or any(ch not in "0123456789abcdef" for ch in release_digest)):
            raise ValueError("Invalid application release digest")
        with database(self.runtime.path, tenant=identity.tenant) as connection:
            snapshot = self._release(connection, identity, spec, release_digest)
        result = {"application": spec.id, "kind": spec.kind, "release_digest": snapshot.digest}
        if spec.kind == "action":
            fields = {"object_id", "expected_version", "request_key"}
            if (not fields <= set(payload) <= fields | {"release_digest", "knowledge_citations"}
                   or type(payload["expected_version"]) is not int or payload["expected_version"] < 1
                   or type(payload["object_id"]) is not str or not payload["object_id"].strip()):
                raise ValueError("A controlled application requires object ID, expected version and request key")
            task = self.runtime.submit(identity.tenant, spec.application, payload["object_id"], identity.actor,
                                       payload["request_key"], identity=identity, release_digest=snapshot.digest,
                                       expected_object_version=payload["expected_version"],
                                       knowledge_citations=payload.get("knowledge_citations"))
            return {**result, "id": task["id"], "status": task["status"]}
        return {**result, **self._advisory(identity, spec, snapshot, payload)}

    def _advisory(self, identity, spec, snapshot, payload):
        if self.retrieval is None:
            raise ModelError("The reference application requires configured knowledge retrieval")
        query = payload.get("query")
        if (set(payload) - {"query", "document_ids", "release_digest"} or type(query) is not str
                or not 1 <= len(query.strip()) <= 512 or len(query.encode("utf-8")) > 2048 or "\x00" in query):
            raise ValueError("Enter a query between 1 and 512 characters")
        app, _, _ = snapshot.registry().definition(spec.application)
        explicit = payload.get("document_ids")
        if spec.kind == "artifact" and explicit is None:
            raise ValueError("Select at least one document for the artifact")
        if explicit is not None and (not isinstance(explicit, list) or not 1 <= len(explicit) <= 20
                   or any(type(doc) is not str or doc not in app["knowledge"] for doc in explicit)
                   or len(set(explicit)) != len(explicit)):
            raise PermissionError("Requested documents are outside the published application scope")

        documents = app["knowledge"] if explicit is None else explicit
        insufficient = {"status": "insufficient_evidence", "text": "", "citations": []}
        if not documents:
            return insufficient
        model, tools = self.runtime.release_adapters.get(snapshot.digest, (self.runtime.model, self.runtime.tools))
        snapshot.check_adapters(model, tools)
        stage = app["agents"][0]
        binding = snapshot.to_document()["models"]["stages"][0]
        if binding["adapter"]["kind"] not in ("demo", "litellm") or (
            binding["fallback"] is not None and binding["fallback"]["adapter"]["kind"] not in ("demo", "litellm")
        ):
            raise PermissionError("Advisory models require the managed gateway")
        used_route = binding["route"]

        def authorize(connection, *, route=None):
            self._release(connection, identity, spec, snapshot.digest)
            if explicit is not None:
                for doc in explicit:
                    self.policy.require(connection, identity, "read", "document", doc)
            if route is not None:
                self.policy.require(connection, identity, "use", "model", route)

        with database(self.runtime.path, tenant=identity.tenant) as connection:
            authorize(connection, route=used_route)
        retrieval = snapshot.retrieval_binding()
        if retrieval is None:
            search_options = {"method": spec.retrieval_method}
        else:
            search_options = {"method": retrieval["method"], "index_version": retrieval["index_id"],
                              "binding_digest": retrieval["binding_digest"]}
        found = self.retrieval.search(identity, query, document_ids=documents, limit=5, **search_options)
        if not found.hits:
            return insufficient
        refs = {hit.citation.id: hit.citation for hit in found.hits}
        with database(self.runtime.path, tenant=identity.tenant) as connection:
            authorize(connection)
            fragments = [citation_fragment(connection, identity, citation) for citation in refs.values()]
        context = {"agent": stage, "scenario": spec.id, "allowed_actions": [], "related": {}, "handoff": None,
                   "object": {"type": "retrieval-request", "state": "advisory", "version": 1,
                              "properties": {"request": query}}, "knowledge": fragments}

        if isinstance(model, ModelGateway):
            call_id = uuid4().hex

            def managed_call(route_id, route, projected):
                nonlocal used_route
                if projected["object"]["properties"].get("request") != query or not projected["knowledge"]:
                    raise PermissionError("The model route has not approved query and document data")

                def admit(connection):
                    authorize(connection, route=route_id)
                    for fragment in projected["knowledge"]:
                        citation_fragment(connection, identity, refs[fragment["id"]])

                call = ModelCall(self.runtime.path, identity.tenant, call_id,
                                 getattr(self.runtime.model, "limits", None), purpose="generation")
                result = call.invoke(route_id, route.version, route.adapter, route.policy.accounting,
                                     lambda remaining: route.adapter.propose(projected, timeout_seconds=remaining),
                                     max_output_tokens=route.adapter.manifest["max_output_tokens"], admit=admit)
                used_route = route_id
                return result

            proposal = model.propose(context, managed_call=managed_call)
        elif type(model) is DemoModel:
            proposal = model.propose(context)
        else:
            raise PermissionError("Advisory models require the managed gateway")

        if (proposal.action is not None or len(set(proposal.evidence_ids)) != len(proposal.evidence_ids)
                or any(ref not in refs for ref in proposal.evidence_ids)):
            raise ModelError("The advisory output exceeded the authorized evidence scope")
        if not proposal.evidence_ids:
            return insufficient
        with database(self.runtime.path, tenant=identity.tenant) as connection:
            authorize(connection, route=used_route)
            evidence = [citation_fragment(connection, identity, refs[ref]) for ref in proposal.evidence_ids]
        text = "\n\n".join(item["text"] for item in evidence)
        if spec.kind == "artifact":
            quote = "\n\n".join("\n".join("> " + line for line in item["text"].splitlines()) for item in evidence)
            text = f"# {spec.label}\n\n{quote}"
        return {"status": "completed", "text": text,
                "citations": [refs[ref].to_document() for ref in proposal.evidence_ids]}
