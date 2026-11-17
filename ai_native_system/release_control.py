"""Local release control commands for the dedicated PostgreSQL control role."""

from pathlib import Path

from .identity import IdentityContext, _name
from .ontology import OntologyRelease
from .policy import Policy
from .releases import AUTHORIZED_FRAGMENTS, RETRIEVAL_METHODS, ReleaseError, ReleaseSnapshot, ReleaseStore
from .tools import ToolRegistry


def add_release_arguments(commands):
    release = commands.add_parser("release", help="Manage immutable releases using the PostgreSQL control role")
    lifecycle = release.add_subparsers(dest="release_command", required=True)
    draft = lifecycle.add_parser("draft", help="Validate and save an immutable draft from the current declarations")
    draft.add_argument("application")
    draft.add_argument("--actor", required=True)
    draft.add_argument("--ontology", type=Path)
    draft.add_argument("--mapping-version")
    draft.add_argument("--owp-profile")
    draft.add_argument("--policy-version")
    draft.add_argument("--knowledge-strategy", choices=("current-by-id-v1", AUTHORIZED_FRAGMENTS))
    draft.add_argument("--knowledge-index", help="Pin a published knowledge index to this application release")
    draft.add_argument("--retrieval-method", choices=RETRIEVAL_METHODS)

    for command, description in (
        ("show", "Read the retained release and its lifecycle state"),
        ("impact", "Compare a release to the selected version before publishing"),
        ("publish", "Publish a validated draft"),
        ("deprecate", "Restrict a release to tasks already pinned to it"),
        ("revoke", "Stop future execution of a release while retaining its history"),
        ("select", "Select a published version for new tasks, including rollback"),
    ):
        operation = lifecycle.add_parser(command, help=description)
        if command == "select":
            operation.add_argument("application")
        operation.add_argument("digest")
        if command not in ("show", "impact"):
            operation.add_argument("--actor", required=True)
        if command == "publish":
            operation.add_argument("--migration-ref")
    return release


def _result(record):
    return {
        "digest": record.snapshot.digest, "application": record.snapshot.application,
        "status": record.status, "created_by": record.created_by, "changed_by": record.changed_by,
        "migration_ref": record.migration_ref,
    }


def draft_retrieval_binding(connection, identity, index_id, method):
    from .release_retrieval import prepare_binding

    if not _name(index_id) or method not in RETRIEVAL_METHODS:
        raise ReleaseError("A retrieval binding requires a knowledge index and a supported search method")
    Policy().require(connection, identity, "read", "knowledge-index", index_id)
    return prepare_binding(connection, identity.tenant, index_id, method)


def run_release_control(connection, args, registry, model, tools=None, *, store=None):
    """Run against a tenant-scoped control transaction provided by the CLI."""
    command, tenant = args.release_command, args.tenant
    if command == "draft":
        index_id, method = getattr(args, "knowledge_index", None), getattr(args, "retrieval_method", None)
        retrieval = None
        if index_id is not None or method is not None:
            retrieval = draft_retrieval_binding(connection, IdentityContext(tenant, args.actor), index_id, method)
        snapshot = ReleaseSnapshot.capture(
            registry, args.application, model, ToolRegistry() if tools is None else tools,
            ontology=OntologyRelease.load(args.ontology) if args.ontology is not None else None,
            mapping_version=args.mapping_version, owp_profile=args.owp_profile, policy_version=args.policy_version,
            knowledge_strategy=getattr(args, "knowledge_strategy", None), retrieval=retrieval,
        )
        return _result(ReleaseStore.draft(connection, tenant, snapshot, publisher=args.actor))
    if command == "show":
        record = ReleaseStore.get(connection, tenant, args.digest)
        if record is None:
            raise ReleaseError("Release is unavailable")
        return {**_result(record), "snapshot": record.snapshot.to_document()}
    if command == "impact":
        return ReleaseStore.impact(connection, tenant, args.digest)
    validation = {}
    if command in ("publish", "select"):
        record = ReleaseStore.get(connection, tenant, args.digest)
        if record is not None and record.snapshot.retrieval_binding() is not None:
            from .p7_control import model_embedding

            models = getattr(args, "models", None)
            embedding = model_embedding(store, models) if store is not None and models is not None else None
            validation = {"embedding": embedding, "identity": IdentityContext(tenant, args.actor)}
    if command == "publish":
        impact = ReleaseStore.impact(connection, tenant, args.digest)
        record = ReleaseStore.publish(connection, tenant, args.digest, publisher=args.actor,
                                      migration_ref=args.migration_ref, **validation)
        return {**_result(record), "impact": impact}
    if command == "select":
        return _result(ReleaseStore.select(connection, tenant, args.application, args.digest, publisher=args.actor,
                                           **validation))
    transition = {"deprecate": ReleaseStore.deprecate, "revoke": ReleaseStore.revoke}[command]
    return _result(transition(connection, tenant, args.digest, publisher=args.actor))
