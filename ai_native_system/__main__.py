import argparse
import json
import os
import signal
import sys
from contextlib import ExitStack
from dataclasses import asdict
from pathlib import Path

from .gateway import ModelGateway, configured_gateway
from .governance_control import add_governance_arguments, run_governance_control
from .release_control import add_release_arguments, run_release_control
from .data import DataService
from .api import make_server
from .model import DemoModel, ModelError, load_model
from .owp_control import add_owp_arguments
from .p4_control import add_p4_arguments
from .p5_control import add_p5_arguments, run_p5
from .p7_control import add_p7_arguments, run_p7
from .registry import Registry, unique_keys
from .runtime import Runtime
from .tools import ToolRegistry, configured_tools

CONFORMANCE = Path(__file__).resolve().parent.parent / "fixtures" / "conformance.json"


def _stop_serving(_signum, _frame):
    raise KeyboardInterrupt


def arguments():
    parser = argparse.ArgumentParser(description="Domain-neutral AI Native System")
    parser.add_argument("--registry", type=Path, default=CONFORMANCE)
    backend = parser.add_mutually_exclusive_group(required=True)
    backend.add_argument("--db", type=Path, help="SQLite file")
    backend.add_argument("--postgres", action="store_true", help="Use the explicitly configured PostgreSQL database")
    parser.add_argument("--tenant", default="local")
    parser.add_argument("--tools-config", type=Path, help="Remote tool adapter configuration")
    parser.add_argument("--models", type=Path, help="Named model route configuration")
    parser.add_argument("--agent-socket", type=Path, help="Delegate managed generation to the isolated Agent socket")
    parser.add_argument("--release-adapters", type=Path, help="Configuration files for archived release adapters")
    commands = parser.add_subparsers(dest="command", required=True)
    add_release_arguments(commands)
    add_governance_arguments(commands)
    add_owp_arguments(commands)
    add_p4_arguments(commands)
    add_p5_arguments(commands)
    add_p7_arguments(commands)
    p6 = commands.add_parser("p6", help="Manage LangGraph PostgreSQL checkpoints and worker claims")
    graph_commands = p6.add_subparsers(dest="p6_command", required=True)
    graph_commands.add_parser("migrate-checkpoints", help="Apply official LangGraph checkpoint schema migrations")
    graph_work = graph_commands.add_parser("work", help="Advance a bounded batch across configured tenants")
    graph_work.add_argument("--queue-tenant", action="append", required=True)
    graph_work.add_argument("--per-tenant", type=int, default=1)
    commands.add_parser("init", help="Insert the registry's seed in the selected database")
    commands.add_parser("migrate", help="Apply PostgreSQL schema revisions with the migration role")
    commands.add_parser("import-sqlite", help="Import a stopped SQLite snapshot into PostgreSQL").add_argument("snapshot", type=Path)
    commands.add_parser("demo", help="Run built-in conformance cases in a new test database")
    submit = commands.add_parser("submit", help="Start or recover a task by request key")
    submit.add_argument("application")
    submit.add_argument("object_id")
    submit.add_argument("--actor", required=True)
    submit.add_argument("--request-key", required=True)
    advance = commands.add_parser("advance", help="Run one agent stage or the approved action")
    advance.add_argument("task_id")
    advance.add_argument("--simulate-timeout", choices=("before-commit", "after-commit"))
    decide = commands.add_parser("decide", help="Approve or reject the exact stored proposal")
    decide.add_argument("task_id")
    decide.add_argument("verdict", choices=("approve", "reject"))
    decide.add_argument("--actor", required=True)
    commands.add_parser("inspect", help="Read task state, handoff, events and effect").add_argument("task_id")
    commands.add_parser("reconcile", help="Look up the existing remote operation receipt").add_argument("task_id")
    retry = commands.add_parser("retry-remote", help="Revalidate and retry the same idempotent remote request")
    retry.add_argument("task_id")
    retry.add_argument("--actor", required=True)
    commands.add_parser("models", help="List configured model routes")
    commands.add_parser("tools", help="List transactional tool versions")
    commands.add_parser("metrics", help="Read tenant task and model counters")
    worker = commands.add_parser("work", help="Advance a bounded batch of persisted tasks")
    worker.add_argument("--limit", type=int, default=20)
    cancel = commands.add_parser("cancel")
    cancel.add_argument("task_id")
    cancel.add_argument("--actor", required=True)
    knowledge = commands.add_parser("knowledge-put")
    knowledge.add_argument("document_id")
    knowledge.add_argument("--text-file", type=Path, required=True)
    knowledge.add_argument("--expected-version", type=int)
    knowledge.add_argument("--actor", required=True)
    search = commands.add_parser("knowledge-search")
    search.add_argument("query")
    search.add_argument("--actor", required=True)
    obj = commands.add_parser("object-put")
    obj.add_argument("file", type=Path)
    obj.add_argument("--expected-version", type=int)
    obj.add_argument("--actor", required=True)
    server = commands.add_parser("serve", help="Start authenticated loopback application API")
    server.add_argument("--port", type=int, default=8789)
    server.add_argument("--application-catalog", type=Path)
    from .p8_control import add_p8_arguments

    add_p8_arguments(commands)
    return parser.parse_args()


def conformance(runtime):
    with runtime.path.open("x"):
        pass
    runtime.initialize()
    traces = {}
    for app, object_id in (("single", "asset-1"), ("collaboration", "artifact-1")):
        task = runtime.submit("local", app, object_id, "requester", app)
        task_id = task["id"]
        stages = len(runtime.registry.applications[app]["agents"])
        for _ in range(stages):
            task = runtime.advance("local", task_id)
            if task["status"] != "planning":
                break
        if task["status"] != "awaiting_approval":
            raise ValueError(f"{app} stopped at {task['status']}; inspect task {task_id}")
        task = runtime.decide("local", task_id, "reviewer", "approve")
        if task["status"] != "ready":
            raise ValueError(f"{app} approval stopped at {task['status']}; inspect task {task_id}")
        task = runtime.advance("local", task_id)
        if task["status"] != "completed":
            raise ValueError(f"{app} write stopped at {task['status']}; inspect task {task_id}")
        traces[app] = runtime.inspect("local", task_id)
    return traces


def _archived_adapters(manifest, default_model, default_tools, *, agent=None):
    if manifest is None:
        return {}
    config = json.loads(manifest.read_text(), object_pairs_hook=unique_keys)
    if not isinstance(config, dict):
        raise ValueError("Expected archived adapter configurations by release digest")
    adapters = {}
    for release, pair in config.items():
        if (len(release) != 64 or any(char not in "0123456789abcdef" for char in release)
                or not isinstance(pair, dict) or not pair or pair.keys() - {"models", "tools"}):
            raise ValueError("Invalid archived release adapter configuration")
        model = default_model
        tools = default_tools
        if "models" in pair:
            model = configured_gateway(
                json.loads((manifest.parent / pair["models"]).read_text(), object_pairs_hook=unique_keys), agent=agent,
            )
        if "tools" in pair:
            tools = configured_tools(json.loads((manifest.parent / pair["tools"]).read_text(), object_pairs_hook=unique_keys))
        adapters[release] = (model, tools)
    return adapters


def main():
    args = arguments()
    command = args.command
    resources = ExitStack()
    try:
        if command == "p8":
            from .client import APIError
            from .p8_control import run_p8

            try:
                print(json.dumps(run_p8(args), ensure_ascii=False, indent=2))
            except APIError as exc:
                print(str(exc), file=sys.stderr)
                return 75 if exc.outcome_unknown or (exc.status is not None and exc.status >= 500) else 2
            return 0
        p7_command = args.p7_command if command == "p7" else None
        if p7_command and not args.postgres:
            raise ValueError("p7 requires --postgres")
        if p7_command == "build-hnsw":
            print(json.dumps(run_p7(args, None), ensure_ascii=False, indent=2))
            return 0
        p6_command = args.p6_command if command == "p6" else None
        if p6_command and not args.postgres:
            raise ValueError("p6 requires --postgres")
        if p6_command == "migrate-checkpoints":
            from .adapters.langgraph_postgres import setup_graph_postgres

            dsn = os.environ.get("AI_NATIVE_GRAPH_MIGRATION_DSN")
            if not dsn:
                raise ValueError("Set AI_NATIVE_GRAPH_MIGRATION_DSN for the checkpoint schema owner")
            print(json.dumps({"checkpoint_revision": setup_graph_postgres(dsn)}))
            return 0
        if command in ("migrate", "import-sqlite"):
            if not args.postgres:
                raise ValueError(f"{command} requires --postgres")
            dsn = os.environ.get("AI_NATIVE_POSTGRES_MIGRATION_DSN")
            if not dsn:
                raise ValueError("Set AI_NATIVE_POSTGRES_MIGRATION_DSN for the migration role")
            try:
                from .adapters.postgres import MigrationError, import_sqlite, migrate_postgres
            except ImportError as exc:
                raise ValueError("Install the postgres extra before using PostgreSQL") from exc
            try:
                result = ({"revision": migrate_postgres(dsn)} if command == "migrate"
                          else asdict(import_sqlite(dsn, args.snapshot)))
            except MigrationError as exc:
                raise ValueError(str(exc)) from exc
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
        p4_command = args.p4_command if command == "p4" else None
        p5_command = args.p5_command if command == "p5" else None
        if p4_command == "verify-source":
            from .p4_control import offline
            print(json.dumps(offline(args), ensure_ascii=False, indent=2))
            return 0
        owp_command = args.owp_command if command == "owp" else None
        if owp_command in ("sign", "verify-evidence"):
            from .owp_control import offline
            print(json.dumps(offline(args), ensure_ascii=False, indent=2))
            return 0
        control = command in ("release", "govern") or owp_command in ("enforce", "revoke")
        control = control or p4_command in ("sequence-create", "sequence-status", "link-compensation")
        if (control or owp_command or p4_command or p5_command) and not args.postgres:
            raise ValueError(f"{command} requires --postgres")
        if command == "demo" and (args.registry.resolve() != CONFORMANCE or args.tenant != "local"):
            raise ValueError("demo uses the built-in registry and local tenant")
        if args.postgres and command == "demo":
            raise ValueError("demo requires a fresh SQLite file; use init to seed PostgreSQL explicitly")
        if args.db is not None and command not in ("init", "demo") and not args.db.is_file():
            raise ValueError("Database does not exist; run init first")
        database_path = args.db
        if args.postgres:
            dsn_name = "AI_NATIVE_POSTGRES_CONTROL_DSN" if control else "AI_NATIVE_POSTGRES_DSN"
            if p4_command == "proof":
                dsn_name = "AI_NATIVE_P4_DELIVERY_DSN"
            elif p5_command == "flush-traces":
                dsn_name = "AI_NATIVE_P5_OBSERVATION_DSN"
            elif p5_command == "usage":
                dsn_name = "AI_NATIVE_P5_USAGE_DSN"
            elif p7_command in ("create-index", "activate-index", "ingest", "rebuild", "resume", "retire", "evaluate",
                               "reapply-tombstone", "propose-evidence", "review-evidence", "invalidate"):
                dsn_name = "AI_NATIVE_KNOWLEDGE_DSN"
            elif owp_command == "register":
                dsn_name = "AI_NATIVE_OWP_ISSUER_DSN"
            elif owp_command in ("pending", "attest"):
                dsn_name = "AI_NATIVE_OWP_EVIDENCE_DSN"
            dsn = os.environ.get(dsn_name)
            if not dsn:
                raise ValueError(f"Set {dsn_name} for this role")
            try:
                from .adapters.postgres import MigrationError
                from .adapters.postgres_runtime import PostgresRuntimeStore
            except ImportError as exc:
                raise ValueError("Install the postgres extra before using PostgreSQL") from exc
            try:
                database_path = resources.enter_context(PostgresRuntimeStore(dsn))
            except MigrationError as exc:
                raise ValueError(str(exc)) from exc
        if command == "govern":
            with database_path.transaction(tenant=args.tenant, write=True) as connection:
                result = run_governance_control(connection, args)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
        if p5_command:
            print(json.dumps(run_p5(args, database_path), ensure_ascii=False, indent=2))
            return 0
        if p7_command:
            print(json.dumps(run_p7(args, database_path), ensure_ascii=False, indent=2))
            return 0
        if p4_command in ("proof", "sequence-create", "sequence-status", "link-compensation"):
            from .p4_control import execute_control
            print(json.dumps(execute_control(args, database_path), ensure_ascii=False, indent=2))
            return 0
        ledgers = {}
        if args.postgres and owp_command not in ("pending", "attest"):
            trust = os.environ.get("AI_NATIVE_OWP_TRUST")
            if trust:
                from .owp_control import load_document
                from .owp_gate import configured_ledgers
                ledgers = configured_ledgers(load_document(Path(trust)))
        if owp_command in ("enforce", "revoke", "pending", "attest"):
            from .owp_control import run
            print(json.dumps(run(args, database_path, ledgers), ensure_ascii=False, indent=2))
            return 0
        registry = Registry.load(args.registry)
        agent = None
        if args.agent_socket is not None:
            if not args.postgres or args.models is None:
                raise ValueError("Isolated generation requires --postgres and an explicit --models file")
            from .agent_process import AgentProcessClient

            agent = AgentProcessClient(args.agent_socket)
        if args.models:
            model = configured_gateway(json.loads(args.models.read_text(), object_pairs_hook=unique_keys), agent=agent)
        else:
            model = ModelGateway(default="default", max_context_bytes=65536)
            live_model = command in ("advance", "demo", "work", "serve", "models", "p4", "p6") or owp_command in (
                "request", "register"
            ) or (
                command == "release" and args.release_command == "draft"
            )
            model.register("default", load_model() if live_model else DemoModel())
        tools = configured_tools(json.loads(args.tools_config.read_text())) if args.tools_config else ToolRegistry()
        if command == "release":
            with database_path.transaction(tenant=args.tenant, write=args.release_command not in ("show", "impact")) as connection:
                result = run_release_control(connection, args, registry, model, tools, store=database_path)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            return 0
        release_adapters = _archived_adapters(args.release_adapters, model, tools, agent=agent)
        runtime_path = database_path
        if owp_command == "register":
            runtime_dsn = os.environ.get("AI_NATIVE_POSTGRES_DSN")
            if not runtime_dsn:
                raise ValueError("Set AI_NATIVE_POSTGRES_DSN for runtime configuration verification")
            runtime_path = resources.enter_context(PostgresRuntimeStore(runtime_dsn))
        if args.postgres:
            try:
                graph_store = None
                graph_dsn = os.environ.get("AI_NATIVE_GRAPH_DSN")
                if graph_dsn and command in ("submit", "advance", "retry-remote", "work", "serve", "p6"):
                    from .adapters.langgraph_postgres import PostgresGraphStore

                    graph_store = resources.enter_context(PostgresGraphStore(
                        graph_dsn, max_connections=int(os.environ.get("AI_NATIVE_GRAPH_MAX_CONNECTIONS", "4")),
                    ))
                runtime = Runtime(runtime_path, registry, model, tools, release_adapters=release_adapters,
                                  owp_ledgers=ledgers, graph_store=graph_store,
                                  graph_queue_limit=int(os.environ.get("AI_NATIVE_GRAPH_QUEUE_LIMIT", "100")))
            except MigrationError as exc:
                raise ValueError(str(exc)) from exc
        else:
            runtime = Runtime(runtime_path, registry, model, tools, release_adapters=release_adapters)
        if owp_command in ("request", "register"):
            from .owp_control import run
            print(json.dumps(run(args, database_path, ledgers, runtime), ensure_ascii=False, indent=2))
            return 0
        if p4_command in ("drain", "query-one"):
            from .p4_control import drain
            dsn = os.environ.get("AI_NATIVE_P4_DELIVERY_DSN")
            if not dsn:
                raise ValueError("Configure AI_NATIVE_P4_DELIVERY_DSN for scheduled jobs")
            delivery_store = resources.enter_context(PostgresRuntimeStore(dsn))
            print(json.dumps(drain(args, runtime, delivery_store, resources), ensure_ascii=False, indent=2))
            return 0
        tenant = args.tenant
        if command == "init":
            runtime.initialize()
            result = {"database": "postgresql" if args.postgres else str(args.db.resolve())}
        elif command == "demo":
            result = conformance(runtime)
        elif command == "submit":
            result = runtime.submit(tenant, args.application, args.object_id, args.actor, args.request_key)
        elif command == "advance":
            result = runtime.advance(tenant, args.task_id, args.simulate_timeout)
        elif command == "decide":
            result = runtime.decide(tenant, args.task_id, args.actor, args.verdict)
        elif command == "inspect":
            result = runtime.inspect(tenant, args.task_id)
        elif command == "reconcile":
            result = runtime.reconcile(tenant, args.task_id)
        elif command == "retry-remote":
            result = runtime.retry_remote(tenant, args.task_id, args.actor)
        elif command == "cancel":
            result = runtime.cancel(tenant, args.task_id, args.actor)
        elif command == "work":
            result = runtime.work(tenant, args.limit)
        elif p6_command == "work":
            result = runtime.work_graph(tuple(args.queue_tenant), args.per_tenant)
        elif command == "metrics":
            result = runtime.metrics(tenant)
        elif command == "models":
            result = model.list_models()
        elif command == "tools":
            result = runtime.tools.list_tools()
        elif command == "knowledge-put":
            result = DataService(database_path, registry).put_knowledge(
                tenant, args.actor, args.document_id, args.text_file.read_text(), args.expected_version)
        elif command == "knowledge-search":
            result = DataService(database_path, registry).search_knowledge(tenant, args.actor, args.query)
        elif command == "object-put":
            result = DataService(database_path, registry).put_object(
                tenant, args.actor, json.loads(args.file.read_text()), args.expected_version)
        else:
            credentials = json.loads(os.environ.get("AI_NATIVE_API_TOKENS", "{}"))
            enterprise = os.environ.get("AI_NATIVE_ENTERPRISE_IDENTITY")
            if enterprise:
                from .identity import EnterpriseIdentity
                enterprise = EnterpriseIdentity.from_config(json.loads(enterprise, object_pairs_hook=unique_keys))
            catalog, control_store, delivery_store, attestation_keys = None, None, None, {}
            if args.application_catalog:
                if not enterprise:
                    raise ValueError("The P8 application catalog requires enterprise authentication")
                from .applications import ApplicationCatalog
                from .knowledge import KnowledgeRetrieval
                from .p7_control import model_embedding

                retrieval = KnowledgeRetrieval(runtime.path, model_embedding(runtime.path, args.models)) if args.models else None
                catalog = ApplicationCatalog.load(runtime, retrieval, args.application_catalog)
            if enterprise:
                from .p8_control import load_attestation_keys

                control_dsn = os.environ.get("AI_NATIVE_POSTGRES_CONTROL_DSN")
                if control_dsn:
                    control_store = resources.enter_context(PostgresRuntimeStore(control_dsn))
                delivery_dsn = os.environ.get("AI_NATIVE_P4_DELIVERY_DSN")
                if delivery_dsn:
                    delivery_store = resources.enter_context(PostgresRuntimeStore(delivery_dsn))
                attestation_keys = load_attestation_keys(os.environ.get("AI_NATIVE_P8_ATTESTATION_KEYS"))
            server = make_server(runtime, credentials, args.port, enterprise_identity=enterprise or None, catalog=catalog,
                                 console=bool(enterprise), control_store=control_store, delivery_store=delivery_store,
                                 attestation_keys=attestation_keys)
            previous = signal.signal(signal.SIGTERM, _stop_serving)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                signal.signal(signal.SIGTERM, previous)
                if not server.drain():
                    print("Request drain reached its deadline; inspect persisted tasks before retrying", file=sys.stderr)
                server.server_close()
            return 0
    except (TimeoutError, ModelError) as exc:
        print(str(exc), file=sys.stderr)
        return 75
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    finally:
        resources.close()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
