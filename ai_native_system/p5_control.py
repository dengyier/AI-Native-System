"""CLI entry points for P5 embedding, usage and the independent trace worker."""

import json
import os
from dataclasses import asdict
from pathlib import Path

from . import governance
from .gateway import configured_gateway
from .identity import IdentityContext
from .model_accounting import ModelAccounting
from .model_service import EmbeddingService
from .observability import LangfuseExporter, drain_model_traces, model_trace_id
from .registry import unique_keys
from .runtime import permitted


def add_p5_arguments(commands):
    p5 = commands.add_parser("p5", help="Embedding, model usage and the Langfuse trace worker")
    operations = p5.add_subparsers(dest="p5_command", required=True)
    usage = operations.add_parser("usage", help="Read the tenant model ledger")
    usage.add_argument("--call-id")
    usage.add_argument("--limit", type=int, default=100)
    drain = operations.add_parser("flush-traces", help="Deliver a bounded batch of sanitized trace events")
    drain.add_argument("--limit", type=int, default=20)
    embed = operations.add_parser("embed", help="Embed a UTF-8 text file with an explicitly allowed route")
    embed.add_argument("route")
    embed.add_argument("file", type=Path)
    embed.add_argument("--scope", choices=("public", "tenant"), required=True)
    embed.add_argument("--purpose", choices=("document", "query"), required=True)
    embed.add_argument("--actor", required=True)


def run_p5(args, store):
    if args.p5_command == "usage":
        report = ModelAccounting(store).usage(args.tenant, args.call_id, limit=args.limit)
        for attempt in report["attempts"]:
            attempt["trace_id"] = model_trace_id(args.tenant, attempt["call_id"])
        return report
    if args.p5_command == "flush-traces":
        exporter = LangfuseExporter(host=os.environ["LANGFUSE_HOST"], public_key=os.environ["LANGFUSE_PUBLIC_KEY"],
                                    secret_key=os.environ["LANGFUSE_SECRET_KEY"])
        return drain_model_traces(store, args.tenant, exporter, limit=args.limit)
    if args.models is None:
        raise ValueError("p5 embed requires --models")
    configuration = json.loads(args.models.read_text(), object_pairs_hook=unique_keys)
    service = EmbeddingService(store, configuration, configured_gateway(configuration).limits)
    with store.transaction(tenant=args.tenant) as connection:
        enterprise = governance.enabled(connection, args.tenant)
        if not enterprise and not permitted(connection, args.tenant, args.actor, "embed"):
            raise PermissionError("Embedding route access denied")
    with args.file.open("rb") as input_file:
        payload = input_file.read(service.max_input_bytes + 1)
    if len(payload) > service.max_input_bytes:
        raise ValueError("Embedding input exceeds the byte limit")
    identity = IdentityContext(args.tenant, args.actor) if enterprise else None
    return asdict(service.embed(args.tenant, args.route, (payload.decode("utf-8"),),
                                scope=args.scope, purpose=args.purpose, identity=identity, actor=args.actor))
