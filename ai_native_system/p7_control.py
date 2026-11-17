"""Trusted operator entry points for the PostgreSQL knowledge pipeline."""

import json
import os
from pathlib import Path

from .identity import IdentityContext
from .registry import unique_keys


def add_p7_arguments(commands):
    p7 = commands.add_parser("p7", help="Manage indexed knowledge, retrieval, scoped memory and evaluation")
    operations = p7.add_subparsers(dest="p7_command", required=True)

    def command(name, *fields):
        parser = operations.add_parser(name)
        parser.add_argument("--actor", required=True)
        for field in fields:
            parser.add_argument(field)
        return parser

    command("create-index", "index_id", "route")
    command("activate-index", "index_id")
    build = operations.add_parser("build-hnsw")
    build.add_argument("index_id")
    ingest = command("ingest", "index_id", "document_id", "source_id")
    ingest.add_argument("file", type=Path)
    ingest.add_argument("--format", choices=("text", "markdown"), default="text")
    ingest.add_argument("--expected-version", type=int)
    command("rebuild", "index_id", "document_id")
    resume = command("resume", "index_id", "document_id")
    resume.add_argument("version", type=int)
    resume.add_argument("--max-batches", type=int, default=16)
    retire = command("retire", "document_id")
    retire.add_argument("--expected-version", required=True, type=int)
    retire.add_argument("--delete", action="store_true")
    command("reapply-tombstone").add_argument("file", type=Path)
    search = command("search", "query")
    search.add_argument("--index-version")
    search.add_argument("--method", choices=("exact", "hnsw", "hybrid"), default="exact")
    search.add_argument("--limit", type=int, default=10)
    compare = command("compare", "query")
    compare.add_argument("--index-version")
    compare.add_argument("--limit", type=int, default=10)
    remember = command("remember", "scope", "scope_id")
    remember.add_argument("citation", type=Path)
    remember.add_argument("--ttl-seconds", type=int, required=True)
    remember.add_argument("--candidate-id")
    command("recall", "scope", "scope_id")
    command("forget", "scope", "scope_id", "memory_id")
    evidence = command("propose-evidence", "release_digest", "kind", "object_id", "name")
    evidence.add_argument("citation", type=Path)
    evidence.add_argument("value", type=Path)
    command("review-evidence", "candidate_id", "verdict")
    invalidate = operations.add_parser("invalidate")
    invalidate.add_argument("--limit", type=int, default=50)
    evaluate = command("evaluate", "release_digest")
    evaluate.add_argument("file", type=Path)


def from_file(path, maximum=2_000_000):
    with path.open("rb") as stream:
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("P7 input exceeds the file byte limit")
    return raw.decode("utf-8")


def model_embedding(store, models):
    from .gateway import configured_gateway
    from .model_service import EmbeddingService

    if models is None:
        raise ValueError("Pass --models for the P5 embedding routes")
    config = json.loads(from_file(models), object_pairs_hook=unique_keys)
    return EmbeddingService(store, config, configured_gateway(config).limits)


def run_p7(args, store):
    name = args.p7_command
    if name == "build-hnsw":
        from .knowledge import build_hnsw

        return build_hnsw(os.environ["AI_NATIVE_KNOWLEDGE_INDEX_DSN"], args.tenant, args.index_id)
    if name == "invalidate":
        from .knowledge_evidence import process_invalidations

        return process_invalidations(store, args.tenant, limit=args.limit)
    identity = IdentityContext(args.tenant, args.actor)
    if name == "evaluate":
        from .evaluation import record_evaluation

        data = json.loads(from_file(args.file), object_pairs_hook=unique_keys)
        return record_evaluation(store, identity, args.release_digest,
                                 data["dataset"], data["observations"], manual=data.get("manual"))
    if name in ("propose-evidence", "review-evidence"):
        from .knowledge_evidence import EvidenceStore

        evidence = EvidenceStore(store)
        if name == "review-evidence":
            return evidence.review(identity, args.candidate_id, args.verdict)
        return evidence.propose(identity, json.loads(from_file(args.citation), object_pairs_hook=unique_keys),
                                release_digest=args.release_digest, kind=args.kind, object_id=args.object_id,
                                name=args.name, value=json.loads(from_file(args.value), object_pairs_hook=unique_keys))
    if name in ("remember", "recall", "forget"):
        from .knowledge import Citation
        from .memory import MemoryStore

        memory = MemoryStore(store)
        if name == "recall":
            return memory.recall(identity, args.scope, args.scope_id)
        if name == "forget":
            return memory.forget(identity, args.scope, args.scope_id, args.memory_id)
        citation = Citation.from_document(json.loads(from_file(args.citation), object_pairs_hook=unique_keys))
        return memory.remember(identity, args.scope, args.scope_id, citation, ttl_seconds=args.ttl_seconds,
                               candidate_id=args.candidate_id)
    embedding = model_embedding(store, args.models) if name in (
        "create-index", "activate-index", "ingest", "rebuild", "resume", "search", "compare",
    ) else None
    if name in ("search", "compare"):
        from .knowledge import KnowledgeRetrieval

        retrieval = KnowledgeRetrieval(store, embedding)
        if name == "compare":
            return retrieval.compare(identity, args.query, limit=args.limit, index_version=args.index_version)
        return retrieval.search(identity, args.query, limit=args.limit,
                                method=args.method, index_version=args.index_version).to_document()
    from .knowledge_ingest import KnowledgeIngestion

    ingestion = KnowledgeIngestion(store, embedding)
    if name == "create-index":
        return ingestion.create_space(identity, args.index_id, args.route)
    if name == "activate-index":
        return ingestion.activate_space(identity, args.index_id)
    if name == "ingest":
        return ingestion.ingest(identity, args.index_id, args.document_id, args.source_id, from_file(args.file),
                                format=args.format, expected_version=args.expected_version)
    if name == "rebuild":
        return ingestion.rebuild(identity, args.index_id, args.document_id)
    if name == "resume":
        return ingestion.resume(identity, args.index_id, args.document_id, args.version, max_batches=args.max_batches)
    if name == "reapply-tombstone":
        return ingestion.reapply_tombstone(identity, json.loads(from_file(args.file), object_pairs_hook=unique_keys))
    return ingestion.retire_document(identity, args.document_id, expected_version=args.expected_version,
                                     delete=args.delete)
