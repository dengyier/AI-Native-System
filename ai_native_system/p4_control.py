"""Operator controls for durable query and evidence workflows."""

import os
from functools import partial
from pathlib import Path

from .owp_control import load_document


def add_p4_arguments(commands):
    parser = commands.add_parser("p4", help="Operate durable reconciliation, evidence and action sequences")
    operations = parser.add_subparsers(dest="p4_command", required=True)
    batch = operations.add_parser("drain", help="Run a bounded batch of lookup or evidence jobs")
    batch.add_argument("kind", choices=("reconcile", "evidence"))
    batch.add_argument("--limit", type=int, default=10)
    batch.add_argument("--proof-dir", type=Path)
    batch.add_argument("--attest-key", type=Path)
    batch.add_argument("--attest-public-key", type=Path)
    one = operations.add_parser("query-one", help="Look up an exhausted operation under an operator lease")
    one.add_argument("operation_id")
    proof = operations.add_parser("proof", help="Read or restore a referenced proof file")
    proof.add_argument("operation_id")
    proof.add_argument("kind", choices=("source_receipt", "runtime_attestation"))
    proof.add_argument("--proof-dir", type=Path, required=True)
    proof.add_argument("--view", choices=("raw", "redacted"), default="redacted")
    proof.add_argument("--repair", action="store_true")
    verify = operations.add_parser("verify-source", help="Verify a source receipt offline")
    verify.add_argument("envelope", type=Path)
    verify.add_argument("--public-key", type=Path, required=True)
    verify.add_argument("--request", type=Path)
    verify.add_argument("--authorization-digest")
    operations.add_parser("sequence-create").add_argument("task_ids", nargs="+")
    operations.add_parser("sequence-status").add_argument("sequence_id")
    link = operations.add_parser("link-compensation")
    link.add_argument("original_task_id")
    link.add_argument("compensation_task_id")


def offline(args):
    from .adapters.owp import key_id, load_public_key
    from .source_receipt import verify_source_receipt

    public = load_public_key(args.public_key.read_bytes())
    return verify_source_receipt(load_document(args.envelope), {key_id(public): public},
                                 operation=load_document(args.request) if args.request else None,
                                 authorization_digest=args.authorization_digest)


def execute_control(args, store):
    if args.p4_command == "proof":
        from .delivery import ProofStore, read_proof, repair_proof

        archive = ProofStore(args.proof_dir)
        if args.repair:
            return {"digest": repair_proof(store, archive, args.tenant, args.operation_id, args.kind, view=args.view)}
        return read_proof(store, archive, args.tenant, args.operation_id, args.kind, view=args.view)
    from .action_sequence import create_sequence, link_compensation, sequence_status

    tenant = args.tenant
    with store.transaction(tenant=tenant, write=args.p4_command != "sequence-status") as connection:
        if args.p4_command == "sequence-create":
            return {"id": create_sequence(connection, tenant, args.task_ids)}
        if args.p4_command == "sequence-status":
            return sequence_status(connection, tenant, args.sequence_id)
        return link_compensation(connection, tenant, args.original_task_id, args.compensation_task_id)


def drain(args, runtime, store, resource_stack):
    from .delivery import ProofStore, run_delivery_batch
    from .p4_execution import evidence_job, reconcile_job

    if args.p4_command == "query-one":
        from .delivery import claim_delivery, finish_delivery

        lease = claim_delivery(store, args.tenant, "reconcile", manual_operation_id=args.operation_id)
        if lease is None:
            raise ValueError("Operation is unavailable for manual lookup")
        try:
            outcome = reconcile_job(runtime, lease)
        except (OSError, ValueError, LookupError):
            outcome = "manual"
        return {"operation_id": lease.operation_id,
                "status": finish_delivery(store, lease, "done" if outcome == "done" else "manual")}
    if args.kind == "reconcile":
        handler = partial(reconcile_job, runtime)
    else:
        if args.proof_dir is None:
            raise ValueError("Evidence publication requires --proof-dir")
        archive = ProofStore(args.proof_dir)
        signer = None
        keys = {}
        attester = None
        if args.attest_key or args.attest_public_key:
            from .adapters.owp import key_id, load_private_key, load_public_key
            from .adapters.postgres_runtime import PostgresRuntimeStore
            from .evidence import sign_effect

            dsn = os.environ.get("AI_NATIVE_OWP_EVIDENCE_DSN")
            if not args.attest_key or not args.attest_public_key or not dsn:
                raise ValueError("Configure an independent attester key pair and AI_NATIVE_OWP_EVIDENCE_DSN")
            private = load_private_key(args.attest_key.read_bytes())
            public = load_public_key(args.attest_public_key.read_bytes())
            if key_id(private.public_key()) != key_id(public):
                raise ValueError("Attester keys do not match")
            keys[key_id(public)] = public
            signer = partial(sign_effect, private_key=private)
            attester = resource_stack.enter_context(PostgresRuntimeStore(dsn))
        handler = partial(evidence_job, runtime, store, archive, signer=signer, keys=keys, attester_store=attester)
    return run_delivery_batch(store, args.tenant, args.kind, handler, limit=args.limit)
