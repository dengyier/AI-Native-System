"""Operator commands for separately authorized issuance, recovery and attestation."""

import json
import time
from dataclasses import asdict
from pathlib import Path
from secrets import token_urlsafe

from .registry import unique_keys


def add_owp_arguments(commands):
    parser = commands.add_parser("owp", help="Manage OpenWorkProof authorization and evidence")
    operations = parser.add_subparsers(dest="owp_command", required=True)
    operations.add_parser("request", help="Read a signing request from an approved task").add_argument("task_id")
    sign = operations.add_parser("sign", help="Sign a prepared request without connecting to PostgreSQL")
    sign.add_argument("request", type=Path)
    sign.add_argument("--key-file", type=Path, required=True)
    sign.add_argument("--ttl", type=int, default=120)
    operations.add_parser("register", help="Register a signed authorization").add_argument("envelope", type=Path)
    revoke = operations.add_parser("revoke", help="Revoke an authorization")
    revoke.add_argument("operation_id")
    revoke.add_argument("--actor", required=True)
    revoke.add_argument("--reason", required=True)
    operations.add_parser("enforce", help="Require OWP releases in this tenant")
    pending = operations.add_parser("pending", help="List committed effects awaiting attestation")
    pending.add_argument("--limit", type=int, default=100)
    attest = operations.add_parser("attest", help="Attest an already committed effect")
    attest.add_argument("operation_id")
    attest.add_argument("--key-file", type=Path, required=True)
    attest.add_argument("--public-key", type=Path, required=True)
    verify = operations.add_parser("verify-evidence", help="Verify an evidence envelope offline")
    verify.add_argument("envelope", type=Path)
    verify.add_argument("--public-key", type=Path, required=True)


def load_document(path):
    return json.loads(path.read_text(), object_pairs_hook=unique_keys)


def offline(args):
    from .adapters.owp import key_id, load_private_key, load_public_key, sign_authorization

    if args.owp_command == "verify-evidence":
        from .evidence import verify_effect

        public = load_public_key(args.public_key.read_bytes())
        return verify_effect(load_document(args.envelope), {key_id(public): public})
    document = load_document(args.request)
    if not isinstance(document, dict) or document.keys() != {"profile", "epoch", "scope"}:
        raise ValueError("Expected a prepared authorization request")
    if not 1 <= args.ttl <= 900:
        raise ValueError("Use an authorization TTL between 1 and 900 seconds")
    now = int(time.time())
    payload = {**document, "nonce": token_urlsafe(32), "issued_at": now, "expires_at": now + args.ttl}
    return sign_authorization(payload, load_private_key(args.key_file.read_bytes()))


def run(args, store, ledgers, runtime=None):
    command, tenant = args.owp_command, args.tenant
    if command == "pending":
        from .evidence import pending_effects
        return pending_effects(store, tenant, limit=args.limit)
    if command == "attest":
        from .adapters.owp import key_id, load_private_key, load_public_key
        from .evidence import deliver_effect, sign_effect

        private = load_private_key(args.key_file.read_bytes())
        public = load_public_key(args.public_key.read_bytes())
        if key_id(private.public_key()) != key_id(public):
            raise ValueError("Attester private and public keys do not match")
        return deliver_effect(store, tenant, args.operation_id, lambda body: sign_effect(body, private),
                              {key_id(public): public})
    with store.transaction(tenant=tenant, write=command != "request") as connection:
        ledger = ledgers.get(tenant)
        if ledger is None:
            raise ValueError("Configure a trusted authority and a recovery epoch for the tenant")
        if command == "enforce":
            from .owp_gate import enforce
            enforce(connection, tenant)
            return {"tenant": tenant, "owp_required": True}
        if command == "revoke":
            return {"changed": ledger.revoke(connection, tenant, args.operation_id, actor=args.actor, reason=args.reason)}
        if command == "request":
            return runtime.authorization_request(connection, tenant, args.task_id)
        envelope = load_document(args.envelope)
        scope = envelope["payload"]["scope"]
        task_id = scope["task_id"]
        current = runtime.authorization_request(connection, tenant, task_id)
        return asdict(ledger.issue(connection, envelope, current["scope"]))
