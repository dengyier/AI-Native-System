"""Tenant setup commands for the separately privileged operator."""
import json
from datetime import datetime
from pathlib import Path

from .governance import activate
from .identity import IdentityContext, create_delegation, revoke_delegation
from .policy import Policy
from .registry import unique_keys


def add_governance_arguments(commands):
    parser = commands.add_parser("govern", help="Activate tenant governance and manage exact grants")
    subcommands = parser.add_subparsers(dest="govern_command", required=True)
    subcommands.add_parser("activate")
    for command in ("grant", "revoke"):
        resource = subcommands.add_parser(command)
        resource.add_argument("principal")
        resource.add_argument("operation")
        resource.add_argument("kind")
        resource.add_argument("resource_id")
        resource.add_argument("--member")
    issue = subcommands.add_parser("delegate")
    issue.add_argument("file", type=Path)
    revoke = subcommands.add_parser("revoke-delegation")
    revoke.add_argument("delegation_id")
    rule = subcommands.add_parser("bind-rule", help="Add a fact prerequisite to a draft release")
    rule.add_argument("release_digest")
    rule.add_argument("rule_name")
    rule.add_argument("--actor", required=True)
    rule.add_argument("--feedback-source")
    rule.add_argument("--feedback-stream")


def run_governance_control(connection, args):
    action = args.govern_command
    if action == "activate":
        activate(connection, args.tenant)
        return {"tenant": args.tenant, "governed": True}
    if action == "grant" or action == "revoke":
        policy = Policy()
        change = policy.grant if action == "grant" else policy.revoke
        changed = change(connection, args.tenant, args.principal, args.operation, args.kind, args.resource_id, args.member)
        return {"changed": changed}
    if action == "revoke-delegation":
        return {"changed": revoke_delegation(connection, args.tenant, args.delegation_id)}
    if action == "bind-rule":
        from .fact_gate import bind_rule

        return bind_rule(connection, args.tenant, args.release_digest, args.rule_name, actor=args.actor,
                         feedback_source=args.feedback_source, feedback_stream=args.feedback_stream)
    delegation = json.loads(args.file.read_text(), object_pairs_hook=unique_keys)
    required = {"actor", "service", "delegation_id", "scopes", "starts_at", "expires_at"}
    if not isinstance(delegation, dict) or delegation.keys() != required:
        raise ValueError("Expected actor, service, delegation ID, scopes and validity period")
    identity = IdentityContext(args.tenant, delegation["actor"], delegation["service"], delegation["delegation_id"])
    create_delegation(
        connection, identity, delegation["scopes"], starts_at=datetime.fromisoformat(delegation["starts_at"]),
        expires_at=datetime.fromisoformat(delegation["expires_at"]),
    )
    return {"delegation_id": identity.delegation_id}
