"""Command-line client of the same enterprise API used by the console."""

from pathlib import Path
import json
import os

from .registry import unique_keys


def add_p8_arguments(commands):
    entry = commands.add_parser("p8", help="Use the enterprise application API through the Python SDK")
    entry.add_argument("--url", default="http://127.0.0.1:8789")
    entry.add_argument("--token-env", default="AI_NATIVE_CLIENT_TOKEN")
    operations = entry.add_subparsers(dest="p8_command", required=True)
    operations.add_parser("apps")
    execute = operations.add_parser("run")
    execute.add_argument("application")
    execute.add_argument("input", type=Path)
    for name in ("task", "evidence", "advance", "cancel", "reconcile", "events"):
        parser = operations.add_parser(name)
        parser.add_argument("task_id")
        if name == "events":
            parser.add_argument("--limit", type=int, default=50)
            parser.add_argument("--cursor")
    decision = operations.add_parser("decide")
    decision.add_argument("task_id")
    decision.add_argument("verdict", choices=("approve", "reject"))
    decision.add_argument("proposal_digest")


def run_p8(args):
    from .client import Client

    client = Client(args.url, os.environ[args.token_env])
    name = args.p8_command
    if name == "apps":
        return client.applications()
    if name == "run":
        from .p7_control import from_file

        body = json.loads(from_file(args.input, maximum=65_536), object_pairs_hook=unique_keys)
        return client.run_application(args.application, body)
    if name == "events":
        return client.events(args.task_id, limit=args.limit, cursor=args.cursor)
    if name == "decide":
        return client.decide(args.task_id, args.verdict, args.proposal_digest)
    if name == "evidence":
        return client.export_evidence(args.task_id)
    return getattr(client, name)(args.task_id)


def load_attestation_keys(configuration):
    if configuration is None:
        return {}
    from .adapters.owp import key_id, load_public_key

    groups = json.loads(configuration, object_pairs_hook=unique_keys)
    if not isinstance(groups, dict) or any(not isinstance(items, list) or not items for items in groups.values()):
        raise ValueError("Configure verification keys by tenant")
    keys = {}
    for tenant, paths in groups.items():
        group = (load_public_key(Path(path).read_bytes()) for path in paths)
        keys[tenant] = {key_id(key): key for key in group}
    return keys
