"""Append captured metadata with an INSERT-only role; never provision grants or execute work."""

import argparse
import json
import sys

from ai_native_system.adapters.postgres_runtime import PostgresRuntimeStore
from ai_native_system.fdesage_readonly import import_observation
from deployment.pilots.fdesage_readonly.settings import load_settings, read_json, secret


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--snapshot", required=True)
    options = parser.parse_args()
    try:
        settings, scope = load_settings(options.config)
        snapshot = read_json(options.snapshot)
        tenant = settings["ainsTenant"]
        with PostgresRuntimeStore(secret(settings, "importDsnEnv"), max_connections=1) as store:
            with store.transaction(tenant=tenant, write=True) as connection:
                object_id = import_observation(connection, tenant, snapshot, scope)
    except Exception:
        print("Readonly observation import failed; verify isolated configuration and privileges.", file=sys.stderr)
        return 1
    print(json.dumps({"tenant": tenant, "objectId": object_id, "semantics": "historical_capture"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
