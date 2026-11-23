"""Capture one explicitly delegated version. Run from the repository root."""

import argparse
import sys

from ai_native_system.fdesage_readonly import SnapshotClient
from deployment.pilots.fdesage_readonly.settings import load_settings, secret, write_capture


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--output", required=True)
    options = parser.parse_args()
    try:
        settings, scope = load_settings(options.config)
        client = SnapshotClient(settings["sourceOrigin"], secret(settings, "sourceTokenEnv"), scope)
        write_capture(options.output, client.capture())
    except Exception:
        print("Readonly capture failed; no usable capture was produced.", file=sys.stderr)
        return 1
    print("Captured selected historical metadata; no source business write was requested.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
