"""Explicit local pilot configuration; credentials remain in separate environment values."""

import json
import os
import re
from pathlib import Path

from ai_native_system.fdesage_readonly import MAX_SNAPSHOT_BYTES, SnapshotScope
from ai_native_system.registry import unique_keys


def read_json(path):
    with Path(path).open("rb") as stream:
        payload = stream.read(MAX_SNAPSHOT_BYTES + 1)
    if len(payload) > MAX_SNAPSHOT_BYTES:
        raise ValueError("Pilot input exceeds the metadata limit")
    return json.loads(payload.decode("utf-8"), object_pairs_hook=unique_keys,
                      parse_constant=reject_constant)


def reject_constant(_):
    raise ValueError("Non-finite pilot input")


def load_settings(path):
    document = read_json(path)
    if type(document) is not dict or document.keys() != {
        "sourceOrigin", "scope", "ainsTenant", "sourceTokenEnv", "importDsnEnv",
    }:
        raise ValueError("Invalid readonly pilot configuration")
    for name in ("sourceTokenEnv", "importDsnEnv"):
        if type(document[name]) is not str or re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", document[name]) is None:
            raise ValueError("Use an explicit credential environment variable name")
    if document["sourceTokenEnv"] == document["importDsnEnv"]:
        raise ValueError("Source and AINS import credentials must be separate")
    return document, SnapshotScope(**document["scope"])


def secret(settings, name):
    value = os.environ.get(settings[name])
    if not value:
        raise ValueError("Required pilot credential is missing")
    return value


def write_capture(path, payload):
    # Preserve existing captures and avoid creating world-readable evidence files.
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
