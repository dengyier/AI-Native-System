"""Build a local MCPB artifact from the exact v0.1.0 release revision."""

import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory


DIRECTORY = Path(__file__).resolve().parent
ROOT = DIRECTORY.parents[1]
REPOSITORY = "https://github.com/dengyier/AI-Native-System"
TAG = "v0.1.0"
REVISION = "e23a19f317b72644277d7c6f2c3d29073f4377d7"
CLI = ("npx", "--yes", "@anthropic-ai/mcpb@2.1.2")
SOURCE_FILES = (
    "LICENSE.md",
    "ai_native_sdk/LICENSE",
    "ai_native_sdk/__init__.py",
    "ai_native_sdk/client.py",
    "ai_native_system/__init__.py",
    "ai_native_system/mcp_server.py",
)


def build(output: Path):
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((DIRECTORY / "manifest.json").read_text(encoding="utf-8"))
    bundle = output / f'{manifest["name"]}-{manifest["version"]}.mcpb'

    with TemporaryDirectory() as directory:
        staging = Path(directory)
        for name in ("manifest.json", "pyproject.toml", "server.py", "PRIVACY.md"):
            shutil.copyfile(DIRECTORY / name, staging / name)
        for name in SOURCE_FILES:
            path = staging / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(subprocess.check_output(["git", "show", f"{REVISION}:{name}"], cwd=ROOT))

        subprocess.run([*CLI, "validate", str(staging / "manifest.json")], check=True)
        subprocess.run([*CLI, "pack", str(staging), str(bundle)], check=True)

    descriptor = {
        "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
        "name": "io.github.dengyier/ai-native-system",
        "title": manifest["display_name"],
        "description": manifest["description"],
        "version": manifest["version"],
        "repository": {"url": REPOSITORY, "source": "github"},
        "packages": [{
            "registryType": "mcpb",
            "identifier": f"{REPOSITORY}/releases/download/{TAG}/{bundle.name}",
            "fileSha256": hashlib.sha256(bundle.read_bytes()).hexdigest(),
            "transport": {"type": "stdio"},
        }],
    }
    registry = output / "server.json"
    registry.write_text(json.dumps(descriptor, indent=2) + "\n", encoding="utf-8")
    print(bundle)
    print(registry)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    build(parser.parse_args().output)
