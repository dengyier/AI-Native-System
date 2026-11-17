"""Build a local MCPB artifact using source from a committed release revision."""

import argparse
import hashlib
import json
import subprocess
import tomllib
from pathlib import Path
from tempfile import TemporaryDirectory


DIRECTORY = Path(__file__).resolve().parent
ROOT = DIRECTORY.parents[1]
REPOSITORY = "https://github.com/dengyier/AI-Native-System"
CLI = ("npx", "--yes", "@anthropic-ai/mcpb@2.1.2")
SOURCE_FILES = (
    "LICENSE.md",
    "ai_native_sdk/LICENSE",
    "ai_native_sdk/__init__.py",
    "ai_native_sdk/client.py",
    "ai_native_system/__init__.py",
    "ai_native_system/mcp_server.py",
)
BUNDLE_FILES = ("manifest.json", "pyproject.toml", "server.py", "PRIVACY.md")


def read_source(tree: str, name: str) -> bytes:
    return subprocess.check_output(["git", "show", f"{tree}:{name}"], cwd=ROOT)


def build(output: Path, ref: str = "HEAD"):
    tree = subprocess.check_output(
        ["git", "rev-parse", "--verify", "--end-of-options", f"{ref}^{{tree}}"], cwd=ROOT, text=True,
    ).strip()
    framework = tomllib.loads(read_source(tree, "pyproject.toml").decode("utf-8"))["project"]
    bundle_files = {name: read_source(tree, f"deployment/mcpb/{name}") for name in BUNDLE_FILES}
    bundle_project = tomllib.loads(bundle_files["pyproject.toml"].decode("utf-8"))["project"]
    manifest = json.loads(bundle_files["manifest.json"])
    version = framework["version"]
    if (manifest["version"] != version or bundle_project["version"] != version
            or manifest["license"] != framework["license"]):
        raise SystemExit("MCPB version and license must match the selected framework revision.")
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    bundle = output / f'{manifest["name"]}-{version}.mcpb'

    with TemporaryDirectory() as directory:
        staging = Path(directory)
        for name, content in bundle_files.items():
            (staging / name).write_bytes(content)
        for name in SOURCE_FILES:
            path = staging / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(read_source(tree, name))

        subprocess.run([*CLI, "validate", str(staging / "manifest.json")], check=True)
        subprocess.run([*CLI, "pack", str(staging), str(bundle)], check=True)

    descriptor = {
        "$schema": "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json",
        "name": "io.github.dengyier/ai-native-system",
        "title": manifest["display_name"],
        "description": manifest["description"],
        "version": version,
        "repository": {"url": REPOSITORY, "source": "github"},
        "packages": [{
            "registryType": "mcpb",
            "identifier": f"{REPOSITORY}/releases/download/v{version}/{bundle.name}",
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
    parser.add_argument("--ref", default="HEAD", help="Git tree or revision containing the release files")
    args = parser.parse_args()
    build(args.output, args.ref)
