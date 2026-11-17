"""Run the P9 Agent containment checks in a disposable Docker Compose project."""

import argparse
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory


ROOT = Path(__file__).resolve().parents[2]
DEPLOYMENT = Path(__file__).resolve().parent
FIXTURE = DEPLOYMENT / "isolation_fixture.py"
PRUNED = ("langfuse", "langgraph", "langgraph-checkpoint-postgres", "llama-index-core",
          "llama-index-vector-stores-postgres", "mcp", "openworkproof")
AGENT_FILES = ("__init__.py", "agent_process.py", "model.py", "adapters/__init__.py", "adapters/litellm.py")
TARGET_PORTS = {"postgres": 5432, "executor-fixture": 18082, "source-fixture": 18083}


def _export_agent_requirements(path):
    arguments = ["uv", "export", "--locked", "--extra", "integrations", "--no-dev",
                 "--no-emit-project", "--no-header", "--no-annotate", "--output-file", str(path)]
    for package in PRUNED:
        arguments.extend(("--prune", package))
    subprocess.run(arguments, cwd=ROOT, check=True, timeout=30)


def _prepare_build(path):
    shutil.copyfile(DEPLOYMENT / "Agent.Dockerfile", path / "Dockerfile")
    for relative in AGENT_FILES:
        source = ROOT / "ai_native_system" / relative
        destination = path / "ai_native_system" / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    _export_agent_requirements(path / "requirements.txt")


def _build_image(image):
    with TemporaryDirectory(prefix="ai-native-agent-image-") as directory:
        path = Path(directory).resolve()
        _prepare_build(path)
        subprocess.run(["docker", "build", "--tag", image, str(path)], check=True, timeout=360)


def _route_configuration():
    return {"allow_providers": ["openai"],
            "routes": {"agent": {"adapter": "litellm", "provider": "openai", "timeout": 10,
                                  "base_url": "http://127.0.0.1:18789/v1", "model": "isolation-fixture",
                                  "api_key_env": "P9_FIXTURE_MODEL_KEY", "max_output_tokens": 256}}}


class Deployment:
    def __init__(self, command, environment):
        self.command = command
        self.environment = environment

    def compose(self, *args, timeout=20, **options):
        return subprocess.run((*self.command, *args), env=self.environment, timeout=timeout, check=True, **options)

    def probe(self, service, *args):
        result = self.compose("exec", "-T", service, "python", "-B", "-", *args, input=FIXTURE.read_text(),
                              capture_output=True, text=True)
        return json.loads(result.stdout)

    def inspect(self, service):
        container = self.compose("ps", "-q", service, capture_output=True, text=True).stdout.strip()
        value, = json.loads(subprocess.check_output(["docker", "inspect", container], text=True, timeout=10))
        return value

    def inspect_network(self, service):
        network, = self.inspect(service)["NetworkSettings"]["Networks"].values()
        value, = json.loads(subprocess.check_output(["docker", "network", "inspect", network["NetworkID"]],
                                                    text=True, timeout=10))
        return value

    def targets(self):
        result = {}
        for name, port in TARGET_PORTS.items():
            networks = self.inspect(name)["NetworkSettings"]["Networks"]
            network, = networks.values()
            result[name] = (network["IPAddress"], port)
        return result

    def ready(self):
        until = time.monotonic() + 35
        while time.monotonic() < until:
            try:
                agent = self.probe("agent", "model_count")
                executor = self.probe("executor-fixture", "network", json.dumps(self.targets()))
                self.compose("exec", "-T", "agent", "test", "-S", "/run/agent/proposal.sock", capture_output=True)
                if agent["requests"] == 0 and all(executor.values()):
                    return
            except (OSError, ValueError, subprocess.SubprocessError):
                pass
            time.sleep(0.5)
        raise RuntimeError("The isolated Agent deployment did not become ready")


@contextmanager
def disposable_isolation():
    project = "ai-native-isolation-" + secrets.token_hex(5)
    image = f"{project}:local"
    command = ("docker", "compose", "-p", project, "-f", str(DEPLOYMENT / "compose.yaml"),
               "-f", str(DEPLOYMENT / "compose.verification.yaml"))
    with TemporaryDirectory(prefix="ai-native-isolation-") as directory:
        temporary = Path(directory).resolve()
        agent_config = temporary / "agent.json"
        agent_config.write_text(json.dumps(_route_configuration()), encoding="utf-8")
        agent_env = temporary / "agent.env"
        agent_env.write_text("P9_FIXTURE_MODEL_KEY=fixture-model-key-only\n", encoding="ascii")
        agent_env.chmod(0o600)
        token = temporary / "business-token"
        token.write_text(secrets.token_urlsafe(32), encoding="ascii")
        token.chmod(0o444)
        environment = {**os.environ, "AI_NATIVE_ISOLATION_IMAGE": image, "AI_NATIVE_ISOLATION_AGENT_CONFIG": str(agent_config),
                       "AI_NATIVE_ISOLATION_AGENT_ENV_FILE": str(agent_env), "AI_NATIVE_ISOLATION_FIXTURE": str(FIXTURE),
                       "AI_NATIVE_ISOLATION_BUSINESS_TOKEN_FILE": str(token),
                       "AI_NATIVE_ISOLATION_EXECUTOR_CREDENTIAL": secrets.token_urlsafe(32),
                       "AI_NATIVE_ISOLATION_PG_PASSWORD": secrets.token_urlsafe(32)}
        deployment = Deployment(command, environment)
        try:
            _build_image(image)
            deployment.compose("config", "--quiet")
            deployment.compose("up", "-d", "--wait", "--wait-timeout", "60", timeout=75)
            deployment.ready()
            yield deployment
        finally:
            deployment.compose("down", "--volumes", "--remove-orphans", timeout=30)
            subprocess.run(["docker", "image", "rm", image], check=False, capture_output=True, timeout=15)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-image", metavar="IMAGE", help="build the isolated Agent image for deployment")
    arguments = parser.parse_args()
    if arguments.build_image:
        _build_image(arguments.build_image)
        return
    environment = {**os.environ, "AI_NATIVE_P9_ISOLATION_SUITE": "1"}
    subprocess.run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-p",
                    "test_executor_isolation.py", "-v"], cwd=ROOT, env=environment, check=True)


if __name__ == "__main__":
    main()
