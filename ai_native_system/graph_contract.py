"""The bounded orchestration options allowed in a published application."""

import re
from dataclasses import dataclass


_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}")
_CHECKS = frozenset({"object_grounded", "knowledge_grounded", "relationships_grounded"})
_FIELDS = frozenset({"version", "deadline_seconds", "checks", "on_check_failure", "max_rounds"})
MAX_GRAPH_AGENTS = 16


@dataclass(frozen=True)
class GraphSpec:
    version: str
    deadline_seconds: int = 120
    checks: tuple[str, ...] = ()
    on_check_failure: str = "block"
    max_rounds: int = 1

    @classmethod
    def from_document(cls, document):
        if not isinstance(document, dict) or document.keys() - _FIELDS:
            raise ValueError("Unsupported application graph fields")
        version = document.get("version")
        if not isinstance(version, str) or _VERSION.fullmatch(version) is None:
            raise ValueError("Application graph requires an explicit version")
        deadline = document.get("deadline_seconds", 120)
        if type(deadline) is not int or not 1 <= deadline <= 86_400:
            raise ValueError("Invalid application graph deadline")
        checks = document.get("checks", [])
        if (not isinstance(checks, list)
                or any(not isinstance(check, str) or check not in _CHECKS for check in checks)
                or len(checks) != len(set(checks))):
            raise ValueError("Application graph checks must be distinct registered read-only checks")
        on_failure = document.get("on_check_failure", "block")
        if on_failure not in ("block", "retry"):
            raise ValueError("Invalid application graph check failure branch")
        rounds = document.get("max_rounds", 1)
        if type(rounds) is not int or not 1 <= rounds <= 4:
            raise ValueError("Invalid application graph check round limit")
        if on_failure == "retry" and (not checks or rounds < 2):
            raise ValueError("Graph retry requires registered checks and two to four rounds")
        if on_failure == "block" and rounds != 1:
            raise ValueError("Graph with a blocking branch requires one round")
        return cls(version=version, deadline_seconds=deadline, checks=tuple(checks),
                   on_check_failure=on_failure, max_rounds=rounds)

    def to_document(self):
        return {"version": self.version, "deadline_seconds": self.deadline_seconds,
                "checks": list(self.checks), "on_check_failure": self.on_check_failure,
                "max_rounds": self.max_rounds}
