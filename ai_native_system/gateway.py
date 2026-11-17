"""Route advisory model calls from registered agent-stage configuration."""

import json
from collections.abc import Iterable
from dataclasses import dataclass

from .model import Model, ModelError, Proposal
from .model_policy import GenerationPolicy


@dataclass(frozen=True)
class _Route:
    adapter: Model
    version: str
    tags: tuple[str, ...]
    enabled: bool
    fallback: str | None
    policy: GenerationPolicy | None


def _nonempty_text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


class ModelGateway:
    """A Model with explicit, named routes and an optional context byte budget.

    Routes are callable only when enabled. Provider-reported failures can
    trigger one explicitly configured fallback. The caller still owns
    proposal validation and authorization.
    """

    def __init__(self, *, default: str, max_context_bytes: int | None = None):
        if not _nonempty_text(default):
            raise ValueError("a default model route is required")
        if max_context_bytes is not None and (
            type(max_context_bytes) is not int or max_context_bytes <= 0
        ):
            raise ValueError("model context byte limit must be a positive integer")
        self.default = default
        self.max_context_bytes = max_context_bytes
        self._routes: dict[str, _Route] = {}
        self.limits = None

    def register(
        self,
        name: str,
        model: Model,
        *,
        version: str = "1",
        tags: Iterable[str] = (),
        enabled: bool = True,
        fallback: str | None = None,
        policy: GenerationPolicy | None = None,
    ) -> None:
        if not _nonempty_text(name) or not _nonempty_text(version):
            raise ValueError("model route name and version are required")
        if name in self._routes:
            raise ValueError("model route is already registered")
        if fallback is not None and (not _nonempty_text(fallback) or fallback == name):
            raise ValueError("fallback must be a different named model route")
        if type(enabled) is not bool:
            raise ValueError("model route enabled flag must be a boolean")
        if isinstance(tags, str) or not isinstance(tags, Iterable):
            raise ValueError("model route tags must be a collection of names")
        tags = tuple(tags)
        if not all(map(_nonempty_text, tags)):
            raise ValueError("model route tags must be nonempty strings")

        from .adapters.litellm import LiteLLMModel

        if isinstance(model, LiteLLMModel) != isinstance(policy, GenerationPolicy):
            raise ValueError("LiteLLM generation routes require a data and accounting policy")
        self._routes[name] = _Route(model, version, tuple(dict.fromkeys(tags)), enabled, fallback, policy)

    def list_models(self) -> list[dict]:
        return [
            {
                "name": name,
                "version": route.version,
                "tags": list(route.tags),
                "enabled": route.enabled,
                "fallback": route.fallback,
            }
            for name, route in sorted(self._routes.items())
        ]

    def propose(self, context: dict, *, managed_call=None) -> Proposal:
        if not isinstance(context, dict) or not isinstance(context.get("agent", {}), dict):
            raise ModelError("model context must contain valid agent configuration")
        name = context.get("agent", {}).get("model", self.default)
        if not _nonempty_text(name) or name not in self._routes:
            raise ModelError("model route is not registered")
        route = self._routes[name]
        if not route.enabled:
            raise ModelError("model route is disabled")
        fallback = self._routes.get(route.fallback)
        if fallback is not None and not self.compatible_fallback(route, fallback):
            raise ModelError("model fallback has an incompatible data policy")
        if route.policy is not None:
            if managed_call is None:
                raise ModelError("LiteLLM calls require PostgreSQL model accounting")
            context = route.policy.data.project(context)
        if self.max_context_bytes is not None:
            self._check_context_budget(context)

        def send(route_name, selected):
            if selected.policy is None:
                return selected.adapter.propose(context)
            return managed_call(route_name, selected, context)

        try:
            return send(name, route)
        except ModelError as exc:
            if route.policy is not None and not getattr(exc, "retryable", False):
                raise
            if route.fallback is None:
                raise ModelError("model route failed") from None
            if fallback is None or not fallback.enabled:
                raise ModelError("model fallback is unavailable") from None
            try:
                return send(route.fallback, fallback)
            except ModelError:
                if route.policy is not None:
                    raise
                raise ModelError("model route and fallback failed") from None

    @staticmethod
    def compatible_fallback(primary, fallback):
        if primary.policy is None or fallback.policy is None:
            return primary.policy is fallback.policy
        return primary.policy.data == fallback.policy.data

    def _check_context_budget(self, context: dict) -> None:
        # Count the serialized context itself, excluding provider framing.
        try:
            payload = json.dumps(context, ensure_ascii=False, allow_nan=False).encode("utf-8")
        except (TypeError, ValueError, RecursionError):
            raise ModelError("model context is not JSON serializable") from None
        if len(payload) > self.max_context_bytes:
            raise ModelError("model context exceeds the byte limit")


def configured_gateway(configuration: dict, *, agent=None):
    """Construct a gateway using route configuration and environment-held credentials."""
    import os
    from .model import DemoModel, OpenAICompatibleModel

    gateway = ModelGateway(default=configuration["default"],
                           max_context_bytes=configuration.get("max_context_bytes", 65536))
    for name, route in configuration["routes"].items():
        adapter_type = route["adapter"]
        policy = None
        if adapter_type == "demo":
            adapter = DemoModel()
        elif adapter_type == "openai-compatible":
            if agent is not None:
                raise ValueError("Isolated generation requires managed LiteLLM routes")
            key_env = route.get("api_key_env")
            key = os.environ[key_env] if key_env else ""
            adapter = OpenAICompatibleModel(route["base_url"], route["model"], key)
        elif adapter_type == "litellm":
            from .adapters.litellm import LiteLLMModel

            if route.keys() - {"adapter", "version", "enabled", "tags", "fallback", "base_url", "model",
                               "api_key_env", "provider", "timeout", "max_output_tokens", "policy"}:
                raise ValueError("Unknown LiteLLM generation route fields")
            policy = GenerationPolicy.from_document(route["policy"])
            adapter = LiteLLMModel(
                route["base_url"], route["model"], api_key_env=route.get("api_key_env", ""),
                provider=route["provider"], allow_providers=configuration["allow_providers"],
                timeout=route.get("timeout", 15), max_output_tokens=route.get("max_output_tokens", 512),
                agent=agent,
            )
        else:
            raise ValueError("Unknown model adapter")
        gateway.register(name, adapter, version=route.get("version", "1"),
                         tags=route.get("tags", ()), enabled=route.get("enabled", True),
                         fallback=route.get("fallback"), policy=policy)
    if any(route.policy is not None for route in gateway._routes.values()) or configuration.get("embeddings"):
        from .model_accounting import ModelLimits

        if gateway.max_context_bytes is None:
            raise ValueError("LiteLLM requires a context byte limit")
        gateway.limits = ModelLimits(**configuration["limits"])
    return gateway
