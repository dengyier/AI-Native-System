"""Model invocation, admission checks and usage on the PostgreSQL runtime path."""

from dataclasses import dataclass
from time import monotonic
from uuid import uuid4

from . import governance
from .adapters.litellm import LiteLLMEmbedding, ProviderCallError
from .model import ModelError
from .model_accounting import ModelAccounting, ModelBudgetError, ModelPrice
from .model_policy import RouteAccounting, _names
from .observability import enqueue_model_trace
from .policy import Policy


class ModelAdmissionError(ModelError):
    """The request no longer has the permissions or state needed to send data."""


class ModelCall:
    def __init__(self, store, tenant, call_id, limits, *, purpose, task_id=None, action_id=None):
        if limits is None or not hasattr(store, "transaction"):
            raise ModelAdmissionError("Managed models require PostgreSQL and configured model limits")
        self.accounting = ModelAccounting(store)
        self.tenant = tenant
        self.call_id = call_id
        self.task_id = task_id
        self.action_id = action_id
        self.purpose = purpose
        self.limits = limits

    def invoke(self, route, version, adapter, policy, send, *, max_output_tokens, admit):
        adapter.validate_credentials()
        self.accounting.open_call(self.tenant, self.call_id, task_id=self.task_id,
                                  purpose=self.purpose, limits=self.limits)
        manifest = adapter.manifest
        price = ModelPrice(policy.price_version, policy.input_nanos, policy.output_nanos)
        permit = self.accounting.reserve(
            self.tenant, self.call_id, route=route, provider=manifest["provider"], model=manifest["model"],
            model_version=version, max_input_tokens=policy.max_input_tokens, max_output_tokens=max_output_tokens,
            price=price, timeout_seconds=manifest["timeout"], admit=admit,
        )
        outcome, result = "failed", None
        started = monotonic()
        sent = False
        try:
            remaining = permit.remaining_seconds()
            sent = True
            result = send(remaining)
            outcome = "succeeded"
            return result
        except ProviderCallError as exc:
            outcome = "timeout" if getattr(exc, "timeout", False) else "failed"
            sent = exc.sent
            result = exc
            raise
        except ModelBudgetError:
            outcome = "timeout"
            raise
        finally:
            elapsed_ms = round((monotonic() - started) * 1000)
            input_tokens = getattr(result, "input_tokens", None) if sent else 0
            output_tokens = getattr(result, "output_tokens", None) if sent else 0

            def observe(connection, row):
                cost = row["actual_cost_nanos"]
                enqueue_model_trace(
                    connection, tenant=self.tenant, call_id=self.call_id, attempt_id=permit.attempt_id,
                    kind=self.purpose, status=outcome, task_id=self.task_id, action_id=self.action_id,
                    input_tokens=input_tokens, output_tokens=output_tokens,
                    cost_nanos=cost if cost is not None and cost < 2**63 else None,
                    elapsed_ms=elapsed_ms, provider=manifest["provider"], route_id=route,
                )

            self.accounting.settle(
                permit, outcome=outcome, input_tokens=input_tokens, output_tokens=output_tokens,
                actual_provider=getattr(result, "provider", None), actual_model=getattr(result, "model", None),
                callback=observe,
            )


@dataclass(frozen=True)
class _EmbeddingRoute:
    adapter: LiteLLMEmbedding
    accounting: RouteAccounting
    scopes: tuple
    enabled: bool


class EmbeddingService:
    """Explicitly authorized embedding for trusted document and query callers."""

    def __init__(self, store, configuration, limits):
        self.store = store
        self.limits = limits
        self.max_input_bytes = configuration.get("max_context_bytes", 65536)
        if type(self.max_input_bytes) is not int or self.max_input_bytes <= 0:
            raise ValueError("Invalid embedding byte limit")
        self.routes = {}
        for name, route in configuration.get("embeddings", {}).items():
            _names((name,))
            if route.keys() - {"base_url", "model", "provider", "api_key_env", "version", "dimensions",
                               "preprocessing_version", "response_model", "timeout", "scopes", "enabled",
                               "accounting"}:
                raise ValueError("Unknown embedding route fields")
            scopes = _names(route["scopes"])
            enabled = route.get("enabled", True)
            if not scopes or set(scopes) - {"public", "tenant"} or type(enabled) is not bool:
                raise ValueError("Invalid embedding data policy")
            adapter = LiteLLMEmbedding(
                route["base_url"], route["model"], api_key_env=route.get("api_key_env", ""),
                provider=route["provider"], allow_providers=configuration["allow_providers"],
                dimensions=route["dimensions"], version=route["version"],
                preprocessing_version=route.get("preprocessing_version", "raw-text-v1"),
                response_model=route.get("response_model"), timeout=route.get("timeout", 15),
            )
            self.routes[name] = _EmbeddingRoute(adapter, RouteAccounting.from_document(route["accounting"]),
                                                scopes, enabled)

    def describe(self, route, *, scope=None):
        selected = self.routes.get(route)
        if selected is None or not selected.enabled:
            raise ModelAdmissionError("Embedding route is unavailable")
        if scope is not None and scope not in selected.scopes:
            raise ModelAdmissionError("Embedding data scope is not allowed")
        return selected.adapter.manifest

    def embed(self, tenant, route, texts, *, scope, purpose, identity=None, actor=None, authorize=None):
        selected = self.routes.get(route)
        if selected is None or not selected.enabled:
            raise ModelAdmissionError("Embedding route is unavailable")
        if scope not in selected.scopes or purpose not in ("document", "query"):
            raise ModelAdmissionError("Embedding data scope or purpose is not allowed")
        if not isinstance(texts, (list, tuple)) or not 1 <= len(texts) <= 64 or any(
            not isinstance(item, str) or not item.strip() for item in texts
        ):
            raise ValueError("Embedding requires 1–64 nonempty texts")
        texts = tuple(texts)
        if sum(len(item.encode("utf-8")) for item in texts) > self.max_input_bytes:
            raise ModelAdmissionError("Embedding input exceeds the byte limit")

        def admit(connection):
            if governance.enabled(connection, tenant):
                governance.require_identity_match(identity, tenant, actor)
                Policy().require(connection, identity, "embed", "model", route, scope)
            else:
                from .runtime import permitted

                if identity is not None or not actor or not permitted(connection, tenant, actor, "embed"):
                    raise PermissionError("Embedding route access denied")
            if authorize is not None:
                authorize(connection)

        adapter = selected.adapter
        call = ModelCall(self.store, tenant, uuid4().hex, self.limits, purpose="embedding")
        return call.invoke(route, adapter.manifest["version"], adapter, selected.accounting,
                           lambda remaining: adapter.embed(texts, timeout_seconds=remaining),
                           max_output_tokens=0, admit=admit)
