"""LiteLLM transport for operator-approved OpenAI-compatible endpoints."""

import asyncio
import hashlib
import json
import logging
import math
import os
import re
import time
from dataclasses import dataclass
from functools import lru_cache
from importlib.metadata import PackageNotFoundError, version
from urllib.parse import urlsplit

from ..model import ModelError, OpenAICompatibleModel, Proposal, _MAX_RESPONSE_BYTES, _SYSTEM_PROMPT


SDK_VERSION = "1.109.1"
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,191}")
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_MAX_INPUT_BYTES = 256 * 1024
_MAX_EMBEDDING_BYTES = 8 * 1024 * 1024


class ProviderCallError(ModelError):
    def __init__(self, message, *, provider, model, input_tokens=None, output_tokens=None,
                 retryable=False, timeout=False, status=None, sent=True):
        super().__init__(message)
        self.provider = provider
        self.model = model
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.retryable = retryable
        self.timeout = timeout
        self.status = status
        self.sent = sent


@dataclass(frozen=True)
class EmbeddingResult:
    vectors: tuple[tuple[float, ...], ...]
    input_tokens: int | None
    output_tokens: int | None
    provider: str
    model: str
    version: str
    preprocessing_version: str
    dimensions: int


@lru_cache(maxsize=1)
def _sdk():
    try:
        if version("litellm") != SDK_VERSION:
            raise ModelError(f"install LiteLLM {SDK_VERSION} from the integration lock")
        # LiteLLM imports its model catalog and configures tracing at import time.
        os.environ["LITELLM_OFFLINE_MODE"] = "true"
        os.environ["LITELLM_LOCAL_MODEL_COST_MAP"] = "true"
        os.environ["USE_DDTRACE"] = "false"
        import httpx2
        import litellm
        import openai
        from litellm.litellm_core_utils.dd_tracing import NullTracer, tracer
    except (ImportError, PackageNotFoundError):
        raise ModelError(f"install LiteLLM {SDK_VERSION} from the integration lock") from None
    if not isinstance(tracer, NullTracer):
        raise ModelError("LiteLLM process tracing must be disabled")

    # SDK debug logs can include whole requests. The framework exports its own traces.
    loggers = ("LiteLLM", "LiteLLM Proxy", "LiteLLM Router", "openai", "openai._base_client",
               "httpx2", "httpcore2", "httpcore2.connection", "httpcore2.http11", "httpcore2.http2")
    for name in loggers:
        logging.getLogger(name).disabled = True
    litellm.set_verbose = False
    litellm.suppress_debug_info = True
    litellm.turn_off_message_logging = True
    litellm.redact_messages_in_exceptions = True
    return litellm, openai, httpx2


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _json_object(data):
    value = json.loads(data, object_pairs_hook=_reject_duplicate_keys)
    if not isinstance(value, dict):
        raise ValueError("expected JSON object")
    return value


def _is_identifier(value):
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _usage(data, *, embedding):
    usage = data.get("usage")
    if not isinstance(usage, dict):
        return None, None

    def count(name):
        value = usage.get(name)
        return value if type(value) is int and 0 <= value < 2 ** 63 else None

    input_tokens, output_tokens = count("prompt_tokens"), count("completion_tokens")
    if embedding and "completion_tokens" not in usage and input_tokens is not None:
        if count("total_tokens") == input_tokens:
            output_tokens = 0
    return input_tokens, output_tokens


class _LiteLLMEndpoint:
    def __init__(self, base_url, model, api_key, *, provider, timeout, allow_providers, api_key_env):
        try:
            endpoint = urlsplit(base_url)
            host = endpoint.hostname
            endpoint.port
        except (TypeError, ValueError):
            raise ModelError("invalid LiteLLM base URL") from None
        secure = endpoint.scheme == "https" or endpoint.scheme == "http" and host in {"127.0.0.1", "::1"}
        if (not secure or not host or endpoint.username is not None or endpoint.query or endpoint.fragment
                or any(character.isspace() or character == "\\" for character in base_url)):
            raise ModelError("LiteLLM base URL must use HTTPS or numeric loopback HTTP")
        if (not isinstance(allow_providers, (list, tuple)) or not all(map(_is_identifier, allow_providers))
                or not _is_identifier(provider) or not _is_identifier(model) or provider not in allow_providers):
            raise ModelError("LiteLLM provider and model must be explicitly allowed")
        if not isinstance(api_key, str) or not isinstance(api_key_env, str) or (
            api_key_env and (api_key or not _ENV_NAME.fullmatch(api_key_env))
        ):
            raise ModelError("invalid LiteLLM credential configuration")
        if type(timeout) not in (int, float) or not 0 < timeout <= 120:
            raise ModelError("LiteLLM timeout must be between 0 and 120 seconds")
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.provider = provider
        self.timeout = timeout
        self.allow_providers = tuple(sorted(set(allow_providers)))
        self.api_key_env = api_key_env
        self._api_key = api_key

    @property
    def manifest(self):
        return {
            "backend": f"litellm-{SDK_VERSION}", "provider": self.provider, "model": self.model,
            "base_url": self.base_url, "timeout": self.timeout, "allowed_providers": list(self.allow_providers),
            "api_key_env": self.api_key_env,
        }

    def _error(self, message, data, *, embedding=False, status=None, retryable=False, timeout=False, sent=True):
        actual_model = data.get("model")
        inputs, outputs = _usage(data, embedding=embedding)
        return ProviderCallError(
            message, provider=self.provider, model=actual_model if _is_identifier(actual_model) else None,
            input_tokens=inputs, output_tokens=outputs, retryable=retryable, timeout=timeout, status=status, sent=sent,
        )

    def _credential(self):
        api_key = os.environ.get(self.api_key_env, "") if self.api_key_env else self._api_key
        if not api_key or not all(33 <= ord(character) <= 126 for character in api_key):
            raise ModelError("an explicit LiteLLM API key is required")
        return api_key

    def validate_credentials(self):
        self._credential()

    def _invoke(self, arguments, *, embedding, timeout_seconds):
        if timeout_seconds is not None and not timeout_seconds > 0:
            raise self._error("provider call deadline expired", {}, retryable=True, timeout=True, sent=False)
        timeout = self.timeout if timeout_seconds is None else min(self.timeout, timeout_seconds)
        deadline = time.monotonic() + timeout
        try:
            api_key = self._credential()
            litellm, openai, http = _sdk()
        except ModelError as exc:
            raise self._error(str(exc), {}, sent=False) from None
        if any(getattr(litellm, name, None) for name in (
            "callbacks", "input_callback", "success_callback", "failure_callback", "_async_input_callback",
            "_async_success_callback", "_async_failure_callback", "pre_call_rules", "post_call_rules", "proxy_auth",
        )):
            raise self._error("LiteLLM callbacks and proxy authentication must be disabled", {}, sent=False)
        endpoint = http.URL(self.base_url + ("/embeddings" if embedding else "/chat/completions"))
        response_limit = _MAX_EMBEDDING_BYTES if embedding else _MAX_RESPONSE_BYTES
        sent, response_timed_out, status, data = False, False, None, {}
        verified_args = _json_object(json.dumps({"model": self.model, **arguments}))

        async def send_once(content):
            nonlocal sent, status
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("provider call deadline expired")
            # Transmit only framework-approved headers. An absolute timeout also interrupts trickling headers.
            headers = {"Content-Type": "application/json", "Authorization": f"Bearer {api_key}",
                       "Accept-Encoding": "identity"}
            raw = bytearray()
            async with asyncio.timeout(remaining), http.AsyncClient(
                trust_env=False, follow_redirects=False, timeout=remaining,
            ) as client:
                sent = True
                async with client.stream("POST", endpoint, content=content, headers=headers) as response:
                    status = response.status_code
                    if response.headers.get("Content-Encoding", "identity").lower() != "identity":
                        raise ValueError("provider response must be uncompressed")
                    async for chunk in response.aiter_raw():
                        if len(raw) + len(chunk) > response_limit:
                            raise ValueError("provider response exceeded the size limit")
                        raw.extend(chunk)
            return raw

        def dispatch(request):
            nonlocal response_timed_out, data
            if sent or request.url != endpoint or request.method != "POST":
                raise ValueError("LiteLLM attempted an unexpected request")
            body = _json_object(request.content)
            if not embedding and "max_completion_tokens" in body and "max_tokens" not in body:
                body["max_tokens"] = body.pop("max_completion_tokens")
            if body != verified_args:
                raise ValueError("LiteLLM changed a provider request argument")
            try:
                raw = asyncio.run(send_once(request.content))
            except (TimeoutError, http.TimeoutException):
                response_timed_out = True
                raise
            if raw:
                data = _json_object(raw)
            # Keep provider error messages out of SDK logging and its error-directed retries.
            sdk_body = bytes(raw) if 200 <= status < 300 else b'{"error":{"message":"provider rejected request"}}'
            return http.Response(status, content=sdk_body, headers={"Content-Type": "application/json"})

        try:
            with http.Client(transport=http.MockTransport(dispatch), trust_env=False,
                             follow_redirects=False, timeout=timeout) as client:
                sdk_client = openai.OpenAI(api_key=api_key, base_url=self.base_url, max_retries=0,
                                           http_client=client, timeout=timeout)
                method = litellm.embedding if embedding else litellm.completion
                method(model=self.model, custom_llm_provider="openai", api_base=self.base_url, api_key=api_key,
                       client=sdk_client, timeout=timeout, num_retries=0, max_retries=0, caching=False,
                       drop_params=False, **{"no-log": True}, **arguments)
        except Exception:
            response_timed_out = response_timed_out or time.monotonic() >= deadline
            retryable = response_timed_out or sent and (status is None or status in {408, 429} or status >= 500)
            message = "provider call timed out" if response_timed_out else "provider call failed"
            if status is not None and not 200 <= status < 300:
                message += f" (HTTP {status})"
            raise self._error(message, data, embedding=embedding, status=status, retryable=retryable,
                              timeout=response_timed_out, sent=sent) from None
        if time.monotonic() >= deadline:
            raise self._error("provider call timed out", data, embedding=embedding, status=status,
                              retryable=True, timeout=True, sent=sent)
        if not sent or status is None or not 200 <= status < 300:
            raise self._error("provider did not return a successful response", data, embedding=embedding,
                              status=status, sent=sent)
        return data


class LiteLLMModel(_LiteLLMEndpoint):
    def __init__(self, base_url, model, api_key="", *, provider="openai", timeout=15,
                 max_output_tokens=512, allow_providers=("openai",), api_key_env="", agent=None):
        super().__init__(base_url, model, api_key, provider=provider, timeout=timeout,
                         allow_providers=allow_providers, api_key_env=api_key_env)
        if type(max_output_tokens) is not int or not 1 <= max_output_tokens <= 8192:
            raise ModelError("invalid LiteLLM output token limit")
        if agent is not None and api_key:
            raise ModelError("Isolated generation uses credentials provisioned to the Agent process")
        self.max_output_tokens = max_output_tokens
        self._agent = agent

    @property
    def manifest(self):
        return {**super().manifest, "purpose": "generation", "max_output_tokens": self.max_output_tokens,
                "system_prompt_sha256": hashlib.sha256(_SYSTEM_PROMPT.encode()).hexdigest()}

    def validate_credentials(self):
        if self._agent is None:
            super().validate_credentials()

    def _isolated_proposal(self, context, timeout_seconds):
        result = self._agent.propose(self.manifest, context, timeout_seconds=timeout_seconds)
        if not isinstance(result, Proposal) or result.provider != self.provider or not _is_identifier(result.model):
            raise self._error("invalid isolated Agent model identity", {})
        if any(value is not None and (type(value) is not int or not 0 <= value < 2**63)
               for value in (result.input_tokens, result.output_tokens)):
            raise self._error("invalid isolated Agent usage", {})
        usage = {"model": result.model, "usage": {"prompt_tokens": result.input_tokens,
                                                  "completion_tokens": result.output_tokens}}
        try:
            if not isinstance(result.evidence_ids, (list, tuple)):
                raise ModelError("invalid isolated Agent references")
            action, rationale, evidence = OpenAICompatibleModel._validate_proposal(
                {"action": result.action, "rationale": result.rationale, "evidence_ids": list(result.evidence_ids)}, context,
            )
        except (ModelError, TypeError, ValueError):
            raise self._error("invalid isolated Agent proposal", usage) from None
        return Proposal(action, rationale, tuple(evidence), self.provider, result.model,
                        result.input_tokens, result.output_tokens)

    def propose(self, context: dict, *, timeout_seconds: float | None = None) -> Proposal:
        user = json.dumps(context, ensure_ascii=False, allow_nan=False)
        if len(user.encode()) > _MAX_INPUT_BYTES:
            raise ModelError("model context exceeded the size limit")
        if self._agent is not None:
            return self._isolated_proposal(context, timeout_seconds)
        data = self._invoke({
            "messages": [{"role": "system", "content": _SYSTEM_PROMPT}, {"role": "user", "content": user}],
            "response_format": {"type": "json_object"}, "max_tokens": self.max_output_tokens,
        }, embedding=False, timeout_seconds=timeout_seconds)
        try:
            choices = data["choices"]
            choice = choices[0]
            message = choice["message"]
            if (len(choices) != 1 or choice["finish_reason"] != "stop" or message.get("role") != "assistant"
                    or message.get("refusal") or message.get("tool_calls") or not _is_identifier(data.get("model"))):
                raise ValueError("invalid provider response")
            proposal = _json_object(message["content"])
            action, rationale, evidence = OpenAICompatibleModel._validate_proposal(proposal, context)
        except (ValueError, TypeError, KeyError, IndexError, AttributeError, RecursionError, ModelError):
            raise self._error("invalid or incomplete provider proposal", data) from None
        return Proposal(action, rationale, tuple(evidence), self.provider, data["model"], *_usage(data, embedding=False))


class LiteLLMEmbedding(_LiteLLMEndpoint):
    def __init__(self, base_url, model, api_key="", *, dimensions, version, preprocessing_version="raw-text-v1",
                 response_model=None, provider="openai", timeout=15, allow_providers=("openai",), api_key_env=""):
        super().__init__(base_url, model, api_key, provider=provider, timeout=timeout,
                         allow_providers=allow_providers, api_key_env=api_key_env)
        self.response_model = model if response_model is None else response_model
        if (type(dimensions) is not int or not 1 <= dimensions <= 4096
                or not all(_is_identifier(label) for label in (version, preprocessing_version, self.response_model))):
            raise ModelError("embedding requires a model identity, version, preprocessing version and dimensions")
        self.dimensions = dimensions
        self.version = version
        self.preprocessing_version = preprocessing_version

    @property
    def manifest(self):
        return {**super().manifest, "purpose": "embedding", "response_model": self.response_model,
                "dimensions": self.dimensions, "version": self.version, "preprocessing_version": self.preprocessing_version}

    def embed(self, texts: list[str] | tuple[str, ...], *, timeout_seconds: float | None = None) -> EmbeddingResult:
        if not isinstance(texts, (list, tuple)) or not 1 <= len(texts) <= 64 or not all(
            isinstance(text, str) and text.strip() for text in texts
        ):
            raise ModelError("embedding requires one to 64 nonempty texts")
        if sum(len(text.encode()) for text in texts) > _MAX_INPUT_BYTES:
            raise ModelError("embedding texts exceeded the size limit")
        data = self._invoke({"input": list(texts), "encoding_format": "float"},
                            embedding=True, timeout_seconds=timeout_seconds)
        vectors = {}
        try:
            if data.get("model") != self.response_model or not isinstance(data.get("data"), list):
                raise ValueError("embedding model identity or response is invalid")
            if len(data["data"]) != len(texts):
                raise ValueError("embedding count does not match input")
            for item in data["data"]:
                index, vector = item["index"], item["embedding"]
                if type(index) is not int or not 0 <= index < len(texts) or index in vectors:
                    raise ValueError("invalid embedding index")
                if not isinstance(vector, list) or len(vector) != self.dimensions or not all(
                    type(coordinate) in (int, float) and math.isfinite(coordinate) for coordinate in vector
                ):
                    raise ValueError("invalid embedding vector")
                vectors[index] = tuple(map(float, vector))
        except (TypeError, KeyError, ValueError, OverflowError):
            raise self._error("invalid provider embedding", data, embedding=True) from None
        input_tokens, output_tokens = _usage(data, embedding=True)
        return EmbeddingResult(tuple(vectors[i] for i in range(len(texts))), input_tokens, output_tokens,
                               self.provider, data["model"], self.version, self.preprocessing_version, self.dimensions)
