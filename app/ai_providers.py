"""Multi-provider AI abstraction layer for AIFT forensic analysis.

This module provides a unified interface for interacting with multiple AI
providers used in AI Forensic Triage (AIFT) analysis workflows. It abstracts
away provider-specific SDK differences behind a common ``AIProvider`` base
class, enabling the rest of the application to perform AI-powered forensic
analysis without coupling to any single vendor.

Supported providers:

* **Claude (Anthropic)** -- via the ``anthropic`` Python SDK.
* **OpenAI** -- via the ``openai`` Python SDK (Chat Completions and
  Responses APIs).
* **Moonshot Kimi** -- via the ``openai`` Python SDK pointed at the
  Moonshot API base URL.
* **OpenAI-compatible local endpoints** -- Ollama, LM Studio, vLLM, or
  any server exposing an OpenAI-compatible ``/v1/chat/completions``
  endpoint.

Key design decisions:

* Each provider implementation handles its own error mapping, converting
  SDK-specific exceptions into a single ``AIProviderError`` that callers
  can catch uniformly.
* Rate-limit retries with exponential back-off (and ``Retry-After``
  header support) are handled transparently inside each provider.
* CSV artifact files can optionally be uploaded as file attachments
  (where the provider API supports it) or inlined into the prompt text
  as a fallback.
* Streaming (SSE) generation is supported for real-time progress
  reporting during long-running forensic analyses.
* Provider construction is driven by the application ``config.yaml``
  through the ``create_provider`` factory function.

Module-level constants:

    DEFAULT_MAX_TOKENS: Default maximum completion tokens across all providers.
    RATE_LIMIT_MAX_RETRIES: Number of retries on rate-limit (HTTP 429) errors.
    DEFAULT_LOCAL_BASE_URL: Default Ollama-style local endpoint URL.
    DEFAULT_LOCAL_REQUEST_TIMEOUT_SECONDS: Default HTTP timeout for local
        endpoints (1 hour, to accommodate large model inference).
    DEFAULT_KIMI_BASE_URL: Default Moonshot Kimi API base URL.
    DEFAULT_CLAUDE_MODEL: Default Anthropic Claude model identifier.
    DEFAULT_OPENAI_MODEL: Default OpenAI model identifier.
    DEFAULT_KIMI_MODEL: Default Moonshot Kimi model identifier.
    DEFAULT_KIMI_FILE_UPLOAD_PURPOSE: File upload purpose string for Kimi.
    DEFAULT_LOCAL_MODEL: Default model identifier for local providers.
"""

from __future__ import annotations

import base64
import logging
import os
import re
from abc import ABC, abstractmethod
from pathlib import Path
import time
from typing import Any, Callable, Iterator, Mapping, TypeVar
from urllib.parse import urlsplit, urlunsplit

logger = logging.getLogger(__name__)
_T = TypeVar("_T")

DEFAULT_MAX_TOKENS = 256000
RATE_LIMIT_MAX_RETRIES = 3
DEFAULT_LOCAL_BASE_URL = "http://localhost:11434/v1"
DEFAULT_LOCAL_REQUEST_TIMEOUT_SECONDS = 3600.0
DEFAULT_KIMI_BASE_URL = "https://api.moonshot.ai/v1"
DEFAULT_CLAUDE_MODEL = "claude-opus-4-6"
DEFAULT_OPENAI_MODEL = "gpt-5.2"
DEFAULT_KIMI_MODEL = "kimi-k2-turbo-preview"
DEFAULT_KIMI_FILE_UPLOAD_PURPOSE = "file-extract"
DEFAULT_LOCAL_MODEL = "llama3.1:70b"

_KIMI_MODEL_ALIASES = {
    "kimi-v2.5": DEFAULT_KIMI_MODEL,
}

_CONTEXT_LENGTH_PATTERNS = (
    "context length",
    "context window",
    "context_length_exceeded",
    "maximum context",
    "too many tokens",
    "token limit",
    "prompt is too long",
    "input is too long",
)

_KIMI_MODEL_NOT_AVAILABLE_PATTERNS = (
    "not found the model",
    "model not found",
    "resource_not_found_error",
    "permission denied",
    "unknown model",
)

_LEADING_REASONING_BLOCK_RE = re.compile(
    r"^\s*(?:"
    r"(?:<\s*(?:think|thinking|reasoning)\b[^>]*>.*?<\s*/\s*(?:think|thinking|reasoning)\s*>\s*)"
    r"|(?:```(?:think|thinking|reasoning)[^\n]*\n.*?```\s*)"
    r")+",
    flags=re.IGNORECASE | re.DOTALL,
)

_SUPPORTED_COMPLETION_TOKEN_LIMIT_RE = re.compile(
    r"supports\s+at\s+most\s+(?P<limit>\d+)\s+(?:completion\s+)?tokens",
    flags=re.IGNORECASE,
)
_MAX_TOKENS_UPPER_BOUND_RE = re.compile(
    r"max[_\s]?tokens?\s*:\s*\d+\s*>\s*(?P<limit>\d+)",
    flags=re.IGNORECASE,
)


class AIProviderError(RuntimeError):
    """Raised when an AI provider request fails with a user-facing message.

    All provider implementations translate SDK-specific exceptions (connection
    errors, authentication failures, context-length overflows, rate limits,
    etc.) into this single exception type so that callers only need one
    ``except`` clause for AI-related failures.

    The message carried by this exception is intended to be safe for display
    in the web UI and API responses without exposing raw tracebacks.
    """


class AIProvider(ABC):
    """Abstract base class defining the interface for all AI providers.

    Every concrete provider (Claude, OpenAI, Kimi, Local) implements this
    interface so that the forensic analysis engine can call any provider
    interchangeably. The interface exposes both synchronous and streaming
    analysis methods, optional file-attachment support, and model metadata
    retrieval.

    Subclasses must implement:
        * ``analyze`` -- single-shot prompt-to-text generation.
        * ``analyze_stream`` -- incremental (streaming) text generation.
        * ``get_model_info`` -- provider/model metadata dictionary.

    Subclasses may override:
        * ``analyze_with_attachments`` -- analysis with CSV file attachments
          uploaded to the provider.

    Attributes:
        attach_csv_as_file (bool): Whether to attempt uploading CSV artifacts
            as file attachments rather than inlining them into the prompt.
            Set per-provider via configuration.
    """

    @abstractmethod
    def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> str:
        """Send a prompt to the provider and return the complete generated text.

        Args:
            system_prompt: The system-level instruction text that sets the
                AI's role and behavioral constraints.
            user_prompt: The user-facing prompt containing investigation
                context and artifact data.
            max_tokens: Maximum number of tokens the model may generate in
                its response.

        Returns:
            The generated text response as a string.

        Raises:
            AIProviderError: If the request fails for any reason (network,
                authentication, context overflow, empty response, etc.).
        """

    @abstractmethod
    def analyze_stream(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> Iterator[str]:
        """Stream generated text chunks for the provided prompt.

        Returns an iterator that yields incremental text deltas as the
        model generates them. This is used to provide real-time progress
        feedback through Server-Sent Events (SSE) during analysis.

        Args:
            system_prompt: The system-level instruction text.
            user_prompt: The user-facing prompt with investigation context.
            max_tokens: Maximum number of tokens the model may generate.

        Yields:
            Individual text chunks (deltas) as they are generated.

        Raises:
            AIProviderError: If the streaming request fails or produces
                no output.
        """

    @abstractmethod
    def get_model_info(self) -> dict[str, str]:
        """Return provider and model metadata for audit logging and reports.

        Returns:
            A dictionary with at least ``"provider"`` and ``"model"`` keys
            identifying the AI backend used for analysis.
        """

    def analyze_with_attachments(
        self,
        system_prompt: str,
        user_prompt: str,
        attachments: list[Mapping[str, str]] | None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> str:
        """Analyze with optional file attachments.

        Providers that support file uploads (e.g., via the OpenAI Responses
        API or Anthropic document blocks) override this method to upload
        CSV artifact files directly. The default implementation ignores
        attachments and delegates to ``analyze``.

        Args:
            system_prompt: The system-level instruction text.
            user_prompt: The user-facing prompt with investigation context.
            attachments: Optional list of attachment descriptors, each a
                mapping with ``"path"``, ``"name"``, and ``"mime_type"``
                keys. May be ``None`` if no attachments are available.
            max_tokens: Maximum number of tokens the model may generate.

        Returns:
            The generated text response as a string.

        Raises:
            AIProviderError: If the request fails.
        """
        return self.analyze(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=max_tokens,
        )

    def _prepare_csv_attachments(
        self,
        attachments: list[Mapping[str, str]] | None,
        *,
        supports_file_attachments: bool = True,
    ) -> list[dict[str, str]] | None:
        """Apply shared CSV-attachment preflight checks and normalization.

        Validates that file-attachment mode is enabled, that attachments
        are provided, and that the provider has not already determined
        that file attachments are unsupported. Returns normalized
        attachment descriptors or ``None`` if attachment mode should be
        skipped.

        Args:
            attachments: Raw attachment descriptors from the caller.
            supports_file_attachments: Whether the provider's SDK client
                exposes the necessary file-upload APIs.

        Returns:
            A list of normalized attachment dicts with validated ``"path"``,
            ``"name"``, and ``"mime_type"`` keys, or ``None`` if attachment
            mode should not be used.
        """
        if not bool(getattr(self, "attach_csv_as_file", False)):
            return None
        if not attachments:
            return None
        if getattr(self, "_csv_attachment_supported", None) is False:
            return None
        if not supports_file_attachments:
            if hasattr(self, "_csv_attachment_supported"):
                setattr(self, "_csv_attachment_supported", False)
            return None

        normalized_attachments = _normalize_attachment_inputs(attachments)
        if not normalized_attachments:
            return None
        return normalized_attachments


def _normalize_api_key_value(value: Any) -> str:
    """Normalize API key-like values from config/env sources.

    Converts the input to a stripped string, treating ``None`` as empty.

    Args:
        value: Raw API key value from config.yaml or an environment variable.
            May be ``None``, an empty string, or a string with whitespace.

    Returns:
        The stripped string representation of the value, or an empty string
        if the input is ``None``.
    """
    if value is None:
        return ""
    return str(value).strip()


def _resolve_api_key(config_key: Any, env_var: str) -> str:
    """Return the API key from config, falling back to an environment variable.

    Args:
        config_key: The API key value from ``config.yaml``. May be ``None``
            or empty if not configured.
        env_var: The name of the environment variable to check as a fallback
            (e.g., ``"ANTHROPIC_API_KEY"``).

    Returns:
        The resolved API key string, or an empty string if neither the
        config value nor the environment variable is set.
    """
    normalized_config_key = _normalize_api_key_value(config_key)
    if normalized_config_key:
        return normalized_config_key
    return _normalize_api_key_value(os.environ.get(env_var, ""))


def _resolve_api_key_candidates(config_key: Any, env_vars: tuple[str, ...]) -> str:
    """Return API key from config, falling back across multiple environment variables.

    Unlike ``_resolve_api_key``, this function accepts multiple environment
    variable names and checks them in order, returning the first non-empty
    match. This is used for providers like Kimi that accept keys from
    either ``MOONSHOT_API_KEY`` or ``KIMI_API_KEY``.

    Args:
        config_key: The API key value from ``config.yaml``.
        env_vars: Tuple of environment variable names to check in priority
            order.

    Returns:
        The resolved API key string, or an empty string if no source
        provides a key.
    """
    normalized_config_key = _normalize_api_key_value(config_key)
    if normalized_config_key:
        return normalized_config_key

    for env_var in env_vars:
        normalized_value = _normalize_api_key_value(os.environ.get(env_var, ""))
        if normalized_value:
            return normalized_value
    return ""


def _resolve_timeout_seconds(value: Any, default_seconds: float) -> float:
    """Normalize timeout values from config/env inputs.

    Converts the raw value to a positive float, falling back to the default
    when the value is missing, non-numeric, or non-positive.

    Args:
        value: Raw timeout value from configuration. May be a number, a
            numeric string, ``None``, or an invalid type.
        default_seconds: Fallback timeout in seconds when the value cannot
            be used.

    Returns:
        A positive float representing the timeout in seconds.
    """
    try:
        timeout_seconds = float(value)
    except (TypeError, ValueError):
        return float(default_seconds)

    if timeout_seconds <= 0:
        return float(default_seconds)
    return timeout_seconds


def _extract_retry_after_seconds(error: Exception) -> float | None:
    """Read ``Retry-After`` hints from API error responses when present.

    Inspects the exception for an attached HTTP response or headers object
    and extracts the ``Retry-After`` header value.

    Args:
        error: The rate-limit or API exception that may carry HTTP headers.

    Returns:
        The retry delay in seconds as a non-negative float, or ``None`` if
        no ``Retry-After`` header is present or parseable.
    """
    response = getattr(error, "response", None)
    headers = getattr(response, "headers", None)
    if headers is None:
        headers = getattr(error, "headers", None)
    if headers is None:
        return None

    retry_after_value = headers.get("retry-after") or headers.get("Retry-After")
    if retry_after_value is None:
        return None

    try:
        retry_after = float(retry_after_value)
    except (TypeError, ValueError):
        return None

    return max(0.0, retry_after)


def _is_context_length_error(error: Exception) -> bool:
    """Best-effort detection for context/token-length failures.

    Checks the exception message, error code, and body against known
    patterns that indicate the prompt exceeded the model's context window.

    Args:
        error: The API exception to inspect.

    Returns:
        ``True`` if the error appears to be a context-length overflow.
    """
    message = str(error).lower()
    if any(pattern in message for pattern in _CONTEXT_LENGTH_PATTERNS):
        return True

    code = getattr(error, "code", None)
    if isinstance(code, str) and "context" in code.lower():
        return True

    body = getattr(error, "body", None)
    if isinstance(body, dict):
        body_text = str(body).lower()
        if any(pattern in body_text for pattern in _CONTEXT_LENGTH_PATTERNS):
            return True

    return False


def _normalize_openai_compatible_base_url(base_url: str, default_base_url: str) -> str:
    """Normalize OpenAI-compatible base URLs.

    OpenAI-compatible SDK clients expect the versioned API prefix (commonly
    ``/v1``). Ollama users often provide ``http://localhost:11434/``; in that
    case we normalize to ``http://localhost:11434/v1``.

    Args:
        base_url: Raw base URL string from configuration. May be empty,
            missing a path prefix, or already correctly formatted.
        default_base_url: Fallback URL to use when ``base_url`` is empty
            or not provided.

    Returns:
        The normalized base URL string with a versioned path prefix.
    """
    raw = str(base_url or "").strip()
    if not raw:
        return default_base_url

    parsed = urlsplit(raw)
    if not parsed.scheme or not parsed.netloc:
        return raw.rstrip("/")

    normalized_path = parsed.path.rstrip("/")
    if normalized_path in ("", "/"):
        normalized_path = "/v1"

    return urlunsplit((parsed.scheme, parsed.netloc, normalized_path, parsed.query, parsed.fragment))


def _normalize_kimi_model_name(model: str) -> str:
    """Normalize Kimi model names and map deprecated aliases.

    Applies alias mapping for deprecated model identifiers (e.g.,
    ``"kimi-v2.5"`` maps to the current default) and logs a warning
    when a deprecated alias is used.

    Args:
        model: Raw model name string from configuration. May be empty or
            contain a deprecated alias.

    Returns:
        The canonical Kimi model identifier string.
    """
    raw = str(model or "").strip()
    if not raw:
        return DEFAULT_KIMI_MODEL

    mapped = _KIMI_MODEL_ALIASES.get(raw.lower())
    if mapped:
        logger.warning("Kimi model '%s' is deprecated; using '%s'.", raw, mapped)
        return mapped
    return raw


def _is_kimi_model_not_available_error(error: Exception) -> bool:
    """Detect model-not-found or model-permission failures from Kimi responses.

    Args:
        error: The API exception to inspect.

    Returns:
        ``True`` if the error indicates the requested model is unavailable
        or not permitted on the Moonshot account.
    """
    message = str(error).lower()
    if "model" in message and any(pattern in message for pattern in _KIMI_MODEL_NOT_AVAILABLE_PATTERNS):
        return True

    body = getattr(error, "body", None)
    if isinstance(body, dict):
        body_text = str(body).lower()
        if "model" in body_text and any(pattern in body_text for pattern in _KIMI_MODEL_NOT_AVAILABLE_PATTERNS):
            return True

    return False


def _extract_anthropic_text(response: Any) -> str:
    """Extract the concatenated text from an Anthropic Messages API response.

    Iterates over content blocks in the response, collecting text from
    both object-style blocks (with a ``.text`` attribute) and dict-style
    blocks (with a ``"text"`` key).

    Args:
        response: The Anthropic ``Message`` response object (or a
            dict-like equivalent).

    Returns:
        The joined text content, stripped of leading/trailing whitespace.
        Returns an empty string if no text blocks are found.
    """
    content = getattr(response, "content", None)
    if not isinstance(content, list):
        return ""

    chunks: list[str] = []
    for block in content:
        text = getattr(block, "text", None)
        if isinstance(text, str):
            chunks.append(text)
            continue

        if isinstance(block, dict):
            block_text = block.get("text")
            if isinstance(block_text, str):
                chunks.append(block_text)

    return "".join(chunks).strip()


def _extract_anthropic_stream_text(event: Any) -> str:
    """Extract text deltas from Anthropic streamed events.

    Handles ``content_block_delta``, ``content_block_start``, and generic
    delta events from the Anthropic streaming API, supporting both
    object-style and dict-style event payloads.

    Args:
        event: A single streamed event from the Anthropic Messages API.
            May be an SDK event object or a raw dict.

    Returns:
        The text delta string from this event, or an empty string if the
        event contains no text content.
    """
    if event is None:
        return ""

    event_type = getattr(event, "type", None)
    if event_type is None and isinstance(event, dict):
        event_type = event.get("type")

    if event_type == "content_block_delta":
        delta = getattr(event, "delta", None)
        if delta is None and isinstance(event, dict):
            delta = event.get("delta")
        text = getattr(delta, "text", None)
        if text is None and isinstance(delta, dict):
            text = delta.get("text")
        if isinstance(text, str):
            return text

    if event_type == "content_block_start":
        content_block = getattr(event, "content_block", None)
        if content_block is None and isinstance(event, dict):
            content_block = event.get("content_block")
        text = getattr(content_block, "text", None)
        if text is None and isinstance(content_block, dict):
            text = content_block.get("text")
        if isinstance(text, str):
            return text

    delta = getattr(event, "delta", None)
    if delta is None and isinstance(event, dict):
        delta = event.get("delta")
    if delta is not None:
        text = getattr(delta, "text", None)
        if text is None and isinstance(delta, dict):
            text = delta.get("text")
        if isinstance(text, str):
            return text

    return ""


def _extract_openai_text(response: Any) -> str:
    """Extract the generated text from an OpenAI Chat Completions API response.

    Handles multiple response shapes including plain string content,
    structured content arrays, and reasoning-model fallback fields
    (``reasoning_content``, ``reasoning``, ``refusal``). Supports both
    object-style and dict-style response payloads for compatibility with
    various OpenAI-compatible endpoints.

    Args:
        response: The OpenAI ``ChatCompletion`` response object or a
            dict-like equivalent.

    Returns:
        The extracted text content, stripped of whitespace. Returns an
        empty string if no usable text is found.
    """
    choices = getattr(response, "choices", None)
    if not choices:
        return ""

    first_choice = choices[0]
    message = getattr(first_choice, "message", None)
    if message is None and isinstance(first_choice, dict):
        message = first_choice.get("message")

    if message is None:
        return ""

    content = getattr(message, "content", None)
    if content is None and isinstance(message, dict):
        content = message.get("content")

    if isinstance(content, str):
        stripped_content = content.strip()
        if stripped_content:
            return stripped_content

    if isinstance(content, list):
        parts: list[str] = []
        for chunk in content:
            text = getattr(chunk, "text", None)
            if isinstance(text, str):
                parts.append(text)
                continue

            if isinstance(chunk, dict):
                chunk_text = chunk.get("text")
                if isinstance(chunk_text, str):
                    parts.append(chunk_text)
                    continue
                chunk_content = chunk.get("content")
                if isinstance(chunk_content, str):
                    parts.append(chunk_content)
        joined = "".join(parts).strip()
        if joined:
            return joined

    # Reasoning-capable local models can return empty message.content while
    # putting output in alternate fields.
    for field_name in ("reasoning_content", "reasoning", "refusal"):
        field_value = getattr(message, field_name, None)
        if field_value is None and isinstance(message, dict):
            field_value = message.get(field_name)
        if isinstance(field_value, str):
            stripped_value = field_value.strip()
            if stripped_value:
                return stripped_value
        if isinstance(field_value, list):
            list_parts: list[str] = []
            for item in field_value:
                if isinstance(item, str):
                    list_parts.append(item)
                    continue
                item_text = getattr(item, "text", None)
                if isinstance(item_text, str):
                    list_parts.append(item_text)
                    continue
                if isinstance(item, dict):
                    dict_text = item.get("text")
                    if isinstance(dict_text, str):
                        list_parts.append(dict_text)
            joined_list = "".join(list_parts).strip()
            if joined_list:
                return joined_list

    return ""


def _extract_openai_delta_text(delta: Any, field_names: tuple[str, ...]) -> str:
    """Extract streaming delta text for one of the requested fields.

    Checks the delta object for the first non-empty text value across the
    given field names. This supports OpenAI-compatible streaming where
    different model types may use ``content``, ``reasoning_content``,
    ``reasoning``, or ``thinking`` fields.

    Args:
        delta: The streaming chunk delta object or dict from a choice.
        field_names: Tuple of field names to check in priority order
            (e.g., ``("content", "reasoning_content")``).

    Returns:
        The first non-empty text value found, or an empty string.
    """
    if delta is None:
        return ""

    for field_name in field_names:
        value = getattr(delta, field_name, None)
        if value is None and isinstance(delta, dict):
            value = delta.get(field_name)
        text = _coerce_openai_text(value)
        if text:
            return text
    return ""


def _coerce_openai_text(value: Any) -> str:
    """Normalize OpenAI-compatible response text payloads into plain strings.

    Handles string values, lists of text items (objects or dicts), and
    returns an empty string for unsupported types. This accounts for the
    varied response shapes across different OpenAI-compatible endpoints.

    Args:
        value: A text value from an OpenAI-compatible response. May be a
            plain string, a list of text objects/dicts, or ``None``.

    Returns:
        The concatenated plain text string, or an empty string if the
        value cannot be coerced.
    """
    if isinstance(value, str):
        return value

    if isinstance(value, list):
        parts: list[str] = []
        for item in value:
            if isinstance(item, str):
                parts.append(item)
                continue
            item_text = getattr(item, "text", None)
            if isinstance(item_text, str):
                parts.append(item_text)
                continue
            if isinstance(item, dict):
                dict_text = item.get("text")
                if isinstance(dict_text, str):
                    parts.append(dict_text)
                    continue
                dict_content = item.get("content")
                if isinstance(dict_content, str):
                    parts.append(dict_content)
        return "".join(parts)

    return ""


def _extract_openai_responses_text(response: Any) -> str:
    """Extract output text from OpenAI Responses API payloads.

    First attempts the convenience ``output_text`` attribute, then falls
    back to iterating over structured ``output`` items and their content
    blocks looking for ``output_text`` or ``text`` type blocks.

    Args:
        response: The OpenAI Responses API response object or dict.

    Returns:
        The extracted and stripped text content, or an empty string if
        no text output is found.
    """
    output_text = getattr(response, "output_text", None)
    text = _coerce_openai_text(output_text).strip()
    if text:
        return text

    output_items = getattr(response, "output", None)
    if output_items is None and isinstance(response, dict):
        output_items = response.get("output")
    if not isinstance(output_items, list):
        return ""

    parts: list[str] = []
    for item in output_items:
        content = getattr(item, "content", None)
        if content is None and isinstance(item, dict):
            content = item.get("content")
        if not isinstance(content, list):
            continue

        for block in content:
            block_type = getattr(block, "type", None)
            if block_type is None and isinstance(block, dict):
                block_type = block.get("type")
            if str(block_type) not in {"output_text", "text"}:
                continue

            block_text = getattr(block, "text", None)
            if block_text is None and isinstance(block, dict):
                block_text = block.get("text")
            normalized = _coerce_openai_text(block_text)
            if normalized:
                parts.append(normalized)

    return "".join(parts).strip()


def _strip_leading_reasoning_blocks(text: str) -> str:
    """Remove leading model-thinking blocks from OpenAI-compatible output.

    Some local reasoning models (e.g., DeepSeek R1) emit ``<think>`` or
    ``<reasoning>`` XML-style blocks or fenced code blocks at the start
    of their output. This function strips those blocks so that only the
    substantive analysis text remains.

    Args:
        text: Raw model output that may begin with reasoning blocks.

    Returns:
        The text with any leading reasoning blocks removed, or an empty
        string if the input is empty.
    """
    value = str(text or "").strip()
    if not value:
        return ""
    return _LEADING_REASONING_BLOCK_RE.sub("", value, count=1).strip()


def _clean_streamed_answer_text(answer_text: str, thinking_text: str) -> str:
    """Drop duplicated streamed thinking text from the final answer channel.

    Some models emit the thinking/reasoning content as a prefix in both the
    thinking stream and the answer stream. This function removes that
    duplication by stripping any leading thinking text from the answer,
    then removing any remaining reasoning blocks.

    Args:
        answer_text: The accumulated answer-channel text from streaming.
        thinking_text: The accumulated thinking-channel text from streaming.

    Returns:
        The cleaned answer text with duplicated reasoning removed.
    """
    answer = str(answer_text or "").strip()
    if not answer:
        return ""

    thinking = str(thinking_text or "").strip()
    if thinking and len(thinking) >= 24 and answer.startswith(thinking):
        answer = answer[len(thinking) :].lstrip()

    return _strip_leading_reasoning_blocks(answer)


def _is_attachment_unsupported_error(error: Exception) -> bool:
    """Detect API errors that indicate attachment/file APIs are unsupported.

    Checks the error message for markers such as ``"404"``, ``"not found"``,
    ``"unsupported"``, etc. that suggest the endpoint does not support the
    ``/files`` or ``/responses`` APIs required for file-attachment mode.

    Args:
        error: The API exception to inspect.

    Returns:
        ``True`` if the error indicates file-attachment APIs are unavailable.
    """
    message = str(error).lower()
    unsupported_markers = (
        "404",
        "not found",
        "unsupported",
        "does not support",
        "input_file",
        "/responses",
        "/files",
        "unrecognized request url",
        "unknown field",
        "supported format",
        "context stuffing file type",
        "but got .csv",
    )
    return any(marker in message for marker in unsupported_markers)


def _is_anthropic_streaming_required_error(error: Exception) -> bool:
    """Detect Anthropic SDK non-streaming timeout guardrails for long requests.

    The Anthropic SDK raises a ``ValueError`` when a non-streaming request
    is estimated to exceed 10 minutes, requiring the caller to switch to
    streaming mode instead.

    Args:
        error: The exception to inspect (typically a ``ValueError``).

    Returns:
        ``True`` if the error message indicates streaming is required due
        to expected long processing time.
    """
    message = str(error).lower()
    if "streaming is required for operations that may take longer than 10 minutes" in message:
        return True
    return "streaming is required" in message and "10 minutes" in message


def _is_unsupported_parameter_error(error: Exception, parameter_name: str) -> bool:
    """Detect API errors that indicate a specific parameter is unsupported.

    Some OpenAI-compatible endpoints do not support newer parameters like
    ``max_completion_tokens``. This function inspects the error's ``param``
    field and message body to determine if the rejection is specifically
    about the named parameter being unrecognized.

    Args:
        error: The API exception to inspect.
        parameter_name: The name of the parameter to check for
            (e.g., ``"max_completion_tokens"``).

    Returns:
        ``True`` if the error indicates the specified parameter is
        unsupported by the endpoint.
    """
    parameter = str(parameter_name or "").strip().lower()
    if not parameter:
        return False

    param = getattr(error, "param", None)
    if isinstance(param, str) and param.lower() == parameter:
        return True

    body = getattr(error, "body", None)
    if isinstance(body, dict):
        error_payload = body.get("error", body)
        if isinstance(error_payload, Mapping):
            body_param = error_payload.get("param")
            if isinstance(body_param, str) and body_param.lower() == parameter:
                return True
            body_message = error_payload.get("message")
            if isinstance(body_message, str):
                lowered_message = body_message.lower()
                if parameter in lowered_message and "unsupported parameter" in lowered_message:
                    return True

        lowered_body = str(body).lower()
        if parameter in lowered_body and "unsupported parameter" in lowered_body:
            return True

    lowered_message = str(error).lower()
    return parameter in lowered_message and "unsupported parameter" in lowered_message


def _extract_supported_completion_token_limit(error: Exception) -> int | None:
    """Extract a provider-declared completion token cap from an API error.

    When a request is rejected because ``max_tokens`` exceeds the model's
    supported limit, the error message often includes the actual cap
    (e.g., ``"supports at most 8192 completion tokens"``). This function
    parses that limit so the caller can retry with a lower value.

    Args:
        error: The API exception whose message may contain the token limit.

    Returns:
        The provider-declared maximum completion token count as a positive
        integer, or ``None`` if no limit could be extracted.
    """
    candidate_messages: list[str] = []
    body = getattr(error, "body", None)
    if isinstance(body, dict):
        error_payload = body.get("error", body)
        if isinstance(error_payload, Mapping):
            body_message = error_payload.get("message")
            if isinstance(body_message, str):
                candidate_messages.append(body_message)
        candidate_messages.append(str(body))
    candidate_messages.append(str(error))

    patterns = (
        _SUPPORTED_COMPLETION_TOKEN_LIMIT_RE,
        _MAX_TOKENS_UPPER_BOUND_RE,
    )
    for message in candidate_messages:
        for pattern in patterns:
            match = pattern.search(message)
            if not match:
                continue
            try:
                limit = int(match.group("limit"))
            except (TypeError, ValueError):
                continue
            if limit > 0:
                return limit
    return None


def _resolve_completion_token_retry_limit(
    error: Exception,
    requested_tokens: int,
) -> int | None:
    """Return a reduced token count when the API reports the model maximum.

    Combines ``_extract_supported_completion_token_limit`` with a check
    that the extracted limit is actually lower than what was requested.
    If so, returns the limit for use in a retry; otherwise returns ``None``
    to indicate the error is not recoverable by reducing tokens.

    Args:
        error: The API exception that triggered the token-limit failure.
        requested_tokens: The ``max_tokens`` value that was rejected.

    Returns:
        A reduced token count to use for retry, or ``None`` if the error
        is not a recoverable token-limit issue.
    """
    if requested_tokens <= 0:
        return None
    supported_limit = _extract_supported_completion_token_limit(error)
    if supported_limit is None or supported_limit >= requested_tokens:
        return None
    return supported_limit


def _prepare_openai_attachment_upload(attachment: Mapping[str, str]) -> tuple[str, str, bool]:
    """Normalize OpenAI attachment upload metadata.

    Some OpenAI Responses API models reject ``.csv`` file extensions for
    context stuffing inputs. For those uploads, this function converts
    the filename extension to ``.txt`` and the MIME type to
    ``text/plain`` while keeping the file contents unchanged.

    Args:
        attachment: A normalized attachment descriptor with ``"path"``,
            ``"name"``, and ``"mime_type"`` keys.

    Returns:
        A 3-tuple of ``(upload_name, upload_mime_type, was_converted)``:

        * ``upload_name`` -- The filename to use for the upload.
        * ``upload_mime_type`` -- The MIME type to use for the upload.
        * ``was_converted`` -- ``True`` if the original CSV metadata was
          converted to TXT format.
    """
    attachment_path = Path(str(attachment.get("path", "")))
    original_name = str(attachment.get("name", "")).strip() or attachment_path.name or "attachment"
    original_mime_type = str(attachment.get("mime_type", "")).strip() or "text/plain"

    lowered_name = original_name.lower()
    lowered_path_suffix = attachment_path.suffix.lower()
    lowered_mime_type = original_mime_type.lower()
    is_csv_attachment = (
        lowered_name.endswith(".csv")
        or lowered_path_suffix == ".csv"
        or lowered_mime_type in {"text/csv", "application/csv"}
    )
    if not is_csv_attachment:
        return original_name, original_mime_type, False

    stem = Path(original_name).stem or Path(attachment_path.name).stem or "attachment"
    return f"{stem}.txt", "text/plain", True


def _inline_attachment_data_into_prompt(
    user_prompt: str,
    attachments: list[Mapping[str, str]] | None,
) -> tuple[str, bool]:
    """Append attachment file contents to the user prompt for text-only fallback.

    When file-upload APIs are unavailable, this function reads each
    attachment from disk and inlines its full contents into the user
    prompt, wrapped in labeled delimiters. All attachment data is inlined
    without truncation -- in DFIR, every row matters. When the resulting
    prompt is too large for the model context window, the caller uses
    chunked analysis to split it.

    Args:
        user_prompt: The original user prompt text.
        attachments: Optional list of attachment descriptors with
            ``"path"``, ``"name"``, and ``"mime_type"`` keys.

    Returns:
        A 2-tuple of ``(modified_prompt, was_inlined)``:

        * ``modified_prompt`` -- The user prompt with attachment data
          appended (or the original prompt if nothing was inlined).
        * ``was_inlined`` -- ``True`` if at least one attachment was
          successfully inlined into the prompt.
    """
    normalized_attachments = _normalize_attachment_inputs(attachments)
    if not normalized_attachments:
        return user_prompt, False

    inline_sections: list[str] = []
    for attachment in normalized_attachments:
        attachment_path = Path(attachment["path"])
        attachment_name = str(attachment.get("name", "")).strip() or attachment_path.name
        try:
            attachment_text = attachment_path.read_text(
                encoding="utf-8-sig",
                errors="replace",
            )
        except OSError:
            continue
        if not attachment_text.strip():
            continue

        inline_sections.append(
            "\n".join(
                [
                    f"--- BEGIN ATTACHMENT: {attachment_name} ---",
                    attachment_text.rstrip(),
                    f"--- END ATTACHMENT: {attachment_name} ---",
                ]
            )
        )

    if not inline_sections:
        return user_prompt, False

    inlined_prompt = "\n\n".join(
        [
            user_prompt.rstrip(),
            "File attachments were unavailable, so the attachment contents are inlined below.",
            "\n\n".join(inline_sections),
        ]
    ).strip()
    return inlined_prompt, True


def _normalize_attachment_input(attachment: Mapping[str, str] | Any) -> dict[str, str] | None:
    """Validate and normalize a single attachment descriptor.

    Checks that the attachment is a mapping with a non-empty ``"path"``
    pointing to an existing file, then returns a cleaned dict with
    ``"path"``, ``"name"``, and ``"mime_type"`` keys.

    Args:
        attachment: A raw attachment descriptor, expected to be a mapping
            with at least a ``"path"`` key.

    Returns:
        A normalized dict with string values for ``"path"``, ``"name"``,
        and ``"mime_type"``, or ``None`` if the input is invalid or the
        file does not exist.
    """
    if not isinstance(attachment, Mapping):
        return None

    path_value = str(attachment.get("path", "")).strip()
    if not path_value:
        return None

    path = Path(path_value)
    if not path.exists() or not path.is_file():
        return None

    filename = str(attachment.get("name", "")).strip() or path.name
    mime_type = str(attachment.get("mime_type", "")).strip() or "text/csv"
    return {
        "path": str(path),
        "name": filename,
        "mime_type": mime_type,
    }


def _normalize_attachment_inputs(
    attachments: list[Mapping[str, str]] | None,
) -> list[dict[str, str]]:
    """Validate and normalize a list of attachment descriptors.

    Filters out invalid entries (non-mapping items, missing paths,
    nonexistent files) and returns only valid, normalized descriptors.

    Args:
        attachments: Optional list of raw attachment descriptors.

    Returns:
        A list of validated attachment dicts. May be empty if all inputs
        are invalid or the input is ``None``.
    """
    normalized: list[dict[str, str]] = []
    for attachment in attachments or []:
        candidate = _normalize_attachment_input(attachment)
        if candidate is not None:
            normalized.append(candidate)
    return normalized


def _run_with_rate_limit_retries(
    request_fn: Callable[[], _T],
    rate_limit_error_type: type[Exception],
    provider_name: str,
) -> _T:
    """Retry rate-limited requests with exponential backoff.

    Executes the given request callable and retries up to
    ``RATE_LIMIT_MAX_RETRIES`` times if a rate-limit error is raised.
    Uses ``Retry-After`` headers when available, otherwise falls back to
    exponential backoff (1s, 2s, 4s, ...).

    Args:
        request_fn: A zero-argument callable that performs the API request
            and returns the result.
        rate_limit_error_type: The exception class to catch as a rate-limit
            signal (e.g., ``anthropic.RateLimitError``).
        provider_name: Human-readable provider name for log messages
            (e.g., ``"Claude"``, ``"OpenAI"``).

    Returns:
        The return value of ``request_fn`` on a successful call.

    Raises:
        AIProviderError: If the rate limit is still exceeded after all
            retries are exhausted.
    """
    last_error: Exception | None = None

    for retry_count in range(RATE_LIMIT_MAX_RETRIES + 1):
        try:
            return request_fn()
        except rate_limit_error_type as error:
            last_error = error
            if retry_count >= RATE_LIMIT_MAX_RETRIES:
                break

            retry_after = _extract_retry_after_seconds(error)
            if retry_after is None:
                retry_after = float(2**retry_count)
            logger.warning(
                "%s rate limited (attempt %d/%d), retrying in %.1fs",
                provider_name,
                retry_count + 1,
                RATE_LIMIT_MAX_RETRIES,
                retry_after,
            )
            time.sleep(retry_after)

    detail = f" Details: {last_error}" if last_error else ""
    raise AIProviderError(
        f"{provider_name} rate limit exceeded after {RATE_LIMIT_MAX_RETRIES} retries.{detail}"
    ) from last_error


class ClaudeProvider(AIProvider):
    """Anthropic Claude provider implementation.

    Uses the ``anthropic`` Python SDK to communicate with the Anthropic
    Messages API. Supports both synchronous and streaming generation,
    CSV file attachments via content blocks (base64-encoded PDFs or
    inline text), and automatic token-limit retry when the requested
    ``max_tokens`` exceeds the model's supported maximum.

    For long-running requests where the Anthropic SDK requires streaming,
    the provider transparently falls back from ``messages.create`` to
    ``messages.stream``.

    Attributes:
        api_key (str): The Anthropic API key.
        model (str): The Claude model identifier (e.g., ``"claude-opus-4-6"``).
        attach_csv_as_file (bool): Whether to upload CSV artifacts as
            content blocks rather than inlining them in the prompt.
        client: The ``anthropic.Anthropic`` SDK client instance.
    """

    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_CLAUDE_MODEL,
        attach_csv_as_file: bool = True,
    ) -> None:
        """Initialize the Claude provider.

        Args:
            api_key: Anthropic API key. Must be non-empty.
            model: Claude model identifier to use for completions.
            attach_csv_as_file: If ``True``, attempt to send CSV artifacts
                as structured content blocks.

        Raises:
            AIProviderError: If the ``anthropic`` SDK is not installed or
                the API key is empty.
        """
        try:
            import anthropic
        except ImportError as error:
            raise AIProviderError(
                "anthropic SDK is not installed. Install it with `pip install anthropic`."
            ) from error

        normalized_api_key = _normalize_api_key_value(api_key)
        if not normalized_api_key:
            raise AIProviderError(
                "Claude API key is not configured. "
                "Set `ai.claude.api_key` in config.yaml or the ANTHROPIC_API_KEY environment variable."
            )

        self._anthropic = anthropic
        self.api_key = normalized_api_key
        self.model = model
        self.attach_csv_as_file = bool(attach_csv_as_file)
        self._csv_attachment_supported: bool | None = None
        self.client = anthropic.Anthropic(api_key=normalized_api_key)
        logger.info("Initialized Claude provider with model %s", model)

    def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> str:
        """Send a prompt to Claude and return the generated text.

        Delegates to ``analyze_with_attachments`` with no attachments.

        Args:
            system_prompt: The system-level instruction text.
            user_prompt: The user-facing prompt with investigation context.
            max_tokens: Maximum completion tokens.

        Returns:
            The generated analysis text.

        Raises:
            AIProviderError: On any API or network failure.
        """
        return self.analyze_with_attachments(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            attachments=None,
            max_tokens=max_tokens,
        )

    def analyze_stream(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> Iterator[str]:
        """Stream generated text chunks from Claude.

        Creates a streaming Messages API request and yields text deltas
        as they arrive. Handles rate-limit retries, token-limit retries,
        and translates SDK exceptions into ``AIProviderError``.

        Args:
            system_prompt: The system-level instruction text.
            user_prompt: The user-facing prompt with investigation context.
            max_tokens: Maximum completion tokens.

        Yields:
            Text chunk strings as they are generated by the model.

        Raises:
            AIProviderError: On empty response, network failure,
                authentication error, context overflow, or other API error.
        """
        def _stream() -> Iterator[str]:
            request_kwargs: dict[str, Any] = {
                "model": self.model,
                "max_tokens": max_tokens,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_prompt}],
                "stream": True,
            }
            try:
                stream = _run_with_rate_limit_retries(
                    request_fn=lambda: self._create_streaming_messages_with_token_limit_retry(request_kwargs),
                    rate_limit_error_type=self._anthropic.RateLimitError,
                    provider_name="Claude",
                )
                emitted = False
                for event in stream:
                    chunk_text = _extract_anthropic_stream_text(event)
                    if not chunk_text:
                        continue
                    emitted = True
                    yield chunk_text
                if not emitted:
                    raise AIProviderError("Claude returned an empty response.")
            except AIProviderError:
                raise
            except self._anthropic.APIConnectionError as error:
                raise AIProviderError(
                    "Unable to connect to Claude API. Check network access and endpoint configuration."
                ) from error
            except self._anthropic.AuthenticationError as error:
                raise AIProviderError(
                    "Claude authentication failed. Check `ai.claude.api_key` or ANTHROPIC_API_KEY."
                ) from error
            except self._anthropic.BadRequestError as error:
                if _is_context_length_error(error):
                    raise AIProviderError(
                        "Claude request exceeded the model context length. Reduce prompt size and retry."
                    ) from error
                raise AIProviderError(f"Claude request was rejected: {error}") from error
            except self._anthropic.APIError as error:
                raise AIProviderError(f"Claude API error: {error}") from error
            except Exception as error:
                raise AIProviderError(f"Unexpected Claude provider error: {error}") from error

        return _stream()

    def analyze_with_attachments(
        self,
        system_prompt: str,
        user_prompt: str,
        attachments: list[Mapping[str, str]] | None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> str:
        """Analyze with optional CSV file attachments via Claude content blocks.

        First attempts to send attachments as structured content blocks
        (base64-encoded PDFs or inline text). If that fails or attachments
        are not provided, falls back to a plain text prompt.

        Args:
            system_prompt: The system-level instruction text.
            user_prompt: The user-facing prompt with investigation context.
            attachments: Optional list of attachment descriptors.
            max_tokens: Maximum completion tokens.

        Returns:
            The generated analysis text.

        Raises:
            AIProviderError: On any API or network failure.
        """
        def _request() -> str:
            attachment_response = self._request_with_csv_attachments(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=max_tokens,
                attachments=attachments,
            )
            if attachment_response:
                return attachment_response

            response = self._create_message_with_stream_fallback(
                system_prompt=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
                max_tokens=max_tokens,
            )
            text = _extract_anthropic_text(response)
            if not text:
                raise AIProviderError("Claude returned an empty response.")
            return text

        return self._run_claude_request(_request)

    def _run_claude_request(self, request_fn: Callable[[], _T]) -> _T:
        """Execute a Claude request with rate-limit retries and error mapping.

        Wraps the given callable with rate-limit retry logic and translates
        all Anthropic SDK exceptions into ``AIProviderError``.

        Args:
            request_fn: A zero-argument callable that performs the Claude
                API request and returns the result.

        Returns:
            The return value of ``request_fn`` on success.

        Raises:
            AIProviderError: On connection failure, authentication error,
                context overflow, bad request, or any other API error.
        """
        try:
            return _run_with_rate_limit_retries(
                request_fn=request_fn,
                rate_limit_error_type=self._anthropic.RateLimitError,
                provider_name="Claude",
            )
        except AIProviderError:
            raise
        except self._anthropic.APIConnectionError as error:
            raise AIProviderError(
                "Unable to connect to Claude API. Check network access and endpoint configuration."
            ) from error
        except self._anthropic.AuthenticationError as error:
            raise AIProviderError(
                "Claude authentication failed. Check `ai.claude.api_key` or ANTHROPIC_API_KEY."
            ) from error
        except self._anthropic.BadRequestError as error:
            if _is_context_length_error(error):
                raise AIProviderError(
                    "Claude request exceeded the model context length. Reduce prompt size and retry."
                ) from error
            raise AIProviderError(f"Claude request was rejected: {error}") from error
        except self._anthropic.APIError as error:
            raise AIProviderError(f"Claude API error: {error}") from error
        except Exception as error:
            raise AIProviderError(f"Unexpected Claude provider error: {error}") from error

    def _request_with_csv_attachments(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int,
        attachments: list[Mapping[str, str]] | None,
    ) -> str | None:
        """Attempt to send a request with CSV files as Claude content blocks.

        Builds structured content blocks from the attachments (base64
        for PDFs, inline text for other types) and sends them alongside
        the user prompt. Falls back to ``None`` if attachments are not
        supported or not provided.

        Args:
            system_prompt: The system-level instruction text.
            user_prompt: The user-facing prompt text.
            max_tokens: Maximum completion tokens.
            attachments: Optional list of attachment descriptors.

        Returns:
            The generated text if attachment mode succeeded, or ``None``
            if attachments were skipped or unsupported.

        Raises:
            AIProviderError: If the request fails for a reason other than
                unsupported attachments.
        """
        normalized_attachments = self._prepare_csv_attachments(attachments)
        if not normalized_attachments:
            return None

        try:
            content_blocks: list[dict[str, Any]] = [{"type": "text", "text": user_prompt}]
            for attachment in normalized_attachments:
                attachment_path = Path(attachment["path"])
                mime_type = attachment["mime_type"].lower()
                if mime_type == "application/pdf":
                    encoded_data = base64.b64encode(attachment_path.read_bytes()).decode("ascii")
                    content_blocks.append(
                        {
                            "type": "document",
                            "source": {
                                "type": "base64",
                                "media_type": "application/pdf",
                                "data": encoded_data,
                            },
                        }
                    )
                else:
                    attachment_name = attachment.get("name", attachment_path.name)
                    try:
                        attachment_text = attachment_path.read_text(
                            encoding="utf-8-sig", errors="replace"
                        )
                    except OSError:
                        continue
                    content_blocks.append(
                        {
                            "type": "text",
                            "text": (
                                f"--- BEGIN ATTACHMENT: {attachment_name} ---\n"
                                f"{attachment_text.rstrip()}\n"
                                f"--- END ATTACHMENT: {attachment_name} ---"
                            ),
                        }
                    )

            response = self._create_message_with_stream_fallback(
                system_prompt=system_prompt,
                messages=[{"role": "user", "content": content_blocks}],
                max_tokens=max_tokens,
            )
            text = _extract_anthropic_text(response)
            if not text:
                raise AIProviderError("Claude returned an empty response for file-attachment mode.")

            self._csv_attachment_supported = True
            return text
        except Exception as error:
            if _is_attachment_unsupported_error(error):
                self._csv_attachment_supported = False
                logger.info(
                    "Claude endpoint does not support CSV attachments; "
                    "falling back to standard text mode."
                )
                return None
            raise

    def _create_message_with_stream_fallback(
        self,
        system_prompt: str,
        messages: list[dict[str, Any]],
        max_tokens: int,
    ) -> Any:
        """Create a Claude message, falling back to streaming for long requests.

        First attempts a non-streaming ``messages.create`` call. If the
        Anthropic SDK raises a ``ValueError`` indicating that streaming is
        required (for requests expected to exceed 10 minutes), retries
        using ``messages.stream`` instead.

        Args:
            system_prompt: The system-level instruction text.
            messages: The conversation messages list for the API call.
            max_tokens: Maximum completion tokens.

        Returns:
            The Anthropic ``Message`` response object.

        Raises:
            ValueError: If the error is not a streaming-required error.
            anthropic.BadRequestError: If the request is rejected for
                reasons other than token limits.
        """
        request_kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "system": system_prompt,
            "messages": messages,
        }
        try:
            return self._create_non_stream_with_token_limit_retry(request_kwargs)
        except ValueError as error:
            if not _is_anthropic_streaming_required_error(error):
                raise
            logger.info(
                "Claude SDK requires streaming for long request; retrying with messages.stream()."
            )
            return self._create_stream_with_token_limit_retry(request_kwargs)

    def _create_non_stream_with_token_limit_retry(self, request_kwargs: Mapping[str, Any]) -> Any:
        """Create a non-streaming message with automatic token-limit retry.

        If the initial request is rejected because ``max_tokens`` exceeds
        the model's supported maximum, retries once with the lower limit
        extracted from the error message.

        Args:
            request_kwargs: Keyword arguments to pass to
                ``client.messages.create``.

        Returns:
            The Anthropic ``Message`` response object.

        Raises:
            anthropic.BadRequestError: If the request fails for a reason
                other than token limits, or if the retry also fails.
        """
        effective_kwargs: dict[str, Any] = dict(request_kwargs)
        for _ in range(2):
            try:
                return self.client.messages.create(**effective_kwargs)
            except self._anthropic.BadRequestError as error:
                requested_tokens = int(effective_kwargs.get("max_tokens", 0))
                retry_token_count = _resolve_completion_token_retry_limit(
                    error=error,
                    requested_tokens=requested_tokens,
                )
                if retry_token_count is None:
                    raise
                logger.warning(
                    "Claude rejected max_tokens=%d; retrying with max_tokens=%d.",
                    requested_tokens,
                    retry_token_count,
                )
                effective_kwargs["max_tokens"] = retry_token_count
        return self.client.messages.create(**effective_kwargs)

    def _create_stream_with_token_limit_retry(self, request_kwargs: Mapping[str, Any]) -> Any:
        """Create a streamed message with automatic token-limit retry.

        Uses ``messages.stream`` context manager and collects the final
        message. If rejected due to token limits, retries once with the
        provider-declared maximum.

        Args:
            request_kwargs: Keyword arguments to pass to
                ``client.messages.stream``.

        Returns:
            The final Anthropic ``Message`` response object.

        Raises:
            anthropic.BadRequestError: If the request fails for a reason
                other than token limits, or if the retry also fails.
        """
        effective_kwargs: dict[str, Any] = dict(request_kwargs)
        for _ in range(2):
            try:
                with self.client.messages.stream(**effective_kwargs) as stream:
                    return stream.get_final_message()
            except self._anthropic.BadRequestError as error:
                requested_tokens = int(effective_kwargs.get("max_tokens", 0))
                retry_token_count = _resolve_completion_token_retry_limit(
                    error=error,
                    requested_tokens=requested_tokens,
                )
                if retry_token_count is None:
                    raise
                logger.warning(
                    "Claude rejected max_tokens=%d during streamed request; retrying with max_tokens=%d.",
                    requested_tokens,
                    retry_token_count,
                )
                effective_kwargs["max_tokens"] = retry_token_count
        with self.client.messages.stream(**effective_kwargs) as stream:
            return stream.get_final_message()

    def _create_streaming_messages_with_token_limit_retry(self, request_kwargs: Mapping[str, Any]) -> Any:
        """Create a streaming ``messages.create`` call with token-limit retry.

        Similar to ``_create_non_stream_with_token_limit_retry`` but used
        for requests where ``stream=True`` is already set in the kwargs.
        Retries once with a reduced ``max_tokens`` if the provider rejects
        the original value.

        Args:
            request_kwargs: Keyword arguments to pass to
                ``client.messages.create`` (should include ``stream=True``).

        Returns:
            The streaming response iterator from ``messages.create``.

        Raises:
            anthropic.BadRequestError: If the request fails for a reason
                other than token limits, or if the retry also fails.
        """
        effective_kwargs: dict[str, Any] = dict(request_kwargs)
        for _ in range(2):
            try:
                return self.client.messages.create(**effective_kwargs)
            except self._anthropic.BadRequestError as error:
                requested_tokens = int(effective_kwargs.get("max_tokens", 0))
                retry_token_count = _resolve_completion_token_retry_limit(
                    error=error,
                    requested_tokens=requested_tokens,
                )
                if retry_token_count is None:
                    raise
                logger.warning(
                    "Claude rejected max_tokens=%d during streamed create request; retrying with max_tokens=%d.",
                    requested_tokens,
                    retry_token_count,
                )
                effective_kwargs["max_tokens"] = retry_token_count
        return self.client.messages.create(**effective_kwargs)

    def get_model_info(self) -> dict[str, str]:
        """Return Claude provider and model metadata.

        Returns:
            A dictionary with ``"provider"`` set to ``"claude"`` and
            ``"model"`` set to the configured model identifier.
        """
        return {"provider": "claude", "model": self.model}


class OpenAIProvider(AIProvider):
    """OpenAI API provider implementation.

    Uses the ``openai`` Python SDK to communicate with the OpenAI Chat
    Completions and Responses APIs. Supports synchronous and streaming
    generation, CSV file attachments via the Responses API file upload,
    and automatic fallback between ``max_completion_tokens`` and
    ``max_tokens`` parameters for backward compatibility.

    Attributes:
        api_key (str): The OpenAI API key.
        model (str): The OpenAI model identifier (e.g., ``"gpt-5.2"``).
        attach_csv_as_file (bool): Whether to upload CSV artifacts as
            file attachments via the Responses API.
        client: The ``openai.OpenAI`` SDK client instance.
    """

    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_OPENAI_MODEL,
        attach_csv_as_file: bool = True,
    ) -> None:
        """Initialize the OpenAI provider.

        Args:
            api_key: OpenAI API key. Must be non-empty.
            model: OpenAI model identifier to use for completions.
            attach_csv_as_file: If ``True``, attempt to send CSV artifacts
                as file uploads via the Responses API.

        Raises:
            AIProviderError: If the ``openai`` SDK is not installed or
                the API key is empty.
        """
        try:
            import openai
        except ImportError as error:
            raise AIProviderError(
                "openai SDK is not installed. Install it with `pip install openai`."
            ) from error

        normalized_api_key = _normalize_api_key_value(api_key)
        if not normalized_api_key:
            raise AIProviderError(
                "OpenAI API key is not configured. "
                "Set `ai.openai.api_key` in config.yaml or the OPENAI_API_KEY environment variable."
            )

        self._openai = openai
        self.api_key = normalized_api_key
        self.model = model
        self.attach_csv_as_file = bool(attach_csv_as_file)
        self._csv_attachment_supported: bool | None = None
        self.client = openai.OpenAI(api_key=normalized_api_key)
        logger.info("Initialized OpenAI provider with model %s", model)

    def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> str:
        """Send a prompt to OpenAI and return the generated text.

        Delegates to ``analyze_with_attachments`` with no attachments.

        Args:
            system_prompt: The system-level instruction text.
            user_prompt: The user-facing prompt with investigation context.
            max_tokens: Maximum completion tokens.

        Returns:
            The generated analysis text.

        Raises:
            AIProviderError: On any API or network failure.
        """
        return self.analyze_with_attachments(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            attachments=None,
            max_tokens=max_tokens,
        )

    def analyze_stream(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> Iterator[str]:
        """Stream generated text chunks from OpenAI.

        Creates a streaming Chat Completions API request and yields text
        deltas as they arrive. Handles rate-limit retries, token-limit
        fallback, and translates SDK exceptions into ``AIProviderError``.

        Args:
            system_prompt: The system-level instruction text.
            user_prompt: The user-facing prompt with investigation context.
            max_tokens: Maximum completion tokens.

        Yields:
            Text chunk strings as they are generated by the model.

        Raises:
            AIProviderError: On empty response, network failure,
                authentication error, context overflow, or other API error.
        """
        def _stream() -> Iterator[str]:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ]
            stream = self._run_openai_request(
                lambda: self._create_chat_completion_stream(
                    messages=messages,
                    max_tokens=max_tokens,
                )
            )
            emitted = False
            try:
                for chunk in stream:
                    choices = getattr(chunk, "choices", None)
                    if not choices:
                        continue
                    choice = choices[0]
                    delta = getattr(choice, "delta", None)
                    if delta is None and isinstance(choice, dict):
                        delta = choice.get("delta")
                    chunk_text = _extract_openai_delta_text(
                        delta,
                        ("content", "reasoning_content", "reasoning", "refusal"),
                    )
                    if not chunk_text:
                        continue
                    emitted = True
                    yield chunk_text
            except AIProviderError:
                raise
            except self._openai.APIConnectionError as error:
                raise AIProviderError(
                    "Unable to connect to OpenAI API. Check network access and endpoint configuration."
                ) from error
            except self._openai.AuthenticationError as error:
                raise AIProviderError(
                    "OpenAI authentication failed. Check `ai.openai.api_key` or OPENAI_API_KEY."
                ) from error
            except self._openai.BadRequestError as error:
                if _is_context_length_error(error):
                    raise AIProviderError(
                        "OpenAI request exceeded the model context length. Reduce prompt size and retry."
                    ) from error
                raise AIProviderError(f"OpenAI request was rejected: {error}") from error
            except self._openai.APIError as error:
                raise AIProviderError(f"OpenAI API error: {error}") from error
            except Exception as error:
                raise AIProviderError(f"Unexpected OpenAI provider error: {error}") from error

            if not emitted:
                raise AIProviderError("OpenAI returned an empty response.")

        return _stream()

    def analyze_with_attachments(
        self,
        system_prompt: str,
        user_prompt: str,
        attachments: list[Mapping[str, str]] | None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> str:
        """Analyze with optional CSV file attachments via the Responses API.

        Attempts file upload via OpenAI's Responses API first, then falls
        back to inlining attachment data into the prompt or using plain
        Chat Completions.

        Args:
            system_prompt: The system-level instruction text.
            user_prompt: The user-facing prompt with investigation context.
            attachments: Optional list of attachment descriptors.
            max_tokens: Maximum completion tokens.

        Returns:
            The generated analysis text.

        Raises:
            AIProviderError: On any API or network failure.
        """
        def _request() -> str:
            return self._request_non_stream(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=max_tokens,
                attachments=attachments,
            )

        return self._run_openai_request(_request)

    def _run_openai_request(self, request_fn: Callable[[], _T]) -> _T:
        """Execute an OpenAI request with rate-limit retries and error mapping.

        Wraps the given callable with rate-limit retry logic and translates
        all OpenAI SDK exceptions into ``AIProviderError``.

        Args:
            request_fn: A zero-argument callable that performs the OpenAI
                API request and returns the result.

        Returns:
            The return value of ``request_fn`` on success.

        Raises:
            AIProviderError: On connection failure, authentication error,
                context overflow, bad request, or any other API error.
        """
        try:
            return _run_with_rate_limit_retries(
                request_fn=request_fn,
                rate_limit_error_type=self._openai.RateLimitError,
                provider_name="OpenAI",
            )
        except AIProviderError:
            raise
        except self._openai.APIConnectionError as error:
            raise AIProviderError(
                "Unable to connect to OpenAI API. Check network access and endpoint configuration."
            ) from error
        except self._openai.AuthenticationError as error:
            raise AIProviderError(
                "OpenAI authentication failed. Check `ai.openai.api_key` or OPENAI_API_KEY."
            ) from error
        except self._openai.BadRequestError as error:
            if _is_context_length_error(error):
                raise AIProviderError(
                    "OpenAI request exceeded the model context length. Reduce prompt size and retry."
                ) from error
            raise AIProviderError(f"OpenAI request was rejected: {error}") from error
        except self._openai.APIError as error:
            raise AIProviderError(f"OpenAI API error: {error}") from error
        except Exception as error:
            raise AIProviderError(f"Unexpected OpenAI provider error: {error}") from error

    def _request_non_stream(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int,
        attachments: list[Mapping[str, str]] | None = None,
    ) -> str:
        """Perform a non-streaming OpenAI request with attachment handling.

        Tries file-attachment mode first, then falls back to inlining
        attachment data into the prompt, and finally issues a plain
        Chat Completions request.

        Args:
            system_prompt: The system-level instruction text.
            user_prompt: The user-facing prompt text.
            max_tokens: Maximum completion tokens.
            attachments: Optional list of attachment descriptors.

        Returns:
            The generated analysis text.

        Raises:
            AIProviderError: If the response is empty or the API rejects
                the request.
        """
        attachment_response = self._request_with_csv_attachments(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=max_tokens,
            attachments=attachments,
        )
        if attachment_response:
            return attachment_response

        prompt_for_completion = user_prompt
        if attachments and self.attach_csv_as_file:
            prompt_for_completion, inlined_attachment_data = _inline_attachment_data_into_prompt(
                user_prompt=user_prompt,
                attachments=attachments,
            )
            if inlined_attachment_data:
                logger.info("OpenAI attachment fallback inlined attachment data into prompt.")

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt_for_completion},
        ]
        response = self._create_chat_completion(
            messages=messages,
            max_tokens=max_tokens,
        )
        text = _extract_openai_text(response)
        if not text:
            raise AIProviderError("OpenAI returned an empty response.")
        return text

    def _create_chat_completion(
        self,
        messages: list[dict[str, str]],
        max_tokens: int,
    ) -> Any:
        """Create a Chat Completions request with token parameter fallback.

        Tries ``max_completion_tokens`` first (newer API parameter), then
        falls back to ``max_tokens`` if the endpoint reports the parameter
        as unsupported. Also retries with a reduced token count when the
        provider rejects the requested maximum.

        Args:
            messages: The conversation messages list for the API call.
            max_tokens: Maximum completion tokens.

        Returns:
            The OpenAI ``ChatCompletion`` response object.

        Raises:
            openai.BadRequestError: If the request is rejected for reasons
                other than unsupported parameters or token limits.
        """
        def _create_with_token_parameter(token_parameter: str, token_count: int) -> Any:
            request_kwargs: dict[str, Any] = {
                "model": self.model,
                "messages": messages,
                token_parameter: token_count,
            }
            try:
                return self.client.chat.completions.create(**request_kwargs)
            except self._openai.BadRequestError as error:
                retry_token_count = _resolve_completion_token_retry_limit(
                    error=error,
                    requested_tokens=token_count,
                )
                if retry_token_count is None:
                    raise
                logger.warning(
                    "OpenAI rejected %s=%d; retrying with %s=%d.",
                    token_parameter,
                    token_count,
                    token_parameter,
                    retry_token_count,
                )
                request_kwargs[token_parameter] = retry_token_count
                return self.client.chat.completions.create(**request_kwargs)

        try:
            return _create_with_token_parameter(
                token_parameter="max_completion_tokens",
                token_count=max_tokens,
            )
        except self._openai.BadRequestError as error:
            if not _is_unsupported_parameter_error(error, "max_completion_tokens"):
                raise
            return _create_with_token_parameter(
                token_parameter="max_tokens",
                token_count=max_tokens,
            )

    def _create_chat_completion_stream(
        self,
        messages: list[dict[str, str]],
        max_tokens: int,
    ) -> Any:
        """Create a streaming Chat Completions request with token parameter fallback.

        Identical to ``_create_chat_completion`` but with ``stream=True``.
        Tries ``max_completion_tokens`` first, then falls back to
        ``max_tokens`` if unsupported.

        Args:
            messages: The conversation messages list for the API call.
            max_tokens: Maximum completion tokens.

        Returns:
            A streaming response iterator from ``chat.completions.create``.

        Raises:
            openai.BadRequestError: If the request is rejected for reasons
                other than unsupported parameters or token limits.
        """
        def _create_with_token_parameter(token_parameter: str, token_count: int) -> Any:
            request_kwargs: dict[str, Any] = {
                "model": self.model,
                "messages": messages,
                token_parameter: token_count,
                "stream": True,
            }
            try:
                return self.client.chat.completions.create(**request_kwargs)
            except self._openai.BadRequestError as error:
                retry_token_count = _resolve_completion_token_retry_limit(
                    error=error,
                    requested_tokens=token_count,
                )
                if retry_token_count is None:
                    raise
                logger.warning(
                    "OpenAI rejected %s=%d for streaming; retrying with %s=%d.",
                    token_parameter,
                    token_count,
                    token_parameter,
                    retry_token_count,
                )
                request_kwargs[token_parameter] = retry_token_count
                return self.client.chat.completions.create(**request_kwargs)

        try:
            return _create_with_token_parameter(
                token_parameter="max_completion_tokens",
                token_count=max_tokens,
            )
        except self._openai.BadRequestError as error:
            if not _is_unsupported_parameter_error(error, "max_completion_tokens"):
                raise
            return _create_with_token_parameter(
                token_parameter="max_tokens",
                token_count=max_tokens,
            )

    def _request_with_csv_attachments(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int,
        attachments: list[Mapping[str, str]] | None,
    ) -> str | None:
        """Attempt to send a request with CSV files via the OpenAI Responses API.

        Uploads each attachment as a file, builds a Responses API request
        with ``input_file`` references, and extracts the output text.
        Cleans up uploaded files in the ``finally`` block.

        Args:
            system_prompt: The system-level instruction text.
            user_prompt: The user-facing prompt text.
            max_tokens: Maximum completion tokens.
            attachments: Optional list of attachment descriptors.

        Returns:
            The generated text if attachment mode succeeded, or ``None``
            if attachments were skipped or unsupported.

        Raises:
            AIProviderError: If the request fails for a reason other than
                unsupported attachments.
        """
        normalized_attachments = self._prepare_csv_attachments(
            attachments,
            supports_file_attachments=hasattr(self.client, "files") and hasattr(self.client, "responses"),
        )
        if not normalized_attachments:
            return None

        uploaded_file_ids: list[str] = []
        try:
            for attachment in normalized_attachments:
                attachment_path = Path(attachment["path"])
                upload_name, upload_mime_type, converted_from_csv = _prepare_openai_attachment_upload(
                    attachment
                )
                if converted_from_csv:
                    logger.debug(
                        "Converting OpenAI attachment upload from CSV to TXT: %s -> %s",
                        attachment.get("name", attachment_path.name),
                        upload_name,
                    )
                with attachment_path.open("rb") as handle:
                    uploaded = self.client.files.create(
                        file=(upload_name, handle.read(), upload_mime_type),
                        purpose="assistants",
                    )

                file_id = getattr(uploaded, "id", None)
                if file_id is None and isinstance(uploaded, dict):
                    file_id = uploaded.get("id")
                if not isinstance(file_id, str) or not file_id.strip():
                    raise AIProviderError("OpenAI file upload returned no file id.")
                uploaded_file_ids.append(file_id)

            user_content: list[dict[str, str]] = [{"type": "input_text", "text": user_prompt}]
            for file_id in uploaded_file_ids:
                user_content.append({"type": "input_file", "file_id": file_id})

            response_request: dict[str, Any] = {
                "model": self.model,
                "input": [
                    {"role": "system", "content": [{"type": "input_text", "text": system_prompt}]},
                    {"role": "user", "content": user_content},
                ],
                "max_output_tokens": max_tokens,
            }
            try:
                response = self.client.responses.create(**response_request)
            except self._openai.BadRequestError as error:
                retry_token_count = _resolve_completion_token_retry_limit(
                    error=error,
                    requested_tokens=max_tokens,
                )
                if retry_token_count is None:
                    raise
                logger.warning(
                    "OpenAI rejected max_output_tokens=%d; retrying with max_output_tokens=%d.",
                    max_tokens,
                    retry_token_count,
                )
                response_request["max_output_tokens"] = retry_token_count
                response = self.client.responses.create(**response_request)
            text = _extract_openai_responses_text(response)
            if not text:
                raise AIProviderError("OpenAI returned an empty response for file-attachment mode.")

            self._csv_attachment_supported = True
            return text
        except Exception as error:
            if _is_attachment_unsupported_error(error):
                self._csv_attachment_supported = False
                logger.info(
                    "OpenAI endpoint does not support CSV attachments via /files + /responses; "
                    "falling back to chat.completions text mode."
                )
                return None
            raise
        finally:
            for uploaded_file_id in uploaded_file_ids:
                try:
                    self.client.files.delete(uploaded_file_id)
                except Exception:
                    continue

    def get_model_info(self) -> dict[str, str]:
        """Return OpenAI provider and model metadata.

        Returns:
            A dictionary with ``"provider"`` set to ``"openai"`` and
            ``"model"`` set to the configured model identifier.
        """
        return {"provider": "openai", "model": self.model}


class KimiProvider(AIProvider):
    """Moonshot Kimi API provider implementation.

    Uses the ``openai`` Python SDK pointed at the Moonshot Kimi API base
    URL. Supports synchronous and streaming generation, CSV file
    attachments via the Responses API, and automatic model-alias mapping
    for deprecated Kimi model identifiers.

    Attributes:
        api_key (str): The Moonshot/Kimi API key.
        model (str): The Kimi model identifier
            (e.g., ``"kimi-k2-turbo-preview"``).
        base_url (str): The normalized Kimi API base URL.
        attach_csv_as_file (bool): Whether to upload CSV artifacts as
            file attachments via the Responses API.
        client: The ``openai.OpenAI`` SDK client instance configured for
            the Kimi endpoint.
    """

    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_KIMI_MODEL,
        base_url: str = DEFAULT_KIMI_BASE_URL,
        attach_csv_as_file: bool = True,
    ) -> None:
        """Initialize the Kimi provider.

        Args:
            api_key: Moonshot/Kimi API key. Must be non-empty.
            model: Kimi model identifier to use for completions. Deprecated
                aliases are automatically mapped to current identifiers.
            base_url: Kimi API base URL. Defaults to the Moonshot production
                endpoint.
            attach_csv_as_file: If ``True``, attempt to send CSV artifacts
                as file uploads via the Responses API.

        Raises:
            AIProviderError: If the ``openai`` SDK is not installed or
                the API key is empty.
        """
        try:
            import openai
        except ImportError as error:
            raise AIProviderError(
                "openai SDK is not installed. Install it with `pip install openai`."
            ) from error

        normalized_api_key = _normalize_api_key_value(api_key)
        if not normalized_api_key:
            raise AIProviderError(
                "Kimi API key is not configured. "
                "Set `ai.kimi.api_key` in config.yaml or the MOONSHOT_API_KEY environment variable."
            )

        self._openai = openai
        self.api_key = normalized_api_key
        self.model = _normalize_kimi_model_name(model)
        self.base_url = _normalize_openai_compatible_base_url(
            base_url=base_url,
            default_base_url=DEFAULT_KIMI_BASE_URL,
        )
        self.attach_csv_as_file = bool(attach_csv_as_file)
        self._csv_attachment_supported: bool | None = None
        self.client = openai.OpenAI(api_key=normalized_api_key, base_url=self.base_url)
        logger.info("Initialized Kimi provider at %s with model %s", self.base_url, self.model)

    def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> str:
        """Send a prompt to Kimi and return the generated text.

        Delegates to ``analyze_with_attachments`` with no attachments.

        Args:
            system_prompt: The system-level instruction text.
            user_prompt: The user-facing prompt with investigation context.
            max_tokens: Maximum completion tokens.

        Returns:
            The generated analysis text.

        Raises:
            AIProviderError: On any API or network failure.
        """
        return self.analyze_with_attachments(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            attachments=None,
            max_tokens=max_tokens,
        )

    def analyze_stream(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> Iterator[str]:
        """Stream generated text chunks from Kimi.

        Creates a streaming Chat Completions API request via the Moonshot
        endpoint and yields text deltas as they arrive. Handles rate-limit
        retries, model-not-available errors, and translates SDK exceptions
        into ``AIProviderError``.

        Args:
            system_prompt: The system-level instruction text.
            user_prompt: The user-facing prompt with investigation context.
            max_tokens: Maximum completion tokens.

        Yields:
            Text chunk strings as they are generated by the model.

        Raises:
            AIProviderError: On empty response, network failure,
                authentication error, context overflow, model unavailability,
                or other API error.
        """
        def _stream() -> Iterator[str]:
            stream = self._run_kimi_request(
                lambda: self.client.chat.completions.create(
                    model=self.model,
                    max_tokens=max_tokens,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    stream=True,
                )
            )
            emitted = False
            try:
                for chunk in stream:
                    choices = getattr(chunk, "choices", None)
                    if not choices:
                        continue
                    choice = choices[0]
                    delta = getattr(choice, "delta", None)
                    if delta is None and isinstance(choice, dict):
                        delta = choice.get("delta")
                    chunk_text = _extract_openai_delta_text(
                        delta,
                        ("content", "reasoning_content", "reasoning", "refusal"),
                    )
                    if not chunk_text:
                        continue
                    emitted = True
                    yield chunk_text
            except AIProviderError:
                raise
            except self._openai.APIConnectionError as error:
                raise AIProviderError(
                    "Unable to connect to Kimi API. Check `ai.kimi.base_url` and network access."
                ) from error
            except self._openai.AuthenticationError as error:
                raise AIProviderError(
                    "Kimi authentication failed. Check `ai.kimi.api_key`, MOONSHOT_API_KEY, or KIMI_API_KEY."
                ) from error
            except self._openai.BadRequestError as error:
                if _is_context_length_error(error):
                    raise AIProviderError(
                        "Kimi request exceeded the model context length. Reduce prompt size and retry."
                    ) from error
                raise AIProviderError(f"Kimi request was rejected: {error}") from error
            except self._openai.APIError as error:
                if _is_kimi_model_not_available_error(error):
                    raise AIProviderError(
                        "Kimi rejected the configured model. "
                        f"Current model: `{self.model}`. "
                        "Set `ai.kimi.model` to a model enabled for your Moonshot account "
                        "(for example `kimi-k2-turbo-preview`) and retry."
                    ) from error
                raise AIProviderError(f"Kimi API error: {error}") from error
            except Exception as error:
                raise AIProviderError(f"Unexpected Kimi provider error: {error}") from error

            if not emitted:
                raise AIProviderError("Kimi returned an empty response.")

        return _stream()

    def analyze_with_attachments(
        self,
        system_prompt: str,
        user_prompt: str,
        attachments: list[Mapping[str, str]] | None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> str:
        """Analyze with optional CSV file attachments via the Kimi Responses API.

        Attempts file upload first, then falls back to plain Chat
        Completions if the Kimi endpoint does not support the Responses API.

        Args:
            system_prompt: The system-level instruction text.
            user_prompt: The user-facing prompt with investigation context.
            attachments: Optional list of attachment descriptors.
            max_tokens: Maximum completion tokens.

        Returns:
            The generated analysis text.

        Raises:
            AIProviderError: On any API or network failure.
        """
        def _request() -> str:
            return self._request_non_stream(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=max_tokens,
                attachments=attachments,
            )

        return self._run_kimi_request(_request)

    def _run_kimi_request(self, request_fn: Callable[[], _T]) -> _T:
        """Execute a Kimi request with rate-limit retries and error mapping.

        Wraps the given callable with rate-limit retry logic and translates
        all OpenAI SDK exceptions into ``AIProviderError`` with Kimi-specific
        error messages, including model-not-available detection.

        Args:
            request_fn: A zero-argument callable that performs the Kimi
                API request and returns the result.

        Returns:
            The return value of ``request_fn`` on success.

        Raises:
            AIProviderError: On connection failure, authentication error,
                context overflow, model unavailability, or any other API error.
        """
        try:
            return _run_with_rate_limit_retries(
                request_fn=request_fn,
                rate_limit_error_type=self._openai.RateLimitError,
                provider_name="Kimi",
            )
        except AIProviderError:
            raise
        except self._openai.APIConnectionError as error:
            raise AIProviderError(
                "Unable to connect to Kimi API. Check `ai.kimi.base_url` and network access."
            ) from error
        except self._openai.AuthenticationError as error:
            raise AIProviderError(
                "Kimi authentication failed. Check `ai.kimi.api_key`, MOONSHOT_API_KEY, or KIMI_API_KEY."
            ) from error
        except self._openai.BadRequestError as error:
            if _is_context_length_error(error):
                raise AIProviderError(
                    "Kimi request exceeded the model context length. Reduce prompt size and retry."
                ) from error
            raise AIProviderError(f"Kimi request was rejected: {error}") from error
        except self._openai.APIError as error:
            if _is_kimi_model_not_available_error(error):
                raise AIProviderError(
                    "Kimi rejected the configured model. "
                    f"Current model: `{self.model}`. "
                    "Set `ai.kimi.model` to a model enabled for your Moonshot account "
                    "(for example `kimi-k2-turbo-preview`) and retry."
                ) from error
            raise AIProviderError(f"Kimi API error: {error}") from error
        except Exception as error:
            raise AIProviderError(f"Unexpected Kimi provider error: {error}") from error

    def _request_non_stream(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int,
        attachments: list[Mapping[str, str]] | None = None,
    ) -> str:
        """Perform a non-streaming Kimi request with attachment handling.

        Tries file-attachment mode first via the Responses API, then falls
        back to a plain Chat Completions request.

        Args:
            system_prompt: The system-level instruction text.
            user_prompt: The user-facing prompt text.
            max_tokens: Maximum completion tokens.
            attachments: Optional list of attachment descriptors.

        Returns:
            The generated analysis text.

        Raises:
            AIProviderError: If the response is empty or the API rejects
                the request.
        """
        attachment_response = self._request_with_csv_attachments(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=max_tokens,
            attachments=attachments,
        )
        if attachment_response:
            return attachment_response

        response = self.client.chat.completions.create(
            model=self.model,
            max_tokens=max_tokens,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
        )
        text = _extract_openai_text(response)
        if not text:
            raise AIProviderError("Kimi returned an empty response.")
        return text

    def _request_with_csv_attachments(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int,
        attachments: list[Mapping[str, str]] | None,
    ) -> str | None:
        """Attempt to send a request with CSV files via the Kimi Responses API.

        Uploads each attachment using the ``file-extract`` purpose, builds
        a Responses API request with ``input_file`` references, and extracts
        the output text. Cleans up uploaded files in the ``finally`` block.

        Args:
            system_prompt: The system-level instruction text.
            user_prompt: The user-facing prompt text.
            max_tokens: Maximum completion tokens.
            attachments: Optional list of attachment descriptors.

        Returns:
            The generated text if attachment mode succeeded, or ``None``
            if attachments were skipped or unsupported.

        Raises:
            AIProviderError: If the request fails for a reason other than
                unsupported attachments.
        """
        normalized_attachments = self._prepare_csv_attachments(
            attachments,
            supports_file_attachments=hasattr(self.client, "files") and hasattr(self.client, "responses"),
        )
        if not normalized_attachments:
            return None

        uploaded_file_ids: list[str] = []
        try:
            for attachment in normalized_attachments:
                attachment_path = Path(attachment["path"])
                with attachment_path.open("rb") as handle:
                    uploaded = self.client.files.create(
                        file=(attachment["name"], handle.read(), attachment["mime_type"]),
                        purpose=DEFAULT_KIMI_FILE_UPLOAD_PURPOSE,
                    )

                file_id = getattr(uploaded, "id", None)
                if file_id is None and isinstance(uploaded, dict):
                    file_id = uploaded.get("id")
                if not isinstance(file_id, str) or not file_id.strip():
                    raise AIProviderError("Kimi file upload returned no file id.")
                uploaded_file_ids.append(file_id)

            user_content: list[dict[str, str]] = [{"type": "input_text", "text": user_prompt}]
            for file_id in uploaded_file_ids:
                user_content.append({"type": "input_file", "file_id": file_id})

            response = self.client.responses.create(
                model=self.model,
                input=[
                    {"role": "system", "content": [{"type": "input_text", "text": system_prompt}]},
                    {"role": "user", "content": user_content},
                ],
                max_output_tokens=max_tokens,
            )
            text = _extract_openai_responses_text(response)
            if not text:
                raise AIProviderError("Kimi returned an empty response for file-attachment mode.")

            self._csv_attachment_supported = True
            return text
        except Exception as error:
            if _is_attachment_unsupported_error(error):
                self._csv_attachment_supported = False
                logger.info(
                    "Kimi endpoint does not support CSV attachments via /files + /responses; "
                    "falling back to chat.completions text mode."
                )
                return None
            raise
        finally:
            for uploaded_file_id in uploaded_file_ids:
                try:
                    self.client.files.delete(uploaded_file_id)
                except Exception:
                    continue

    def get_model_info(self) -> dict[str, str]:
        """Return Kimi provider and model metadata.

        Returns:
            A dictionary with ``"provider"`` set to ``"kimi"`` and
            ``"model"`` set to the configured model identifier.
        """
        return {"provider": "kimi", "model": self.model}


class LocalProvider(AIProvider):
    """OpenAI-compatible local provider implementation.

    Uses the ``openai`` Python SDK pointed at a local OpenAI-compatible
    endpoint (Ollama, LM Studio, vLLM, or similar). Supports synchronous
    and streaming generation, CSV file attachments via the Responses API
    when available, automatic reasoning-block stripping for local
    reasoning models, and configurable request timeouts.

    Attributes:
        base_url (str): The normalized local endpoint base URL.
        model (str): The local model identifier (e.g., ``"llama3.1:70b"``).
        api_key (str): The API key for the local endpoint (often
            ``"not-needed"``).
        attach_csv_as_file (bool): Whether to attempt file-attachment
            mode via the Responses API.
        request_timeout_seconds (float): HTTP timeout in seconds for
            requests to the local endpoint.
        client: The ``openai.OpenAI`` SDK client instance configured for
            the local endpoint.
    """

    def __init__(
        self,
        base_url: str,
        model: str,
        api_key: str = "not-needed",
        attach_csv_as_file: bool = True,
        request_timeout_seconds: float = DEFAULT_LOCAL_REQUEST_TIMEOUT_SECONDS,
    ) -> None:
        """Initialize the local provider.

        Args:
            base_url: Base URL for the local OpenAI-compatible endpoint.
                Automatically normalized to include ``/v1`` if missing.
            model: Model identifier to use for completions.
            api_key: API key for the local endpoint. Defaults to
                ``"not-needed"`` for endpoints that do not require auth.
            attach_csv_as_file: If ``True``, attempt to send CSV artifacts
                as file uploads via the Responses API.
            request_timeout_seconds: HTTP timeout in seconds. Defaults to
                3600 (1 hour) to accommodate large model inference.

        Raises:
            AIProviderError: If the ``openai`` SDK is not installed.
        """
        try:
            import openai
        except ImportError as error:
            raise AIProviderError(
                "openai SDK is not installed. Install it with `pip install openai`."
            ) from error

        normalized_api_key = _normalize_api_key_value(api_key) or "not-needed"

        self._openai = openai
        self.base_url = _normalize_openai_compatible_base_url(
            base_url=base_url,
            default_base_url=DEFAULT_LOCAL_BASE_URL,
        )
        self.model = model
        self.api_key = normalized_api_key
        self.attach_csv_as_file = bool(attach_csv_as_file)
        self.request_timeout_seconds = _resolve_timeout_seconds(
            request_timeout_seconds,
            DEFAULT_LOCAL_REQUEST_TIMEOUT_SECONDS,
        )
        self._api_timeout_error_type = getattr(openai, "APITimeoutError", None)
        self._csv_attachment_supported: bool | None = None
        self.client = openai.OpenAI(
            api_key=normalized_api_key,
            base_url=self.base_url,
            timeout=self.request_timeout_seconds,
            max_retries=0,
        )
        logger.info(
            "Initialized local provider at %s with model %s (timeout %.1fs)",
            self.base_url,
            model,
            self.request_timeout_seconds,
        )

    def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> str:
        """Send a prompt to the local endpoint and return the generated text.

        Delegates to ``analyze_with_attachments`` with no attachments.

        Args:
            system_prompt: The system-level instruction text.
            user_prompt: The user-facing prompt with investigation context.
            max_tokens: Maximum completion tokens.

        Returns:
            The generated analysis text.

        Raises:
            AIProviderError: On any API or network failure.
        """
        return self.analyze_with_attachments(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            attachments=None,
            max_tokens=max_tokens,
        )

    def analyze_stream(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> Iterator[str]:
        """Stream generated text chunks from the local endpoint.

        Creates a streaming Chat Completions request and yields text deltas.
        Falls back to a non-streaming request if the endpoint reports
        that streaming is unsupported. Handles rate-limit retries, timeout
        errors, and translates SDK exceptions into ``AIProviderError``.

        Args:
            system_prompt: The system-level instruction text.
            user_prompt: The user-facing prompt with investigation context.
            max_tokens: Maximum completion tokens.

        Yields:
            Text chunk strings as they are generated by the model.

        Raises:
            AIProviderError: On empty response, timeout, connection failure,
                authentication error, context overflow, or other API error.
        """
        def _stream() -> Iterator[str]:
            try:
                prompt_for_completion = self._build_chat_completion_prompt(
                    user_prompt=user_prompt,
                    attachments=None,
                )
                try:
                    stream = _run_with_rate_limit_retries(
                        request_fn=lambda: self.client.chat.completions.create(
                            model=self.model,
                            max_tokens=max_tokens,
                            messages=[
                                {"role": "system", "content": system_prompt},
                                {"role": "user", "content": prompt_for_completion},
                            ],
                            stream=True,
                        ),
                        rate_limit_error_type=self._openai.RateLimitError,
                        provider_name="Local provider",
                    )
                except self._openai.BadRequestError as error:
                    lowered_error = str(error).lower()
                    if "stream" in lowered_error and ("unsupported" in lowered_error or "not support" in lowered_error):
                        fallback_text = self._request_non_stream(
                            system_prompt=system_prompt,
                            user_prompt=user_prompt,
                            max_tokens=max_tokens,
                            attachments=None,
                        )
                        if fallback_text:
                            yield fallback_text
                            return
                    raise

                emitted = False
                for chunk in stream:
                    choices = getattr(chunk, "choices", None)
                    if not choices:
                        continue
                    choice = choices[0]
                    delta = getattr(choice, "delta", None)
                    if delta is None and isinstance(choice, dict):
                        delta = choice.get("delta")
                    chunk_text = _extract_openai_delta_text(
                        delta,
                        ("content", "reasoning_content", "reasoning", "thinking"),
                    )
                    if not chunk_text:
                        continue
                    emitted = True
                    yield chunk_text

                if not emitted:
                    raise AIProviderError(
                        "Local AI provider returned an empty streamed response. "
                        "Try a different local model or increase max tokens."
                    )
            except AIProviderError:
                raise
            except self._openai.APIConnectionError as error:
                if (
                    self._api_timeout_error_type is not None
                    and isinstance(error, self._api_timeout_error_type)
                ) or "timeout" in str(error).lower():
                    raise AIProviderError(
                        "Local AI request timed out after "
                        f"{self.request_timeout_seconds:g} seconds. "
                        "Increase `ai.local.request_timeout_seconds` for long-running prompts."
                    ) from error
                raise AIProviderError(
                    "Unable to connect to local AI endpoint. Check `ai.local.base_url` and ensure the server is running."
                ) from error
            except self._openai.AuthenticationError as error:
                raise AIProviderError(
                    "Local AI endpoint rejected authentication. Check `ai.local.api_key` if your server requires one."
                ) from error
            except self._openai.BadRequestError as error:
                if _is_context_length_error(error):
                    raise AIProviderError(
                        "Local model request exceeded the context length. Reduce prompt size and retry."
                    ) from error
                raise AIProviderError(f"Local provider request was rejected: {error}") from error
            except self._openai.APIError as error:
                error_text = str(error).lower()
                if "404" in error_text or "not found" in error_text:
                    raise AIProviderError(
                        "Local AI endpoint returned 404 (not found). "
                        "This is often caused by a base URL missing `/v1`. "
                        f"Current base URL: {self.base_url}"
                    ) from error
                raise AIProviderError(f"Local provider API error: {error}") from error
            except Exception as error:
                raise AIProviderError(f"Unexpected local provider error: {error}") from error

        return _stream()

    def analyze_with_attachments(
        self,
        system_prompt: str,
        user_prompt: str,
        attachments: list[Mapping[str, str]] | None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> str:
        """Analyze with optional CSV file attachments via the local endpoint.

        Attempts file upload via the Responses API if available, then
        falls back to inlining attachment data into the prompt for
        Chat Completions.

        Args:
            system_prompt: The system-level instruction text.
            user_prompt: The user-facing prompt with investigation context.
            attachments: Optional list of attachment descriptors.
            max_tokens: Maximum completion tokens.

        Returns:
            The generated analysis text.

        Raises:
            AIProviderError: On any API or network failure.
        """
        def _request() -> str:
            return self._request_non_stream(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=max_tokens,
                attachments=attachments,
            )

        return self._run_local_request(_request)

    def _run_local_request(self, request_fn: Callable[[], _T]) -> _T:
        """Execute a local endpoint request with rate-limit retries and error mapping.

        Wraps the given callable with rate-limit retry logic and translates
        all OpenAI SDK exceptions into ``AIProviderError`` with local-provider
        specific error messages, including timeout and 404 detection.

        Args:
            request_fn: A zero-argument callable that performs the local
                API request and returns the result.

        Returns:
            The return value of ``request_fn`` on success.

        Raises:
            AIProviderError: On timeout, connection failure, authentication
                error, context overflow, 404 errors, or any other API error.
        """
        try:
            return _run_with_rate_limit_retries(
                request_fn=request_fn,
                rate_limit_error_type=self._openai.RateLimitError,
                provider_name="Local provider",
            )
        except AIProviderError:
            raise
        except self._openai.APIConnectionError as error:
            if (
                self._api_timeout_error_type is not None
                and isinstance(error, self._api_timeout_error_type)
            ) or "timeout" in str(error).lower():
                raise AIProviderError(
                    "Local AI request timed out after "
                    f"{self.request_timeout_seconds:g} seconds. "
                    "Increase `ai.local.request_timeout_seconds` for long-running prompts."
                ) from error
            raise AIProviderError(
                "Unable to connect to local AI endpoint. Check `ai.local.base_url` and ensure the server is running."
            ) from error
        except self._openai.AuthenticationError as error:
            raise AIProviderError(
                "Local AI endpoint rejected authentication. Check `ai.local.api_key` if your server requires one."
            ) from error
        except self._openai.BadRequestError as error:
            if _is_context_length_error(error):
                raise AIProviderError(
                    "Local model request exceeded the context length. Reduce prompt size and retry."
                ) from error
            raise AIProviderError(f"Local provider request was rejected: {error}") from error
        except self._openai.APIError as error:
            error_text = str(error).lower()
            if "404" in error_text or "not found" in error_text:
                raise AIProviderError(
                    "Local AI endpoint returned 404 (not found). "
                    "This is often caused by a base URL missing `/v1`. "
                    f"Current base URL: {self.base_url}"
                ) from error
            raise AIProviderError(f"Local provider API error: {error}") from error
        except Exception as error:
            raise AIProviderError(f"Unexpected local provider error: {error}") from error

    def analyze_with_progress(
        self,
        system_prompt: str,
        user_prompt: str,
        progress_callback: Callable[[dict[str, str]], None] | None,
        attachments: list[Mapping[str, str]] | None = None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> str:
        """Analyze with streamed progress updates when supported by the local endpoint.

        Streams the response and periodically invokes ``progress_callback``
        with accumulated thinking and answer text. Separates reasoning
        output (``reasoning_content``, ``thinking``) from answer output
        (``content``) and cleans up duplicated reasoning blocks. Falls
        back to ``analyze_with_attachments`` when no callback is provided.

        Args:
            system_prompt: The system-level instruction text.
            user_prompt: The user-facing prompt with investigation context.
            progress_callback: Optional callable that receives progress dicts
                with ``"status"``, ``"thinking_text"``, and ``"partial_text"``
                keys. May be ``None`` to skip progress reporting.
            attachments: Optional list of attachment descriptors.
            max_tokens: Maximum completion tokens.

        Returns:
            The generated analysis text with reasoning blocks removed.

        Raises:
            AIProviderError: On empty response, timeout, or any other
                API error.
        """
        if progress_callback is None:
            return self.analyze_with_attachments(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                attachments=attachments,
                max_tokens=max_tokens,
            )

        def _request() -> str:
            attachment_response = self._request_with_csv_attachments(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                max_tokens=max_tokens,
                attachments=attachments,
            )
            if attachment_response:
                cleaned_attachment_response = _strip_leading_reasoning_blocks(attachment_response)
                return cleaned_attachment_response or attachment_response.strip()

            prompt_for_completion = self._build_chat_completion_prompt(
                user_prompt=user_prompt,
                attachments=attachments,
            )

            try:
                stream = self.client.chat.completions.create(
                    model=self.model,
                    max_tokens=max_tokens,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": prompt_for_completion},
                    ],
                    stream=True,
                )
            except self._openai.BadRequestError as error:
                lowered_error = str(error).lower()
                if "stream" in lowered_error and ("unsupported" in lowered_error or "not support" in lowered_error):
                    return self._request_non_stream(
                        system_prompt=system_prompt,
                        user_prompt=user_prompt,
                        max_tokens=max_tokens,
                        attachments=attachments,
                    )
                raise

            thinking_parts: list[str] = []
            answer_parts: list[str] = []
            last_emit_at = 0.0
            last_sent_thinking = ""
            last_sent_answer = ""

            for chunk in stream:
                choices = getattr(chunk, "choices", None)
                if not choices:
                    continue
                choice = choices[0]
                delta = getattr(choice, "delta", None)
                if delta is None and isinstance(choice, dict):
                    delta = choice.get("delta")
                if delta is None:
                    continue

                answer_delta = _extract_openai_delta_text(delta, ("content",))
                thinking_delta = _extract_openai_delta_text(
                    delta,
                    ("reasoning_content", "reasoning", "thinking"),
                )

                if thinking_delta:
                    thinking_parts.append(thinking_delta)
                if answer_delta:
                    answer_parts.append(answer_delta)

                current_thinking = "".join(thinking_parts).strip()
                current_answer = _clean_streamed_answer_text(
                    answer_text="".join(answer_parts),
                    thinking_text=current_thinking,
                )

                if not current_thinking and not current_answer:
                    continue

                now = time.monotonic()
                changed = (
                    current_thinking != last_sent_thinking
                    or current_answer != last_sent_answer
                )
                if not changed:
                    continue

                # Throttle UI updates to avoid flooding SSE with tiny chunks.
                if now - last_emit_at < 0.35 and (
                    len(current_thinking) - len(last_sent_thinking) < 80
                    and len(current_answer) - len(last_sent_answer) < 80
                ):
                    continue

                last_emit_at = now
                last_sent_thinking = current_thinking
                last_sent_answer = current_answer
                try:
                    progress_callback(
                        {
                            "status": "thinking",
                            "thinking_text": current_thinking,
                            "partial_text": current_answer,
                        }
                    )
                except Exception:
                    # Progress callbacks are best-effort and must not break analysis.
                    pass

            final_thinking = "".join(thinking_parts).strip()
            final_answer = _clean_streamed_answer_text(
                answer_text="".join(answer_parts),
                thinking_text=final_thinking,
            )
            if final_answer:
                return final_answer

            if final_thinking:
                return final_thinking

            raise AIProviderError(
                "Local AI provider returned an empty streamed response. "
                "Try a different local model or increase max tokens."
            )

        return self._run_local_request(_request)

    def _request_non_stream(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int,
        attachments: list[Mapping[str, str]] | None = None,
    ) -> str:
        """Perform a non-streaming local request with attachment handling.

        Tries file-attachment mode first, then falls back to inlining
        attachment data into the prompt for a Chat Completions request.
        Strips leading reasoning blocks from the response text.

        Args:
            system_prompt: The system-level instruction text.
            user_prompt: The user-facing prompt text.
            max_tokens: Maximum completion tokens.
            attachments: Optional list of attachment descriptors.

        Returns:
            The generated analysis text with reasoning blocks removed.

        Raises:
            AIProviderError: If the response is empty or the API rejects
                the request.
        """
        attachment_response = self._request_with_csv_attachments(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            max_tokens=max_tokens,
            attachments=attachments,
        )
        if attachment_response:
            cleaned_attachment_response = _strip_leading_reasoning_blocks(attachment_response)
            if cleaned_attachment_response:
                return cleaned_attachment_response
            return attachment_response.strip()

        prompt_for_completion = self._build_chat_completion_prompt(
            user_prompt=user_prompt,
            attachments=attachments,
        )

        response = self.client.chat.completions.create(
            model=self.model,
            max_tokens=max_tokens,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt_for_completion},
            ],
        )
        text = _extract_openai_text(response)
        if text:
            cleaned_text = _strip_leading_reasoning_blocks(text)
            if cleaned_text:
                return cleaned_text
            return text.strip()

        finish_reason = None
        choices = getattr(response, "choices", None)
        if choices:
            first_choice = choices[0]
            finish_reason = getattr(first_choice, "finish_reason", None)
            if finish_reason is None and isinstance(first_choice, dict):
                finish_reason = first_choice.get("finish_reason")
        reason_detail = f" (finish_reason={finish_reason})" if finish_reason else ""
        raise AIProviderError(
            "Local AI provider returned an empty response"
            f"{reason_detail}. This can happen with reasoning-only outputs or very low token limits."
        )

    def _build_chat_completion_prompt(
        self,
        user_prompt: str,
        attachments: list[Mapping[str, str]] | None,
    ) -> str:
        """Build the user prompt for Chat Completions, inlining attachments if needed.

        When ``attach_csv_as_file`` is enabled and attachments are provided,
        inlines the attachment file contents directly into the prompt text
        as a fallback for endpoints that do not support the Responses API.

        Args:
            user_prompt: The original user-facing prompt text.
            attachments: Optional list of attachment descriptors.

        Returns:
            The prompt string, potentially with attachment data appended.
        """
        prompt_for_completion = user_prompt
        if attachments and self.attach_csv_as_file:
            prompt_for_completion, inlined_attachment_data = _inline_attachment_data_into_prompt(
                user_prompt=user_prompt,
                attachments=attachments,
            )
            if inlined_attachment_data:
                logger.info("Local attachment fallback inlined attachment data into prompt.")
        return prompt_for_completion

    def _request_with_csv_attachments(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int,
        attachments: list[Mapping[str, str]] | None,
    ) -> str | None:
        """Attempt to send a request with CSV files via the local Responses API.

        Uploads each attachment as a file, builds a Responses API request
        with ``input_file`` references, and extracts the output text.
        Cleans up uploaded files in the ``finally`` block.

        Args:
            system_prompt: The system-level instruction text.
            user_prompt: The user-facing prompt text.
            max_tokens: Maximum completion tokens.
            attachments: Optional list of attachment descriptors.

        Returns:
            The generated text if attachment mode succeeded, or ``None``
            if attachments were skipped or unsupported.

        Raises:
            AIProviderError: If the request fails for a reason other than
                unsupported attachments.
        """
        normalized_attachments = self._prepare_csv_attachments(
            attachments,
            supports_file_attachments=hasattr(self.client, "files") and hasattr(self.client, "responses"),
        )
        if not normalized_attachments:
            return None

        uploaded_file_ids: list[str] = []
        try:
            for attachment in normalized_attachments:
                attachment_path = Path(attachment["path"])
                with attachment_path.open("rb") as handle:
                    uploaded = self.client.files.create(
                        file=(attachment["name"], handle.read(), attachment["mime_type"]),
                        purpose="assistants",
                    )

                file_id = getattr(uploaded, "id", None)
                if file_id is None and isinstance(uploaded, dict):
                    file_id = uploaded.get("id")
                if not isinstance(file_id, str) or not file_id.strip():
                    raise AIProviderError("Local provider file upload returned no file id.")
                uploaded_file_ids.append(file_id)

            user_content: list[dict[str, str]] = [{"type": "input_text", "text": user_prompt}]
            for file_id in uploaded_file_ids:
                user_content.append({"type": "input_file", "file_id": file_id})

            response = self.client.responses.create(
                model=self.model,
                input=[
                    {"role": "system", "content": [{"type": "input_text", "text": system_prompt}]},
                    {"role": "user", "content": user_content},
                ],
                max_output_tokens=max_tokens,
            )
            text = _extract_openai_responses_text(response)
            if not text:
                raise AIProviderError("Local provider returned an empty response for file-attachment mode.")

            self._csv_attachment_supported = True
            return text
        except Exception as error:
            if _is_attachment_unsupported_error(error):
                self._csv_attachment_supported = False
                logger.info(
                    "Local endpoint does not support file attachments via /files + /responses; "
                    "falling back to chat.completions text mode."
                )
                return None
            raise
        finally:
            for uploaded_file_id in uploaded_file_ids:
                try:
                    self.client.files.delete(uploaded_file_id)
                except Exception:
                    continue

    def get_model_info(self) -> dict[str, str]:
        """Return local provider and model metadata.

        Returns:
            A dictionary with ``"provider"`` set to ``"local"`` and
            ``"model"`` set to the configured model identifier.
        """
        return {"provider": "local", "model": self.model}


def create_provider(config: dict[str, Any]) -> AIProvider:
    """Create and return an AI provider instance based on application config.

    Reads the ``ai.provider`` key from the configuration dictionary and
    constructs the corresponding provider class (``ClaudeProvider``,
    ``OpenAIProvider``, ``KimiProvider``, or ``LocalProvider``) with
    settings from the provider-specific sub-section. API keys are resolved
    from config values first, falling back to environment variables.

    Args:
        config: The application configuration dictionary, expected to
            contain an ``"ai"`` section with a ``"provider"`` key and
            provider-specific sub-sections (e.g., ``"ai.claude"``,
            ``"ai.openai"``).

    Returns:
        A configured ``AIProvider`` instance ready for use.

    Raises:
        ValueError: If the ``ai`` section is missing or malformed, or if
            the provider name is not one of the supported values
            (``claude``, ``openai``, ``kimi``, ``local``).
        AIProviderError: If the selected provider cannot be initialized
            (e.g., missing SDK or empty API key).
    """
    ai_config = config.get("ai", {})
    if not isinstance(ai_config, dict):
        raise ValueError("Invalid configuration: `ai` section must be a dictionary.")

    provider_name = str(ai_config.get("provider", "claude")).strip().lower()

    if provider_name == "claude":
        claude_config = ai_config.get("claude", {})
        if not isinstance(claude_config, dict):
            raise ValueError("Invalid configuration: `ai.claude` must be a dictionary.")
        api_key = _resolve_api_key(
            claude_config.get("api_key", ""),
            "ANTHROPIC_API_KEY",
        )
        return ClaudeProvider(
            api_key=api_key,
            model=str(claude_config.get("model", DEFAULT_CLAUDE_MODEL)),
            attach_csv_as_file=bool(claude_config.get("attach_csv_as_file", True)),
        )

    if provider_name == "openai":
        openai_config = ai_config.get("openai", {})
        if not isinstance(openai_config, dict):
            raise ValueError("Invalid configuration: `ai.openai` must be a dictionary.")
        api_key = _resolve_api_key(
            openai_config.get("api_key", ""),
            "OPENAI_API_KEY",
        )
        return OpenAIProvider(
            api_key=api_key,
            model=str(openai_config.get("model", DEFAULT_OPENAI_MODEL)),
            attach_csv_as_file=bool(openai_config.get("attach_csv_as_file", True)),
        )

    if provider_name == "local":
        local_config = ai_config.get("local", {})
        if not isinstance(local_config, dict):
            raise ValueError("Invalid configuration: `ai.local` must be a dictionary.")
        return LocalProvider(
            base_url=str(local_config.get("base_url", DEFAULT_LOCAL_BASE_URL)),
            model=str(local_config.get("model", DEFAULT_LOCAL_MODEL)),
            api_key=_normalize_api_key_value(local_config.get("api_key", "not-needed")) or "not-needed",
            attach_csv_as_file=bool(local_config.get("attach_csv_as_file", True)),
            request_timeout_seconds=_resolve_timeout_seconds(
                local_config.get("request_timeout_seconds", DEFAULT_LOCAL_REQUEST_TIMEOUT_SECONDS),
                DEFAULT_LOCAL_REQUEST_TIMEOUT_SECONDS,
            ),
        )

    if provider_name == "kimi":
        kimi_config = ai_config.get("kimi", {})
        if not isinstance(kimi_config, dict):
            raise ValueError("Invalid configuration: `ai.kimi` must be a dictionary.")
        api_key = _resolve_api_key_candidates(
            kimi_config.get("api_key", ""),
            ("MOONSHOT_API_KEY", "KIMI_API_KEY"),
        )
        return KimiProvider(
            api_key=api_key,
            model=str(kimi_config.get("model", DEFAULT_KIMI_MODEL)),
            base_url=str(kimi_config.get("base_url", DEFAULT_KIMI_BASE_URL)),
            attach_csv_as_file=bool(kimi_config.get("attach_csv_as_file", True)),
        )

    raise ValueError(
        f"Unsupported AI provider '{provider_name}'. Expected one of: claude, openai, kimi, local."
    )


__all__ = [
    "AIProvider",
    "AIProviderError",
    "ClaudeProvider",
    "OpenAIProvider",
    "KimiProvider",
    "LocalProvider",
    "create_provider",
]
