"""Core abstractions, constants, and shared utilities for AI providers.

This module contains the foundational components shared across all AI provider
implementations: the ``AIProvider`` abstract base class, the ``AIProviderError``
exception, rate-limit retry logic, configuration resolution helpers, and
error-detection utilities.

Attributes:
    DEFAULT_MAX_TOKENS: Default maximum completion tokens across all providers.
    RATE_LIMIT_MAX_RETRIES: Number of retries on rate-limit (HTTP 429) errors.
    DEFAULT_LOCAL_BASE_URL: Default Ollama-style local endpoint URL.
    DEFAULT_CLOUD_REQUEST_TIMEOUT_SECONDS: Default HTTP timeout for cloud
        provider endpoints (10 minutes).
    DEFAULT_LOCAL_REQUEST_TIMEOUT_SECONDS: Default HTTP timeout for local
        endpoints (1 hour, to accommodate large model inference).
    DEFAULT_KIMI_BASE_URL: Default Moonshot Kimi API base URL.
    DEFAULT_CLAUDE_MODEL: Default Anthropic Claude model identifier.
    DEFAULT_OPENAI_MODEL: Default OpenAI model identifier.
    DEFAULT_KIMI_MODEL: Default Moonshot Kimi model identifier.
    DEFAULT_KIMI_FILE_UPLOAD_PURPOSE: File upload purpose string for Kimi.
    DEFAULT_LOCAL_MODEL: Default model identifier for local providers.
    _RATE_LIMIT_STATE: Module-level dict mapping provider names to
        ``RateLimitState`` instances.
    _RATE_LIMIT_STATE_LOCK: Threading lock protecting ``_RATE_LIMIT_STATE``.
"""

from __future__ import annotations

import logging
import os
import re
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator, Mapping, TypeVar
from urllib.parse import urlsplit, urlunsplit

logger = logging.getLogger(__name__)
_T = TypeVar("_T")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_MAX_TOKENS = 16384
RATE_LIMIT_MAX_RETRIES = 3
DEFAULT_LOCAL_BASE_URL = "http://localhost:11434/v1"
DEFAULT_CLOUD_REQUEST_TIMEOUT_SECONDS = 600.0
DEFAULT_LOCAL_REQUEST_TIMEOUT_SECONDS = 3600.0
DEFAULT_KIMI_BASE_URL = "https://api.moonshot.ai/v1"
DEFAULT_CLAUDE_MODEL = "claude-opus-4-6"
DEFAULT_OPENAI_MODEL = "gpt-5.4"
DEFAULT_KIMI_MODEL = "kimi-k2-turbo-preview"
DEFAULT_KIMI_FILE_UPLOAD_PURPOSE = "file-extract"
DEFAULT_LOCAL_MODEL = "llama3.1:70b"


class _NeverRaisedError(Exception):
    """Sentinel exception that is never raised.

    Used as the default for ``AIProvider._rate_limit_error_class`` so that
    the ``except`` clause in ``_run_with_rate_limit_retries`` is syntactically
    valid even when a subclass does not override the attribute.
    """

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

_SUPPORTED_COMPLETION_TOKEN_LIMIT_RE = re.compile(
    r"supports\s+at\s+most\s+(?P<limit>\d+)\s+(?:completion\s+)?tokens",
    flags=re.IGNORECASE,
)
_MAX_TOKENS_UPPER_BOUND_RE = re.compile(
    r"max[_\s]?tokens?\s*:\s*\d+\s*>\s*(?P<limit>\d+)",
    flags=re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Rate-limit state
# ---------------------------------------------------------------------------


@dataclass
class RateLimitState:
    """Persistent rate-limit tracking state for a single AI provider.

    Attributes:
        last_request_time: Monotonic timestamp of the last API request attempt.
        backoff_duration: Current backoff duration in seconds. Reset to 0.0
            on a successful request.
        consecutive_error_count: Number of consecutive rate-limit errors.
            Reset to 0 on a successful request.
        lock: Per-provider lock for thread-safe state access.
    """

    last_request_time: float = 0.0
    backoff_duration: float = 0.0
    consecutive_error_count: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)


_RATE_LIMIT_STATE: dict[str, RateLimitState] = {}
_RATE_LIMIT_STATE_LOCK = threading.Lock()


def _get_rate_limit_state(provider_name: str) -> RateLimitState:
    """Get or create the persistent rate-limit state for a provider.

    Args:
        provider_name: Human-readable provider name (e.g., ``"Claude"``).

    Returns:
        The ``RateLimitState`` instance for the given provider.
    """
    with _RATE_LIMIT_STATE_LOCK:
        if provider_name not in _RATE_LIMIT_STATE:
            _RATE_LIMIT_STATE[provider_name] = RateLimitState()
        return _RATE_LIMIT_STATE[provider_name]


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------


class AIProviderError(RuntimeError):
    """Raised when an AI provider request fails with a user-facing message.

    All provider implementations translate SDK-specific exceptions into this
    single exception type so that callers only need one ``except`` clause for
    AI-related failures. The message is safe for display in the web UI.
    """


# ---------------------------------------------------------------------------
# Abstract base class
# ---------------------------------------------------------------------------


class AIProvider(ABC):
    """Abstract base class defining the interface for all AI providers.

    Every concrete provider (Claude, OpenAI, Kimi, Local) implements this
    interface so that the forensic analysis engine can call any provider
    interchangeably.

    Subclasses must implement:
        * ``analyze_stream`` -- incremental (streaming) text generation.
        * ``get_model_info`` -- provider/model metadata dictionary.
        * ``analyze_with_attachments`` -- analysis with CSV file attachments
          (unless the default inline-into-prompt behavior is sufficient).

    Subclasses should set:
        * ``_provider_display_name`` -- human-readable name for error messages.
        * ``_rate_limit_error_class`` -- SDK-specific rate-limit exception type.

    Attributes:
        attach_csv_as_file (bool): Whether to attempt uploading CSV artifacts
            as file attachments rather than inlining them into the prompt.
        _provider_display_name (str): Human-readable provider name used in
            error messages and log entries.  Override in subclasses.
        _rate_limit_error_class (type[Exception]): The SDK exception class that
            signals a rate-limit (HTTP 429) error.  Override in subclasses.
            Defaults to ``_NeverRaisedError`` (a sentinel that is never raised).
    """

    _provider_display_name: str = "AI"
    _rate_limit_error_class: type[Exception] = _NeverRaisedError

    def analyze(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> str:
        """Send a prompt to the provider and return the complete generated text.

        Delegates to ``analyze_with_attachments`` with no attachments.
        Subclasses typically do not need to override this method.

        Args:
            system_prompt: The system-level instruction text.
            user_prompt: The user-facing prompt with investigation context.
            max_tokens: Maximum number of tokens the model may generate.

        Returns:
            The generated text response as a string.

        Raises:
            AIProviderError: If the request fails for any reason.
        """
        return self.analyze_with_attachments(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            attachments=None,
            max_tokens=max_tokens,
        )

    @abstractmethod
    def analyze_stream(
        self,
        system_prompt: str,
        user_prompt: str,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> Iterator[str]:
        """Stream generated text chunks for the provided prompt.

        Args:
            system_prompt: The system-level instruction text.
            user_prompt: The user-facing prompt with investigation context.
            max_tokens: Maximum number of tokens the model may generate.

        Yields:
            Individual text chunks (deltas) as they are generated.

        Raises:
            AIProviderError: If the streaming request fails or produces no output.
        """

    @abstractmethod
    def get_model_info(self) -> dict[str, str]:
        """Return provider and model metadata for audit logging and reports.

        Returns:
            A dictionary with at least ``"provider"`` and ``"model"`` keys.
        """

    def analyze_with_attachments(
        self,
        system_prompt: str,
        user_prompt: str,
        attachments: list[Mapping[str, str]] | None,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> str:
        """Analyze with optional file attachments.

        Providers that support file uploads override this method. The default
        implementation inlines attachment content into the prompt so the model
        always receives the evidence data, then delegates to ``analyze``.

        Args:
            system_prompt: The system-level instruction text.
            user_prompt: The user-facing prompt with investigation context.
            attachments: Optional list of attachment descriptors with
                ``"path"``, ``"name"``, and ``"mime_type"`` keys.
            max_tokens: Maximum number of tokens the model may generate.

        Returns:
            The generated text response as a string.

        Raises:
            AIProviderError: If the request fails.
        """
        from .utils import _inline_attachment_data_into_prompt

        effective_prompt = user_prompt
        if attachments:
            effective_prompt, inlined = _inline_attachment_data_into_prompt(
                user_prompt=user_prompt,
                attachments=attachments,
            )
            if inlined:
                logger.info("Base provider inlined attachment data into prompt.")

        return "".join(self.analyze_stream(
            system_prompt=system_prompt,
            user_prompt=effective_prompt,
            max_tokens=max_tokens,
        ))

    def _prepare_csv_attachments(
        self,
        attachments: list[Mapping[str, str]] | None,
        *,
        supports_file_attachments: bool = True,
    ) -> list[dict[str, str]] | None:
        """Apply shared CSV-attachment preflight checks and normalization.

        Args:
            attachments: Raw attachment descriptors from the caller.
            supports_file_attachments: Whether the provider's SDK client
                exposes the necessary file-upload APIs.

        Returns:
            A list of normalized attachment dicts, or ``None`` if attachment
            mode should be skipped.
        """
        from .utils import normalize_attachment_inputs

        if not bool(getattr(self, "attach_csv_as_file", False)):
            return None
        if not attachments:
            return None
        attachment_lock = getattr(self, "_attachment_lock", None)
        if attachment_lock is not None:
            with attachment_lock:
                if getattr(self, "_csv_attachment_supported", None) is False:
                    return None
        elif getattr(self, "_csv_attachment_supported", None) is False:
            return None
        if not supports_file_attachments:
            if hasattr(self, "_csv_attachment_supported"):
                if attachment_lock is not None:
                    with attachment_lock:
                        setattr(self, "_csv_attachment_supported", False)
                else:
                    setattr(self, "_csv_attachment_supported", False)
            return None

        normalized_attachments = normalize_attachment_inputs(attachments)
        if not normalized_attachments:
            return None
        return normalized_attachments

    # ------------------------------------------------------------------
    # Shared error mapping
    # ------------------------------------------------------------------

    def _map_api_error(self, error: Exception) -> AIProviderError:
        """Map an SDK exception to an ``AIProviderError`` with a user-friendly message.

        The base implementation handles the four error types common to every
        provider that wraps an OpenAI-style or Anthropic-style SDK:
        ``APIConnectionError``, ``AuthenticationError``, ``BadRequestError``
        (with context-length detection), and generic ``APIError``.

        Subclasses with provider-specific error handling (e.g. Kimi
        model-not-available, Local timeout detection) should override this
        method and call ``super()._map_api_error(error)`` in the fallback
        path.

        Args:
            error: The raw SDK or network exception.

        Returns:
            An ``AIProviderError`` with a user-friendly message.
        """
        name = self._provider_display_name
        # Dynamically resolve the SDK module stored by the subclass.
        sdk = getattr(self, "_openai", None) or getattr(self, "_anthropic", None)
        if sdk is None:
            return AIProviderError(f"Unexpected {name} provider error: {error}")

        if isinstance(error, sdk.APIConnectionError):
            return AIProviderError(
                f"Unable to connect to {name} API. Check network access and endpoint configuration."
            )
        if isinstance(error, sdk.AuthenticationError):
            return AIProviderError(
                f"{name} authentication failed. Check the API key configuration."
            )
        if isinstance(error, sdk.BadRequestError):
            if _is_context_length_error(error):
                return AIProviderError(
                    f"{name} request exceeded the model context length. Reduce prompt size and retry."
                )
            return AIProviderError(f"{name} request was rejected: {error}")
        if isinstance(error, sdk.APIError):
            return AIProviderError(f"{name} API error: {error}")
        return AIProviderError(f"Unexpected {name} provider error: {error}")

    # ------------------------------------------------------------------
    # Shared request runner
    # ------------------------------------------------------------------

    def _run_request(self, request_fn: Callable[[], _T]) -> _T:
        """Execute a provider request with rate-limit retries and error mapping.

        This is the standard request-execution wrapper shared by all
        providers.  It delegates to ``_run_with_rate_limit_retries`` using
        the subclass-configured ``_rate_limit_error_class`` and
        ``_provider_display_name``, then maps any remaining exceptions via
        ``_map_api_error``.

        Args:
            request_fn: A zero-argument callable that performs the API request.

        Returns:
            The return value of ``request_fn`` on success.

        Raises:
            AIProviderError: On any SDK or network error.
        """
        try:
            return _run_with_rate_limit_retries(
                request_fn=request_fn,
                rate_limit_error_type=self._rate_limit_error_class,
                provider_name=self._provider_display_name,
            )
        except AIProviderError:
            raise
        except Exception as exc:
            raise self._map_api_error(exc) from exc


# ---------------------------------------------------------------------------
# Rate-limit retry wrapper
# ---------------------------------------------------------------------------


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
        request_fn: A zero-argument callable that performs the API request.
        rate_limit_error_type: The exception class to catch as a rate-limit
            signal (e.g., ``anthropic.RateLimitError``).
        provider_name: Human-readable provider name for log messages.

    Returns:
        The return value of ``request_fn`` on a successful call.

    Raises:
        AIProviderError: If the rate limit is still exceeded after all retries.
    """
    state = _get_rate_limit_state(provider_name)
    last_error: Exception | None = None

    with state.lock:
        if state.backoff_duration > 0.0 and state.last_request_time > 0.0:
            elapsed = time.monotonic() - state.last_request_time
            remaining = state.backoff_duration - elapsed
            if remaining > 0.0:
                logger.info(
                    "%s: honouring residual backoff from prior request, "
                    "waiting %.1fs before first attempt",
                    provider_name,
                    remaining,
                )
                wait_time = remaining
            else:
                wait_time = 0.0
        else:
            wait_time = 0.0

    if wait_time > 0.0:
        time.sleep(wait_time)

    for retry_count in range(RATE_LIMIT_MAX_RETRIES + 1):
        try:
            with state.lock:
                state.last_request_time = time.monotonic()

            result = request_fn()

            # Only reset backoff state for non-streaming responses.
            # Streaming responses return a lazy iterator; the actual
            # API data consumption happens later when the caller
            # iterates.  Resetting here would falsely signal success
            # before any data has been received.
            is_streaming = hasattr(result, '__next__')
            if not is_streaming:
                with state.lock:
                    state.backoff_duration = 0.0
                    state.consecutive_error_count = 0

            return result
        except rate_limit_error_type as error:
            last_error = error

            retry_after = _extract_retry_after_seconds(error)
            if retry_after is None:
                retry_after = float(2**retry_count)

            with state.lock:
                state.consecutive_error_count += 1
                state.backoff_duration = retry_after
                state.last_request_time = time.monotonic()

            if retry_count >= RATE_LIMIT_MAX_RETRIES:
                break

            logger.warning(
                "%s rate limited (attempt %d/%d, %d consecutive), "
                "retrying in %.1fs",
                provider_name,
                retry_count + 1,
                RATE_LIMIT_MAX_RETRIES,
                state.consecutive_error_count,
                retry_after,
            )
            time.sleep(retry_after)

    detail = f" Details: {last_error}" if last_error else ""
    raise AIProviderError(
        f"{provider_name} rate limit exceeded after {RATE_LIMIT_MAX_RETRIES} retries.{detail}"
    ) from last_error


# ---------------------------------------------------------------------------
# Configuration resolution helpers
# ---------------------------------------------------------------------------


def _normalize_api_key_value(value: Any) -> str:
    """Normalize API key-like values from config/env sources.

    Args:
        value: Raw API key value. May be ``None``, empty, or whitespace-padded.

    Returns:
        The stripped string, or empty string if input is ``None``.
    """
    if value is None:
        return ""
    return str(value).strip()


def _resolve_api_key(config_key: Any, env_var: str) -> str:
    """Return the API key from config, falling back to an environment variable.

    Args:
        config_key: The API key value from ``config.yaml``.
        env_var: The environment variable name to check as fallback.

    Returns:
        The resolved API key string, or empty string if not found.
    """
    normalized_config_key = _normalize_api_key_value(config_key)
    if normalized_config_key:
        return normalized_config_key
    return _normalize_api_key_value(os.environ.get(env_var, ""))


def _resolve_api_key_candidates(config_key: Any, env_vars: tuple[str, ...]) -> str:
    """Return API key from config, falling back across multiple environment variables.

    Args:
        config_key: The API key value from ``config.yaml``.
        env_vars: Tuple of environment variable names to check in order.

    Returns:
        The resolved API key string, or empty string if not found.
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

    Args:
        value: Raw timeout value from configuration.
        default_seconds: Fallback timeout in seconds.

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


# ---------------------------------------------------------------------------
# Error detection helpers
# ---------------------------------------------------------------------------


def _extract_retry_after_seconds(error: Exception) -> float | None:
    """Read ``Retry-After`` hints from API error responses when present.

    Args:
        error: The rate-limit or API exception that may carry HTTP headers.

    Returns:
        The retry delay in seconds, or ``None`` if not present.
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


def _is_attachment_unsupported_error(error: Exception) -> bool:
    """Detect API errors that indicate attachment/file APIs are unsupported.

    Args:
        error: The API exception to inspect.

    Returns:
        ``True`` if the error indicates file-attachment APIs are unavailable.
    """
    message = str(error).lower()
    unsupported_markers = (
        "file not found",
        "file_not_found",
        "attachment not found",
        "unsupported file",
        "file upload not supported",
        "attachments not supported",
        "unsupported_content",
        "unsupported document",
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
    """Detect Anthropic SDK non-streaming timeout guardrails.

    Args:
        error: The exception to inspect (typically a ``ValueError``).

    Returns:
        ``True`` if streaming is required due to expected long processing time.
    """
    message = str(error).lower()
    if "streaming is required for operations that may take longer than 10 minutes" in message:
        return True
    return "streaming is required" in message and "10 minutes" in message


def _is_unsupported_parameter_error(error: Exception, parameter_name: str) -> bool:
    """Detect API errors that indicate a specific parameter is unsupported.

    Args:
        error: The API exception to inspect.
        parameter_name: The parameter name to check for.

    Returns:
        ``True`` if the error indicates the parameter is unsupported.
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

    Args:
        error: The API exception whose message may contain the token limit.

    Returns:
        The maximum completion token count, or ``None`` if not found.
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

    Args:
        error: The API exception that triggered the token-limit failure.
        requested_tokens: The ``max_tokens`` value that was rejected.

    Returns:
        A reduced token count for retry, or ``None`` if not recoverable.
    """
    if requested_tokens <= 0:
        return None
    supported_limit = _extract_supported_completion_token_limit(error)
    if supported_limit is None or supported_limit >= requested_tokens:
        return None
    return supported_limit


# ---------------------------------------------------------------------------
# URL / model normalization
# ---------------------------------------------------------------------------


def _normalize_openai_compatible_base_url(base_url: str, default_base_url: str) -> str:
    """Normalize OpenAI-compatible base URLs.

    Ensures the URL has a versioned path prefix (``/v1``). Ollama users
    often provide ``http://localhost:11434/``; this normalizes it.

    Args:
        base_url: Raw base URL string from configuration.
        default_base_url: Fallback URL when ``base_url`` is empty.

    Returns:
        The normalized base URL string.
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

    Args:
        model: Raw model name string from configuration.

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
    """Detect model-not-found or model-permission failures from Kimi.

    Args:
        error: The API exception to inspect.

    Returns:
        ``True`` if the error indicates the model is unavailable.
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
