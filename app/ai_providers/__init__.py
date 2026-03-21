"""Multi-provider AI abstraction layer for AIFT forensic analysis.

This package provides a unified interface for interacting with multiple AI
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
"""

from __future__ import annotations

from .base import (
    AIProvider,
    AIProviderError,
    DEFAULT_CLAUDE_MODEL,
    DEFAULT_CLOUD_REQUEST_TIMEOUT_SECONDS,
    DEFAULT_KIMI_BASE_URL,
    DEFAULT_KIMI_FILE_UPLOAD_PURPOSE,
    DEFAULT_KIMI_MODEL,
    DEFAULT_LOCAL_BASE_URL,
    DEFAULT_LOCAL_MODEL,
    DEFAULT_LOCAL_REQUEST_TIMEOUT_SECONDS,
    DEFAULT_MAX_TOKENS,
    DEFAULT_OPENAI_MODEL,
    RATE_LIMIT_MAX_RETRIES,
    RateLimitState,
    _extract_retry_after_seconds,
    _is_context_length_error,
    _normalize_api_key_value,
    _normalize_openai_compatible_base_url,
    _resolve_api_key,
    _resolve_api_key_candidates,
)
from .claude_provider import ClaudeProvider
from .factory import create_provider
from .kimi_provider import KimiProvider
from .local_provider import LocalProvider
from .openai_provider import OpenAIProvider
from .utils import (
    _extract_anthropic_text,
    _extract_openai_text,
    normalize_attachment_input as _normalize_attachment_input,
    normalize_attachment_inputs as _normalize_attachment_inputs,
)

__all__ = [
    "AIProvider",
    "AIProviderError",
    "ClaudeProvider",
    "OpenAIProvider",
    "KimiProvider",
    "LocalProvider",
    "create_provider",
    "base",
    "claude_provider",
    "factory",
    "kimi_provider",
    "local_provider",
    "openai_provider",
    "utils",
]
