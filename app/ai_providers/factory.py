"""AI provider factory for creating provider instances from configuration.

This module contains the ``create_provider`` function that reads the
application ``config.yaml`` and constructs the appropriate provider
class based on the configured provider name.

Attributes:
    logger: Module-level logger for factory operations.
"""

from __future__ import annotations

import logging
from typing import Any

from .base import (
    AIProviderError,
    DEFAULT_CLAUDE_MODEL,
    DEFAULT_CLOUD_REQUEST_TIMEOUT_SECONDS,
    DEFAULT_KIMI_BASE_URL,
    DEFAULT_KIMI_MODEL,
    DEFAULT_LOCAL_BASE_URL,
    DEFAULT_LOCAL_MODEL,
    DEFAULT_LOCAL_REQUEST_TIMEOUT_SECONDS,
    DEFAULT_OPENAI_MODEL,
    AIProvider,
    _normalize_api_key_value,
    _resolve_api_key,
    _resolve_api_key_candidates,
    _resolve_timeout_seconds,
)

logger = logging.getLogger(__name__)


def create_provider(config: dict[str, Any]) -> AIProvider:
    """Create and return an AI provider instance based on application config.

    Reads the ``ai.provider`` key from the configuration dictionary and
    constructs the corresponding provider class with settings from the
    provider-specific sub-section.

    Args:
        config: The application configuration dictionary, expected to
            contain an ``"ai"`` section with a ``"provider"`` key.

    Returns:
        A configured ``AIProvider`` instance ready for use.

    Raises:
        ValueError: If the ``ai`` section is missing or the provider
            name is not supported.
        AIProviderError: If the selected provider cannot be initialized.
    """
    ai_config = config.get("ai", {})
    if not isinstance(ai_config, dict):
        raise ValueError("Invalid configuration: `ai` section must be a dictionary.")

    provider_name = str(ai_config.get("provider", "claude")).strip().lower()

    if provider_name == "claude":
        return _create_claude_provider(ai_config)

    if provider_name == "openai":
        return _create_openai_provider(ai_config)

    if provider_name == "local":
        return _create_local_provider(ai_config)

    if provider_name == "kimi":
        return _create_kimi_provider(ai_config)

    raise ValueError(
        f"Unsupported AI provider '{provider_name}'. Expected one of: claude, openai, kimi, local."
    )


def _create_claude_provider(ai_config: dict[str, Any]) -> AIProvider:
    """Create a ClaudeProvider from the ``ai.claude`` config section.

    Args:
        ai_config: The ``ai`` section of the application configuration.

    Returns:
        A configured ``ClaudeProvider`` instance.
    """
    from .claude_provider import ClaudeProvider

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
        request_timeout_seconds=_resolve_timeout_seconds(
            claude_config.get("request_timeout_seconds", DEFAULT_CLOUD_REQUEST_TIMEOUT_SECONDS),
            DEFAULT_CLOUD_REQUEST_TIMEOUT_SECONDS,
        ),
    )


def _create_openai_provider(ai_config: dict[str, Any]) -> AIProvider:
    """Create an OpenAIProvider from the ``ai.openai`` config section.

    Args:
        ai_config: The ``ai`` section of the application configuration.

    Returns:
        A configured ``OpenAIProvider`` instance.
    """
    from .openai_provider import OpenAIProvider

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
        request_timeout_seconds=_resolve_timeout_seconds(
            openai_config.get("request_timeout_seconds", DEFAULT_CLOUD_REQUEST_TIMEOUT_SECONDS),
            DEFAULT_CLOUD_REQUEST_TIMEOUT_SECONDS,
        ),
    )


def _create_local_provider(ai_config: dict[str, Any]) -> AIProvider:
    """Create a LocalProvider from the ``ai.local`` config section.

    Args:
        ai_config: The ``ai`` section of the application configuration.

    Returns:
        A configured ``LocalProvider`` instance.
    """
    from .local_provider import LocalProvider

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


def _create_kimi_provider(ai_config: dict[str, Any]) -> AIProvider:
    """Create a KimiProvider from the ``ai.kimi`` config section.

    Args:
        ai_config: The ``ai`` section of the application configuration.

    Returns:
        A configured ``KimiProvider`` instance.
    """
    from .kimi_provider import KimiProvider

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
        request_timeout_seconds=_resolve_timeout_seconds(
            kimi_config.get("request_timeout_seconds", DEFAULT_CLOUD_REQUEST_TIMEOUT_SECONDS),
            DEFAULT_CLOUD_REQUEST_TIMEOUT_SECONDS,
        ),
    )
