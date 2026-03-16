"""Configuration loading and persistence for AIFT.

Manages the application's layered configuration system:

1. **Hardcoded defaults** -- ``DEFAULT_CONFIG`` provides sensible values for
   every setting so the application runs out of the box.
2. **YAML file** -- User overrides in ``config.yaml`` are deep-merged on top
   of the defaults.
3. **Environment variables** -- API keys from ``ANTHROPIC_API_KEY``,
   ``OPENAI_API_KEY``, and ``MOONSHOT_API_KEY`` / ``KIMI_API_KEY`` take
   highest precedence.

The :func:`save_config` helper persists the current configuration back to
YAML so settings changed through the UI are retained across restarts.

Attributes:
    PROJECT_ROOT: Resolved path to the repository root directory.
    DEFAULT_CONFIG: Complete default configuration dictionary.
    LOGO_FILE_CANDIDATES: Ordered tuple of logo filenames to search for in
        the ``images/`` directory.
"""

from __future__ import annotations

import logging
from copy import deepcopy
import os
from pathlib import Path
from typing import Any

import yaml

__all__ = [
    "load_config",
    "save_config",
    "get_default_config",
    "apply_env_overrides",
    "PROJECT_ROOT",
    "DEFAULT_CONFIG",
]

logger = logging.getLogger(__name__)

KNOWN_AI_PROVIDERS = ("claude", "openai", "kimi", "local")

PROJECT_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_CONFIG: dict[str, Any] = {
    "ai": {
        "provider": "claude",
        "claude": {
            "api_key": "",
            "model": "claude-opus-4-6",
            "attach_csv_as_file": True,
            "request_timeout_seconds": 600,
        },
        "openai": {
            "api_key": "",
            "model": "gpt-5.2",
            "attach_csv_as_file": True,
            "request_timeout_seconds": 600,
        },
        "kimi": {
            "api_key": "",
            "model": "kimi-k2-turbo-preview",
            "base_url": "https://api.moonshot.ai/v1",
            "attach_csv_as_file": True,
            "request_timeout_seconds": 600,
        },
        "local": {
            "base_url": "http://localhost:11434/v1",
            "model": "llama3.1:70b",
            "api_key": "not-needed",
            "attach_csv_as_file": True,
            "request_timeout_seconds": 3600,
        },
    },
    "server": {
        "port": 5000,
        "host": "127.0.0.1",
        "max_upload_mb": 2048,
    },
    "evidence": {
        "large_file_threshold_mb": 2048,
        "csv_output_dir": "",
    },
    "analysis": {
        "ai_max_tokens": 128000,
        "shortened_prompt_cutoff_tokens": 64000,
        "connection_test_max_tokens": 256,
        "date_buffer_days": 7,
        "citation_spot_check_limit": 20,
        "artifact_deduplication_enabled": True,
        "artifact_ai_columns_config_path": "config/artifact_ai_columns.yaml",
    },
    # NOTE: artifact_profiles are stored as JSON files on disk (in the profiles/
    # directory next to config.yaml), not in this config dict.  No default key is
    # needed here — see _resolve_profiles_root() in routes.py.
}

# Ordered list of logo filenames to look for in the images/ directory.
# The first match wins; the fallback in routes.py picks any image alphabetically.
LOGO_FILE_CANDIDATES = (
    "AIFT Logo - White Text.png",
    "AIFT Logo - Dark Text.png",
)


def _deep_merge_inplace(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge *override* into *base* in-place. Returns *base*.

    Nested dictionaries are merged recursively; all other value types in
    *override* replace the corresponding entry in *base*.  The caller is
    responsible for passing a copy of *base* if the original must not be
    mutated.

    Args:
        base: The target dictionary that will be updated in-place.
        override: The dictionary whose values take precedence.

    Returns:
        The mutated *base* dictionary (returned for convenience).
    """
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge_inplace(base[key], value)
        else:
            base[key] = value
    return base


def get_default_config() -> dict[str, Any]:
    """Return a deep copy of :data:`DEFAULT_CONFIG` safe for mutation."""
    return deepcopy(DEFAULT_CONFIG)


def apply_env_overrides(config: dict[str, Any]) -> dict[str, Any]:
    """Overlay API keys from environment variables onto *config*.

    Checks ``ANTHROPIC_API_KEY``, ``OPENAI_API_KEY``, and
    ``MOONSHOT_API_KEY`` / ``KIMI_API_KEY``.  Non-empty values replace the
    corresponding ``api_key`` entries in the configuration dictionary.

    Args:
        config: The configuration dictionary to update in place.

    Returns:
        The mutated *config* dictionary.
    """
    anthropic_api_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
    openai_api_key = os.getenv("OPENAI_API_KEY", "").strip()
    kimi_api_key = os.getenv("MOONSHOT_API_KEY", "").strip() or os.getenv("KIMI_API_KEY", "").strip()

    if anthropic_api_key:
        config.setdefault("ai", {}).setdefault("claude", {})["api_key"] = anthropic_api_key
    if openai_api_key:
        config.setdefault("ai", {}).setdefault("openai", {})["api_key"] = openai_api_key
    if kimi_api_key:
        config.setdefault("ai", {}).setdefault("kimi", {})["api_key"] = kimi_api_key

    return config


def validate_config(config: dict[str, Any]) -> list[str]:
    """Validate configuration values and return a list of error descriptions.

    Checks that values in the merged configuration are within acceptable
    ranges and of the correct types.  An empty returned list means the
    configuration is fully valid.

    Args:
        config: The fully merged configuration dictionary to validate.

    Returns:
        A list of human-readable validation error strings.  Empty when
        the configuration passes all checks.
    """
    errors: list[str] = []

    # --- server section ---
    server = config.get("server", {})
    if not isinstance(server, dict):
        errors.append("server: expected a mapping")
    else:
        port = server.get("port")
        if not isinstance(port, int) or not (1 <= port <= 65535):
            errors.append(
                f"server.port: must be an integer between 1 and 65535, got {port!r}"
            )

        host = server.get("host")
        if not isinstance(host, str) or not host.strip():
            errors.append(
                f"server.host: must be a non-empty string, got {host!r}"
            )

        max_upload = server.get("max_upload_mb")
        if not isinstance(max_upload, (int, float)) or max_upload <= 0:
            errors.append(
                f"server.max_upload_mb: must be a positive number, got {max_upload!r}"
            )

    # --- ai section ---
    ai = config.get("ai", {})
    if not isinstance(ai, dict):
        errors.append("ai: expected a mapping")
    else:
        provider = ai.get("provider")
        if provider not in KNOWN_AI_PROVIDERS:
            errors.append(
                f"ai.provider: must be one of {KNOWN_AI_PROVIDERS}, got {provider!r}"
            )

        for name in KNOWN_AI_PROVIDERS:
            prov_cfg = ai.get(name)
            if not isinstance(prov_cfg, dict):
                continue

            model = prov_cfg.get("model")
            if not isinstance(model, str) or not model.strip():
                errors.append(
                    f"ai.{name}.model: must be a non-empty string, got {model!r}"
                )

            api_key = prov_cfg.get("api_key")
            if not isinstance(api_key, str):
                errors.append(
                    f"ai.{name}.api_key: must be a string, got {type(api_key).__name__}"
                )

            base_url = prov_cfg.get("base_url")
            if base_url is not None:
                if not isinstance(base_url, str) or not (
                    base_url.startswith("http://") or base_url.startswith("https://")
                ):
                    errors.append(
                        f"ai.{name}.base_url: must start with http:// or https://, got {base_url!r}"
                    )

    # --- analysis section ---
    analysis = config.get("analysis", {})
    if isinstance(analysis, dict):
        ai_max_tokens = analysis.get("ai_max_tokens")
        if not isinstance(ai_max_tokens, int) or ai_max_tokens <= 0:
            errors.append(
                f"analysis.ai_max_tokens: must be a positive integer, got {ai_max_tokens!r}"
            )

    # --- evidence section ---
    evidence = config.get("evidence", {})
    if isinstance(evidence, dict):
        threshold = evidence.get("large_file_threshold_mb")
        if not isinstance(threshold, (int, float)) or threshold <= 0:
            errors.append(
                f"evidence.large_file_threshold_mb: must be a positive number, got {threshold!r}"
            )

    return errors


def load_config(path: str | Path | None = None, use_env_overrides: bool = True) -> dict[str, Any]:
    """Load the AIFT configuration from a YAML file with layered defaults.

    If the configuration file does not exist, a new file is created from
    the defaults. Environment variable overrides are applied last unless
    *use_env_overrides* is ``False``.

    Args:
        path: Explicit path to a YAML configuration file.  Defaults to
            ``<PROJECT_ROOT>/config.yaml``.
        use_env_overrides: When *True* (default), API keys from environment
            variables take precedence over file values.

    Returns:
        The fully merged configuration dictionary.

    Raises:
        ValueError: If the YAML file contains a non-dictionary root value.
    """
    config_path = Path(path) if path is not None else PROJECT_ROOT / "config.yaml"
    config = get_default_config()

    if config_path.exists():
        with config_path.open("r", encoding="utf-8") as file:
            parsed = yaml.safe_load(file) or {}

        if not isinstance(parsed, dict):
            raise ValueError(f"Invalid configuration format in {config_path}.")

        _deep_merge_inplace(config, parsed)
    else:
        save_config(config, config_path)

    if use_env_overrides:
        apply_env_overrides(config)

    warnings = validate_config(config)
    for warning in warnings:
        logger.warning("Config validation: %s", warning)

    return config


def save_config(config: dict[str, Any], path: str | Path | None = None) -> None:
    """Persist the configuration dictionary to a YAML file.

    Parent directories are created automatically when they do not exist.

    Args:
        config: The configuration dictionary to serialise.
        path: Destination file path.  Defaults to
            ``<PROJECT_ROOT>/config.yaml``.
    """
    config_path = Path(path) if path is not None else PROJECT_ROOT / "config.yaml"
    if config_path.parent != Path("."):
        config_path.parent.mkdir(parents=True, exist_ok=True)

    with config_path.open("w", encoding="utf-8") as file:
        yaml.safe_dump(config, file, sort_keys=False)
