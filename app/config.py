"""Configuration loading and persistence for AIFT."""

from __future__ import annotations

from copy import deepcopy
import os
from pathlib import Path
from typing import Any

import yaml

DEFAULT_CONFIG: dict[str, Any] = {
    "ai": {
        "provider": "claude",
        "claude": {
            "api_key": "",
            "model": "claude-opus-4-6",
            "attach_csv_as_file": True,
        },
        "openai": {
            "api_key": "",
            "model": "gpt-5.2",
            "attach_csv_as_file": True,
        },
        "kimi": {
            "api_key": "",
            "model": "kimi-k2-turbo-preview",
            "base_url": "https://api.moonshot.ai/v1",
            "attach_csv_as_file": True,
        },
        "local": {
            "base_url": "http://localhost:11434/v1",
            "model": "llama3.1:70b",
            "api_key": "not-needed",
            "attach_csv_as_file": True,
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
        "ai_max_tokens": 256000,
        "connection_test_max_tokens": 256,
        "date_buffer_days": 7,
        "citation_spot_check_limit": 20,
        "artifact_deduplication_enabled": True,
        "artifact_ai_columns_config_path": "config/artifact_ai_columns.yaml",
    },
    "artifact_profiles": [],
}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def get_default_config() -> dict[str, Any]:
    return deepcopy(DEFAULT_CONFIG)


def apply_env_overrides(config: dict[str, Any]) -> dict[str, Any]:
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


def load_config(path: str | Path = "config.yaml", use_env_overrides: bool = True) -> dict[str, Any]:
    config_path = Path(path)
    config = get_default_config()

    if config_path.exists():
        with config_path.open("r", encoding="utf-8") as file:
            parsed = yaml.safe_load(file) or {}

        if not isinstance(parsed, dict):
            raise ValueError(f"Invalid configuration format in {config_path}.")

        _deep_merge(config, parsed)
    else:
        save_config(config, config_path)

    if use_env_overrides:
        return apply_env_overrides(config)
    return config


def save_config(config: dict[str, Any], path: str | Path = "config.yaml") -> None:
    config_path = Path(path)
    if config_path.parent != Path("."):
        config_path.parent.mkdir(parents=True, exist_ok=True)

    with config_path.open("w", encoding="utf-8") as file:
        yaml.safe_dump(config, file, sort_keys=False)
