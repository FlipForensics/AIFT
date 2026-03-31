from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import yaml

from app.config import (
    ConfigurationError,
    DEFAULT_CONFIG,
    KNOWN_AI_PROVIDERS,
    LOGO_FILE_CANDIDATES,
    PROJECT_ROOT,
    _deep_merge_inplace,
    apply_env_overrides,
    get_default_config,
    load_config,
    save_config,
    validate_config,
)


class ConfigTests(unittest.TestCase):
    def test_load_config_creates_default_config_on_first_run(self) -> None:
        with TemporaryDirectory(prefix="aift-config-test-") as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            self.assertFalse(config_path.exists())

            config = load_config(config_path)

            self.assertTrue(config_path.exists())
            self.assertEqual(config.get("ai", {}).get("provider"), "claude")
            self.assertEqual(config.get("server", {}).get("port"), 5000)
            self.assertNotIn("max_upload_mb", config.get("server", {}))
            self.assertEqual(config.get("evidence", {}).get("large_file_threshold_mb"), 0)
            self.assertEqual(config.get("evidence", {}).get("csv_output_dir"), "")
            self.assertEqual(
                config.get("ai", {}).get("local", {}).get("request_timeout_seconds"),
                3600,
            )
            self.assertEqual(config.get("analysis", {}).get("ai_max_tokens"), 128000)
            self.assertEqual(config.get("analysis", {}).get("shortened_prompt_cutoff_tokens"), 64000)
            self.assertEqual(config.get("analysis", {}).get("artifact_deduplication_enabled"), True)
            self.assertEqual(
                config.get("analysis", {}).get("artifact_ai_columns_config_path"),
                "config/artifact_ai_columns.yaml",
            )

            persisted = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
            self.assertEqual(persisted.get("ai", {}).get("provider"), "claude")
            self.assertEqual(persisted.get("server", {}).get("port"), 5000)
            self.assertEqual(persisted.get("evidence", {}).get("large_file_threshold_mb"), 0)
            self.assertEqual(
                persisted.get("ai", {}).get("local", {}).get("request_timeout_seconds"),
                3600,
            )
            self.assertEqual(persisted.get("analysis", {}).get("ai_max_tokens"), 128000)
            self.assertEqual(persisted.get("analysis", {}).get("shortened_prompt_cutoff_tokens"), 64000)
            self.assertEqual(persisted.get("analysis", {}).get("artifact_deduplication_enabled"), True)
            self.assertEqual(
                persisted.get("analysis", {}).get("artifact_ai_columns_config_path"),
                "config/artifact_ai_columns.yaml",
            )

    def test_load_config_applies_environment_variable_overrides(self) -> None:
        with TemporaryDirectory(prefix="aift-config-test-") as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            load_config(config_path)

            with patch.dict(
                "os.environ",
                {
                    "ANTHROPIC_API_KEY": "anthropic-from-env",
                    "OPENAI_API_KEY": "openai-from-env",
                },
                clear=False,
            ):
                config = load_config(config_path)

        self.assertEqual(config.get("ai", {}).get("claude", {}).get("api_key"), "anthropic-from-env")
        self.assertEqual(config.get("ai", {}).get("openai", {}).get("api_key"), "openai-from-env")

    def test_load_config_skips_env_overrides_when_disabled(self) -> None:
        """When use_env_overrides=False, environment variables must not apply."""
        with TemporaryDirectory(prefix="aift-config-test-") as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            with patch.dict(
                "os.environ",
                {"ANTHROPIC_API_KEY": "should-not-appear"},
                clear=False,
            ):
                config = load_config(config_path, use_env_overrides=False)
        self.assertEqual(config["ai"]["claude"]["api_key"], "")

    def test_load_config_merges_yaml_overrides(self) -> None:
        """Values from an existing YAML file override defaults."""
        with TemporaryDirectory(prefix="aift-config-test-") as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text(
                yaml.safe_dump({"server": {"port": 9999}, "ai": {"provider": "openai"}}),
                encoding="utf-8",
            )
            config = load_config(config_path, use_env_overrides=False)
        self.assertEqual(config["server"]["port"], 9999)
        self.assertEqual(config["ai"]["provider"], "openai")
        # Defaults for keys not in the YAML file should still be present.
        self.assertEqual(config["server"]["host"], "127.0.0.1")

    def test_load_config_raises_on_non_dict_yaml(self) -> None:
        """A YAML file whose root is not a dict must raise ValueError."""
        with TemporaryDirectory(prefix="aift-config-test-") as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text("- item1\n- item2\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_config(config_path)

    def test_load_config_handles_empty_yaml_file(self) -> None:
        """An empty YAML file should result in default config."""
        with TemporaryDirectory(prefix="aift-config-test-") as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text("", encoding="utf-8")
            config = load_config(config_path, use_env_overrides=False)
        self.assertEqual(config["ai"]["provider"], "claude")
        self.assertEqual(config["server"]["port"], 5000)


class ConfigPathResolutionTests(unittest.TestCase):
    """Verify that config paths resolve relative to the project root, not CWD."""

    def test_project_root_points_to_aift_directory(self) -> None:
        self.assertTrue((PROJECT_ROOT / "aift.py").exists())
        self.assertTrue((PROJECT_ROOT / "app" / "config.py").exists())

    def test_load_config_default_path_uses_project_root(self) -> None:
        """When no path argument is given, the config file should be resolved
        relative to PROJECT_ROOT regardless of the current working directory."""
        with TemporaryDirectory(prefix="aift-cwd-test-") as fake_cwd:
            with patch("os.getcwd", return_value=fake_cwd):
                expected = PROJECT_ROOT / "config.yaml"
                # Call load_config with no arguments; it should NOT create
                # config.yaml in the fake CWD.
                load_config()
                spurious = Path(fake_cwd) / "config.yaml"
                self.assertFalse(
                    spurious.exists(),
                    f"config.yaml was created in CWD ({fake_cwd}) instead of PROJECT_ROOT",
                )
                # It should have used the project-root path.
                self.assertTrue(
                    expected.exists(),
                    "config.yaml should exist at PROJECT_ROOT after load_config()",
                )

    def test_save_config_default_path_uses_project_root(self) -> None:
        """save_config() with no explicit path writes next to the project root."""
        expected = PROJECT_ROOT / "config.yaml"
        # Ensure the file exists first so we can verify it's overwritten there.
        original_content = None
        if expected.exists():
            original_content = expected.read_text(encoding="utf-8")
        try:
            config = {"ai": {"provider": "test-sentinel"}}
            save_config(config)
            self.assertTrue(expected.exists())
            reloaded = yaml.safe_load(expected.read_text(encoding="utf-8")) or {}
            self.assertEqual(reloaded.get("ai", {}).get("provider"), "test-sentinel")
        finally:
            # Restore original content so we don't corrupt the real config.
            if original_content is not None:
                expected.write_text(original_content, encoding="utf-8")
            elif expected.exists():
                expected.unlink()

    def test_load_config_with_explicit_path_still_works(self) -> None:
        with TemporaryDirectory(prefix="aift-config-explicit-") as temp_dir:
            config_path = Path(temp_dir) / "custom_config.yaml"
            config = load_config(config_path)
            self.assertTrue(config_path.exists())
            self.assertEqual(config.get("ai", {}).get("provider"), "claude")


class DeepMergeTests(unittest.TestCase):
    def test_flat_override_replaces_value(self) -> None:
        base = {"a": 1, "b": 2}
        result = _deep_merge_inplace(base, {"b": 99})
        self.assertEqual(result, {"a": 1, "b": 99})
        self.assertIs(result, base)

    def test_nested_dicts_are_merged_recursively(self) -> None:
        base = {"ai": {"provider": "claude", "claude": {"model": "opus"}}}
        override = {"ai": {"claude": {"api_key": "sk-test"}}}
        result = _deep_merge_inplace(base, override)
        self.assertEqual(result["ai"]["provider"], "claude")
        self.assertEqual(result["ai"]["claude"]["model"], "opus")
        self.assertEqual(result["ai"]["claude"]["api_key"], "sk-test")

    def test_override_adds_new_keys(self) -> None:
        base = {"a": 1}
        result = _deep_merge_inplace(base, {"b": 2, "c": {"nested": True}})
        self.assertEqual(result, {"a": 1, "b": 2, "c": {"nested": True}})

    def test_override_replaces_non_dict_with_dict(self) -> None:
        base = {"a": "string_value"}
        result = _deep_merge_inplace(base, {"a": {"nested": True}})
        self.assertEqual(result["a"], {"nested": True})

    def test_override_replaces_dict_with_non_dict(self) -> None:
        base = {"a": {"nested": True}}
        result = _deep_merge_inplace(base, {"a": 42})
        self.assertEqual(result["a"], 42)

    def test_empty_override_leaves_base_unchanged(self) -> None:
        base = {"a": 1, "b": {"c": 2}}
        original = {"a": 1, "b": {"c": 2}}
        _deep_merge_inplace(base, {})
        self.assertEqual(base, original)

    def test_deeply_nested_merge(self) -> None:
        base = {"l1": {"l2": {"l3": {"value": "old", "keep": True}}}}
        override = {"l1": {"l2": {"l3": {"value": "new"}}}}
        result = _deep_merge_inplace(base, override)
        self.assertEqual(result["l1"]["l2"]["l3"]["value"], "new")
        self.assertTrue(result["l1"]["l2"]["l3"]["keep"])

    def test_both_empty_dicts(self) -> None:
        base: dict = {}
        result = _deep_merge_inplace(base, {})
        self.assertEqual(result, {})

    def test_empty_base_with_override(self) -> None:
        base: dict = {}
        result = _deep_merge_inplace(base, {"x": 1, "y": {"z": 2}})
        self.assertEqual(result, {"x": 1, "y": {"z": 2}})


class ConfigRoundtripTests(unittest.TestCase):
    def test_save_then_load_preserves_custom_values(self) -> None:
        with TemporaryDirectory(prefix="aift-config-roundtrip-") as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config = load_config(config_path)
            config["ai"]["provider"] = "openai"
            config["server"]["port"] = 8080
            save_config(config, config_path)

            reloaded = load_config(config_path, use_env_overrides=False)

        self.assertEqual(reloaded["ai"]["provider"], "openai")
        self.assertEqual(reloaded["server"]["port"], 8080)

    def test_save_creates_parent_directories(self) -> None:
        with TemporaryDirectory(prefix="aift-config-roundtrip-") as temp_dir:
            config_path = Path(temp_dir) / "subdir" / "deep" / "config.yaml"
            save_config({"ai": {"provider": "test"}}, config_path)
            self.assertTrue(config_path.exists())
            reloaded = yaml.safe_load(config_path.read_text(encoding="utf-8"))
            self.assertEqual(reloaded["ai"]["provider"], "test")


class ApplyEnvOverridesTests(unittest.TestCase):
    def test_kimi_api_key_from_moonshot_env(self) -> None:
        with TemporaryDirectory(prefix="aift-config-test-") as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            with patch.dict(
                "os.environ",
                {"MOONSHOT_API_KEY": "moonshot-key-123"},
                clear=False,
            ):
                config = load_config(config_path)
        self.assertEqual(config.get("ai", {}).get("kimi", {}).get("api_key"), "moonshot-key-123")

    def test_kimi_api_key_from_kimi_env_fallback(self) -> None:
        with TemporaryDirectory(prefix="aift-config-test-") as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            with patch.dict(
                "os.environ",
                {"KIMI_API_KEY": "kimi-key-456"},
                clear=False,
            ):
                config = load_config(config_path)
        self.assertEqual(config.get("ai", {}).get("kimi", {}).get("api_key"), "kimi-key-456")

    def test_empty_env_vars_are_ignored(self) -> None:
        with TemporaryDirectory(prefix="aift-config-test-") as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            with patch.dict(
                "os.environ",
                {"ANTHROPIC_API_KEY": "", "OPENAI_API_KEY": "  "},
                clear=False,
            ):
                config = load_config(config_path, use_env_overrides=True)
        self.assertEqual(config.get("ai", {}).get("claude", {}).get("api_key"), "")
        self.assertEqual(config.get("ai", {}).get("openai", {}).get("api_key"), "")

    def test_apply_env_overrides_direct_call(self) -> None:
        """Call apply_env_overrides directly with a minimal config dict."""
        config: dict = {"ai": {"claude": {"api_key": ""}, "openai": {"api_key": ""}, "kimi": {"api_key": ""}}}
        with patch.dict(
            "os.environ",
            {"ANTHROPIC_API_KEY": "ak-direct", "OPENAI_API_KEY": "ok-direct"},
            clear=False,
        ):
            result = apply_env_overrides(config)
        self.assertIs(result, config)
        self.assertEqual(config["ai"]["claude"]["api_key"], "ak-direct")
        self.assertEqual(config["ai"]["openai"]["api_key"], "ok-direct")

    def test_apply_env_overrides_creates_missing_keys(self) -> None:
        """apply_env_overrides should use setdefault to build missing nesting."""
        config: dict = {}
        with patch.dict(
            "os.environ",
            {"ANTHROPIC_API_KEY": "ak-new"},
            clear=False,
        ):
            apply_env_overrides(config)
        self.assertEqual(config["ai"]["claude"]["api_key"], "ak-new")

    def test_moonshot_takes_precedence_over_kimi_env(self) -> None:
        """When both MOONSHOT_API_KEY and KIMI_API_KEY are set, MOONSHOT wins."""
        config = get_default_config()
        with patch.dict(
            "os.environ",
            {"MOONSHOT_API_KEY": "moonshot-wins", "KIMI_API_KEY": "kimi-loses"},
            clear=False,
        ):
            apply_env_overrides(config)
        self.assertEqual(config["ai"]["kimi"]["api_key"], "moonshot-wins")

    def test_kimi_env_used_when_moonshot_is_empty(self) -> None:
        """When MOONSHOT_API_KEY is empty, KIMI_API_KEY is used as fallback."""
        config = get_default_config()
        with patch.dict(
            "os.environ",
            {"MOONSHOT_API_KEY": "", "KIMI_API_KEY": "kimi-fallback"},
            clear=False,
        ):
            apply_env_overrides(config)
        self.assertEqual(config["ai"]["kimi"]["api_key"], "kimi-fallback")


class GetDefaultConfigTests(unittest.TestCase):
    """Tests for the get_default_config function."""

    def test_returns_deep_copy(self) -> None:
        """Returned dict should be a deep copy, not the original DEFAULT_CONFIG."""
        config = get_default_config()
        self.assertEqual(config, DEFAULT_CONFIG)
        self.assertIsNot(config, DEFAULT_CONFIG)

    def test_mutation_does_not_affect_defaults(self) -> None:
        """Mutating the returned dict must not change DEFAULT_CONFIG."""
        config = get_default_config()
        config["ai"]["provider"] = "mutated"
        config["server"]["port"] = 99999
        self.assertEqual(DEFAULT_CONFIG["ai"]["provider"], "claude")
        self.assertEqual(DEFAULT_CONFIG["server"]["port"], 5000)

    def test_contains_all_expected_top_level_keys(self) -> None:
        config = get_default_config()
        for key in ("ai", "server", "evidence", "analysis"):
            self.assertIn(key, config)

    def test_all_providers_present(self) -> None:
        config = get_default_config()
        for provider in KNOWN_AI_PROVIDERS:
            self.assertIn(provider, config["ai"])


class ValidateConfigTests(unittest.TestCase):
    """Tests for the validate_config function."""

    def _valid_config(self) -> dict:
        """Return a config that passes all validation checks."""
        return get_default_config()

    def test_valid_default_config_passes(self) -> None:
        errors = validate_config(self._valid_config())
        self.assertEqual(errors, [])

    # --- server section ---

    def test_server_not_a_dict(self) -> None:
        config = self._valid_config()
        config["server"] = "not-a-dict"
        errors = validate_config(config)
        self.assertTrue(any("server: expected a mapping" in e for e in errors))

    def test_invalid_port_type(self) -> None:
        config = self._valid_config()
        config["server"]["port"] = "not-an-int"
        errors = validate_config(config)
        self.assertTrue(any("server.port" in e for e in errors))

    def test_port_zero(self) -> None:
        config = self._valid_config()
        config["server"]["port"] = 0
        errors = validate_config(config)
        self.assertTrue(any("server.port" in e for e in errors))

    def test_port_too_high(self) -> None:
        config = self._valid_config()
        config["server"]["port"] = 70000
        errors = validate_config(config)
        self.assertTrue(any("server.port" in e for e in errors))

    def test_port_boundary_1(self) -> None:
        config = self._valid_config()
        config["server"]["port"] = 1
        errors = validate_config(config)
        port_errors = [e for e in errors if "server.port" in e]
        self.assertEqual(port_errors, [])

    def test_port_boundary_65535(self) -> None:
        config = self._valid_config()
        config["server"]["port"] = 65535
        errors = validate_config(config)
        port_errors = [e for e in errors if "server.port" in e]
        self.assertEqual(port_errors, [])

    def test_empty_host(self) -> None:
        config = self._valid_config()
        config["server"]["host"] = ""
        errors = validate_config(config)
        self.assertTrue(any("server.host" in e for e in errors))

    def test_whitespace_only_host(self) -> None:
        config = self._valid_config()
        config["server"]["host"] = "   "
        errors = validate_config(config)
        self.assertTrue(any("server.host" in e for e in errors))

    def test_host_not_a_string(self) -> None:
        config = self._valid_config()
        config["server"]["host"] = 12345
        errors = validate_config(config)
        self.assertTrue(any("server.host" in e for e in errors))

    # --- ai section ---

    def test_ai_not_a_dict(self) -> None:
        config = self._valid_config()
        config["ai"] = "not-a-dict"
        errors = validate_config(config)
        self.assertTrue(any("ai: expected a mapping" in e for e in errors))

    def test_unknown_ai_provider(self) -> None:
        config = self._valid_config()
        config["ai"]["provider"] = "unknown-provider"
        errors = validate_config(config)
        self.assertTrue(any("ai.provider" in e for e in errors))

    def test_valid_ai_providers_accepted(self) -> None:
        for provider in KNOWN_AI_PROVIDERS:
            config = self._valid_config()
            config["ai"]["provider"] = provider
            errors = validate_config(config)
            provider_errors = [e for e in errors if "ai.provider" in e]
            self.assertEqual(provider_errors, [], f"Provider {provider!r} should be valid")

    def test_empty_model_string(self) -> None:
        config = self._valid_config()
        config["ai"]["claude"]["model"] = ""
        errors = validate_config(config)
        self.assertTrue(any("ai.claude.model" in e for e in errors))

    def test_model_not_a_string(self) -> None:
        config = self._valid_config()
        config["ai"]["openai"]["model"] = 42
        errors = validate_config(config)
        self.assertTrue(any("ai.openai.model" in e for e in errors))

    def test_api_key_not_a_string(self) -> None:
        config = self._valid_config()
        config["ai"]["claude"]["api_key"] = 12345
        errors = validate_config(config)
        self.assertTrue(any("ai.claude.api_key" in e for e in errors))

    def test_empty_api_key_is_valid(self) -> None:
        """An empty string for api_key is allowed (it just means unconfigured)."""
        config = self._valid_config()
        config["ai"]["claude"]["api_key"] = ""
        errors = validate_config(config)
        key_errors = [e for e in errors if "api_key" in e]
        self.assertEqual(key_errors, [])

    def test_base_url_must_start_with_http(self) -> None:
        config = self._valid_config()
        config["ai"]["local"]["base_url"] = "ftp://localhost:11434"
        errors = validate_config(config)
        self.assertTrue(any("ai.local.base_url" in e for e in errors))

    def test_base_url_http_is_valid(self) -> None:
        config = self._valid_config()
        config["ai"]["local"]["base_url"] = "http://localhost:11434/v1"
        errors = validate_config(config)
        url_errors = [e for e in errors if "base_url" in e]
        self.assertEqual(url_errors, [])

    def test_base_url_https_is_valid(self) -> None:
        config = self._valid_config()
        config["ai"]["kimi"]["base_url"] = "https://api.moonshot.ai/v1"
        errors = validate_config(config)
        url_errors = [e for e in errors if "base_url" in e]
        self.assertEqual(url_errors, [])

    def test_base_url_not_a_string(self) -> None:
        config = self._valid_config()
        config["ai"]["local"]["base_url"] = 12345
        errors = validate_config(config)
        self.assertTrue(any("ai.local.base_url" in e for e in errors))

    def test_base_url_none_is_valid(self) -> None:
        """Providers without a base_url (None) should not trigger an error."""
        config = self._valid_config()
        config["ai"]["claude"]["base_url"] = None
        errors = validate_config(config)
        url_errors = [e for e in errors if "base_url" in e]
        self.assertEqual(url_errors, [])

    def test_provider_config_not_a_dict_is_skipped(self) -> None:
        """If a provider entry is not a dict, model/api_key checks are skipped."""
        config = self._valid_config()
        config["ai"]["claude"] = "not-a-dict"
        errors = validate_config(config)
        # Should not crash; claude-specific errors should not appear.
        claude_model_errors = [e for e in errors if "ai.claude.model" in e]
        self.assertEqual(claude_model_errors, [])

    # --- analysis section ---

    def test_ai_max_tokens_zero(self) -> None:
        config = self._valid_config()
        config["analysis"]["ai_max_tokens"] = 0
        errors = validate_config(config)
        self.assertTrue(any("analysis.ai_max_tokens" in e for e in errors))

    def test_ai_max_tokens_negative(self) -> None:
        config = self._valid_config()
        config["analysis"]["ai_max_tokens"] = -100
        errors = validate_config(config)
        self.assertTrue(any("analysis.ai_max_tokens" in e for e in errors))

    def test_ai_max_tokens_not_an_int(self) -> None:
        config = self._valid_config()
        config["analysis"]["ai_max_tokens"] = "many"
        errors = validate_config(config)
        self.assertTrue(any("analysis.ai_max_tokens" in e for e in errors))

    def test_ai_max_tokens_float_rejected(self) -> None:
        """ai_max_tokens must be int, not float."""
        config = self._valid_config()
        config["analysis"]["ai_max_tokens"] = 128000.5
        errors = validate_config(config)
        self.assertTrue(any("analysis.ai_max_tokens" in e for e in errors))

    # --- evidence section ---

    def test_large_file_threshold_zero_is_valid(self) -> None:
        config = self._valid_config()
        config["evidence"]["large_file_threshold_mb"] = 0
        errors = validate_config(config)
        threshold_errors = [e for e in errors if "large_file_threshold_mb" in e]
        self.assertEqual(threshold_errors, [])

    def test_large_file_threshold_negative(self) -> None:
        config = self._valid_config()
        config["evidence"]["large_file_threshold_mb"] = -5
        errors = validate_config(config)
        self.assertTrue(any("evidence.large_file_threshold_mb" in e for e in errors))

    def test_large_file_threshold_not_a_number(self) -> None:
        config = self._valid_config()
        config["evidence"]["large_file_threshold_mb"] = "big"
        errors = validate_config(config)
        self.assertTrue(any("evidence.large_file_threshold_mb" in e for e in errors))

    def test_large_file_threshold_float_is_valid(self) -> None:
        config = self._valid_config()
        config["evidence"]["large_file_threshold_mb"] = 1024.5
        errors = validate_config(config)
        threshold_errors = [e for e in errors if "large_file_threshold_mb" in e]
        self.assertEqual(threshold_errors, [])

    # --- multiple errors ---

    def test_multiple_errors_returned(self) -> None:
        """Multiple validation issues should produce multiple error strings."""
        config = self._valid_config()
        config["server"]["port"] = -1
        config["server"]["host"] = ""
        config["ai"]["provider"] = "invalid"
        config["analysis"]["ai_max_tokens"] = 0
        errors = validate_config(config)
        self.assertGreaterEqual(len(errors), 4)

    # --- missing sections ---

    def test_missing_server_section_uses_empty_dict(self) -> None:
        """If 'server' key is absent, validate_config should still work."""
        config = self._valid_config()
        del config["server"]
        errors = validate_config(config)
        # Should report port/host errors from empty dict defaults
        self.assertTrue(any("server.port" in e for e in errors))

    def test_missing_analysis_section(self) -> None:
        config = self._valid_config()
        del config["analysis"]
        # Should not crash; .get("analysis", {}) returns empty dict which is
        # a dict, so checks run and find None for ai_max_tokens.
        errors = validate_config(config)
        self.assertTrue(any("analysis.ai_max_tokens" in e for e in errors))

    def test_missing_evidence_section(self) -> None:
        config = self._valid_config()
        del config["evidence"]
        # .get("evidence", {}) returns empty dict, so threshold is None.
        errors = validate_config(config)
        self.assertTrue(any("evidence.large_file_threshold_mb" in e for e in errors))


class ConstantsTests(unittest.TestCase):
    """Tests for module-level constants."""

    def test_known_ai_providers_is_tuple(self) -> None:
        self.assertIsInstance(KNOWN_AI_PROVIDERS, tuple)

    def test_known_ai_providers_contains_expected_values(self) -> None:
        for expected in ("claude", "openai", "kimi", "local"):
            self.assertIn(expected, KNOWN_AI_PROVIDERS)

    def test_logo_file_candidates_is_tuple(self) -> None:
        self.assertIsInstance(LOGO_FILE_CANDIDATES, tuple)

    def test_logo_file_candidates_not_empty(self) -> None:
        self.assertGreater(len(LOGO_FILE_CANDIDATES), 0)

    def test_project_root_is_absolute(self) -> None:
        self.assertTrue(PROJECT_ROOT.is_absolute())

    def test_default_config_has_all_provider_sections(self) -> None:
        for provider in KNOWN_AI_PROVIDERS:
            self.assertIn(provider, DEFAULT_CONFIG["ai"])


class SaveConfigTests(unittest.TestCase):
    """Additional tests for save_config edge cases."""

    def test_save_config_overwrites_existing_file(self) -> None:
        with TemporaryDirectory(prefix="aift-config-save-") as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            save_config({"version": 1}, config_path)
            save_config({"version": 2}, config_path)
            reloaded = yaml.safe_load(config_path.read_text(encoding="utf-8"))
            self.assertEqual(reloaded["version"], 2)
            # The old key should not be present (full overwrite, not merge).
            self.assertNotIn("ai", reloaded)

    def test_save_config_writes_utf8(self) -> None:
        with TemporaryDirectory(prefix="aift-config-save-") as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            save_config({"note": "unicode test: \u00e9\u00e0\u00fc\u00f1"}, config_path)
            content = config_path.read_text(encoding="utf-8")
            self.assertIn("unicode test", content)


class LoadConfigValidationEnforcementTests(unittest.TestCase):
    """Regression tests: load_config must reject invalid persisted configs."""

    def test_load_config_raises_on_invalid_port(self) -> None:
        """A persisted config with an out-of-range port must raise ConfigurationError."""
        with TemporaryDirectory(prefix="aift-config-test-") as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text(
                yaml.safe_dump({"server": {"port": "not-a-number"}}),
                encoding="utf-8",
            )
            with self.assertRaises(ConfigurationError) as ctx:
                load_config(config_path, use_env_overrides=False)
            self.assertTrue(any("server.port" in e for e in ctx.exception.errors))

    def test_load_config_raises_on_invalid_provider(self) -> None:
        """A persisted config with an unknown AI provider must raise ConfigurationError."""
        with TemporaryDirectory(prefix="aift-config-test-") as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text(
                yaml.safe_dump({"ai": {"provider": "doesnotexist"}}),
                encoding="utf-8",
            )
            with self.assertRaises(ConfigurationError) as ctx:
                load_config(config_path, use_env_overrides=False)
            self.assertTrue(any("ai.provider" in e for e in ctx.exception.errors))

    def test_load_config_error_contains_all_issues(self) -> None:
        """ConfigurationError should list every validation failure."""
        with TemporaryDirectory(prefix="aift-config-test-") as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text(
                yaml.safe_dump({
                    "server": {"port": -1, "host": ""},
                    "ai": {"provider": "bad"},
                    "evidence": {"large_file_threshold_mb": -1},
                }),
                encoding="utf-8",
            )
            with self.assertRaises(ConfigurationError) as ctx:
                load_config(config_path, use_env_overrides=False)
            self.assertGreaterEqual(len(ctx.exception.errors), 4)

    def test_valid_config_still_loads_successfully(self) -> None:
        """Ensure valid configs are not rejected by the new strictness."""
        with TemporaryDirectory(prefix="aift-config-test-") as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config_path.write_text(
                yaml.safe_dump({"server": {"port": 8080}, "ai": {"provider": "openai"}}),
                encoding="utf-8",
            )
            config = load_config(config_path, use_env_overrides=False)
            self.assertEqual(config["server"]["port"], 8080)
            self.assertEqual(config["ai"]["provider"], "openai")


if __name__ == "__main__":
    unittest.main()
