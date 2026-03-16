from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import yaml

from app.config import PROJECT_ROOT, _deep_merge_inplace, load_config, save_config


class ConfigTests(unittest.TestCase):
    def test_load_config_creates_default_config_on_first_run(self) -> None:
        with TemporaryDirectory(prefix="aift-config-test-") as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            self.assertFalse(config_path.exists())

            config = load_config(config_path)

            self.assertTrue(config_path.exists())
            self.assertEqual(config.get("ai", {}).get("provider"), "claude")
            self.assertEqual(config.get("server", {}).get("port"), 5000)
            self.assertEqual(config.get("server", {}).get("max_upload_mb"), 2048)
            self.assertEqual(config.get("evidence", {}).get("large_file_threshold_mb"), 2048)
            self.assertEqual(config.get("evidence", {}).get("csv_output_dir"), "")
            self.assertEqual(
                config.get("ai", {}).get("local", {}).get("request_timeout_seconds"),
                3600,
            )
            self.assertEqual(config.get("analysis", {}).get("ai_max_tokens"), 128000)
            self.assertEqual(config.get("analysis", {}).get("shortened_prompt_cutoff_tokens"), 64000)
            self.assertEqual(config.get("analysis", {}).get("date_buffer_days"), 7)
            self.assertEqual(config.get("analysis", {}).get("artifact_deduplication_enabled"), True)
            self.assertEqual(
                config.get("analysis", {}).get("artifact_ai_columns_config_path"),
                "config/artifact_ai_columns.yaml",
            )

            persisted = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
            self.assertEqual(persisted.get("ai", {}).get("provider"), "claude")
            self.assertEqual(persisted.get("server", {}).get("port"), 5000)
            self.assertEqual(persisted.get("evidence", {}).get("large_file_threshold_mb"), 2048)
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


class ConfigRoundtripTests(unittest.TestCase):
    def test_save_then_load_preserves_custom_values(self) -> None:
        with TemporaryDirectory(prefix="aift-config-roundtrip-") as temp_dir:
            config_path = Path(temp_dir) / "config.yaml"
            config = load_config(config_path)
            config["ai"]["provider"] = "openai"
            config["server"]["port"] = 8080
            config["analysis"]["date_buffer_days"] = 14
            save_config(config, config_path)

            reloaded = load_config(config_path, use_env_overrides=False)

        self.assertEqual(reloaded["ai"]["provider"], "openai")
        self.assertEqual(reloaded["server"]["port"], 8080)
        self.assertEqual(reloaded["analysis"]["date_buffer_days"], 14)

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


if __name__ == "__main__":
    unittest.main()
