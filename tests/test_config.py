from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import yaml

from app.config import PROJECT_ROOT, load_config, save_config


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


if __name__ == "__main__":
    unittest.main()
