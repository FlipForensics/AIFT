from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

import yaml

from app.config import load_config


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
            self.assertEqual(config.get("analysis", {}).get("ai_max_tokens"), 128000)
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
            self.assertEqual(persisted.get("analysis", {}).get("ai_max_tokens"), 128000)
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


if __name__ == "__main__":
    unittest.main()
