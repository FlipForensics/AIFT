from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

import app.routes.artifacts as routes_artifacts
import app.routes.state as routes_state


class ArtifactProfileHelperTests(unittest.TestCase):
    def test_load_profile_file_supports_legacy_selections(self) -> None:
        with TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "legacy_profile.json"
            path.write_text(
                json.dumps(
                    {
                        "name": "Legacy Profile",
                        "selections": [
                            "runkeys",
                            {"artifact_key": "mft", "mode": routes_artifacts.MODE_PARSE_ONLY},
                        ],
                    }
                ),
                encoding="utf-8",
            )

            profile = routes_artifacts._load_profile_file(path)

        self.assertIsNotNone(profile)
        self.assertEqual(profile["name"], "Legacy Profile")
        self.assertEqual(
            profile["artifact_options"],
            [
                {"artifact_key": "runkeys", "mode": routes_artifacts.MODE_PARSE_AND_AI},
                {"artifact_key": "mft", "mode": routes_artifacts.MODE_PARSE_ONLY},
            ],
        )

    def test_load_profiles_from_directory_skips_case_insensitive_duplicate_names(self) -> None:
        with TemporaryDirectory() as tmpdir:
            profiles_root = Path(tmpdir)
            (profiles_root / "a_profile.json").write_text(
                json.dumps({"name": "Alpha", "artifact_options": ["runkeys"]}),
                encoding="utf-8",
            )
            (profiles_root / "b_profile.json").write_text(
                json.dumps({"name": "alpha", "artifact_options": ["mft"]}),
                encoding="utf-8",
            )

            profiles = routes_artifacts.load_profiles_from_directory(profiles_root)

        custom_profiles = [
            profile
            for profile in profiles
            if str(profile.get("name", "")).strip().lower() != routes_artifacts.BUILTIN_RECOMMENDED_PROFILE
        ]
        self.assertEqual(len(custom_profiles), 1)
        self.assertEqual(custom_profiles[0]["name"], "Alpha")


class AuditConfigChangeTests(unittest.TestCase):
    def tearDown(self) -> None:
        routes_state.CASE_STATES.clear()

    def test_audit_config_change_continues_when_one_logger_fails(self) -> None:
        good_logger = MagicMock()
        failing_logger = MagicMock()
        failing_logger.log.side_effect = RuntimeError("boom")
        other_good_logger = MagicMock()
        routes_state.CASE_STATES.clear()
        routes_state.CASE_STATES.update(
            {
                "case-1": {"audit": good_logger},
                "case-2": {"audit": failing_logger},
                "case-3": {"audit": other_good_logger},
                "case-4": {"audit": None},
            }
        )

        routes_state.audit_config_change(["server.port", "ai.openai.api_key", "server.port"])

        expected_details = {
            "changed_keys": ["server.port", "ai.openai.api_key (redacted)"],
            "changed_count": 2,
        }
        good_logger.log.assert_called_once_with("config_changed", expected_details)
        failing_logger.log.assert_called_once_with("config_changed", expected_details)
        other_good_logger.log.assert_called_once_with("config_changed", expected_details)


class ResolveLogoFilenameTests(unittest.TestCase):
    def test_falls_back_to_first_available_image_file(self) -> None:
        with TemporaryDirectory() as tmpdir:
            images_root = Path(tmpdir)
            (images_root / "zeta.webp").write_bytes(b"demo")
            (images_root / "alpha.png").write_bytes(b"demo")
            (images_root / "ignore.txt").write_text("not an image", encoding="utf-8")

            with patch.object(routes_state, "IMAGES_ROOT", images_root):
                result = routes_state.resolve_logo_filename()

        self.assertEqual(result, "alpha.png")


if __name__ == "__main__":
    unittest.main()
