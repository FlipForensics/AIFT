from __future__ import annotations

from datetime import date, datetime, time, timezone
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch
import unittest

from app.audit import (
    ACTION_TYPES,
    AuditLogger,
    DEFAULT_TOOL_VERSION,
    _json_default,
    _resolve_dissect_version,
    _utc_now_iso8601_ms,
)


class AuditLoggerTests(unittest.TestCase):
    @staticmethod
    def _read_audit_entries(audit_path: Path) -> list[dict[str, object]]:
        return [
            json.loads(line)
            for line in audit_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def test_log_serializes_non_json_native_detail_values(self) -> None:
        with TemporaryDirectory(prefix="aift-audit-test-") as temp_dir:
            logger = AuditLogger(temp_dir)
            logger.log(
                "config_changed",
                {
                    "timestamp_value": datetime(2026, 1, 15, 12, 30, 45),
                    "date_value": date(2026, 1, 15),
                    "time_value": time(12, 30, 45),
                    "path_value": Path("C:/Evidence/SUSPECT.E01"),
                    "bytes_value": b"\xde\xad\xbe\xef",
                },
            )

            audit_path = Path(temp_dir) / "audit.jsonl"
            entry = json.loads(audit_path.read_text(encoding="utf-8").splitlines()[-1])
            details = entry["details"]

        self.assertEqual(details["timestamp_value"], "2026-01-15T12:30:45")
        self.assertEqual(details["date_value"], "2026-01-15")
        self.assertEqual(details["time_value"], "12:30:45")
        self.assertEqual(details["path_value"], "C:\\Evidence\\SUSPECT.E01")
        self.assertEqual(details["bytes_value"], "deadbeef")

    def test_log_accepts_every_supported_action_type(self) -> None:
        with TemporaryDirectory(prefix="aift-audit-test-") as temp_dir:
            logger = AuditLogger(temp_dir)
            audit_path = Path(temp_dir) / "audit.jsonl"

            for action in ACTION_TYPES:
                logger.log(action, {"case_id": "case-001"})

            entries = self._read_audit_entries(audit_path)

        self.assertEqual(len(entries), len(ACTION_TYPES))
        self.assertEqual({str(entry["action"]) for entry in entries}, set(ACTION_TYPES))

    def test_log_rejects_invalid_action_type(self) -> None:
        with TemporaryDirectory(prefix="aift-audit-test-") as temp_dir:
            logger = AuditLogger(temp_dir)

            with self.assertRaises(ValueError):
                logger.log("not_a_real_action", {"case_id": "case-001"})

    def test_log_is_append_only_across_multiple_calls(self) -> None:
        with TemporaryDirectory(prefix="aift-audit-test-") as temp_dir:
            logger = AuditLogger(temp_dir)
            audit_path = Path(temp_dir) / "audit.jsonl"

            logger.log("prompt_submitted", {"case_id": "case-append", "prompt": "one"})
            first_lines = audit_path.read_text(encoding="utf-8").splitlines()
            first_size = audit_path.stat().st_size

            logger.log("report_generated", {"case_id": "case-append", "report_filename": "report.html"})
            second_lines = audit_path.read_text(encoding="utf-8").splitlines()
            second_size = audit_path.stat().st_size

        self.assertEqual(len(first_lines), 1)
        self.assertEqual(len(second_lines), 2)
        self.assertEqual(second_lines[0], first_lines[0])
        self.assertGreater(second_size, first_size)

    def test_log_entries_are_valid_json_with_expected_fields(self) -> None:
        with TemporaryDirectory(prefix="aift-audit-test-") as temp_dir:
            logger = AuditLogger(temp_dir)
            logger.log("case_created", {"case_id": "case-json", "name": "JSON Field Check"})

            audit_path = Path(temp_dir) / "audit.jsonl"
            raw_line = audit_path.read_text(encoding="utf-8").splitlines()[-1]
            entry = json.loads(raw_line)

        self.assertIsInstance(entry, dict)
        self.assertIn("timestamp", entry)
        self.assertIn("action", entry)
        self.assertIn("details", entry)
        self.assertEqual(str(entry["action"]), "case_created")
        self.assertEqual(str(entry["details"]["case_id"]), "case-json")
        parsed_timestamp = datetime.fromisoformat(str(entry["timestamp"]).replace("Z", "+00:00"))
        self.assertIsNotNone(parsed_timestamp)


    def test_log_rejects_non_dict_details(self) -> None:
        with TemporaryDirectory(prefix="aift-audit-test-") as temp_dir:
            logger = AuditLogger(temp_dir)

            with self.assertRaises(TypeError):
                logger.log("case_created", "not-a-dict")

            with self.assertRaises(TypeError):
                logger.log("case_created", ["list", "of", "items"])

    def test_log_entries_contain_session_id(self) -> None:
        with TemporaryDirectory(prefix="aift-audit-test-") as temp_dir:
            logger = AuditLogger(temp_dir)
            logger.log("case_created", {"case_id": "session-test"})

            audit_path = Path(temp_dir) / "audit.jsonl"
            entry = json.loads(audit_path.read_text(encoding="utf-8").splitlines()[-1])

        self.assertIn("session_id", entry)
        self.assertIsInstance(entry["session_id"], str)
        self.assertGreater(len(entry["session_id"]), 0)

    def test_log_timestamp_is_utc_iso8601(self) -> None:
        with TemporaryDirectory(prefix="aift-audit-test-") as temp_dir:
            logger = AuditLogger(temp_dir)
            logger.log("case_created", {"case_id": "ts-test"})

            audit_path = Path(temp_dir) / "audit.jsonl"
            entry = json.loads(audit_path.read_text(encoding="utf-8").splitlines()[-1])

        ts = str(entry["timestamp"])
        self.assertTrue(ts.endswith("Z") or "+00:00" in ts)
        parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        self.assertIsNotNone(parsed)

    def test_session_id_is_consistent_across_calls(self) -> None:
        with TemporaryDirectory(prefix="aift-audit-test-") as temp_dir:
            logger = AuditLogger(temp_dir)
            logger.log("case_created", {"case_id": "c1"})
            logger.log("report_generated", {"case_id": "c1"})

            audit_path = Path(temp_dir) / "audit.jsonl"
            entries = self._read_audit_entries(audit_path)

        self.assertEqual(entries[0]["session_id"], entries[1]["session_id"])

    def test_different_loggers_have_different_session_ids(self) -> None:
        with TemporaryDirectory(prefix="aift-audit-test-") as temp_dir:
            logger1 = AuditLogger(Path(temp_dir) / "case1")
            logger2 = AuditLogger(Path(temp_dir) / "case2")

        self.assertNotEqual(logger1.session_id, logger2.session_id)


class UtcNowIso8601MsTests(unittest.TestCase):
    """Tests for the _utc_now_iso8601_ms helper."""

    def test_returns_string_ending_with_z(self) -> None:
        result = _utc_now_iso8601_ms()
        self.assertIsInstance(result, str)
        self.assertTrue(result.endswith("Z"))

    def test_parseable_as_iso8601(self) -> None:
        result = _utc_now_iso8601_ms()
        parsed = datetime.fromisoformat(result.replace("Z", "+00:00"))
        self.assertEqual(parsed.tzinfo, timezone.utc)

    def test_has_millisecond_precision(self) -> None:
        result = _utc_now_iso8601_ms()
        # Format: YYYY-MM-DDTHH:MM:SS.mmmZ  — 3 digits after the dot
        before_z = result.rstrip("Z")
        fractional = before_z.split(".")[-1]
        self.assertEqual(len(fractional), 3)

    @patch("app.audit.datetime")
    def test_uses_utc(self, mock_datetime: object) -> None:
        fixed = datetime(2026, 6, 15, 10, 30, 0, 123000, tzinfo=timezone.utc)
        mock_datetime.now.return_value = fixed
        # Delegate isoformat to the real datetime
        fixed_iso = fixed.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        result = _utc_now_iso8601_ms()
        self.assertEqual(result, fixed_iso)
        mock_datetime.now.assert_called_once_with(timezone.utc)


class ResolveDissectVersionTests(unittest.TestCase):
    """Tests for the _resolve_dissect_version helper."""

    @patch("app.audit.metadata.version", return_value="3.14.0")
    def test_returns_dissect_version_when_available(self, mock_version: object) -> None:
        result = _resolve_dissect_version()
        self.assertEqual(result, "3.14.0")
        mock_version.assert_called_once_with("dissect")

    @patch("app.audit.metadata.version")
    def test_falls_back_to_dissect_target(self, mock_version: object) -> None:
        from importlib.metadata import PackageNotFoundError

        def side_effect(pkg: str) -> str:
            if pkg == "dissect":
                raise PackageNotFoundError()
            return "2.0.0"

        mock_version.side_effect = side_effect
        result = _resolve_dissect_version()
        self.assertEqual(result, "2.0.0")

    @patch("app.audit.metadata.version")
    def test_returns_unknown_when_no_package_found(self, mock_version: object) -> None:
        from importlib.metadata import PackageNotFoundError

        mock_version.side_effect = PackageNotFoundError()
        result = _resolve_dissect_version()
        self.assertEqual(result, "unknown")


class JsonDefaultTests(unittest.TestCase):
    """Tests for the _json_default fallback serializer."""

    def test_datetime_value(self) -> None:
        self.assertEqual(_json_default(datetime(2026, 1, 15, 12, 0, 0)), "2026-01-15T12:00:00")

    def test_date_value(self) -> None:
        self.assertEqual(_json_default(date(2026, 1, 15)), "2026-01-15")

    def test_time_value(self) -> None:
        self.assertEqual(_json_default(time(8, 30, 0)), "08:30:00")

    def test_path_value(self) -> None:
        p = Path("/some/path")
        self.assertEqual(_json_default(p), str(p))

    def test_bytes_value(self) -> None:
        self.assertEqual(_json_default(b"\xca\xfe"), "cafe")

    def test_bytearray_value(self) -> None:
        self.assertEqual(_json_default(bytearray(b"\x00\xff")), "00ff")

    def test_memoryview_value(self) -> None:
        self.assertEqual(_json_default(memoryview(b"\xab\xcd")), "abcd")

    def test_fallback_uses_str(self) -> None:
        self.assertEqual(_json_default(42), "42")
        self.assertEqual(_json_default(None), "None")
        self.assertEqual(_json_default({"key": "val"}), "{'key': 'val'}")


class AuditLoggerInitTests(unittest.TestCase):
    """Tests for AuditLogger.__init__ behaviour."""

    def test_creates_case_directory_if_missing(self) -> None:
        with TemporaryDirectory(prefix="aift-audit-test-") as temp_dir:
            nested = Path(temp_dir) / "sub" / "deep"
            logger = AuditLogger(nested)
            self.assertTrue(nested.is_dir())
            self.assertTrue(logger.audit_file.exists())

    def test_audit_file_created_on_init(self) -> None:
        with TemporaryDirectory(prefix="aift-audit-test-") as temp_dir:
            logger = AuditLogger(temp_dir)
            self.assertTrue(logger.audit_file.exists())
            self.assertEqual(logger.audit_file.name, "audit.jsonl")

    def test_custom_tool_version(self) -> None:
        with TemporaryDirectory(prefix="aift-audit-test-") as temp_dir:
            logger = AuditLogger(temp_dir, tool_version="9.9.9")
            self.assertEqual(logger.tool_version, "9.9.9")

    def test_default_tool_version(self) -> None:
        with TemporaryDirectory(prefix="aift-audit-test-") as temp_dir:
            logger = AuditLogger(temp_dir)
            self.assertEqual(logger.tool_version, DEFAULT_TOOL_VERSION)

    def test_custom_dissect_version(self) -> None:
        with TemporaryDirectory(prefix="aift-audit-test-") as temp_dir:
            logger = AuditLogger(temp_dir, dissect_version="1.2.3")
            self.assertEqual(logger.dissect_version, "1.2.3")

    @patch("app.audit._resolve_dissect_version", return_value="auto-detected")
    def test_auto_detects_dissect_version_when_none(self, mock_resolve: object) -> None:
        with TemporaryDirectory(prefix="aift-audit-test-") as temp_dir:
            logger = AuditLogger(temp_dir)
            self.assertEqual(logger.dissect_version, "auto-detected")

    def test_session_id_is_uuid_string(self) -> None:
        import uuid

        with TemporaryDirectory(prefix="aift-audit-test-") as temp_dir:
            logger = AuditLogger(temp_dir)
            # Should not raise
            parsed = uuid.UUID(logger.session_id)
            self.assertEqual(str(parsed), logger.session_id)

    def test_accepts_string_path(self) -> None:
        with TemporaryDirectory(prefix="aift-audit-test-") as temp_dir:
            logger = AuditLogger(temp_dir)  # string, not Path
            self.assertIsInstance(logger.case_directory, Path)


class AuditLoggerLogExtendedTests(unittest.TestCase):
    """Additional tests for AuditLogger.log beyond the basics."""

    @staticmethod
    def _read_entries(audit_path: Path) -> list[dict[str, object]]:
        return [
            json.loads(line)
            for line in audit_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def test_record_contains_tool_and_dissect_versions(self) -> None:
        with TemporaryDirectory(prefix="aift-audit-test-") as temp_dir:
            logger = AuditLogger(temp_dir, tool_version="1.0.0", dissect_version="2.0.0")
            logger.log("case_created", {"id": "1"})

            entries = self._read_entries(logger.audit_file)
        self.assertEqual(entries[0]["tool_version"], "1.0.0")
        self.assertEqual(entries[0]["dissect_version"], "2.0.0")

    def test_empty_details_dict_is_valid(self) -> None:
        with TemporaryDirectory(prefix="aift-audit-test-") as temp_dir:
            logger = AuditLogger(temp_dir)
            logger.log("case_created", {})

            entries = self._read_entries(logger.audit_file)
        self.assertEqual(entries[0]["details"], {})

    def test_log_with_nested_details(self) -> None:
        with TemporaryDirectory(prefix="aift-audit-test-") as temp_dir:
            logger = AuditLogger(temp_dir)
            logger.log("config_changed", {"settings": {"key": "value", "nested": {"deep": True}}})

            entries = self._read_entries(logger.audit_file)
        self.assertEqual(entries[0]["details"]["settings"]["nested"]["deep"], True)

    def test_append_only_across_logger_instances(self) -> None:
        with TemporaryDirectory(prefix="aift-audit-test-") as temp_dir:
            logger1 = AuditLogger(temp_dir)
            logger1.log("case_created", {"id": "1"})

            logger2 = AuditLogger(temp_dir)
            logger2.log("report_generated", {"id": "2"})

            entries = self._read_entries(logger1.audit_file)

        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["action"], "case_created")
        self.assertEqual(entries[1]["action"], "report_generated")
        # Different sessions
        self.assertNotEqual(entries[0]["session_id"], entries[1]["session_id"])

    def test_log_rejects_none_details(self) -> None:
        with TemporaryDirectory(prefix="aift-audit-test-") as temp_dir:
            logger = AuditLogger(temp_dir)
            with self.assertRaises(TypeError):
                logger.log("case_created", None)

    def test_log_rejects_integer_details(self) -> None:
        with TemporaryDirectory(prefix="aift-audit-test-") as temp_dir:
            logger = AuditLogger(temp_dir)
            with self.assertRaises(TypeError):
                logger.log("case_created", 42)

    def test_log_rejects_empty_string_action(self) -> None:
        with TemporaryDirectory(prefix="aift-audit-test-") as temp_dir:
            logger = AuditLogger(temp_dir)
            with self.assertRaises(ValueError):
                logger.log("", {"id": "1"})

    def test_error_message_lists_allowed_actions(self) -> None:
        with TemporaryDirectory(prefix="aift-audit-test-") as temp_dir:
            logger = AuditLogger(temp_dir)
            with self.assertRaises(ValueError) as ctx:
                logger.log("bogus_action", {})
            self.assertIn("case_created", str(ctx.exception))
            self.assertIn("bogus_action", str(ctx.exception))


class ActionTypesTests(unittest.TestCase):
    """Tests for the ACTION_TYPES constant."""

    def test_action_types_is_frozenset(self) -> None:
        self.assertIsInstance(ACTION_TYPES, frozenset)

    def test_action_types_not_empty(self) -> None:
        self.assertGreater(len(ACTION_TYPES), 0)

    def test_all_action_types_are_strings(self) -> None:
        for action in ACTION_TYPES:
            self.assertIsInstance(action, str)


if __name__ == "__main__":
    unittest.main()
