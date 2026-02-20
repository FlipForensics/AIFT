from __future__ import annotations

from datetime import date, datetime, time
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from app.audit import ACTION_TYPES, AuditLogger


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


if __name__ == "__main__":
    unittest.main()
