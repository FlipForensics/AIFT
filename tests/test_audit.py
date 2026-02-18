from __future__ import annotations

from datetime import date, datetime, time
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from app.audit import AuditLogger


class AuditLoggerTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
