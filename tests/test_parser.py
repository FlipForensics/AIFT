from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from app.parser import ARTIFACT_REGISTRY, EVTX_MAX_RECORDS_PER_FILE, ForensicParser, UnsupportedPluginError


class FakeAuditLogger:
    def __init__(self) -> None:
        self.entries: list[tuple[str, dict]] = []

    def log(self, action: str, details: dict) -> None:
        self.entries.append((action, details))


class FakeRecord:
    def __init__(self, values: dict) -> None:
        self._values = values

    def _asdict(self) -> dict:
        return dict(self._values)


class BrowserNamespace:
    def history(self) -> list[int]:
        return [1]


class SRUNamespace:
    def network_data(self) -> list[int]:
        return [3]


class ParserTests(unittest.TestCase):
    def _create_parser(self, target: object, case_dir: Path, audit: FakeAuditLogger) -> ForensicParser:
        with patch("app.parser.Target.open", return_value=target):
            return ForensicParser("evidence.E01", case_dir, audit)

    def test_init_opens_target_and_creates_parsed_directory(self) -> None:
        target = object()
        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            case_dir = Path(temp_dir)
            with patch("app.parser.Target.open", return_value=target) as open_mock:
                parser = ForensicParser("sample.E01", case_dir, audit)

            self.assertIs(parser.target, target)
            self.assertTrue((case_dir / "parsed").exists())
            open_mock.assert_called_once()

    def test_init_uses_custom_parsed_directory_when_provided(self) -> None:
        target = object()
        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            case_dir = Path(temp_dir) / "case"
            parsed_dir = Path(temp_dir) / "csv output" / "case-123" / "parsed"
            with patch("app.parser.Target.open", return_value=target):
                parser = ForensicParser(
                    "sample.E01",
                    case_dir,
                    audit,
                    parsed_dir=parsed_dir,
                )

            self.assertEqual(parser.parsed_dir, parsed_dir)
            self.assertTrue(parsed_dir.exists())

    def test_get_image_metadata_handles_missing_attributes(self) -> None:
        class MetadataTarget:
            hostname = "host-01"
            ips = ["10.1.1.5", "10.1.1.8"]

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(MetadataTarget(), Path(temp_dir), audit)
            metadata = parser.get_image_metadata()

        self.assertEqual(metadata["hostname"], "host-01")
        self.assertEqual(metadata["os_version"], "Unknown")
        self.assertEqual(metadata["domain"], "Unknown")
        self.assertEqual(metadata["ips"], "10.1.1.5, 10.1.1.8")

    def test_get_available_artifacts_adds_available_flag(self) -> None:
        class AvailabilityTarget:
            def has_function(self, function_name: str) -> bool:
                return function_name in {"runkeys", "browser.history"}

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(AvailabilityTarget(), Path(temp_dir), audit)
            artifacts = parser.get_available_artifacts()

        runkeys = next(item for item in artifacts if item["key"] == "runkeys")
        tasks = next(item for item in artifacts if item["key"] == "tasks")
        self.assertTrue(runkeys["available"])
        self.assertFalse(tasks["available"])
        self.assertIn("available", runkeys)

    def test_registry_artifact_guidance_comes_from_prompt_files(self) -> None:
        runkeys_prompt_path = Path(__file__).resolve().parents[1] / "prompts" / "artifact_instructions" / "runkeys.md"
        expected_prompt = runkeys_prompt_path.read_text(encoding="utf-8").strip()

        self.assertTrue(expected_prompt)
        self.assertIn("runkeys", ARTIFACT_REGISTRY)
        self.assertEqual(ARTIFACT_REGISTRY["runkeys"].get("artifact_guidance", ""), expected_prompt)

    def test_call_target_function_handles_namespaced_functions(self) -> None:
        class DispatchTarget:
            browser = BrowserNamespace()
            sru = SRUNamespace()

            def shimcache(self) -> list[int]:
                return [2]

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(DispatchTarget(), Path(temp_dir), audit)
            self.assertEqual(parser._call_target_function("browser.history"), [1])
            self.assertEqual(parser._call_target_function("shimcache"), [2])
            self.assertEqual(parser._call_target_function("sru.network_data"), [3])

    def test_parse_artifact_writes_csv_with_safe_string_conversion(self) -> None:
        class ParseTarget:
            def runkeys(self) -> list[FakeRecord]:
                return [
                    FakeRecord(
                        {
                            "ts": datetime(2026, 1, 1, 12, 30, 45),
                            "blob": b"\xde\xad",
                            "empty": None,
                            "value": 7,
                            "obj": {"a": 1},
                        }
                    ),
                    FakeRecord(
                        {
                            "ts": datetime(2026, 1, 1, 12, 40, 0),
                            "blob": b"\xbe\xef",
                            "empty": None,
                            "value": 8,
                            "obj": {"b": 2},
                        }
                    ),
                ]

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(ParseTarget(), Path(temp_dir), audit)
            result = parser.parse_artifact("runkeys")

            self.assertTrue(result["success"])
            self.assertEqual(result["record_count"], 2)
            csv_path = Path(result["csv_path"])
            self.assertTrue(csv_path.exists())

            with csv_path.open("r", newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))

        self.assertEqual(rows[0]["blob"], "dead")
        self.assertEqual(rows[0]["empty"], "")
        self.assertEqual(rows[0]["ts"], "2026-01-01T12:30:45")
        self.assertEqual(rows[0]["obj"], "{'a': 1}")
        self.assertEqual(audit.entries[0][0], "parsing_started")
        self.assertEqual(audit.entries[-1][0], "parsing_completed")

    def test_parse_artifact_catches_plugin_errors(self) -> None:
        class ErrorTarget:
            def runkeys(self) -> list[FakeRecord]:
                raise UnsupportedPluginError("runkeys not supported")

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(ErrorTarget(), Path(temp_dir), audit)
            result = parser.parse_artifact("runkeys")

        self.assertFalse(result["success"])
        self.assertIn("runkeys not supported", result["error"])
        self.assertEqual(audit.entries[0][0], "parsing_started")
        self.assertEqual(audit.entries[-1][0], "parsing_failed")
        self.assertIn("traceback", audit.entries[-1][1])
        self.assertIn("runkeys", str(audit.entries[-1][1]["traceback"]))

    def test_parse_evtx_splits_by_channel_and_rotates_files(self) -> None:
        class EvtxTarget:
            def evtx(self) -> list[FakeRecord]:
                return [
                    FakeRecord({"channel": "Security", "event_id": 4624}),
                    FakeRecord({"channel": "Security", "event_id": 4625}),
                    FakeRecord({"channel": "Security", "event_id": 4688}),
                    FakeRecord({"channel": "System", "event_id": 7045}),
                ]

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(EvtxTarget(), Path(temp_dir), audit)
            with patch("app.parser.EVTX_MAX_RECORDS_PER_FILE", 2):
                result = parser.parse_artifact("evtx")

            parsed_dir = Path(temp_dir) / "parsed"
            security_csv = parsed_dir / "evtx_Security.csv"
            security_part2_csv = parsed_dir / "evtx_Security_part2.csv"
            system_csv = parsed_dir / "evtx_System.csv"

            self.assertTrue(result["success"])
            self.assertEqual(result["record_count"], 4)
            self.assertTrue(security_csv.exists())
            self.assertTrue(security_part2_csv.exists())
            self.assertTrue(system_csv.exists())

    def test_evtx_default_cap_constant(self) -> None:
        self.assertEqual(EVTX_MAX_RECORDS_PER_FILE, 500_000)

    def test_evtx_returns_csv_paths_list(self) -> None:
        class EvtxTarget:
            def evtx(self) -> list[FakeRecord]:
                return [
                    FakeRecord({"channel": "Security", "event_id": 4624}),
                    FakeRecord({"channel": "System", "event_id": 7045}),
                ]

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(EvtxTarget(), Path(temp_dir), audit)
            result = parser.parse_artifact("evtx")

            self.assertTrue(result["success"])
            self.assertIn("csv_paths", result)
            self.assertEqual(len(result["csv_paths"]), 2)

    def test_parse_artifact_handles_variable_csv_headers(self) -> None:
        """Records with different schemas must not lose extra columns."""

        class VariableTarget:
            def amcache(self) -> list[FakeRecord]:
                return [
                    FakeRecord({"path": "C:\\app.exe", "hash": "abc"}),
                    FakeRecord({"path": "C:\\lib.dll", "hash": "def", "size": 1024}),
                    FakeRecord({"path": "C:\\tool.exe", "version": "1.0"}),
                ]

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(VariableTarget(), Path(temp_dir), audit)
            result = parser.parse_artifact("amcache")

            self.assertTrue(result["success"])
            self.assertEqual(result["record_count"], 3)

            csv_path = Path(result["csv_path"])
            with csv_path.open("r", newline="", encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))

        # All four unique columns must be present
        self.assertIn("size", rows[1])
        self.assertEqual(rows[1]["size"], "1024")
        self.assertIn("version", rows[2])
        self.assertEqual(rows[2]["version"], "1.0")
        # Earlier rows get empty strings for columns they didn't have
        self.assertEqual(rows[0].get("size", ""), "")
        self.assertEqual(rows[0].get("version", ""), "")

    def test_get_image_metadata_includes_timezone_and_install_date(self) -> None:
        class FullMetadataTarget:
            hostname = "dc-01"
            os_version = "Windows Server 2019"
            domain = "corp.local"
            ips = ["192.168.1.10"]
            timezone = "UTC"
            install_date = "2024-06-15"

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(FullMetadataTarget(), Path(temp_dir), audit)
            metadata = parser.get_image_metadata()

        self.assertEqual(metadata["timezone"], "UTC")
        self.assertEqual(metadata["install_date"], "2024-06-15")


if __name__ == "__main__":
    unittest.main()
