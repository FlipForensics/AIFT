from __future__ import annotations

import csv
from datetime import date, datetime, time
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch, MagicMock

from app.parser import WINDOWS_ARTIFACT_REGISTRY, EVTX_MAX_RECORDS_PER_FILE, ForensicParser, UnsupportedPluginError
from app.parser.registry import (
    LINUX_ARTIFACT_REGISTRY,
    get_artifact_registry,
    _artifact_prompt_name_candidates,
    _load_artifact_guidance_prompt,
    _apply_artifact_guidance_from_prompts,
)

# Patch targets point to where the names are looked up at runtime (the core module).
_PATCH_TARGET_OPEN = "app.parser.core.Target.open"
_PATCH_EVTX_CAP = "app.parser.core.EVTX_MAX_RECORDS_PER_FILE"
_PATCH_MAX_RECORDS = "app.parser.core.MAX_RECORDS_PER_ARTIFACT"


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
        with patch(_PATCH_TARGET_OPEN, return_value=target):
            return ForensicParser("evidence.E01", case_dir, audit)

    def test_init_opens_target_and_creates_parsed_directory(self) -> None:
        target = object()
        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            case_dir = Path(temp_dir)
            with patch(_PATCH_TARGET_OPEN, return_value=target) as open_mock:
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
            with patch(_PATCH_TARGET_OPEN, return_value=target):
                parser = ForensicParser(
                    "sample.E01",
                    case_dir,
                    audit,
                    parsed_dir=parsed_dir,
                )

            self.assertEqual(parser.parsed_dir, parsed_dir)
            self.assertTrue(parsed_dir.exists())

    def test_close_closes_target_once(self) -> None:
        class ClosableTarget:
            def __init__(self) -> None:
                self.close_calls = 0

            def close(self) -> None:
                self.close_calls += 1

        target = ClosableTarget()
        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(target, Path(temp_dir), audit)
            parser.close()
            parser.close()

        self.assertEqual(target.close_calls, 1)

    def test_close_handles_target_without_close_method(self) -> None:
        """Close should not raise when the target has no close method."""
        target = object()  # no close attribute
        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(target, Path(temp_dir), audit)
            parser.close()  # should not raise
            self.assertTrue(parser._closed)

    def test_close_handles_getattr_exception(self) -> None:
        """Close should handle targets where getattr raises an exception."""
        class ExplodingTarget:
            def __getattr__(self, name: str) -> None:
                raise RuntimeError("cannot access attributes")

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(object(), Path(temp_dir), audit)
            parser.target = ExplodingTarget()
            parser.close()  # should not raise
            self.assertTrue(parser._closed)

    def test_context_manager_closes_target(self) -> None:
        target = Mock()
        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            with patch(_PATCH_TARGET_OPEN, return_value=target):
                with ForensicParser("sample.E01", Path(temp_dir), audit) as parser:
                    self.assertIs(parser.target, target)

        target.close.assert_called_once_with()

    def test_context_manager_returns_false_on_exit(self) -> None:
        """__exit__ should return False so exceptions are not suppressed."""
        target = Mock()
        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(target, Path(temp_dir), audit)
            result = parser.__exit__(None, None, None)
            self.assertFalse(result)

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

    def test_get_image_metadata_ips_empty_list_returns_unknown(self) -> None:
        """When ips is an empty list, metadata should show Unknown."""
        class EmptyIpsTarget:
            hostname = "host-01"
            ips = []

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(EmptyIpsTarget(), Path(temp_dir), audit)
            metadata = parser.get_image_metadata()

        self.assertEqual(metadata["ips"], "Unknown")

    def test_get_image_metadata_ips_list_with_none_values(self) -> None:
        """ips list containing None and empty strings should filter them out."""
        class NoneIpsTarget:
            hostname = "host-01"
            ips = [None, "", "10.0.0.1"]

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(NoneIpsTarget(), Path(temp_dir), audit)
            metadata = parser.get_image_metadata()

        self.assertEqual(metadata["ips"], "10.0.0.1")

    def test_get_image_metadata_ips_as_string(self) -> None:
        """When ips is a plain string, metadata should return it as-is."""
        class StringIpsTarget:
            hostname = "host-01"
            ips = "192.168.1.1"

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(StringIpsTarget(), Path(temp_dir), audit)
            metadata = parser.get_image_metadata()

        self.assertEqual(metadata["ips"], "192.168.1.1")

    def test_get_image_metadata_ips_as_tuple(self) -> None:
        """When ips is a tuple, metadata should join them."""
        class TupleIpsTarget:
            hostname = "host-01"
            ips = ("10.0.0.1", "10.0.0.2")

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(TupleIpsTarget(), Path(temp_dir), audit)
            metadata = parser.get_image_metadata()

        self.assertEqual(metadata["ips"], "10.0.0.1, 10.0.0.2")

    def test_get_image_metadata_callable_attribute(self) -> None:
        """Metadata should call callable attributes to get values."""
        class CallableTarget:
            def hostname(self) -> str:
                return "callable-host"
            ips = "1.2.3.4"

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(CallableTarget(), Path(temp_dir), audit)
            metadata = parser.get_image_metadata()

        self.assertEqual(metadata["hostname"], "callable-host")

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

    def test_get_available_artifacts_handles_plugin_error(self) -> None:
        """Artifacts that raise PluginError should be marked unavailable."""
        from dissect.target.exceptions import PluginError

        class ErrorTarget:
            def has_function(self, function_name: str) -> bool:
                raise PluginError("plugin broken")

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(ErrorTarget(), Path(temp_dir), audit)
            artifacts = parser.get_available_artifacts()

        # All should be marked unavailable
        for artifact in artifacts:
            self.assertFalse(artifact["available"])

    def test_get_available_artifacts_handles_unsupported_plugin_error(self) -> None:
        """Artifacts that raise UnsupportedPluginError should be marked unavailable."""
        class UnsupportedTarget:
            def has_function(self, function_name: str) -> bool:
                raise UnsupportedPluginError("not supported")

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(UnsupportedTarget(), Path(temp_dir), audit)
            artifacts = parser.get_available_artifacts()

        for artifact in artifacts:
            self.assertFalse(artifact["available"])

    def test_get_available_artifacts_returns_all_registry_entries(self) -> None:
        """Every artifact in WINDOWS_ARTIFACT_REGISTRY should appear in the result."""
        class NoOpTarget:
            def has_function(self, function_name: str) -> bool:
                return False

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(NoOpTarget(), Path(temp_dir), audit)
            artifacts = parser.get_available_artifacts()

        returned_keys = {a["key"] for a in artifacts}
        self.assertEqual(returned_keys, set(WINDOWS_ARTIFACT_REGISTRY.keys()))

    def test_registry_artifact_guidance_comes_from_prompt_files(self) -> None:
        runkeys_prompt_path = Path(__file__).resolve().parents[1] / "prompts" / "artifact_instructions" / "runkeys.md"
        expected_prompt = runkeys_prompt_path.read_text(encoding="utf-8").strip()

        self.assertTrue(expected_prompt)
        self.assertIn("runkeys", WINDOWS_ARTIFACT_REGISTRY)
        self.assertEqual(WINDOWS_ARTIFACT_REGISTRY["runkeys"].get("artifact_guidance", ""), expected_prompt)

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

    def test_call_target_function_returns_non_callable_attribute(self) -> None:
        """When a simple attribute is not callable, return it directly."""
        class AttrTarget:
            data_value = [1, 2, 3]

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(AttrTarget(), Path(temp_dir), audit)
            result = parser._call_target_function("data_value")
            self.assertEqual(result, [1, 2, 3])

    def test_call_target_function_returns_non_callable_nested_attribute(self) -> None:
        """When a dotted attribute resolves to a non-callable, return it directly."""
        class Inner:
            value = 42

        class OuterTarget:
            nested = Inner()

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(OuterTarget(), Path(temp_dir), audit)
            result = parser._call_target_function("nested.value")
            self.assertEqual(result, 42)

    def test_call_target_function_raises_on_missing_nested_attribute(self) -> None:
        """Failed nested attribute resolution should raise."""
        class EmptyTarget:
            pass

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(EmptyTarget(), Path(temp_dir), audit)
            with self.assertRaises(AttributeError):
                parser._call_target_function("nonexistent.function")

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

    def test_parse_artifact_unknown_key_returns_error(self) -> None:
        """Parsing with a key not in the registry should return an error result."""
        target = object()
        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(target, Path(temp_dir), audit)
            result = parser.parse_artifact("nonexistent_artifact")

        self.assertFalse(result["success"])
        self.assertIn("Unknown artifact key", result["error"])
        self.assertEqual(result["record_count"], 0)
        self.assertEqual(result["csv_path"], "")

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

    def test_parse_artifact_catches_generic_exceptions(self) -> None:
        """Non-plugin exceptions should also be caught and returned as errors."""
        class CrashTarget:
            def runkeys(self) -> list[FakeRecord]:
                raise RuntimeError("disk read error")

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(CrashTarget(), Path(temp_dir), audit)
            result = parser.parse_artifact("runkeys")

        self.assertFalse(result["success"])
        self.assertIn("disk read error", result["error"])

    def test_parse_artifact_evtx_empty_records_creates_empty_file(self) -> None:
        """EVTX parsing with zero records should create a touchfile."""
        class EmptyEvtxTarget:
            def evtx(self) -> list:
                return []

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(EmptyEvtxTarget(), Path(temp_dir), audit)
            result = parser.parse_artifact("evtx")

            self.assertTrue(result["success"])
            self.assertEqual(result["record_count"], 0)
            self.assertTrue(Path(result["csv_path"]).exists())
            self.assertIn("csv_paths", result)

    def test_parse_artifact_progress_callback_invoked(self) -> None:
        """Progress callback should be invoked every 1000 records and at the end."""
        records = [FakeRecord({"id": i}) for i in range(2500)]

        class BulkTarget:
            def runkeys(self) -> list[FakeRecord]:
                return records

        callback = Mock()
        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(BulkTarget(), Path(temp_dir), audit)
            result = parser.parse_artifact("runkeys", progress_callback=callback)

        self.assertTrue(result["success"])
        self.assertEqual(result["record_count"], 2500)
        # Callback at 1000, 2000, and final
        self.assertTrue(callback.call_count >= 3)

    def test_parse_artifact_caps_at_max_records(self) -> None:
        """Records should be capped at MAX_RECORDS_PER_ARTIFACT."""
        records = [FakeRecord({"id": i}) for i in range(20)]

        class ManyTarget:
            def runkeys(self) -> list[FakeRecord]:
                return records

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(ManyTarget(), Path(temp_dir), audit)
            with patch(_PATCH_MAX_RECORDS, 10):
                result = parser.parse_artifact("runkeys")

        self.assertTrue(result["success"])
        self.assertEqual(result["record_count"], 10)
        # Should have logged a capping event
        capped_entries = [e for e in audit.entries if e[0] == "parsing_capped"]
        self.assertEqual(len(capped_entries), 1)

    def test_parse_evtx_caps_at_max_records(self) -> None:
        """EVTX records should be capped at MAX_RECORDS_PER_ARTIFACT."""
        records = [
            FakeRecord({"channel": "Security", "event_id": i})
            for i in range(20)
        ]

        class EvtxTarget:
            def evtx(self) -> list[FakeRecord]:
                return records

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(EvtxTarget(), Path(temp_dir), audit)
            with patch(_PATCH_MAX_RECORDS, 10):
                result = parser.parse_artifact("evtx")

        self.assertTrue(result["success"])
        self.assertEqual(result["record_count"], 10)
        capped_entries = [e for e in audit.entries if e[0] == "parsing_capped"]
        self.assertEqual(len(capped_entries), 1)
        self.assertEqual(capped_entries[0][1]["max_records"], 10)

    def test_parse_evtx_cap_closes_files_safely(self) -> None:
        """EVTX cap should still close all file handles and produce valid CSVs."""
        records = [
            FakeRecord({"channel": "Security", "event_id": i})
            for i in range(15)
        ]

        class EvtxTarget:
            def evtx(self) -> list[FakeRecord]:
                return records

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(EvtxTarget(), Path(temp_dir), audit)
            with patch(_PATCH_MAX_RECORDS, 5):
                result = parser.parse_artifact("evtx")

            self.assertTrue(result["success"])
            self.assertEqual(result["record_count"], 5)
            # Verify the CSV is valid and has the right row count
            csv_path = Path(result["csv_paths"][0])
            with csv_path.open("r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            self.assertEqual(len(rows), 5)

    def test_parse_evtx_cap_with_multiple_channels(self) -> None:
        """EVTX cap should apply globally across all channels."""
        records = [
            FakeRecord({"channel": "Security", "event_id": i})
            for i in range(5)
        ] + [
            FakeRecord({"channel": "System", "event_id": i})
            for i in range(5)
        ]

        class EvtxTarget:
            def evtx(self) -> list[FakeRecord]:
                return records

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(EvtxTarget(), Path(temp_dir), audit)
            with patch(_PATCH_MAX_RECORDS, 7):
                result = parser.parse_artifact("evtx")

        self.assertTrue(result["success"])
        self.assertEqual(result["record_count"], 7)
        capped_entries = [e for e in audit.entries if e[0] == "parsing_capped"]
        self.assertEqual(len(capped_entries), 1)

    def test_parse_artifact_result_includes_duration(self) -> None:
        """Successful result should have a positive duration_seconds."""
        class SimpleTarget:
            def runkeys(self) -> list[FakeRecord]:
                return [FakeRecord({"a": 1})]

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(SimpleTarget(), Path(temp_dir), audit)
            result = parser.parse_artifact("runkeys")

        self.assertIn("duration_seconds", result)
        self.assertGreaterEqual(result["duration_seconds"], 0.0)

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
            with patch(_PATCH_EVTX_CAP, 2):
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

    def test_parse_artifact_non_evtx_does_not_include_csv_paths(self) -> None:
        """Non-EVTX artifacts should not have a csv_paths key in the result."""
        class SimpleTarget:
            def runkeys(self) -> list[FakeRecord]:
                return [FakeRecord({"key": "value"})]

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(SimpleTarget(), Path(temp_dir), audit)
            result = parser.parse_artifact("runkeys")

        self.assertTrue(result["success"])
        self.assertNotIn("csv_paths", result)

    def test_parse_artifact_evtx_progress_callback(self) -> None:
        """EVTX progress callback should fire every 1000 records and at the end."""
        records = [FakeRecord({"channel": "Security", "event_id": i}) for i in range(1500)]

        class BulkEvtxTarget:
            def evtx(self) -> list[FakeRecord]:
                return records

        callback = Mock()
        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(BulkEvtxTarget(), Path(temp_dir), audit)
            result = parser.parse_artifact("evtx", progress_callback=callback)

        self.assertTrue(result["success"])
        self.assertEqual(result["record_count"], 1500)
        # At least one progress call at 1000 and a final call
        self.assertTrue(callback.call_count >= 2)


    def test_evtx_schema_expansion_preserves_later_fields(self) -> None:
        """EVTX records with expanding schemas must not lose extra columns.

        Record 1 has fields A and B; record 2 has A, B, and C.
        The final CSV must contain column C with the correct value,
        and earlier rows must have an empty string for C.
        """

        class EvtxTarget:
            def evtx(self) -> list[FakeRecord]:
                return [
                    FakeRecord({"channel": "Security", "A": "a1", "B": "b1"}),
                    FakeRecord({"channel": "Security", "A": "a2", "B": "b2", "C": "c2"}),
                ]

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(EvtxTarget(), Path(temp_dir), audit)
            result = parser.parse_artifact("evtx")

            self.assertTrue(result["success"])
            self.assertEqual(result["record_count"], 2)

            csv_path = Path(temp_dir) / "parsed" / "evtx_Security.csv"
            self.assertTrue(csv_path.exists())

            with csv_path.open("r", newline="", encoding="utf-8") as fh:
                rows = list(csv.DictReader(fh))

        self.assertEqual(len(rows), 2)
        # Column C must be present in headers
        self.assertIn("C", rows[0])
        self.assertIn("C", rows[1])
        # First row should have empty C, second row has the value
        self.assertEqual(rows[0]["C"], "")
        self.assertEqual(rows[1]["C"], "c2")
        # Original fields still intact
        self.assertEqual(rows[0]["A"], "a1")
        self.assertEqual(rows[1]["A"], "a2")

    def test_evtx_schema_expansion_across_channels(self) -> None:
        """Schema expansion works independently per channel group."""

        class EvtxTarget:
            def evtx(self) -> list[FakeRecord]:
                return [
                    FakeRecord({"channel": "Security", "X": "1"}),
                    FakeRecord({"channel": "System", "X": "2", "Y": "3"}),
                    FakeRecord({"channel": "Security", "X": "4", "Z": "5"}),
                ]

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(EvtxTarget(), Path(temp_dir), audit)
            result = parser.parse_artifact("evtx")

            self.assertTrue(result["success"])

            sec_csv = Path(temp_dir) / "parsed" / "evtx_Security.csv"
            sys_csv = Path(temp_dir) / "parsed" / "evtx_System.csv"

            with sec_csv.open("r", newline="", encoding="utf-8") as fh:
                sec_rows = list(csv.DictReader(fh))
            with sys_csv.open("r", newline="", encoding="utf-8") as fh:
                sys_rows = list(csv.DictReader(fh))

        # Security: first row missing Z, second has it
        self.assertEqual(len(sec_rows), 2)
        self.assertIn("Z", sec_rows[0])
        self.assertEqual(sec_rows[0]["Z"], "")
        self.assertEqual(sec_rows[1]["Z"], "5")

        # System should NOT have Z column (different channel)
        self.assertEqual(len(sys_rows), 1)
        self.assertNotIn("Z", sys_rows[0])
        self.assertIn("Y", sys_rows[0])


class RecordToDictTests(unittest.TestCase):
    """Tests for ForensicParser._record_to_dict with various value types."""

    def test_asdict_record(self) -> None:
        record = FakeRecord({"name": "test", "value": 42})
        result = ForensicParser._record_to_dict(record)
        self.assertEqual(result, {"name": "test", "value": 42})

    def test_plain_dict_passthrough(self) -> None:
        result = ForensicParser._record_to_dict({"a": 1, "b": 2})
        self.assertEqual(result, {"a": 1, "b": 2})

    def test_object_with_dict_attr(self) -> None:
        class SimpleObj:
            def __init__(self) -> None:
                self.field1 = "hello"
                self.field2 = 99

        result = ForensicParser._record_to_dict(SimpleObj())
        self.assertEqual(result["field1"], "hello")
        self.assertEqual(result["field2"], 99)

    def test_unconvertible_raises_type_error(self) -> None:
        with self.assertRaises(TypeError):
            ForensicParser._record_to_dict(42)

    def test_asdict_returns_non_dict(self) -> None:
        """When _asdict() returns a non-dict, fall through to dict(vars(record))."""
        class WeirdRecord:
            def __init__(self) -> None:
                self.x = 10

            def _asdict(self) -> str:
                return "not a dict"

        result = ForensicParser._record_to_dict(WeirdRecord())
        self.assertEqual(result["x"], 10)

    def test_returns_copy_not_original(self) -> None:
        """The returned dict should be a copy, not the original."""
        original = {"a": 1}
        result = ForensicParser._record_to_dict(original)
        result["b"] = 2
        self.assertNotIn("b", original)


class StringifyCsvValueTests(unittest.TestCase):
    """Tests for ForensicParser._stringify_csv_value with all special types."""

    def test_none_returns_empty_string(self) -> None:
        self.assertEqual(ForensicParser._stringify_csv_value(None), "")

    def test_datetime_returns_isoformat(self) -> None:
        dt = datetime(2026, 3, 15, 10, 30, 45)
        self.assertEqual(ForensicParser._stringify_csv_value(dt), "2026-03-15T10:30:45")

    def test_date_returns_isoformat(self) -> None:
        d = date(2026, 3, 15)
        self.assertEqual(ForensicParser._stringify_csv_value(d), "2026-03-15")

    def test_time_returns_isoformat(self) -> None:
        t = time(10, 30, 45)
        self.assertEqual(ForensicParser._stringify_csv_value(t), "10:30:45")

    def test_bytes_returns_hex(self) -> None:
        self.assertEqual(ForensicParser._stringify_csv_value(b"\xde\xad\xbe\xef"), "deadbeef")

    def test_bytearray_returns_hex(self) -> None:
        self.assertEqual(ForensicParser._stringify_csv_value(bytearray(b"\xca\xfe")), "cafe")

    def test_path_returns_string(self) -> None:
        result = ForensicParser._stringify_csv_value(Path("C:/Users/test/file.txt"))
        self.assertIn("file.txt", result)

    def test_int_returns_string(self) -> None:
        self.assertEqual(ForensicParser._stringify_csv_value(42), "42")

    def test_nested_dict_returns_string_repr(self) -> None:
        result = ForensicParser._stringify_csv_value({"key": "value"})
        self.assertIn("key", result)

    def test_memoryview_returns_hex(self) -> None:
        """memoryview should be converted to hex like bytes."""
        mv = memoryview(b"\xab\xcd")
        result = ForensicParser._stringify_csv_value(mv)
        self.assertEqual(result, "abcd")

    def test_large_bytes_truncated_with_ellipsis(self) -> None:
        """Bytes longer than 512 should be truncated with '...' appended."""
        large_blob = bytes(range(256)) * 3  # 768 bytes
        result = ForensicParser._stringify_csv_value(large_blob)
        self.assertTrue(result.endswith("..."))
        # The hex portion should be 512 bytes = 1024 hex chars
        self.assertEqual(len(result), 1024 + 3)  # hex chars + "..."

    def test_empty_bytes_returns_empty_hex(self) -> None:
        self.assertEqual(ForensicParser._stringify_csv_value(b""), "")

    def test_boolean_returns_string(self) -> None:
        self.assertEqual(ForensicParser._stringify_csv_value(True), "True")
        self.assertEqual(ForensicParser._stringify_csv_value(False), "False")

    def test_list_returns_string(self) -> None:
        result = ForensicParser._stringify_csv_value([1, 2, 3])
        self.assertEqual(result, "[1, 2, 3]")

    def test_empty_string_returns_empty_string(self) -> None:
        self.assertEqual(ForensicParser._stringify_csv_value(""), "")


class EvtxGroupNameTests(unittest.TestCase):
    """Tests for ForensicParser._extract_evtx_group_name."""

    def _create_parser(self, case_dir: Path) -> ForensicParser:
        target = object()
        audit = FakeAuditLogger()
        with patch(_PATCH_TARGET_OPEN, return_value=target):
            return ForensicParser("evidence.E01", case_dir, audit)

    def test_channel_key_is_preferred(self) -> None:
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(Path(temp_dir))
            result = parser._extract_evtx_group_name(
                {"channel": "Security", "provider": "Microsoft-Windows-EventLog"}
            )
        self.assertEqual(result, "Security")

    def test_provider_used_when_no_channel(self) -> None:
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(Path(temp_dir))
            result = parser._extract_evtx_group_name(
                {"provider": "Microsoft-Windows-Sysmon"}
            )
        self.assertEqual(result, "Microsoft-Windows-Sysmon")

    def test_uppercase_channel_key(self) -> None:
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(Path(temp_dir))
            result = parser._extract_evtx_group_name({"Channel": "Application"})
        self.assertEqual(result, "Application")

    def test_log_name_key(self) -> None:
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(Path(temp_dir))
            result = parser._extract_evtx_group_name({"log_name": "System"})
        self.assertEqual(result, "System")

    def test_unknown_when_no_keys_match(self) -> None:
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(Path(temp_dir))
            result = parser._extract_evtx_group_name({"event_id": 4624})
        self.assertEqual(result, "unknown")

    def test_empty_channel_falls_through_to_provider(self) -> None:
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(Path(temp_dir))
            result = parser._extract_evtx_group_name(
                {"channel": "", "Provider": "Sysmon"}
            )
        self.assertEqual(result, "Sysmon")

    def test_none_channel_falls_through_to_provider(self) -> None:
        """A None channel value should fall through to provider."""
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(Path(temp_dir))
            result = parser._extract_evtx_group_name(
                {"channel": None, "provider_name": "MyProvider"}
            )
        self.assertEqual(result, "MyProvider")

    def test_event_log_key(self) -> None:
        """The EventLog key variant should be recognized."""
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(Path(temp_dir))
            result = parser._extract_evtx_group_name({"EventLog": "Setup"})
        self.assertEqual(result, "Setup")

    def test_source_key_as_provider(self) -> None:
        """The Source key should be used as a provider fallback."""
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(Path(temp_dir))
            result = parser._extract_evtx_group_name({"Source": "EventSystem"})
        self.assertEqual(result, "EventSystem")


class SanitizeFilenameTests(unittest.TestCase):
    """Tests for ForensicParser._sanitize_filename."""

    def test_simple_name_unchanged(self) -> None:
        self.assertEqual(ForensicParser._sanitize_filename("runkeys"), "runkeys")

    def test_dots_and_hyphens_preserved(self) -> None:
        self.assertEqual(ForensicParser._sanitize_filename("browser.history"), "browser.history")
        self.assertEqual(ForensicParser._sanitize_filename("my-artifact"), "my-artifact")

    def test_special_characters_replaced_with_underscore(self) -> None:
        result = ForensicParser._sanitize_filename("channel/provider name")
        self.assertNotIn("/", result)
        self.assertNotIn(" ", result)
        self.assertIn("_", result)

    def test_empty_string_returns_artifact(self) -> None:
        self.assertEqual(ForensicParser._sanitize_filename(""), "artifact")

    def test_only_special_characters_returns_artifact(self) -> None:
        self.assertEqual(ForensicParser._sanitize_filename("///"), "artifact")

    def test_leading_trailing_underscores_stripped(self) -> None:
        result = ForensicParser._sanitize_filename("  hello  ")
        self.assertFalse(result.startswith("_"))
        self.assertFalse(result.endswith("_"))
        self.assertIn("hello", result)

    def test_windows_path_separators_replaced(self) -> None:
        result = ForensicParser._sanitize_filename("Microsoft\\Windows\\Sysmon")
        self.assertNotIn("\\", result)


class IsEvtxArtifactTests(unittest.TestCase):
    """Tests for ForensicParser._is_evtx_artifact."""

    def test_evtx_returns_true(self) -> None:
        self.assertTrue(ForensicParser._is_evtx_artifact("evtx"))

    def test_dotted_evtx_returns_true(self) -> None:
        self.assertTrue(ForensicParser._is_evtx_artifact("defender.evtx"))

    def test_non_evtx_returns_false(self) -> None:
        self.assertFalse(ForensicParser._is_evtx_artifact("runkeys"))
        self.assertFalse(ForensicParser._is_evtx_artifact("shimcache"))
        self.assertFalse(ForensicParser._is_evtx_artifact("browser.history"))

    def test_evtx_as_prefix_returns_false(self) -> None:
        """A function named 'evtx_something' is not an EVTX artifact."""
        self.assertFalse(ForensicParser._is_evtx_artifact("evtx_parser"))

    def test_evtx_in_middle_returns_false(self) -> None:
        self.assertFalse(ForensicParser._is_evtx_artifact("something.evtx.other"))


class FindRecordValueTests(unittest.TestCase):
    """Tests for ForensicParser._find_record_value."""

    def test_first_key_found(self) -> None:
        record = {"channel": "Security", "provider": "Sysmon"}
        result = ForensicParser._find_record_value(record, ("channel", "provider"))
        self.assertEqual(result, "Security")

    def test_second_key_when_first_missing(self) -> None:
        record = {"provider": "Sysmon"}
        result = ForensicParser._find_record_value(record, ("channel", "provider"))
        self.assertEqual(result, "Sysmon")

    def test_empty_string_when_no_keys_found(self) -> None:
        record = {"event_id": 4624}
        result = ForensicParser._find_record_value(record, ("channel", "provider"))
        self.assertEqual(result, "")

    def test_skips_none_values(self) -> None:
        record = {"channel": None, "provider": "Sysmon"}
        result = ForensicParser._find_record_value(record, ("channel", "provider"))
        self.assertEqual(result, "Sysmon")

    def test_skips_empty_string_values(self) -> None:
        record = {"channel": "", "provider": "Sysmon"}
        result = ForensicParser._find_record_value(record, ("channel", "provider"))
        self.assertEqual(result, "Sysmon")

    def test_converts_non_string_value_to_string(self) -> None:
        record = {"count": 42}
        result = ForensicParser._find_record_value(record, ("count",))
        self.assertEqual(result, "42")

    def test_empty_dict_returns_empty_string(self) -> None:
        result = ForensicParser._find_record_value({}, ("a", "b", "c"))
        self.assertEqual(result, "")


class EmitProgressTests(unittest.TestCase):
    """Tests for ForensicParser._emit_progress with varying callback signatures."""

    def test_dict_signature_callback(self) -> None:
        """Callback accepting a single dict argument."""
        received = {}

        def callback(payload: dict) -> None:
            received.update(payload)

        ForensicParser._emit_progress(callback, "runkeys", 1000)
        self.assertEqual(received["artifact_key"], "runkeys")
        self.assertEqual(received["record_count"], 1000)

    def test_two_arg_signature_callback(self) -> None:
        """Callback accepting (artifact_key, record_count)."""
        calls = []

        def callback(key: str, count: int) -> None:
            calls.append((key, count))

        # This callback rejects a single dict, so it should fall through
        # to the two-arg call
        class StrictCallback:
            def __call__(self, key: str, count: int) -> None:
                calls.append((key, count))

        # Use a lambda that explicitly rejects dict
        def strict_cb(a: str, b: int) -> None:
            if isinstance(a, dict):
                raise TypeError("expected str")
            calls.append((a, b))

        ForensicParser._emit_progress(strict_cb, "shimcache", 2000)
        self.assertEqual(calls, [("shimcache", 2000)])

    def test_single_int_signature_callback(self) -> None:
        """Callback accepting only the record count."""
        calls = []

        def strict_cb(count: int) -> None:
            if isinstance(count, dict):
                raise TypeError("no dict")
            if isinstance(count, str):
                raise TypeError("no str")
            calls.append(count)

        ForensicParser._emit_progress(strict_cb, "amcache", 3000)
        self.assertEqual(calls, [3000])

    def test_callback_that_always_raises_typeerror_falls_through(self) -> None:
        """A callback that always raises TypeError should fall through all attempts."""
        calls = []

        def bad_callback(*args: object, **kwargs: object) -> None:
            calls.append(args)
            raise TypeError("wrong signature")

        # Should not raise -- the final except Exception catches it
        ForensicParser._emit_progress(bad_callback, "runkeys", 100)
        # All three call attempts should have been made
        self.assertEqual(len(calls), 3)


class SafeReadTargetAttributeTests(unittest.TestCase):
    """Tests for ForensicParser._safe_read_target_attribute."""

    def _create_parser(self, target: object) -> ForensicParser:
        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            with patch(_PATCH_TARGET_OPEN, return_value=target):
                parser = ForensicParser("evidence.E01", Path(temp_dir), audit)
        return parser

    def test_returns_first_valid_attribute(self) -> None:
        class Target:
            hostname = "host-01"
            computer_name = "host-02"

        parser = self._create_parser(Target())
        result = parser._safe_read_target_attribute(("hostname", "computer_name"))
        self.assertEqual(result, "host-01")

    def test_skips_none_attribute(self) -> None:
        class Target:
            hostname = None
            computer_name = "host-02"

        parser = self._create_parser(Target())
        result = parser._safe_read_target_attribute(("hostname", "computer_name"))
        self.assertEqual(result, "host-02")

    def test_skips_empty_string_attribute(self) -> None:
        class Target:
            hostname = ""
            computer_name = "host-02"

        parser = self._create_parser(Target())
        result = parser._safe_read_target_attribute(("hostname", "computer_name"))
        self.assertEqual(result, "host-02")

    def test_returns_unknown_when_all_fail(self) -> None:
        class Target:
            pass

        parser = self._create_parser(Target())
        result = parser._safe_read_target_attribute(("hostname", "computer_name"))
        self.assertEqual(result, "Unknown")

    def test_calls_callable_attribute(self) -> None:
        class Target:
            def hostname(self) -> str:
                return "callable-host"

        parser = self._create_parser(Target())
        result = parser._safe_read_target_attribute(("hostname",))
        self.assertEqual(result, "callable-host")

    def test_skips_callable_that_raises(self) -> None:
        class Target:
            def hostname(self) -> str:
                raise RuntimeError("broken")
            computer_name = "fallback"

        parser = self._create_parser(Target())
        result = parser._safe_read_target_attribute(("hostname", "computer_name"))
        self.assertEqual(result, "fallback")

    def test_skips_callable_returning_none(self) -> None:
        class Target:
            def hostname(self) -> None:
                return None
            computer_name = "fallback"

        parser = self._create_parser(Target())
        result = parser._safe_read_target_attribute(("hostname", "computer_name"))
        self.assertEqual(result, "fallback")

    def test_skips_attribute_that_raises_on_getattr(self) -> None:
        class Target:
            @property
            def hostname(self) -> str:
                raise OSError("property broken")
            computer_name = "fallback"

        parser = self._create_parser(Target())
        result = parser._safe_read_target_attribute(("hostname", "computer_name"))
        self.assertEqual(result, "fallback")


class RewriteCsvWithExpandedHeadersTests(unittest.TestCase):
    """Tests for ForensicParser._rewrite_csv_with_expanded_headers."""

    def _create_parser(self, case_dir: Path) -> ForensicParser:
        target = object()
        audit = FakeAuditLogger()
        with patch(_PATCH_TARGET_OPEN, return_value=target):
            return ForensicParser("evidence.E01", case_dir, audit)

    def test_rewrite_adds_missing_columns_and_pads_rows(self) -> None:
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(Path(temp_dir))
            csv_path = parser.parsed_dir / "test.csv"

            # Write a CSV with an incomplete header
            with csv_path.open("w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["a", "b"])
                writer.writerow(["1", "2"])
                writer.writerow(["3", "4"])

            # Rewrite with expanded headers
            parser._rewrite_csv_with_expanded_headers(csv_path, ["a", "b", "c"])

            with csv_path.open("r", newline="", encoding="utf-8") as f:
                reader = csv.reader(f)
                header = next(reader)
                rows = list(reader)

        self.assertEqual(header, ["a", "b", "c"])
        self.assertEqual(rows[0], ["1", "2", ""])
        self.assertEqual(rows[1], ["3", "4", ""])

    def test_rewrite_preserves_full_length_rows(self) -> None:
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(Path(temp_dir))
            csv_path = parser.parsed_dir / "test.csv"

            with csv_path.open("w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["a", "b"])
                writer.writerow(["1", "2"])

            parser._rewrite_csv_with_expanded_headers(csv_path, ["a", "b"])

            with csv_path.open("r", newline="", encoding="utf-8") as f:
                reader = csv.reader(f)
                header = next(reader)
                rows = list(reader)

        self.assertEqual(header, ["a", "b"])
        self.assertEqual(rows[0], ["1", "2"])


class OpenEvtxWriterTests(unittest.TestCase):
    """Tests for ForensicParser._open_evtx_writer."""

    def _create_parser(self, case_dir: Path) -> ForensicParser:
        target = object()
        audit = FakeAuditLogger()
        with patch(_PATCH_TARGET_OPEN, return_value=target):
            return ForensicParser("evidence.E01", case_dir, audit)

    def test_part_1_filename_has_no_part_suffix(self) -> None:
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(Path(temp_dir))
            state = parser._open_evtx_writer("evtx", "Security", part=1)
            try:
                self.assertTrue(str(state["path"]).endswith("evtx_Security.csv"))
                self.assertIsNone(state["writer"])
                self.assertIsNone(state["fieldnames"])
                self.assertEqual(state["records_in_file"], 0)
                self.assertEqual(state["part"], 1)
            finally:
                state["handle"].close()

    def test_part_2_filename_has_part_suffix(self) -> None:
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(Path(temp_dir))
            state = parser._open_evtx_writer("evtx", "Security", part=2)
            try:
                self.assertTrue(str(state["path"]).endswith("evtx_Security_part2.csv"))
            finally:
                state["handle"].close()

    def test_group_name_is_sanitized(self) -> None:
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(Path(temp_dir))
            state = parser._open_evtx_writer("evtx", "Microsoft-Windows/Sysmon", part=1)
            try:
                filename = state["path"].name
                self.assertNotIn("/", filename)
            finally:
                state["handle"].close()


class ArtifactPromptNameCandidatesTests(unittest.TestCase):
    """Tests for registry._artifact_prompt_name_candidates."""

    def test_simple_key(self) -> None:
        candidates = _artifact_prompt_name_candidates("runkeys")
        self.assertIn("runkeys", candidates)

    def test_dotted_key_generates_underscore_variant(self) -> None:
        candidates = _artifact_prompt_name_candidates("browser.history")
        self.assertIn("browser.history", candidates)
        self.assertIn("browser_history", candidates)

    def test_underscore_key_generates_dot_variant(self) -> None:
        candidates = _artifact_prompt_name_candidates("sru_network")
        self.assertIn("sru_network", candidates)
        self.assertIn("sru.network", candidates)

    def test_empty_key_returns_empty_list(self) -> None:
        self.assertEqual(_artifact_prompt_name_candidates(""), [])

    def test_whitespace_only_returns_empty_list(self) -> None:
        self.assertEqual(_artifact_prompt_name_candidates("   "), [])

    def test_case_insensitive(self) -> None:
        candidates = _artifact_prompt_name_candidates("RunKeys")
        self.assertIn("runkeys", candidates)

    def test_no_duplicates(self) -> None:
        candidates = _artifact_prompt_name_candidates("simple")
        # "simple" with dots replaced by underscores is still "simple"
        # so there should be no duplicates
        self.assertEqual(len(candidates), len(set(candidates)))


class LoadArtifactGuidancePromptTests(unittest.TestCase):
    """Tests for registry._load_artifact_guidance_prompt."""

    def test_returns_prompt_for_known_artifact(self) -> None:
        """runkeys.md should exist and be loaded."""
        result = _load_artifact_guidance_prompt("runkeys")
        self.assertTrue(len(result) > 0)

    def test_returns_empty_for_unknown_artifact(self) -> None:
        result = _load_artifact_guidance_prompt("nonexistent_artifact_xyz_12345")
        self.assertEqual(result, "")

    def test_returns_empty_for_empty_key(self) -> None:
        result = _load_artifact_guidance_prompt("")
        self.assertEqual(result, "")


class ApplyArtifactGuidanceFromPromptsTests(unittest.TestCase):
    """Tests for registry._apply_artifact_guidance_from_prompts."""

    def test_sets_guidance_from_prompt_file(self) -> None:
        """If a prompt file exists, artifact_guidance should be populated."""
        registry = {
            "runkeys": {
                "name": "Run Keys",
                "analysis_hint": "inline hint",
            }
        }
        _apply_artifact_guidance_from_prompts(registry)
        # runkeys.md exists in the prompts directory
        self.assertIn("artifact_guidance", registry["runkeys"])
        self.assertNotEqual(registry["runkeys"]["artifact_guidance"], "")

    def test_falls_back_to_analysis_hint(self) -> None:
        """When no prompt file exists, falls back to analysis_hint."""
        registry = {
            "nonexistent_xyz_99999": {
                "name": "Fake",
                "analysis_hint": "use this hint",
            }
        }
        _apply_artifact_guidance_from_prompts(registry)
        self.assertEqual(
            registry["nonexistent_xyz_99999"].get("artifact_guidance", ""),
            "use this hint",
        )

    def test_falls_back_to_analysis_instructions(self) -> None:
        """When no prompt file exists, falls back to analysis_instructions."""
        registry = {
            "nonexistent_xyz_99998": {
                "name": "Fake",
                "analysis_instructions": "detailed instructions",
            }
        }
        _apply_artifact_guidance_from_prompts(registry)
        self.assertEqual(
            registry["nonexistent_xyz_99998"].get("artifact_guidance", ""),
            "detailed instructions",
        )

    def test_no_guidance_when_nothing_available(self) -> None:
        """When no prompt file and no hints exist, no guidance is set."""
        registry = {
            "nonexistent_xyz_99997": {
                "name": "Fake",
            }
        }
        _apply_artifact_guidance_from_prompts(registry)
        self.assertNotIn("artifact_guidance", registry["nonexistent_xyz_99997"])


class ArtifactRegistryTests(unittest.TestCase):
    """Tests for the WINDOWS_ARTIFACT_REGISTRY data structure."""

    def test_all_entries_have_required_keys(self) -> None:
        """Every registry entry should have name, category, function, description."""
        for key, details in WINDOWS_ARTIFACT_REGISTRY.items():
            self.assertIn("name", details, f"{key} missing 'name'")
            self.assertIn("category", details, f"{key} missing 'category'")
            self.assertIn("function", details, f"{key} missing 'function'")
            self.assertIn("description", details, f"{key} missing 'description'")

    def test_registry_is_not_empty(self) -> None:
        self.assertGreater(len(WINDOWS_ARTIFACT_REGISTRY), 0)

    def test_known_artifacts_present(self) -> None:
        expected_keys = {"runkeys", "tasks", "services", "evtx", "mft", "shimcache", "prefetch"}
        for key in expected_keys:
            self.assertIn(key, WINDOWS_ARTIFACT_REGISTRY)

    def test_evtx_artifacts_identified_correctly(self) -> None:
        """EVTX-type artifacts should have function names ending with 'evtx'."""
        for key, details in WINDOWS_ARTIFACT_REGISTRY.items():
            func = details["function"]
            if "evtx" in key:
                self.assertTrue(
                    ForensicParser._is_evtx_artifact(func),
                    f"{key} with function '{func}' should be identified as EVTX",
                )


class LinuxParserTests(unittest.TestCase):
    """Tests for ForensicParser with Linux targets."""

    def _create_parser(self, target: object, case_dir: Path, audit: FakeAuditLogger) -> ForensicParser:
        """Create a ForensicParser with a mock target."""
        with patch(_PATCH_TARGET_OPEN, return_value=target):
            return ForensicParser("evidence.tar", case_dir, audit)

    def test_linux_target_sets_os_type_to_linux(self) -> None:
        """Parser should detect os_type='linux' from target.os."""
        class LinuxTarget:
            os = "linux"
            def has_function(self, function_name: str) -> bool:
                return False

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(LinuxTarget(), Path(temp_dir), audit)
            self.assertEqual(parser.os_type, "linux")

    def test_get_available_artifacts_returns_linux_entries_for_linux_target(self) -> None:
        """A Linux target should return Linux registry artifacts."""
        class LinuxTarget:
            os = "linux"
            def has_function(self, function_name: str) -> bool:
                return False

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(LinuxTarget(), Path(temp_dir), audit)
            artifacts = parser.get_available_artifacts()

        returned_keys = {a["key"] for a in artifacts}
        self.assertEqual(returned_keys, set(LINUX_ARTIFACT_REGISTRY.keys()))

    def test_parse_artifact_resolves_linux_key(self) -> None:
        """Parsing a Linux-only artifact key should work on a Linux target."""
        class LinuxParseTarget:
            os = "linux"
            def has_function(self, function_name: str) -> bool:
                return True
            def bash_history(self) -> list[FakeRecord]:
                return [
                    FakeRecord({"ts": "2025-01-15 10:00:00", "command": "whoami", "shell": "bash"}),
                ]

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(LinuxParseTarget(), Path(temp_dir), audit)
            result = parser.parse_artifact("bash_history")

        self.assertTrue(result["success"])
        self.assertEqual(result["record_count"], 1)

    def test_os_type_defaults_to_unknown_on_detection_failure(self) -> None:
        """When target.os raises, os_type should default to 'unknown'."""
        class BrokenOsTarget:
            @property
            def os(self) -> str:
                raise RuntimeError("cannot detect OS")
            def has_function(self, function_name: str) -> bool:
                return False

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(BrokenOsTarget(), Path(temp_dir), audit)
            self.assertEqual(parser.os_type, "unknown")

    def test_parse_unknown_linux_artifact_returns_error(self) -> None:
        """Parsing an artifact not in the Linux registry returns error."""
        class LinuxTarget:
            os = "linux"

        audit = FakeAuditLogger()
        with TemporaryDirectory(prefix="aift-parser-test-") as temp_dir:
            parser = self._create_parser(LinuxTarget(), Path(temp_dir), audit)
            result = parser.parse_artifact("shimcache")

        self.assertFalse(result["success"])
        self.assertIn("Unknown artifact key", result["error"])


class LinuxArtifactRegistryTests(unittest.TestCase):
    """Tests for the LINUX_ARTIFACT_REGISTRY and get_artifact_registry."""

    def test_linux_registry_is_not_empty(self) -> None:
        """The Linux registry should contain artifacts."""
        self.assertGreater(len(LINUX_ARTIFACT_REGISTRY), 0)

    def test_linux_registry_has_required_keys(self) -> None:
        """Every Linux registry entry should have name, category, function, description."""
        for key, details in LINUX_ARTIFACT_REGISTRY.items():
            self.assertIn("name", details, f"{key} missing 'name'")
            self.assertIn("category", details, f"{key} missing 'category'")
            self.assertIn("function", details, f"{key} missing 'function'")
            self.assertIn("description", details, f"{key} missing 'description'")

    def test_known_linux_artifacts_present(self) -> None:
        """All registered Linux artifacts should be present in the registry."""
        expected = {
            "bash_history", "zsh_history", "fish_history", "python_history",
            "wtmp", "btmp", "lastlog", "users", "groups", "sudoers",
            "cronjobs", "services",
            "syslog", "journalctl", "packagemanager",
            "ssh.authorized_keys", "ssh.known_hosts",
            "network.interfaces",
        }
        for key in expected:
            self.assertIn(key, LINUX_ARTIFACT_REGISTRY, f"Expected Linux artifact '{key}' not found")

    def test_get_artifact_registry_returns_linux_for_linux(self) -> None:
        """get_artifact_registry('linux') should return the Linux registry."""
        result = get_artifact_registry("linux")
        self.assertIs(result, LINUX_ARTIFACT_REGISTRY)

    def test_get_artifact_registry_returns_windows_for_windows(self) -> None:
        """get_artifact_registry('windows') should return the Windows registry."""
        result = get_artifact_registry("windows")
        self.assertIs(result, WINDOWS_ARTIFACT_REGISTRY)

    def test_get_artifact_registry_defaults_to_windows(self) -> None:
        """get_artifact_registry with unknown OS should default to Windows."""
        result = get_artifact_registry("esxi")
        self.assertIs(result, WINDOWS_ARTIFACT_REGISTRY)

    def test_get_artifact_registry_handles_none(self) -> None:
        """get_artifact_registry(None) should default to Windows."""
        result = get_artifact_registry(None)  # type: ignore[arg-type]
        self.assertIs(result, WINDOWS_ARTIFACT_REGISTRY)

    def test_linux_registry_loads_guidance_from_correct_directory(self) -> None:
        """Linux artifact guidance should be loaded from artifact_instructions_linux/."""
        from app.parser.registry import _LINUX_PROMPTS_DIR
        self.assertTrue(
            str(_LINUX_PROMPTS_DIR).endswith("artifact_instructions_linux"),
            f"_LINUX_PROMPTS_DIR should point to artifact_instructions_linux, got: {_LINUX_PROMPTS_DIR}",
        )

    def test_linux_registry_has_artifact_guidance(self) -> None:
        """At least some Linux artifacts should have artifact_guidance loaded from prompt files."""
        guided = [key for key, d in LINUX_ARTIFACT_REGISTRY.items() if d.get("artifact_guidance")]
        self.assertGreater(
            len(guided), 0,
            "No Linux artifacts have 'artifact_guidance' — prompt loading may be broken.",
        )

    def test_apply_guidance_from_linux_prompts_dir(self) -> None:
        """_apply_artifact_guidance_from_prompts loads from the Linux prompts directory."""
        with TemporaryDirectory() as tmpdir:
            prompts_dir = Path(tmpdir)
            (prompts_dir / "bash_history.md").write_text("LINUX BASH GUIDE", encoding="utf-8")
            registry = {"bash_history": {"name": "Bash History", "analysis_hint": "fallback"}}
            _apply_artifact_guidance_from_prompts(registry, prompts_dir)
            self.assertEqual(registry["bash_history"]["artifact_guidance"], "LINUX BASH GUIDE")

    def test_linux_no_duplicate_artifact_keys_with_windows(self) -> None:
        """Linux-only artifacts should not accidentally collide with Windows keys.

        'services' is intentionally shared (Dissect uses the same function
        name), but other Linux keys should be distinct.
        """
        shared_allowed = {"services"}
        overlap = set(LINUX_ARTIFACT_REGISTRY) & set(WINDOWS_ARTIFACT_REGISTRY) - shared_allowed
        self.assertEqual(
            overlap, set(),
            f"Unexpected key overlap between Linux and Windows registries: {overlap}",
        )


if __name__ == "__main__":
    unittest.main()
