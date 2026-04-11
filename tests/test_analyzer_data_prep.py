"""Tests for analyzer utility functions and data preparation helpers.

Covers standalone function tests from app.analyzer.utils, app.analyzer.chunking,
and citation validation helpers.
"""
from __future__ import annotations

import csv
import unittest
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from app.analyzer import ForensicAnalyzer



class TestStringifyValue(unittest.TestCase):
    """Tests for utils.stringify_value."""

    def test_none_returns_empty(self) -> None:
        from app.analyzer.utils import stringify_value
        self.assertEqual(stringify_value(None), "")

    def test_string_stripped(self) -> None:
        from app.analyzer.utils import stringify_value
        self.assertEqual(stringify_value("  hello  "), "hello")

    def test_int_converted(self) -> None:
        from app.analyzer.utils import stringify_value
        self.assertEqual(stringify_value(42), "42")

    def test_empty_string(self) -> None:
        from app.analyzer.utils import stringify_value
        self.assertEqual(stringify_value(""), "")


class TestFormatDatetime(unittest.TestCase):
    """Tests for utils.format_datetime."""

    def test_none_returns_na(self) -> None:
        from app.analyzer.utils import format_datetime
        self.assertEqual(format_datetime(None), "N/A")

    def test_datetime_returns_iso(self) -> None:
        from app.analyzer.utils import format_datetime
        dt = datetime(2026, 1, 15, 12, 0, 0)
        self.assertEqual(format_datetime(dt), "2026-01-15T12:00:00")


class TestNormalizeTableCell(unittest.TestCase):
    """Tests for utils.normalize_table_cell."""

    def test_short_value_unchanged(self) -> None:
        from app.analyzer.utils import normalize_table_cell
        self.assertEqual(normalize_table_cell("hello", 100), "hello")

    def test_long_value_truncated_with_ellipsis(self) -> None:
        from app.analyzer.utils import normalize_table_cell
        result = normalize_table_cell("a" * 50, 20)
        self.assertTrue(result.endswith("..."))
        self.assertEqual(len(result), 20)

    def test_very_small_limit(self) -> None:
        from app.analyzer.utils import normalize_table_cell
        result = normalize_table_cell("abcdef", 3)
        self.assertEqual(result, "abc")

    def test_newlines_replaced(self) -> None:
        from app.analyzer.utils import normalize_table_cell
        result = normalize_table_cell("line1\nline2\rline3", 100)
        self.assertNotIn("\n", result)
        self.assertNotIn("\r", result)

    def test_pipe_escaped(self) -> None:
        from app.analyzer.utils import normalize_table_cell
        result = normalize_table_cell("a|b", 100)
        self.assertIn(r"\|", result)


class TestSanitizeFilename(unittest.TestCase):
    """Tests for utils.sanitize_filename."""

    def test_clean_name_unchanged(self) -> None:
        from app.analyzer.utils import sanitize_filename
        self.assertEqual(sanitize_filename("runkeys"), "runkeys")

    def test_special_chars_replaced(self) -> None:
        from app.analyzer.utils import sanitize_filename
        result = sanitize_filename("evtx/Security!@#")
        self.assertNotIn("/", result)
        self.assertNotIn("!", result)

    def test_empty_returns_artifact(self) -> None:
        from app.analyzer.utils import sanitize_filename
        self.assertEqual(sanitize_filename(""), "artifact")

    def test_only_special_chars_returns_artifact(self) -> None:
        from app.analyzer.utils import sanitize_filename
        self.assertEqual(sanitize_filename("!!!"), "artifact")


class TestTruncateForPrompt(unittest.TestCase):
    """Tests for utils.truncate_for_prompt."""

    def test_short_string_unchanged(self) -> None:
        from app.analyzer.utils import truncate_for_prompt
        self.assertEqual(truncate_for_prompt("hello", 100), "hello")

    def test_long_string_truncated(self) -> None:
        from app.analyzer.utils import truncate_for_prompt
        result = truncate_for_prompt("a" * 100, 50)
        self.assertIn("[truncated]", result)
        # The function uses limit - 14 for the prefix, plus " ... [truncated]"
        # which is 14 chars, so the result may be close to but not exceed limit+2.
        self.assertLess(len(result), 60)

    def test_very_small_limit(self) -> None:
        from app.analyzer.utils import truncate_for_prompt
        result = truncate_for_prompt("abcdefghij", 5)
        self.assertEqual(result, "abcde")

    def test_none_value(self) -> None:
        from app.analyzer.utils import truncate_for_prompt
        result = truncate_for_prompt(None, 100)
        self.assertEqual(result, "")


class TestUniquePreserveOrder(unittest.TestCase):
    """Tests for utils.unique_preserve_order."""

    def test_deduplicates_case_insensitive(self) -> None:
        from app.analyzer.utils import unique_preserve_order
        result = unique_preserve_order(["Alpha", "alpha", "Beta"])
        self.assertEqual(result, ["Alpha", "Beta"])

    def test_strips_quotes_and_brackets(self) -> None:
        from app.analyzer.utils import unique_preserve_order
        result = unique_preserve_order(['"hello"', "'world'", "[test]"])
        self.assertEqual(result, ["hello", "world", "test"])

    def test_empty_values_skipped(self) -> None:
        from app.analyzer.utils import unique_preserve_order
        result = unique_preserve_order(["", "  ", "a"])
        self.assertEqual(result, ["a"])

    def test_trailing_punctuation_stripped(self) -> None:
        from app.analyzer.utils import unique_preserve_order
        result = unique_preserve_order(["hello.", "world;"])
        self.assertEqual(result, ["hello", "world"])


class TestBuildDatetime(unittest.TestCase):
    """Tests for utils.build_datetime."""

    def test_valid_date(self) -> None:
        from app.analyzer.utils import build_datetime
        result = build_datetime("2026", "1", "15")
        self.assertEqual(result, datetime(2026, 1, 15))

    def test_invalid_date_returns_none(self) -> None:
        from app.analyzer.utils import build_datetime
        result = build_datetime("2026", "13", "1")
        self.assertIsNone(result)

    def test_invalid_day_returns_none(self) -> None:
        from app.analyzer.utils import build_datetime
        result = build_datetime("2026", "2", "30")
        self.assertIsNone(result)


class TestNormalizeDatetime(unittest.TestCase):
    """Tests for utils.normalize_datetime."""

    def test_naive_unchanged(self) -> None:
        from app.analyzer.utils import normalize_datetime
        dt = datetime(2026, 1, 15, 12, 0, 0)
        result = normalize_datetime(dt)
        self.assertEqual(result, dt)
        self.assertIsNone(result.tzinfo)

    def test_aware_converted_to_naive_utc(self) -> None:
        from app.analyzer.utils import normalize_datetime
        dt = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        result = normalize_datetime(dt)
        self.assertEqual(result, datetime(2026, 1, 15, 12, 0, 0))
        self.assertIsNone(result.tzinfo)


class TestParseInt(unittest.TestCase):
    """Tests for utils.parse_int."""

    def test_simple_int(self) -> None:
        from app.analyzer.utils import parse_int
        self.assertEqual(parse_int("42"), 42)

    def test_negative_int(self) -> None:
        from app.analyzer.utils import parse_int
        self.assertEqual(parse_int("-5"), -5)

    def test_embedded_int(self) -> None:
        from app.analyzer.utils import parse_int
        self.assertEqual(parse_int("row 123 here"), 123)

    def test_empty_returns_none(self) -> None:
        from app.analyzer.utils import parse_int
        self.assertIsNone(parse_int(""))

    def test_no_digits_returns_none(self) -> None:
        from app.analyzer.utils import parse_int
        self.assertIsNone(parse_int("abc"))


class TestParseDatetimeValue(unittest.TestCase):
    """Tests for utils.parse_datetime_value."""

    def test_iso_format(self) -> None:
        from app.analyzer.utils import parse_datetime_value
        result = parse_datetime_value("2026-01-15T12:00:00")
        self.assertEqual(result, datetime(2026, 1, 15, 12, 0, 0))

    def test_iso_with_z(self) -> None:
        from app.analyzer.utils import parse_datetime_value
        result = parse_datetime_value("2026-01-15T12:00:00Z")
        self.assertIsNotNone(result)
        self.assertEqual(result, datetime(2026, 1, 15, 12, 0, 0))

    def test_date_only(self) -> None:
        from app.analyzer.utils import parse_datetime_value
        result = parse_datetime_value("2026-01-15")
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2026)

    def test_empty_returns_none(self) -> None:
        from app.analyzer.utils import parse_datetime_value
        self.assertIsNone(parse_datetime_value(""))

    def test_none_returns_none(self) -> None:
        from app.analyzer.utils import parse_datetime_value
        self.assertIsNone(parse_datetime_value(None))

    def test_epoch_seconds(self) -> None:
        from app.analyzer.utils import parse_datetime_value
        # 2026-01-15 00:00:00 UTC = 1768435200
        result = parse_datetime_value("1768435200")
        self.assertIsNotNone(result)

    def test_epoch_millis(self) -> None:
        from app.analyzer.utils import parse_datetime_value
        result = parse_datetime_value("1768435200000")
        self.assertIsNotNone(result)

    def test_garbage_returns_none(self) -> None:
        from app.analyzer.utils import parse_datetime_value
        self.assertIsNone(parse_datetime_value("not-a-date"))

    def test_epoch_rejected_when_allow_epoch_false(self) -> None:
        """Epoch integers should be rejected when allow_epoch=False."""
        from app.analyzer.utils import parse_datetime_value
        result = parse_datetime_value("1768435200", allow_epoch=False)
        self.assertIsNone(result)

    def test_string_date_accepted_when_allow_epoch_false(self) -> None:
        """String-format dates should still parse when allow_epoch=False."""
        from app.analyzer.utils import parse_datetime_value
        result = parse_datetime_value("2026-01-15T12:00:00", allow_epoch=False)
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2026)


class TestLooksLikeTimestampColumn(unittest.TestCase):
    """Tests for utils.looks_like_timestamp_column."""

    def test_timestamp_hint(self) -> None:
        from app.analyzer.utils import looks_like_timestamp_column
        self.assertTrue(looks_like_timestamp_column("ts"))
        self.assertTrue(looks_like_timestamp_column("Timestamp"))
        self.assertTrue(looks_like_timestamp_column("created_date"))
        self.assertTrue(looks_like_timestamp_column("LastModified"))

    def test_non_timestamp(self) -> None:
        from app.analyzer.utils import looks_like_timestamp_column
        self.assertFalse(looks_like_timestamp_column("name"))
        self.assertFalse(looks_like_timestamp_column("EventID"))


class TestExtractRowDatetime(unittest.TestCase):
    """Tests for utils.extract_row_datetime."""

    def test_finds_timestamp_column(self) -> None:
        from app.analyzer.utils import extract_row_datetime
        row = {"ts": "2026-01-15T12:00:00", "name": "test"}
        result = extract_row_datetime(row)
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2026)

    def test_returns_none_for_no_timestamps(self) -> None:
        from app.analyzer.utils import extract_row_datetime
        row = {"name": "test", "value": "abc"}
        result = extract_row_datetime(row)
        self.assertIsNone(result)

    def test_with_explicit_columns(self) -> None:
        from app.analyzer.utils import extract_row_datetime
        row = {"ts": "2026-01-15T12:00:00", "name": "test"}
        result = extract_row_datetime(row, columns=["ts", "name"])
        self.assertIsNotNone(result)

    def test_numeric_id_without_timestamp_columns_returns_none(self) -> None:
        """Numeric IDs in non-timestamp columns must not be mistaken for epochs."""
        from app.analyzer.utils import extract_row_datetime
        row = {"record_id": "1768435200", "name": "test", "count": "42"}
        result = extract_row_datetime(row)
        self.assertIsNone(result)

    def test_numeric_id_ignored_when_timestamp_column_present(self) -> None:
        """When a timestamp column exists, numeric IDs in other columns are irrelevant."""
        from app.analyzer.utils import extract_row_datetime
        row = {"ts": "2026-01-15T12:00:00", "record_id": "9999999999"}
        result = extract_row_datetime(row)
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2026)

    def test_epoch_in_timestamp_column_still_works(self) -> None:
        """Epoch integers in a timestamp-named column should still parse."""
        from app.analyzer.utils import extract_row_datetime
        # 1768435200 = 2026-01-15 00:00:00 UTC
        row = {"timestamp": "1768435200", "name": "test"}
        result = extract_row_datetime(row)
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2026)

    def test_string_date_in_non_timestamp_column_still_works(self) -> None:
        """String-format dates in non-timestamp columns should still parse."""
        from app.analyzer.utils import extract_row_datetime
        row = {"event_info": "2026-01-15T12:00:00", "id": "42"}
        result = extract_row_datetime(row)
        self.assertIsNotNone(result)
        self.assertEqual(result.year, 2026)

    def test_all_numeric_non_timestamp_columns_returns_none(self) -> None:
        """Rows with only numeric values and no timestamp columns produce None."""
        from app.analyzer.utils import extract_row_datetime
        row = {"id": "1000000001", "size": "2000000000", "count": "3000000000"}
        result = extract_row_datetime(row)
        self.assertIsNone(result)


class TestTimeRangeForRows(unittest.TestCase):
    """Tests for utils.time_range_for_rows."""

    def test_computes_range(self) -> None:
        from app.analyzer.utils import time_range_for_rows
        rows = [
            {"ts": "2026-01-15T10:00:00"},
            {"ts": "2026-01-17T10:00:00"},
            {"ts": "2026-01-16T10:00:00"},
        ]
        min_t, max_t = time_range_for_rows(rows)
        self.assertIsNotNone(min_t)
        self.assertIsNotNone(max_t)
        self.assertEqual(min_t.day, 15)
        self.assertEqual(max_t.day, 17)

    def test_empty_rows(self) -> None:
        from app.analyzer.utils import time_range_for_rows
        min_t, max_t = time_range_for_rows([])
        self.assertIsNone(min_t)
        self.assertIsNone(max_t)

    def test_no_timestamps(self) -> None:
        from app.analyzer.utils import time_range_for_rows
        rows = [{"name": "test"}, {"name": "test2"}]
        min_t, max_t = time_range_for_rows(rows)
        self.assertIsNone(min_t)
        self.assertIsNone(max_t)

    def test_numeric_ids_not_mistaken_for_time_range(self) -> None:
        """Rows with only numeric IDs in non-timestamp columns produce no range."""
        from app.analyzer.utils import time_range_for_rows
        rows = [
            {"id": "1000000001", "size": "2000000000"},
            {"id": "1000000002", "size": "2000000001"},
        ]
        min_t, max_t = time_range_for_rows(rows)
        self.assertIsNone(min_t)
        self.assertIsNone(max_t)

    def test_real_timestamps_still_produce_correct_range(self) -> None:
        """Genuine timestamp columns still yield correct time ranges."""
        from app.analyzer.utils import time_range_for_rows
        rows = [
            {"created_date": "2026-01-10T08:00:00", "id": "1000000001"},
            {"created_date": "2026-01-20T08:00:00", "id": "1000000002"},
        ]
        min_t, max_t = time_range_for_rows(rows)
        self.assertIsNotNone(min_t)
        self.assertIsNotNone(max_t)
        self.assertEqual(min_t.day, 10)
        self.assertEqual(max_t.day, 20)


class TestNormalizeArtifactKey(unittest.TestCase):
    """Tests for utils.normalize_artifact_key."""

    def test_known_normalizations(self) -> None:
        from app.analyzer.utils import normalize_artifact_key
        self.assertEqual(normalize_artifact_key("mft"), "mft")
        self.assertEqual(normalize_artifact_key("MFT"), "mft")
        self.assertEqual(normalize_artifact_key("evtx_Security"), "evtx_security")
        self.assertEqual(normalize_artifact_key("evtx_System"), "evtx_system")
        self.assertEqual(normalize_artifact_key("shimcache_data"), "shimcache_data")
        self.assertEqual(normalize_artifact_key("amcache.applications"), "amcache.applications")
        self.assertEqual(normalize_artifact_key("prefetch_data"), "prefetch_data")
        self.assertEqual(normalize_artifact_key("services_list"), "services_list")
        self.assertEqual(normalize_artifact_key("tasks_scheduled"), "tasks_scheduled")
        self.assertEqual(normalize_artifact_key("userassist_data"), "userassist_data")
        self.assertEqual(normalize_artifact_key("runkeys_data"), "runkeys_data")

    def test_unknown_key_lowered(self) -> None:
        from app.analyzer.utils import normalize_artifact_key
        self.assertEqual(normalize_artifact_key("CustomArtifact"), "customartifact")

    def test_linux_artifact_keys_pass_through(self) -> None:
        """Linux artifact keys should normalize to themselves (no special-case rewriting)."""
        from app.analyzer.utils import normalize_artifact_key

        linux_keys = [
            "bash_history", "zsh_history", "fish_history", "python_history",
            "wtmp", "btmp", "lastlog", "users", "groups", "sudoers",
            "cronjobs", "syslog", "journalctl", "packagemanager",
            "ssh.authorized_keys", "ssh.known_hosts", "network.interfaces",
        ]
        for key in linux_keys:
            self.assertEqual(
                normalize_artifact_key(key), key,
                f"Linux key '{key}' should pass through unchanged",
            )

    def test_services_normalizes_for_both_os(self) -> None:
        """The shared 'services' key should normalize consistently."""
        from app.analyzer.utils import normalize_artifact_key
        self.assertEqual(normalize_artifact_key("services"), "services")


class TestNormalizeOsType(unittest.TestCase):
    """Tests for utils.normalize_os_type."""

    def test_linux(self) -> None:
        from app.analyzer.utils import normalize_os_type
        self.assertEqual(normalize_os_type("linux"), "linux")

    def test_windows(self) -> None:
        from app.analyzer.utils import normalize_os_type
        self.assertEqual(normalize_os_type("windows"), "windows")

    def test_none_defaults_to_windows(self) -> None:
        from app.analyzer.utils import normalize_os_type
        self.assertEqual(normalize_os_type(None), "windows")

    def test_empty_defaults_to_windows(self) -> None:
        from app.analyzer.utils import normalize_os_type
        self.assertEqual(normalize_os_type(""), "windows")

    def test_strips_and_lowercases(self) -> None:
        from app.analyzer.utils import normalize_os_type
        self.assertEqual(normalize_os_type("  Linux  "), "linux")
        self.assertEqual(normalize_os_type("WINDOWS"), "windows")

    def test_unknown_os_passthrough(self) -> None:
        from app.analyzer.utils import normalize_os_type
        self.assertEqual(normalize_os_type("esxi"), "esxi")


class TestExtractUrlHost(unittest.TestCase):
    """Tests for utils.extract_url_host."""

    def test_full_url(self) -> None:
        from app.analyzer.utils import extract_url_host
        self.assertEqual(extract_url_host("https://evil.example.com/path"), "evil.example.com")

    def test_url_with_port(self) -> None:
        from app.analyzer.utils import extract_url_host
        self.assertEqual(extract_url_host("http://host.com:8080/path"), "host.com")

    def test_bare_host(self) -> None:
        from app.analyzer.utils import extract_url_host
        self.assertEqual(extract_url_host("example.com/path"), "example.com")


class TestNormalizeCsvRow(unittest.TestCase):
    """Tests for utils.normalize_csv_row."""

    def test_normalizes_values(self) -> None:
        from app.analyzer.utils import normalize_csv_row
        row = {"col1": "  hello  ", "col2": None, "col3": 42}
        result = normalize_csv_row(row, ["col1", "col2"])
        self.assertEqual(result["col1"], "hello")
        self.assertEqual(result["col2"], "")

    def test_extra_fields(self) -> None:
        from app.analyzer.utils import normalize_csv_row
        row = {"col1": "val1", None: ["extra1", "extra2"]}
        result = normalize_csv_row(row, ["col1"])
        self.assertIn("__extra__", result)
        self.assertIn("extra1", result["__extra__"])


class TestCoerceProjectionColumns(unittest.TestCase):
    """Tests for utils.coerce_projection_columns."""

    def test_string_split(self) -> None:
        from app.analyzer.utils import coerce_projection_columns
        result = coerce_projection_columns("ts, name, command")
        self.assertEqual(result, ["ts", "name", "command"])

    def test_list_input(self) -> None:
        from app.analyzer.utils import coerce_projection_columns
        result = coerce_projection_columns(["ts", "name"])
        self.assertEqual(result, ["ts", "name"])

    def test_deduplicates(self) -> None:
        from app.analyzer.utils import coerce_projection_columns
        result = coerce_projection_columns(["ts", "name", "ts"])
        self.assertEqual(result, ["ts", "name"])

    def test_non_string_non_list_returns_empty(self) -> None:
        from app.analyzer.utils import coerce_projection_columns
        result = coerce_projection_columns(42)
        self.assertEqual(result, [])


class TestEmitAnalysisProgress(unittest.TestCase):
    """Tests for utils.emit_analysis_progress."""

    def test_three_arg_callback(self) -> None:
        from app.analyzer.utils import emit_analysis_progress
        calls = []
        def cb(key, status, payload):
            calls.append((key, status, payload))
        emit_analysis_progress(cb, "art1", "started", {"msg": "hi"})
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "art1")

    def test_single_arg_fallback(self) -> None:
        from app.analyzer.utils import emit_analysis_progress
        calls = []
        def cb(payload):
            calls.append(payload)
        emit_analysis_progress(cb, "art1", "started", {"msg": "hi"})
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["artifact_key"], "art1")

    def test_broken_callback_does_not_raise(self) -> None:
        from app.analyzer.utils import emit_analysis_progress
        def cb(*args, **kwargs):
            raise RuntimeError("broken")
        # Should not raise
        emit_analysis_progress(cb, "art1", "started", {"msg": "hi"})


class TestReadIntSetting(unittest.TestCase):
    """Tests for utils.read_int_setting."""

    def test_default_used(self) -> None:
        from app.analyzer.utils import read_int_setting
        self.assertEqual(read_int_setting({}, "key", 10), 10)

    def test_value_parsed(self) -> None:
        from app.analyzer.utils import read_int_setting
        self.assertEqual(read_int_setting({"key": "42"}, "key", 10), 42)

    def test_minimum_clamping(self) -> None:
        from app.analyzer.utils import read_int_setting
        self.assertEqual(read_int_setting({"key": -5}, "key", 10, minimum=1), 1)

    def test_maximum_clamping(self) -> None:
        from app.analyzer.utils import read_int_setting
        self.assertEqual(read_int_setting({"key": 100}, "key", 10, maximum=50), 50)

    def test_invalid_value_uses_default(self) -> None:
        from app.analyzer.utils import read_int_setting
        self.assertEqual(read_int_setting({"key": "abc"}, "key", 10), 10)


class TestReadBoolSetting(unittest.TestCase):
    """Tests for utils.read_bool_setting."""

    def test_bool_value(self) -> None:
        from app.analyzer.utils import read_bool_setting
        self.assertTrue(read_bool_setting({"key": True}, "key", False))
        self.assertFalse(read_bool_setting({"key": False}, "key", True))

    def test_string_true_variants(self) -> None:
        from app.analyzer.utils import read_bool_setting
        for val in ("true", "1", "yes", "on", "True", "YES"):
            self.assertTrue(read_bool_setting({"key": val}, "key", False))

    def test_string_false_variants(self) -> None:
        from app.analyzer.utils import read_bool_setting
        for val in ("false", "0", "no", "off"):
            self.assertFalse(read_bool_setting({"key": val}, "key", True))

    def test_int_value(self) -> None:
        from app.analyzer.utils import read_bool_setting
        self.assertTrue(read_bool_setting({"key": 1}, "key", False))
        self.assertFalse(read_bool_setting({"key": 0}, "key", True))

    def test_default_on_missing(self) -> None:
        from app.analyzer.utils import read_bool_setting
        self.assertTrue(read_bool_setting({}, "key", True))

    def test_non_parseable_uses_default(self) -> None:
        from app.analyzer.utils import read_bool_setting
        self.assertTrue(read_bool_setting({"key": "maybe"}, "key", True))


class TestReadPathSetting(unittest.TestCase):
    """Tests for utils.read_path_setting."""

    def test_string_value(self) -> None:
        from app.analyzer.utils import read_path_setting
        self.assertEqual(read_path_setting({"key": "/some/path"}, "key", "/default"), "/some/path")

    def test_empty_string_uses_default(self) -> None:
        from app.analyzer.utils import read_path_setting
        self.assertEqual(read_path_setting({"key": ""}, "key", "/default"), "/default")

    def test_missing_uses_default(self) -> None:
        from app.analyzer.utils import read_path_setting
        self.assertEqual(read_path_setting({}, "key", "/default"), "/default")

    def test_path_object(self) -> None:
        from app.analyzer.utils import read_path_setting
        result = read_path_setting({"key": Path("/some/path")}, "key", "/default")
        # On Windows, Path("/some/path") becomes "\\some\\path", so compare Path objects.
        self.assertEqual(Path(result), Path("/some/path"))


class TestIsDeupSafeIdentifierColumn(unittest.TestCase):
    """Tests for utils.is_dedup_safe_identifier_column."""

    def test_safe_columns(self) -> None:
        from app.analyzer.utils import is_dedup_safe_identifier_column
        self.assertTrue(is_dedup_safe_identifier_column("record_id"))
        self.assertTrue(is_dedup_safe_identifier_column("RecordID"))
        self.assertTrue(is_dedup_safe_identifier_column("entry_id"))
        self.assertTrue(is_dedup_safe_identifier_column("index"))
        self.assertTrue(is_dedup_safe_identifier_column("sequence_number"))

    def test_unsafe_columns(self) -> None:
        from app.analyzer.utils import is_dedup_safe_identifier_column
        self.assertFalse(is_dedup_safe_identifier_column("EventID"))
        self.assertFalse(is_dedup_safe_identifier_column("ProcessID"))
        self.assertFalse(is_dedup_safe_identifier_column("name"))


class TestEstimateTokensStandalone(unittest.TestCase):
    """Tests for utils.estimate_tokens as standalone function."""

    def test_empty_returns_one(self) -> None:
        from app.analyzer.utils import estimate_tokens
        self.assertEqual(estimate_tokens(""), 1)

    def test_heuristic_ascii(self) -> None:
        from app.analyzer.utils import estimate_tokens
        text = "a" * 400
        result = estimate_tokens(text, model_info={"provider": "anthropic", "model": "claude"})
        self.assertGreaterEqual(result, 100)

    def test_none_model_info(self) -> None:
        from app.analyzer.utils import estimate_tokens
        result = estimate_tokens("hello world")
        self.assertGreaterEqual(result, 1)


###############################################################################
# chunking.py — standalone function tests
###############################################################################


class TestSplitCsvIntoChunks(unittest.TestCase):
    """Tests for chunking.split_csv_into_chunks."""

    def test_small_csv_returns_single_chunk(self) -> None:
        from app.analyzer.chunking import split_csv_into_chunks
        csv_text = "header\nrow1\nrow2"
        result = split_csv_into_chunks(csv_text, max_chars=1000)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], csv_text)

    def test_splits_at_row_boundaries(self) -> None:
        from app.analyzer.chunking import split_csv_into_chunks
        header = "col1,col2"
        rows = [f"val{i},data{i}" for i in range(100)]
        csv_text = header + "\n" + "\n".join(rows)
        result = split_csv_into_chunks(csv_text, max_chars=200)
        self.assertGreater(len(result), 1)
        for chunk in result:
            self.assertTrue(chunk.startswith(header))

    def test_zero_max_chars_returns_single_chunk(self) -> None:
        from app.analyzer.chunking import split_csv_into_chunks
        csv_text = "header\nrow1"
        result = split_csv_into_chunks(csv_text, max_chars=0)
        self.assertEqual(len(result), 1)

    def test_header_only_csv(self) -> None:
        from app.analyzer.chunking import split_csv_into_chunks
        csv_text = "col1,col2"
        result = split_csv_into_chunks(csv_text, max_chars=5)
        self.assertEqual(len(result), 1)

    def test_empty_string(self) -> None:
        from app.analyzer.chunking import split_csv_into_chunks
        result = split_csv_into_chunks("", max_chars=100)
        self.assertEqual(len(result), 1)

    def test_quoted_multiline_field_not_split(self) -> None:
        """A CSV row with a quoted field containing newlines must stay intact."""
        from app.analyzer.chunking import split_csv_into_chunks
        csv_text = (
            'name,description\n'
            '"Alice","Short desc"\n'
            '"Bob","Line one\nLine two\nLine three"'
        )
        # Budget large enough for everything → single chunk, no corruption
        result = split_csv_into_chunks(csv_text, max_chars=5000)
        self.assertEqual(len(result), 1)
        # Re-parse the chunk to verify both data rows survived
        import csv, io
        rows = list(csv.reader(io.StringIO(result[0])))
        self.assertEqual(len(rows), 3)  # header + 2 data rows
        self.assertEqual(rows[1][0], "Alice")
        self.assertEqual(rows[2][0], "Bob")
        self.assertIn("Line one\nLine two\nLine three", rows[2][1])

    def test_multiline_field_chunked_across_boundary(self) -> None:
        """Multiline rows must not be split across chunk boundaries."""
        from app.analyzer.chunking import split_csv_into_chunks
        header = "id,notes"
        # Build rows where the second has an embedded newline
        row1 = '"1","normal row"'
        row2 = '"2","has\nnewline"'
        row3 = '"3","another normal"'
        csv_text = f"{header}\n{row1}\n{row2}\n{row3}"
        # Force multiple chunks with a tight budget
        result = split_csv_into_chunks(csv_text, max_chars=38)
        self.assertGreater(len(result), 1)
        # Every chunk must be valid CSV with the header
        import csv, io
        all_data_rows = []
        for chunk in result:
            self.assertTrue(chunk.startswith("id,notes"))
            rows = list(csv.reader(io.StringIO(chunk)))
            self.assertGreaterEqual(len(rows), 2)  # header + at least 1 row
            all_data_rows.extend(rows[1:])
        # All 3 original data rows must be present and intact
        ids = sorted(r[0] for r in all_data_rows)
        self.assertEqual(ids, ["1", "2", "3"])
        # The multiline field must be preserved
        row2_data = [r for r in all_data_rows if r[0] == "2"][0]
        self.assertIn("\n", row2_data[1])

    def test_headers_preserved_in_all_chunks_with_multiline(self) -> None:
        """Each chunk starts with the header even when rows have newlines."""
        from app.analyzer.chunking import split_csv_into_chunks
        rows = [f'"val{i}","line1\nline2"' for i in range(20)]
        csv_text = "col1,col2\n" + "\n".join(rows)
        result = split_csv_into_chunks(csv_text, max_chars=200)
        self.assertGreater(len(result), 1)
        for chunk in result:
            self.assertTrue(chunk.startswith("col1,col2"))


class TestSplitCsvAndSuffix(unittest.TestCase):
    """Tests for chunking.split_csv_and_suffix."""

    def test_plain_csv(self) -> None:
        from app.analyzer.chunking import split_csv_and_suffix
        csv_data, suffix = split_csv_and_suffix("col1,col2\nval1,val2")
        self.assertEqual(csv_data, "col1,col2\nval1,val2")
        self.assertEqual(suffix, "")

    def test_with_trailing_fence(self) -> None:
        from app.analyzer.chunking import split_csv_and_suffix
        text = "col1,col2\nval1,val2\n```"
        csv_data, suffix = split_csv_and_suffix(text)
        self.assertEqual(csv_data, "col1,col2\nval1,val2")
        self.assertIn("```", suffix)

    def test_with_final_context_reminder(self) -> None:
        from app.analyzer.chunking import split_csv_and_suffix
        text = "col1,col2\nval1,val2\n\n## Final Context Reminder\nDo not ignore."
        csv_data, suffix = split_csv_and_suffix(text)
        self.assertEqual(csv_data, "col1,col2\nval1,val2")
        self.assertIn("Final Context Reminder", suffix)



if __name__ == "__main__":
    unittest.main()
