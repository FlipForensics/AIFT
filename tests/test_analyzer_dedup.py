"""Tests for analyzer deduplication, data preparation, and core method helpers.

Covers standalone function tests from app.analyzer.data_prep,
app.analyzer.constants, and ForensicAnalyzer core methods including
AI retry logic, audit logging, prompt saving, and artifact CSV handling.
"""
from __future__ import annotations

import csv
import os
import unittest
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from app.ai_providers import AIProviderError
from app.analyzer import ForensicAnalyzer
from app.case_logging import case_log_context, register_case_log_handler, unregister_case_log_handler
from conftest import FakeAuditLogger, FakeProvider


###############################################################################
# data_prep.py — standalone function tests
###############################################################################


class TestCounterNormalize(unittest.TestCase):
    """Tests for data_prep.counter_normalize."""

    def test_low_signal_returns_empty(self) -> None:
        from app.analyzer.data_prep import counter_normalize
        self.assertEqual(counter_normalize("none"), "")
        self.assertEqual(counter_normalize("N/A"), "")
        self.assertEqual(counter_normalize(""), "")

    def test_normal_value_returned(self) -> None:
        from app.analyzer.data_prep import counter_normalize
        self.assertNotEqual(counter_normalize("cmd.exe"), "")


class TestSelectAiColumns(unittest.TestCase):
    """Tests for data_prep.select_ai_columns."""

    def test_no_projection_returns_all(self) -> None:
        from app.analyzer.data_prep import select_ai_columns
        cols, applied = select_ai_columns("runkeys", ["ts", "name", "cmd"], {})
        self.assertEqual(cols, ["ts", "name", "cmd"])
        self.assertFalse(applied)

    def test_projection_applied(self) -> None:
        from app.analyzer.data_prep import select_ai_columns
        projections = {"runkeys": ("ts", "name")}
        cols, applied = select_ai_columns("runkeys", ["ts", "name", "cmd"], projections)
        self.assertEqual(cols, ["ts", "name"])
        self.assertTrue(applied)

    def test_missing_columns_logged(self) -> None:
        from app.analyzer.data_prep import select_ai_columns
        audit_calls = []
        def audit_fn(action, details):
            audit_calls.append((action, details))
        projections = {"runkeys": ("ts", "nonexistent")}
        cols, applied = select_ai_columns("runkeys", ["ts", "name"], projections, audit_log_fn=audit_fn)
        self.assertEqual(cols, ["ts"])
        self.assertTrue(applied)
        self.assertGreater(len(audit_calls), 0)

    def test_all_columns_missing_returns_all(self) -> None:
        from app.analyzer.data_prep import select_ai_columns
        projections = {"runkeys": ("x", "y")}
        cols, applied = select_ai_columns("runkeys", ["ts", "name"], projections)
        self.assertEqual(cols, ["ts", "name"])
        self.assertFalse(applied)

    def test_wildcard_passes_through_remaining_columns(self) -> None:
        """A ``*`` entry should include all columns not already listed."""
        from app.analyzer.data_prep import select_ai_columns
        projections = {"services": ("ts", "name", "*")}
        available = ["ts", "name", "Unit_Description", "Service_ExecStart"]
        cols, applied = select_ai_columns("services_linux", available, projections)
        self.assertTrue(applied)
        # Explicit columns come first in order, then the dynamic ones.
        self.assertEqual(cols, ["ts", "name", "Unit_Description", "Service_ExecStart"])

    def test_wildcard_does_not_duplicate_explicit_columns(self) -> None:
        """Wildcard pass-through must not re-add columns already selected."""
        from app.analyzer.data_prep import select_ai_columns
        projections = {"myart": ("ts", "name", "*")}
        available = ["ts", "name", "extra"]
        cols, applied = select_ai_columns("myart", available, projections)
        self.assertEqual(cols, ["ts", "name", "extra"])
        self.assertEqual(cols.count("ts"), 1)


class TestProjectRowsForAnalysis(unittest.TestCase):
    """Tests for data_prep.project_rows_for_analysis."""

    def test_projects_columns(self) -> None:
        from app.analyzer.data_prep import project_rows_for_analysis
        rows = [{"ts": "2026-01-15", "name": "a", "extra": "x", "_row_ref": "1"}]
        result = project_rows_for_analysis(rows, ["ts", "name"])
        self.assertEqual(len(result), 1)
        self.assertIn("ts", result[0])
        self.assertIn("name", result[0])
        self.assertNotIn("extra", result[0])
        self.assertEqual(result[0]["_row_ref"], "1")


class TestDeduplicateRowsForAnalysis(unittest.TestCase):
    """Tests for data_prep.deduplicate_rows_for_analysis standalone."""

    def test_empty_rows(self) -> None:
        from app.analyzer.data_prep import deduplicate_rows_for_analysis
        kept, cols, removed, annotated, variants = deduplicate_rows_for_analysis([], [])
        self.assertEqual(kept, [])
        self.assertEqual(removed, 0)

    def test_no_variant_columns(self) -> None:
        from app.analyzer.data_prep import deduplicate_rows_for_analysis
        rows = [{"name": "a"}, {"name": "b"}]
        kept, cols, removed, annotated, variants = deduplicate_rows_for_analysis(rows, ["name"])
        self.assertEqual(len(kept), 2)
        self.assertEqual(removed, 0)
        self.assertEqual(variants, [])


class TestBuildFullDataCsvStandalone(unittest.TestCase):
    """Tests for data_prep.build_full_data_csv standalone."""

    def test_no_columns(self) -> None:
        from app.analyzer.data_prep import build_full_data_csv
        result = build_full_data_csv([{"a": "1"}], [])
        self.assertEqual(result, "No columns available.")

    def test_serializes(self) -> None:
        from app.analyzer.data_prep import build_full_data_csv
        rows = [{"_row_ref": "1", "ts": "2026-01-15", "name": "test"}]
        result = build_full_data_csv(rows, ["ts", "name"])
        self.assertIn("row_ref,ts,name", result)
        self.assertIn("test", result)


class TestResolveAnalysisInputOutputDir(unittest.TestCase):
    """Tests for data_prep.resolve_analysis_input_output_dir."""

    def test_with_case_dir(self) -> None:
        from app.analyzer.data_prep import resolve_analysis_input_output_dir
        result = resolve_analysis_input_output_dir(Path("/case"), Path("/case/parsed/art.csv"))
        self.assertEqual(result, Path("/case/parsed_deduplicated"))

    def test_without_case_dir_parsed_parent(self) -> None:
        from app.analyzer.data_prep import resolve_analysis_input_output_dir
        result = resolve_analysis_input_output_dir(None, Path("/some/parsed/art.csv"))
        self.assertEqual(result, Path("/some/parsed_deduplicated"))

    def test_without_case_dir_non_parsed(self) -> None:
        from app.analyzer.data_prep import resolve_analysis_input_output_dir
        result = resolve_analysis_input_output_dir(None, Path("/some/other/art.csv"))
        self.assertEqual(result, Path("/some/other/parsed_deduplicated"))


class TestWriteAnalysisInputCsv(unittest.TestCase):
    """Tests for data_prep.write_analysis_input_csv."""

    def test_writes_csv(self) -> None:
        from app.analyzer.data_prep import write_analysis_input_csv
        with TemporaryDirectory(prefix="aift-write-") as tmp_dir:
            source = Path(tmp_dir) / "parsed" / "art.csv"
            source.parent.mkdir(parents=True)
            source.write_text("ts,name\n2026-01-15,test\n", encoding="utf-8")
            rows = [{"ts": "2026-01-15", "name": "test"}]
            result = write_analysis_input_csv(source, rows, ["ts", "name"])
            self.assertTrue(result.exists())
            content = result.read_text(encoding="utf-8")
            self.assertIn("ts,name", content)
            self.assertIn("test", content)


class TestBuildArtifactCsvAttachment(unittest.TestCase):
    """Tests for data_prep.build_artifact_csv_attachment."""

    def test_basic(self) -> None:
        from app.analyzer.data_prep import build_artifact_csv_attachment
        csv_path = Path("/path/to/file.csv")
        result = build_artifact_csv_attachment("runkeys", csv_path)
        self.assertEqual(result["path"], str(csv_path))
        self.assertEqual(result["mime_type"], "text/csv")
        self.assertIn("runkeys", result["name"])


class TestResolveAnalysisInstructions(unittest.TestCase):
    """Tests for data_prep._resolve_analysis_instructions."""

    def test_instruction_from_prompts(self) -> None:
        from app.analyzer.data_prep import _resolve_analysis_instructions
        result = _resolve_analysis_instructions(
            artifact_key="evtx_Security",
            artifact_metadata={},
            artifact_instruction_prompts={"evtx": "EVTX INSTRUCTIONS"},
        )
        self.assertEqual(result, "EVTX INSTRUCTIONS")

    def test_instruction_from_metadata(self) -> None:
        from app.analyzer.data_prep import _resolve_analysis_instructions
        result = _resolve_analysis_instructions(
            artifact_key="custom",
            artifact_metadata={"analysis_instructions": "Custom guidance"},
            artifact_instruction_prompts={},
        )
        self.assertEqual(result, "Custom guidance")

    def test_default_message(self) -> None:
        from app.analyzer.data_prep import _resolve_analysis_instructions
        result = _resolve_analysis_instructions(
            artifact_key="custom",
            artifact_metadata={},
            artifact_instruction_prompts={},
        )
        self.assertIn("No specific analysis instructions", result)

    def test_dotted_key_matches_underscore_prompt(self) -> None:
        """ssh.authorized_keys should match prompt keyed as ssh_authorized_keys."""
        from app.analyzer.data_prep import _resolve_analysis_instructions
        result = _resolve_analysis_instructions(
            artifact_key="ssh.authorized_keys",
            artifact_metadata={},
            artifact_instruction_prompts={"ssh_authorized_keys": "SSH KEY GUIDE"},
        )
        self.assertEqual(result, "SSH KEY GUIDE")

    def test_underscore_key_matches_dotted_prompt(self) -> None:
        """network_interfaces should match prompt keyed as network.interfaces."""
        from app.analyzer.data_prep import _resolve_analysis_instructions
        result = _resolve_analysis_instructions(
            artifact_key="network_interfaces",
            artifact_metadata={},
            artifact_instruction_prompts={"network.interfaces": "NETWORK GUIDE"},
        )
        self.assertEqual(result, "NETWORK GUIDE")


###############################################################################
# constants.py — UnavailableProvider tests
###############################################################################


class TestUnavailableProvider(unittest.TestCase):
    """Tests for constants.UnavailableProvider."""

    def test_analyze_raises(self) -> None:
        from app.analyzer.constants import UnavailableProvider
        provider = UnavailableProvider("Test error")
        with self.assertRaises(AIProviderError):
            provider.analyze("sys", "user")

    def test_get_model_info(self) -> None:
        from app.analyzer.constants import UnavailableProvider
        provider = UnavailableProvider("err")
        info = provider.get_model_info()
        self.assertEqual(info["provider"], "unavailable")
        self.assertEqual(info["model"], "unavailable")


###############################################################################
# core.py — ForensicAnalyzer method tests
###############################################################################


class TestCallAiWithRetry(unittest.TestCase):
    """Tests for ForensicAnalyzer._call_ai_with_retry."""

    def test_success_on_first_try(self) -> None:
        fake_provider = FakeProvider(responses=["ok"])
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        result = analyzer._call_ai_with_retry(lambda: "success")
        self.assertEqual(result, "success")

    def test_raises_ai_provider_error_immediately(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        with self.assertRaises(AIProviderError):
            analyzer._call_ai_with_retry(lambda: (_ for _ in ()).throw(AIProviderError("permanent")))

    @patch("app.analyzer.core.sleep")
    def test_retries_on_transient_error(self, mock_sleep) -> None:
        call_count = 0
        def flaky():
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise RuntimeError("transient")
            return "success"
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        result = analyzer._call_ai_with_retry(flaky)
        self.assertEqual(result, "success")
        self.assertEqual(call_count, 3)

    @patch("app.analyzer.core.sleep")
    def test_raises_last_error_after_all_retries(self, mock_sleep) -> None:
        def always_fail():
            raise RuntimeError("fail")
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        with self.assertRaises(RuntimeError):
            analyzer._call_ai_with_retry(always_fail)


class TestAuditLog(unittest.TestCase):
    """Tests for ForensicAnalyzer._audit_log."""

    def test_logs_with_audit_logger(self) -> None:
        audit = FakeAuditLogger()
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer(audit_logger=audit)
        analyzer._audit_log("test_action", {"key": "value"})
        self.assertEqual(len(audit.entries), 1)
        self.assertEqual(audit.entries[0][0], "test_action")

    def test_no_audit_logger_does_not_raise(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        # Should not raise
        analyzer._audit_log("test_action", {"key": "value"})

    def test_broken_audit_logger_does_not_raise(self) -> None:
        class BrokenLogger:
            def log(self, action, details):
                raise RuntimeError("broken")
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer(audit_logger=BrokenLogger())
        # Should not raise
        analyzer._audit_log("test_action", {"key": "value"})


class TestSaveCasePrompt(unittest.TestCase):
    """Tests for ForensicAnalyzer._save_case_prompt."""

    def test_saves_prompt_file(self) -> None:
        with TemporaryDirectory(prefix="aift-save-") as tmp_dir:
            fake_provider = FakeProvider()
            with patch("app.analyzer.core.create_provider", return_value=fake_provider):
                analyzer = ForensicAnalyzer(case_dir=tmp_dir)
            analyzer._save_case_prompt("test.md", "system", "user")
            prompt_path = Path(tmp_dir) / "prompts" / "test.md"
            self.assertTrue(prompt_path.exists())
            content = prompt_path.read_text(encoding="utf-8")
            self.assertIn("system", content)
            self.assertIn("user", content)

    def test_no_case_dir_does_not_raise(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        # Should not raise
        analyzer._save_case_prompt("test.md", "sys", "usr")


class TestResolveArtifactCsvPath(unittest.TestCase):
    """Tests for ForensicAnalyzer._resolve_artifact_csv_path."""

    def test_mapped_path(self) -> None:
        with TemporaryDirectory(prefix="aift-path-") as tmp_dir:
            csv_path = Path(tmp_dir) / "art.csv"
            csv_path.write_text("ts,name\n", encoding="utf-8")
            analyzer = ForensicAnalyzer(artifact_csv_paths={"art": csv_path})
            result = analyzer._resolve_artifact_csv_path("art")
            self.assertEqual(result, csv_path)

    def test_raises_on_missing(self) -> None:
        analyzer = ForensicAnalyzer()
        with self.assertRaises(FileNotFoundError):
            analyzer._resolve_artifact_csv_path("nonexistent_artifact")

    def test_case_dir_parsed_lookup(self) -> None:
        with TemporaryDirectory(prefix="aift-path-") as tmp_dir:
            parsed_dir = Path(tmp_dir) / "parsed"
            parsed_dir.mkdir()
            csv_path = parsed_dir / "runkeys.csv"
            csv_path.write_text("ts,name\n", encoding="utf-8")
            fake_provider = FakeProvider()
            with patch("app.analyzer.core.create_provider", return_value=fake_provider):
                analyzer = ForensicAnalyzer(case_dir=tmp_dir)
            result = analyzer._resolve_artifact_csv_path("runkeys")
            self.assertEqual(result, csv_path)


class TestRegisterArtifactPathsFromMetadata(unittest.TestCase):
    """Tests for ForensicAnalyzer._register_artifact_paths_from_metadata."""

    def test_registers_from_artifact_csv_paths(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        analyzer._register_artifact_paths_from_metadata({
            "artifact_csv_paths": {"art1": "/path/to/art1.csv"},
        })
        self.assertIn("art1", analyzer.artifact_csv_paths)

    def test_registers_from_artifacts_container(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        analyzer._register_artifact_paths_from_metadata({
            "artifacts": {"art1": {"csv_path": "/path/art1.csv"}},
        })
        self.assertIn("art1", analyzer.artifact_csv_paths)

    def test_none_metadata_does_not_raise(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        analyzer._register_artifact_paths_from_metadata(None)

    def test_registers_from_list_container(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        analyzer._register_artifact_paths_from_metadata({
            "artifacts": [{"artifact_key": "art1", "csv_path": "/path.csv"}],
        })
        self.assertIn("art1", analyzer.artifact_csv_paths)


class TestRegisterArtifactPathEntry(unittest.TestCase):
    """Tests for ForensicAnalyzer._register_artifact_path_entry."""

    def test_mapping_with_csv_path(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        analyzer._register_artifact_path_entry("art1", {"csv_path": "/path.csv"})
        self.assertEqual(analyzer.artifact_csv_paths["art1"], Path("/path.csv"))

    def test_mapping_with_csv_paths_list(self) -> None:
        """Split artifacts with multiple csv_paths preserve all paths."""
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        analyzer._register_artifact_path_entry("art1", {"csv_paths": ["/first.csv", "/second.csv"]})
        self.assertEqual(analyzer.artifact_csv_paths["art1"], [Path("/first.csv"), Path("/second.csv")])

    def test_string_value(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        analyzer._register_artifact_path_entry("art1", "/path.csv")
        self.assertEqual(analyzer.artifact_csv_paths["art1"], Path("/path.csv"))

    def test_empty_key_ignored(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        analyzer._register_artifact_path_entry("", "/path.csv")
        self.assertEqual(len(analyzer.artifact_csv_paths), 0)

    def test_none_key_ignored(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        analyzer._register_artifact_path_entry(None, "/path.csv")
        self.assertEqual(len(analyzer.artifact_csv_paths), 0)

    def test_single_csv_paths_list_collapses(self) -> None:
        """A csv_paths list with one entry should collapse to a single Path."""
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        analyzer._register_artifact_path_entry("art1", {"csv_paths": ["/only.csv"]})
        self.assertEqual(analyzer.artifact_csv_paths["art1"], Path("/only.csv"))


class TestSplitArtifactCsvHandling(unittest.TestCase):
    """Tests for multi-CSV (split artifact) handling in the analyzer."""

    def test_init_accepts_list_of_paths(self) -> None:
        """ForensicAnalyzer.__init__ stores list[Path] for multi-path artifacts."""
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer(
                artifact_csv_paths={"evtx": ["/a.csv", "/b.csv"]},
            )
        self.assertIsInstance(analyzer.artifact_csv_paths["evtx"], list)
        self.assertEqual(len(analyzer.artifact_csv_paths["evtx"]), 2)

    def test_init_single_path_stays_path(self) -> None:
        """Single-file artifacts remain a plain Path after init."""
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer(
                artifact_csv_paths={"runkeys": "/runkeys.csv"},
            )
        self.assertIsInstance(analyzer.artifact_csv_paths["runkeys"], Path)

    def test_resolve_artifact_csv_path_returns_first_for_list(self) -> None:
        """_resolve_artifact_csv_path returns the first path for split artifacts."""
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer(
                artifact_csv_paths={"evtx": ["/first.csv", "/second.csv"]},
            )
        result = analyzer._resolve_artifact_csv_path("evtx")
        self.assertEqual(result, Path("/first.csv"))

    def test_resolve_all_artifact_csv_paths_returns_full_list(self) -> None:
        """_resolve_all_artifact_csv_paths returns all paths for split artifacts."""
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer(
                artifact_csv_paths={"evtx": ["/a.csv", "/b.csv", "/c.csv"]},
            )
        result = analyzer._resolve_all_artifact_csv_paths("evtx")
        self.assertEqual(len(result), 3)
        self.assertEqual(result[0], Path("/a.csv"))
        self.assertEqual(result[2], Path("/c.csv"))

    def test_resolve_all_artifact_csv_paths_single_file(self) -> None:
        """_resolve_all_artifact_csv_paths wraps single Path in a list."""
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer(
                artifact_csv_paths={"runkeys": "/runkeys.csv"},
            )
        result = analyzer._resolve_all_artifact_csv_paths("runkeys")
        self.assertEqual(result, [Path("/runkeys.csv")])

    def test_resolve_all_artifact_csv_paths_fallback_split(self) -> None:
        """_resolve_all_artifact_csv_paths discovers all split parts from case_dir/parsed."""
        with TemporaryDirectory(prefix="aift-split-") as tmp_dir:
            parsed_dir = Path(tmp_dir) / "parsed"
            parsed_dir.mkdir()
            csv1 = parsed_dir / "evtx_Security.csv"
            csv2 = parsed_dir / "evtx_System.csv"
            csv3 = parsed_dir / "evtx_Application.csv"
            for f in (csv1, csv2, csv3):
                f.write_text("ts,msg\n", encoding="utf-8")
            fake_provider = FakeProvider()
            with patch("app.analyzer.core.create_provider", return_value=fake_provider):
                analyzer = ForensicAnalyzer(case_dir=tmp_dir)
            result = analyzer._resolve_all_artifact_csv_paths("evtx")
            self.assertEqual(len(result), 3)
            # Ordering must be deterministic (sorted).
            self.assertEqual(result, sorted(result))
            # All parts must be present.
            basenames = {p.name for p in result}
            self.assertEqual(basenames, {"evtx_Application.csv", "evtx_Security.csv", "evtx_System.csv"})

    def test_resolve_all_artifact_csv_paths_fallback_ignores_generated_combined_csv(self) -> None:
        """Fallback split discovery must ignore generated *_combined.csv files."""
        with TemporaryDirectory(prefix="aift-split-") as tmp_dir:
            parsed_dir = Path(tmp_dir) / "parsed"
            parsed_dir.mkdir()
            csv1 = parsed_dir / "evtx_Security.csv"
            csv2 = parsed_dir / "evtx_System.csv"
            combined = parsed_dir / "evtx_combined.csv"
            for f in (csv1, csv2, combined):
                f.write_text("ts,msg\n", encoding="utf-8")
            fake_provider = FakeProvider()
            with patch("app.analyzer.core.create_provider", return_value=fake_provider):
                analyzer = ForensicAnalyzer(case_dir=tmp_dir)
            result = analyzer._resolve_all_artifact_csv_paths("evtx")
            self.assertEqual(len(result), 2)
            self.assertEqual({p.name for p in result}, {"evtx_Security.csv", "evtx_System.csv"})

    def test_resolve_all_artifact_csv_paths_fallback_single(self) -> None:
        """_resolve_all_artifact_csv_paths returns single CSV from case_dir/parsed."""
        with TemporaryDirectory(prefix="aift-single-") as tmp_dir:
            parsed_dir = Path(tmp_dir) / "parsed"
            parsed_dir.mkdir()
            csv_path = parsed_dir / "runkeys.csv"
            csv_path.write_text("ts,name\n", encoding="utf-8")
            fake_provider = FakeProvider()
            with patch("app.analyzer.core.create_provider", return_value=fake_provider):
                analyzer = ForensicAnalyzer(case_dir=tmp_dir)
            result = analyzer._resolve_all_artifact_csv_paths("runkeys")
            self.assertEqual(result, [csv_path])

    def test_combine_csv_files(self) -> None:
        """_combine_csv_files merges multiple CSVs into one with all rows."""
        with TemporaryDirectory() as tmpdir:
            csv1 = Path(tmpdir) / "evtx_Security.csv"
            csv2 = Path(tmpdir) / "evtx_System.csv"
            csv1.write_text("ts,msg\n2025-01-01,logon\n2025-01-02,logoff\n", encoding="utf-8")
            csv2.write_text("ts,msg\n2025-02-01,start\n", encoding="utf-8")

            fake_provider = FakeProvider()
            with patch("app.analyzer.core.create_provider", return_value=fake_provider):
                analyzer = ForensicAnalyzer(
                    artifact_csv_paths={"evtx": [str(csv1), str(csv2)]},
                )
            combined = analyzer._combine_csv_files("evtx", [csv1, csv2])
            self.assertTrue(combined.exists())
            lines = combined.read_text(encoding="utf-8").strip().splitlines()
            self.assertEqual(lines[0], "ts,msg")
            self.assertEqual(len(lines), 4)  # header + 3 data rows

    def test_combine_csv_files_superset_headers(self) -> None:
        """_combine_csv_files handles CSVs with different column sets."""
        with TemporaryDirectory() as tmpdir:
            csv1 = Path(tmpdir) / "evtx_a.csv"
            csv2 = Path(tmpdir) / "evtx_b.csv"
            csv1.write_text("ts,msg\n2025-01-01,logon\n", encoding="utf-8")
            csv2.write_text("ts,msg,extra\n2025-02-01,start,val\n", encoding="utf-8")

            fake_provider = FakeProvider()
            with patch("app.analyzer.core.create_provider", return_value=fake_provider):
                analyzer = ForensicAnalyzer()
            combined = analyzer._combine_csv_files("evtx", [csv1, csv2])
            lines = combined.read_text(encoding="utf-8").strip().splitlines()
            self.assertIn("extra", lines[0])
            self.assertEqual(len(lines), 3)  # header + 2 data rows

    def test_register_from_metadata_preserves_multi_paths(self) -> None:
        """_register_artifact_paths_from_metadata stores list for multi-path entries."""
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        analyzer._register_artifact_paths_from_metadata({
            "artifact_csv_paths": {"evtx": ["/a.csv", "/b.csv"]},
        })
        self.assertIsInstance(analyzer.artifact_csv_paths["evtx"], list)
        self.assertEqual(len(analyzer.artifact_csv_paths["evtx"]), 2)

    def test_analyze_artifact_uses_all_split_csvs(self) -> None:
        """analyze_artifact combines split CSVs before sending to the AI."""
        with TemporaryDirectory() as tmpdir:
            prompts_dir = Path(tmpdir) / "prompts"
            prompts_dir.mkdir()
            (prompts_dir / "artifact_analysis.md").write_text(
                "Key={{artifact_key}}\nData:\n{{data_csv}}\n", encoding="utf-8",
            )
            (prompts_dir / "artifact_analysis_small_context.md").write_text(
                "Key={{artifact_key}}\nData:\n{{data_csv}}\n", encoding="utf-8",
            )
            (prompts_dir / "system_prompt.md").write_text("SYS", encoding="utf-8")
            (prompts_dir / "summary_prompt.md").write_text("SUM", encoding="utf-8")

            csv1 = Path(tmpdir) / "evtx_Security.csv"
            csv2 = Path(tmpdir) / "evtx_System.csv"
            csv1.write_text("ts,msg\n2025-01-01,logon\n", encoding="utf-8")
            csv2.write_text("ts,msg\n2025-02-01,start\n", encoding="utf-8")

            fake_provider = FakeProvider(responses=["AI analysis of split artifact"])
            with patch("app.analyzer.core.create_provider", return_value=fake_provider):
                analyzer = ForensicAnalyzer(
                    case_dir=tmpdir,
                    artifact_csv_paths={"evtx": [str(csv1), str(csv2)]},
                    prompts_dir=prompts_dir,
                )
                analyzer.ai_provider = fake_provider
            result = analyzer.analyze_artifact("evtx", "test investigation")
            self.assertTrue(result.get("analysis"))
            self.assertNotIn("Analysis failed", result["analysis"])
            # Verify data from both CSVs was present in the prompt
            prompt_sent = fake_provider.calls[0]["user_prompt"]
            self.assertIn("2025-01-01", prompt_sent)
            self.assertIn("2025-02-01", prompt_sent)


class TestResolveArtifactMetadata(unittest.TestCase):
    """Tests for ForensicAnalyzer._resolve_artifact_metadata."""

    def test_unknown_key_returns_defaults(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        result = analyzer._resolve_artifact_metadata("completely_unknown_artifact_xyz")
        self.assertEqual(result["name"], "completely_unknown_artifact_xyz")
        self.assertIn("No artifact description", result["description"])

    def test_linux_os_type_resolves_services_to_linux_registry(self) -> None:
        """When os_type='linux', shared keys like 'services' resolve to the Linux entry."""
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer(os_type="linux")
        result = analyzer._resolve_artifact_metadata("services")
        # Linux registry describes systemd services; Windows describes Windows services.
        self.assertIn("Systemd", result.get("name", ""), "Expected Linux 'Systemd Services' entry")

    def test_windows_os_type_resolves_services_to_windows_registry(self) -> None:
        """When os_type='windows', shared keys like 'services' resolve to the Windows entry."""
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer(os_type="windows")
        result = analyzer._resolve_artifact_metadata("services")
        # Windows registry name is just "Services" (not "Systemd Services").
        self.assertNotIn("Systemd", result.get("name", ""))

    def test_linux_analyzer_resolves_linux_only_artifact(self) -> None:
        """Linux-only artifacts like bash_history resolve from the Linux registry."""
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer(os_type="linux")
        result = analyzer._resolve_artifact_metadata("bash_history")
        self.assertEqual(result["name"], "Bash History")

    def test_windows_analyzer_resolves_windows_only_artifact(self) -> None:
        """Windows-only artifacts like shimcache resolve from the Windows registry."""
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer(os_type="windows")
        result = analyzer._resolve_artifact_metadata("shimcache")
        self.assertEqual(result["name"], "Shimcache")


class TestReadModelInfo(unittest.TestCase):
    """Tests for ForensicAnalyzer._read_model_info."""

    def test_returns_provider_info(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        self.assertEqual(analyzer.model_info["provider"], "fake")
        self.assertEqual(analyzer.model_info["model"], "fake-model-1")

    def test_broken_provider_returns_unknown(self) -> None:
        class BrokenProvider:
            def get_model_info(self):
                raise RuntimeError("broken")
            def analyze(self, **kwargs):
                return "ok"
        with patch("app.analyzer.core.create_provider", return_value=BrokenProvider()):
            analyzer = ForensicAnalyzer()
        self.assertEqual(analyzer.model_info["provider"], "unknown")

    def test_non_mapping_returns_unknown(self) -> None:
        class WeirdProvider:
            def get_model_info(self):
                return "not a dict"
            def analyze(self, **kwargs):
                return "ok"
        with patch("app.analyzer.core.create_provider", return_value=WeirdProvider()):
            analyzer = ForensicAnalyzer()
        self.assertEqual(analyzer.model_info["provider"], "unknown")


class TestSetAndResolveAnalysisInputCsvPath(unittest.TestCase):
    """Tests for _set_analysis_input_csv_path and _resolve_analysis_input_csv_path."""

    def test_set_and_resolve(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        path = Path("/some/path.csv")
        analyzer._set_analysis_input_csv_path("runkeys", path)
        result = analyzer._resolve_analysis_input_csv_path("runkeys", Path("/fallback.csv"))
        self.assertEqual(result, path)

    def test_fallback_when_not_set(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        fallback = Path("/fallback.csv")
        result = analyzer._resolve_analysis_input_csv_path("unknown_key", fallback)
        self.assertEqual(result, fallback)


class TestGenerateSummaryFailure(unittest.TestCase):
    """Tests for ForensicAnalyzer.generate_summary error handling."""

    def test_returns_failure_message_on_error(self) -> None:
        fake_provider = FakeProvider(fail_calls={0, 1, 2})
        with patch("app.analyzer.core.create_provider", return_value=fake_provider), \
             patch("app.analyzer.core.sleep"):
            with TemporaryDirectory(prefix="aift-sum-") as tmp_dir:
                prompts_dir = Path(tmp_dir) / "prompts"
                prompts_dir.mkdir()
                (prompts_dir / "summary_prompt.md").write_text("{{per_artifact_findings}}", encoding="utf-8")
                (prompts_dir / "system_prompt.md").write_text("sys", encoding="utf-8")
                analyzer = ForensicAnalyzer(
                    case_dir=tmp_dir,
                    audit_logger=FakeAuditLogger(),
                    prompts_dir=prompts_dir,
                )
                result = analyzer.generate_summary([], "ctx", {})
        self.assertTrue(result.startswith("Analysis failed:"))


class TestCreateAiProvider(unittest.TestCase):
    """Tests for ForensicAnalyzer._create_ai_provider."""

    def test_fallback_to_unavailable_provider(self) -> None:
        from app.analyzer.constants import UnavailableProvider
        with patch("app.analyzer.core.create_provider", side_effect=RuntimeError("cannot create")):
            analyzer = ForensicAnalyzer()
        self.assertIsInstance(analyzer.ai_provider, UnavailableProvider)

    def test_default_config_when_no_config(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider) as mock_create:
            analyzer = ForensicAnalyzer()
        # Should have been called with the default local config
        call_args = mock_create.call_args[0][0]
        self.assertIn("ai", call_args)


class TestLoadAnalysisSettings(unittest.TestCase):
    """Tests for ForensicAnalyzer._load_analysis_settings."""

    def test_default_settings(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer()
        self.assertEqual(analyzer.ai_max_tokens, 128000)
        self.assertTrue(analyzer.artifact_deduplication_enabled)

    def test_custom_settings(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer(config={
                "analysis": {
                    "ai_max_tokens": 50000,
                    "artifact_deduplication_enabled": False,
                }
            })
        self.assertEqual(analyzer.ai_max_tokens, 50000)
        self.assertFalse(analyzer.artifact_deduplication_enabled)

    def test_non_mapping_analysis_config(self) -> None:
        fake_provider = FakeProvider()
        with patch("app.analyzer.core.create_provider", return_value=fake_provider):
            analyzer = ForensicAnalyzer(config={"analysis": "not a dict"})
        # Should use defaults without error
        self.assertEqual(analyzer.ai_max_tokens, 128000)


class TestInitConvenienceShorthand(unittest.TestCase):
    """Tests for ForensicAnalyzer init with mapping as case_dir (convenience shorthand)."""

    def test_mapping_as_case_dir(self) -> None:
        with TemporaryDirectory(prefix="aift-init-") as tmp_dir:
            csv_path = Path(tmp_dir) / "art.csv"
            csv_path.write_text("ts,name\n", encoding="utf-8")
            analyzer = ForensicAnalyzer({"art": csv_path})
        self.assertIsNone(analyzer.case_dir)
        self.assertIn("art", analyzer.artifact_csv_paths)


class TestUnavailableProviderFailsAnalysis(unittest.TestCase):
    """Regression: run_full_analysis must fail immediately with UnavailableProvider."""

    def test_run_full_analysis_raises_on_unavailable_provider(self) -> None:
        """If provider init failed, run_full_analysis must raise AIProviderError."""
        with patch("app.analyzer.core.create_provider", side_effect=RuntimeError("bad key")):
            analyzer = ForensicAnalyzer()

        with self.assertRaises(AIProviderError) as ctx:
            analyzer.run_full_analysis(
                artifact_keys=["runkeys"],
                investigation_context="test",
                metadata=None,
            )
        self.assertIn("bad key", str(ctx.exception))

    def test_run_full_analysis_succeeds_with_valid_provider(self) -> None:
        """Normal providers must not be blocked by the UnavailableProvider guard."""
        fake_provider = FakeProvider(responses=["finding", "summary"])
        with TemporaryDirectory(prefix="aift-ok-") as tmp_dir:
            csv_path = Path(tmp_dir) / "runkeys.csv"
            csv_path.write_text("ts,name\n2024-01-01,test\n", encoding="utf-8")
            with patch("app.analyzer.core.create_provider", return_value=fake_provider):
                analyzer = ForensicAnalyzer(
                    case_dir=tmp_dir,
                    config={"analysis": {"ai_max_tokens": 4096}},
                    artifact_csv_paths={"runkeys": csv_path},
                )
            result = analyzer.run_full_analysis(
                artifact_keys=["runkeys"],
                investigation_context="test context",
                metadata=None,
            )
        self.assertIn("per_artifact", result)
        self.assertIn("summary", result)


class DeduplicationDoesNotShrinkNonDuplicateRowsTest(unittest.TestCase):
    """Verify that deduplication only removes actual duplicates, not unique rows."""

    def test_dedup_preserves_all_unique_rows(self) -> None:
        """Deduplication must not reduce row count when all rows are unique."""
        from app.analyzer.data_prep import deduplicate_rows_for_analysis

        columns = ["ts", "name", "command", "key"]
        rows = [
            {"ts": "2026-01-15T08:00:00", "name": "EntryA", "command": "cmd_a.exe", "key": "HKCU\\Run"},
            {"ts": "2026-01-16T09:00:00", "name": "EntryB", "command": "cmd_b.exe", "key": "HKCU\\Run"},
            {"ts": "2026-01-17T10:00:00", "name": "EntryC", "command": "cmd_c.exe", "key": "HKLM\\Run"},
            {"ts": "2026-01-18T11:00:00", "name": "EntryD", "command": "cmd_d.exe", "key": "HKLM\\Run"},
            {"ts": "2026-01-19T12:00:00", "name": "EntryE", "command": "cmd_e.exe", "key": "HKCU\\Run"},
        ]

        kept_rows, _, removed_count, _, _ = deduplicate_rows_for_analysis(
            rows=rows, columns=columns,
        )
        self.assertEqual(len(kept_rows), len(rows))
        self.assertEqual(removed_count, 0)

    def test_dedup_only_removes_actual_duplicates(self) -> None:
        """Deduplication must only remove rows that are true duplicates (differ only in timestamp/ID)."""
        from app.analyzer.data_prep import deduplicate_rows_for_analysis

        columns = ["ts", "name", "command", "key"]
        rows = [
            {"ts": "2026-01-15T08:00:00", "name": "EntryA", "command": "cmd_a.exe", "key": "HKCU\\Run"},
            {"ts": "2026-01-16T09:00:00", "name": "EntryA", "command": "cmd_a.exe", "key": "HKCU\\Run"},
            {"ts": "2026-01-17T10:00:00", "name": "EntryB", "command": "cmd_b.exe", "key": "HKLM\\Run"},
            {"ts": "2026-01-18T11:00:00", "name": "EntryC", "command": "cmd_c.exe", "key": "HKLM\\Run"},
        ]

        kept_rows, _, removed_count, _, _ = deduplicate_rows_for_analysis(
            rows=rows, columns=columns,
        )
        # Only the duplicate of EntryA should be removed.
        self.assertEqual(len(kept_rows), 3)
        self.assertEqual(removed_count, 1)
        kept_names = [r["name"] for r in kept_rows]
        self.assertIn("EntryA", kept_names)
        self.assertIn("EntryB", kept_names)
        self.assertIn("EntryC", kept_names)

    def test_dedup_with_no_timestamp_columns_returns_all_rows(self) -> None:
        """When there are no timestamp/ID variant columns, all rows must be preserved."""
        from app.analyzer.data_prep import deduplicate_rows_for_analysis

        columns = ["name", "command", "key"]
        rows = [
            {"name": "EntryA", "command": "cmd_a.exe", "key": "HKCU\\Run"},
            {"name": "EntryB", "command": "cmd_b.exe", "key": "HKLM\\Run"},
            {"name": "EntryC", "command": "cmd_c.exe", "key": "HKCU\\Run"},
        ]

        kept_rows, _, removed_count, _, _ = deduplicate_rows_for_analysis(
            rows=rows, columns=columns,
        )
        self.assertEqual(len(kept_rows), len(rows))
        self.assertEqual(removed_count, 0)

    def test_dedup_with_large_dataset_preserves_unique_row_count(self) -> None:
        """Deduplication on a larger dataset must preserve the unique row count exactly."""
        from app.analyzer.data_prep import deduplicate_rows_for_analysis

        columns = ["ts", "source", "event_id", "message"]
        unique_rows = [
            {"ts": f"2026-01-{d:02d}T{h:02d}:00:00", "source": f"Src{i}", "event_id": str(1000 + i), "message": f"Event message {i}"}
            for i, (d, h) in enumerate(((day, hour) for day in range(1, 11) for hour in range(0, 24, 6)), start=1)
        ]
        # Add duplicates that differ only in timestamp.
        duplicates = [
            {"ts": "2026-02-01T00:00:00", "source": row["source"], "event_id": row["event_id"], "message": row["message"]}
            for row in unique_rows[:10]
        ]
        all_rows = unique_rows + duplicates
        original_unique_count = len(unique_rows)

        kept_rows, _, removed_count, _, _ = deduplicate_rows_for_analysis(
            rows=all_rows, columns=columns,
        )
        self.assertEqual(removed_count, len(duplicates))
        self.assertEqual(len(kept_rows), original_unique_count)


if __name__ == "__main__":
    unittest.main()
