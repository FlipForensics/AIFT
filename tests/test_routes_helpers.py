"""Tests for route helper functions (state, evidence, artifacts, tasks).

Covers StateHelperTests, EvidenceHelperTests, ArtifactHelperTests,
and TaskHelperTests extracted from the main test_routes module.
"""
from __future__ import annotations

import json
import logging
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import time
import unittest
from unittest.mock import MagicMock, patch
from zipfile import ZipFile

import yaml

from app import create_app
from app.case_logging import unregister_all_case_log_handlers
import app.routes as routes
import app.routes.artifacts as routes_artifacts
import app.routes.analysis as routes_analysis
import app.routes.chat as routes_chat
import app.routes.evidence as routes_evidence
import app.routes.handlers as routes_handlers
import app.routes.images as routes_images
import app.routes.tasks as routes_tasks
import app.routes.tasks_chat as routes_tasks_chat
import app.routes.state as routes_state

from tests.conftest import (
    ImmediateThread,
    FakeParser as _BaseFakeParser,
    FakeAnalyzer,
    FakeReportGenerator,
)

class StateHelperTests(unittest.TestCase):
    """Tests for helper functions in app.routes.state."""

    def test_project_root_points_to_repo_root(self) -> None:
        """PROJECT_ROOT must resolve to the repository root, not app/."""
        self.assertTrue(
            (routes_state.PROJECT_ROOT / "app").is_dir(),
            "PROJECT_ROOT should contain the 'app' package directory",
        )
        self.assertTrue(
            (routes_state.PROJECT_ROOT / "app" / "routes" / "state.py").is_file(),
            "PROJECT_ROOT should be two levels above state.py",
        )
        self.assertNotEqual(
            routes_state.PROJECT_ROOT.name,
            "app",
            "PROJECT_ROOT must not point inside 'app/'",
        )

    def test_cases_root_under_project_root(self) -> None:
        """CASES_ROOT must be PROJECT_ROOT / 'cases'."""
        self.assertEqual(
            routes_state.CASES_ROOT,
            routes_state.PROJECT_ROOT / "cases",
        )

    def test_images_root_under_project_root(self) -> None:
        """IMAGES_ROOT must be PROJECT_ROOT / 'images'."""
        self.assertEqual(
            routes_state.IMAGES_ROOT,
            routes_state.PROJECT_ROOT / "images",
        )

    def test_now_iso_format(self) -> None:
        result = routes_state.now_iso()
        self.assertTrue(result.endswith("Z"))
        self.assertIn("T", result)

    def test_safe_name_replaces_special_chars(self) -> None:
        self.assertEqual(routes_state.safe_name("hello world!"), "hello_world")
        self.assertEqual(routes_state.safe_name("normal"), "normal")
        self.assertEqual(routes_state.safe_name(""), "item")
        self.assertEqual(routes_state.safe_name("!!!"), "item")
        self.assertEqual(routes_state.safe_name("   ", fallback="default"), "default")

    def test_safe_int_converts_values(self) -> None:
        self.assertEqual(routes_state.safe_int("42"), 42)
        self.assertEqual(routes_state.safe_int(3.7), 3)
        self.assertEqual(routes_state.safe_int("bad"), 0)
        self.assertEqual(routes_state.safe_int(None), 0)
        self.assertEqual(routes_state.safe_int("bad", default=99), 99)

    def test_normalize_case_status(self) -> None:
        self.assertEqual(routes_state.normalize_case_status("Running"), "running")
        self.assertEqual(routes_state.normalize_case_status("  Completed  "), "completed")
        self.assertEqual(routes_state.normalize_case_status(None), "")
        self.assertEqual(routes_state.normalize_case_status(""), "")

    def test_new_progress_default_status(self) -> None:
        prog = routes_state.new_progress()
        self.assertEqual(prog["status"], "idle")
        self.assertEqual(prog["events"], [])
        self.assertIsNone(prog["error"])
        self.assertIn("created_at", prog)

    def test_new_progress_custom_status(self) -> None:
        prog = routes_state.new_progress(status="running")
        self.assertEqual(prog["status"], "running")

    def test_set_progress_status(self) -> None:
        store: dict[str, dict] = {}
        routes_state.set_progress_status(store, "case1", "running")
        self.assertEqual(store["case1"]["status"], "running")
        self.assertIsNone(store["case1"]["error"])
        routes_state.set_progress_status(store, "case1", "failed", "Something broke")
        self.assertEqual(store["case1"]["status"], "failed")
        self.assertEqual(store["case1"]["error"], "Something broke")

    def test_emit_progress_appends_events(self) -> None:
        store: dict[str, dict] = {}
        routes_state.emit_progress(store, "case1", {"type": "started"})
        routes_state.emit_progress(store, "case1", {"type": "progress"})
        self.assertEqual(len(store["case1"]["events"]), 2)
        self.assertEqual(store["case1"]["events"][0]["sequence"], 0)
        self.assertEqual(store["case1"]["events"][1]["sequence"], 1)
        self.assertIn("timestamp", store["case1"]["events"][0])

    def test_get_case_returns_none_for_missing(self) -> None:
        routes_state.CASE_STATES.clear()
        self.assertIsNone(routes_state.get_case("nonexistent"))

    def test_get_case_returns_state(self) -> None:
        routes_state.CASE_STATES.clear()
        routes_state.CASE_STATES["test-id"] = {"status": "active"}
        result = routes_state.get_case("test-id")
        self.assertEqual(result["status"], "active")
        routes_state.CASE_STATES.clear()

    def test_mark_case_status(self) -> None:
        routes_state.CASE_STATES.clear()
        routes_state.CASE_STATES["test-id"] = {"status": "active"}
        routes_state.mark_case_status("test-id", "Completed")
        self.assertEqual(routes_state.CASE_STATES["test-id"]["status"], "completed")
        # No-op for missing case
        routes_state.mark_case_status("missing", "completed")
        routes_state.CASE_STATES.clear()

    def test_cleanup_case_entries(self) -> None:
        routes_state.CASE_STATES["test-id"] = {"status": "active"}
        routes_state.PARSE_PROGRESS["test-id"] = routes_state.new_progress()
        routes_state.ANALYSIS_PROGRESS["test-id"] = routes_state.new_progress()
        routes_state.CHAT_PROGRESS["test-id"] = routes_state.new_progress()
        routes_state.cleanup_case_entries("test-id")
        self.assertNotIn("test-id", routes_state.CASE_STATES)
        self.assertNotIn("test-id", routes_state.PARSE_PROGRESS)
        self.assertNotIn("test-id", routes_state.ANALYSIS_PROGRESS)
        self.assertNotIn("test-id", routes_state.CHAT_PROGRESS)

    def test_mask_sensitive_masks_keys(self) -> None:
        data = {
            "name": "test",
            "api_key": "secret123",
            "nested": {"password": "pass123", "model": "gpt-4"},
            "list_data": [{"token": "tok123"}],
        }
        masked = routes_state.mask_sensitive(data)
        self.assertEqual(masked["name"], "test")
        self.assertEqual(masked["api_key"], "********")
        self.assertEqual(masked["nested"]["password"], "********")
        self.assertEqual(masked["nested"]["model"], "gpt-4")
        self.assertEqual(masked["list_data"][0]["token"], "********")

    def test_mask_sensitive_empty_sensitive_value(self) -> None:
        data = {"api_key": "real-key", "token": "", "password": "  "}
        masked = routes_state.mask_sensitive(data)
        self.assertEqual(masked["api_key"], "********")
        # Empty string stays empty
        self.assertEqual(masked["token"], "")
        # Whitespace-only string is treated as empty
        self.assertEqual(masked["password"], "")

    def test_mask_sensitive_scalar_passthrough(self) -> None:
        self.assertEqual(routes_state.mask_sensitive(42), 42)
        self.assertEqual(routes_state.mask_sensitive("hello"), "hello")

    def test_deep_merge_updates_values(self) -> None:
        current = {"a": 1, "b": {"c": 2, "d": 3}}
        updates = {"a": 10, "b": {"c": 20}}
        changed = routes_state.deep_merge(current, updates)
        self.assertEqual(current["a"], 10)
        self.assertEqual(current["b"]["c"], 20)
        self.assertEqual(current["b"]["d"], 3)
        self.assertIn("a", changed)
        self.assertIn("b.c", changed)

    def test_deep_merge_skips_masked_sensitive(self) -> None:
        current = {"api_key": "real-secret"}
        updates = {"api_key": "********"}
        changed = routes_state.deep_merge(current, updates)
        self.assertEqual(current["api_key"], "real-secret")
        self.assertEqual(changed, [])

    def test_deep_merge_skips_non_string_keys(self) -> None:
        current = {"a": 1}
        updates = {123: "value", "b": 2}
        changed = routes_state.deep_merge(current, updates)
        self.assertIn("b", changed)
        self.assertNotIn(123, current)

    def test_sanitize_changed_keys(self) -> None:
        keys = ["server.port", "ai.openai.api_key", "", "  ", "server.port"]
        result = routes_state.sanitize_changed_keys(keys)
        self.assertIn("server.port", result)
        self.assertIn("ai.openai.api_key (redacted)", result)
        # Deduplication
        self.assertEqual(result.count("server.port"), 1)
        # Empty strings removed
        self.assertTrue(all(r.strip() for r in result))

    def test_sanitize_changed_keys_non_string(self) -> None:
        keys = [42, None, "valid.key"]
        result = routes_state.sanitize_changed_keys(keys)
        self.assertEqual(result, ["valid.key"])

    def test_cleanup_terminal_cases_excludes_specified(self) -> None:
        """Excluded case survives cleanup even when TTL-expired."""
        routes_state.CASE_STATES.clear()
        routes_state.PARSE_PROGRESS.clear()
        routes_state.ANALYSIS_PROGRESS.clear()
        routes_state.CHAT_PROGRESS.clear()
        expired_time = time.monotonic() - routes_state.CASE_TTL_SECONDS - 1
        routes_state.CASE_STATES["keep-me"] = {
            "status": "completed", "_terminal_since": expired_time,
        }
        routes_state.CASE_STATES["remove-me"] = {
            "status": "completed", "_terminal_since": expired_time,
        }
        routes_state.cleanup_terminal_cases(exclude_case_id="keep-me")
        self.assertIn("keep-me", routes_state.CASE_STATES)
        self.assertNotIn("remove-me", routes_state.CASE_STATES)
        routes_state.CASE_STATES.clear()

    def test_cleanup_terminal_cases_preserves_recent(self) -> None:
        """Recently-completed cases survive cleanup."""
        routes_state.CASE_STATES.clear()
        routes_state.PARSE_PROGRESS.clear()
        routes_state.ANALYSIS_PROGRESS.clear()
        routes_state.CHAT_PROGRESS.clear()
        routes_state.CASE_STATES["recent"] = {
            "status": "completed", "_terminal_since": time.monotonic(),
        }
        routes_state.cleanup_terminal_cases()
        self.assertIn("recent", routes_state.CASE_STATES)
        routes_state.CASE_STATES.clear()

    def test_mark_case_status_sets_terminal_since(self) -> None:
        """Transitioning to terminal status records _terminal_since."""
        routes_state.CASE_STATES["ts-test"] = {"status": "active"}
        before = time.monotonic()
        routes_state.mark_case_status("ts-test", "completed")
        after = time.monotonic()
        terminal_since = routes_state.CASE_STATES["ts-test"]["_terminal_since"]
        self.assertGreaterEqual(terminal_since, before)
        self.assertLessEqual(terminal_since, after)
        # Second call should not overwrite
        routes_state.mark_case_status("ts-test", "completed")
        self.assertEqual(routes_state.CASE_STATES["ts-test"]["_terminal_since"], terminal_since)
        routes_state.CASE_STATES.clear()

    def test_cleanup_never_deletes_case_from_disk(self) -> None:
        """Cleanup only removes in-memory state, never disk data."""
        with TemporaryDirectory(prefix="aift-cleanup-disk-") as tmpdir:
            case_dir = Path(tmpdir) / "cases" / "disk-test"
            case_dir.mkdir(parents=True)
            (case_dir / "audit.jsonl").write_text("{}\n", encoding="utf-8")
            (case_dir / "parsed").mkdir()
            (case_dir / "parsed" / "runkeys.csv").write_text("col\nval\n", encoding="utf-8")

            expired_time = time.monotonic() - routes_state.CASE_TTL_SECONDS - 1
            routes_state.CASE_STATES.clear()
            routes_state.PARSE_PROGRESS.clear()
            routes_state.ANALYSIS_PROGRESS.clear()
            routes_state.CHAT_PROGRESS.clear()
            routes_state.CASE_STATES["disk-test"] = {
                "status": "completed",
                "case_dir": str(case_dir),
                "_terminal_since": expired_time,
            }
            routes_state.PARSE_PROGRESS["disk-test"] = routes_state.new_progress(status="completed")

            routes_state.cleanup_terminal_cases()

            # Memory evicted
            self.assertNotIn("disk-test", routes_state.CASE_STATES)
            # Disk intact
            self.assertTrue(case_dir.exists())
            self.assertTrue((case_dir / "audit.jsonl").exists())
            self.assertTrue((case_dir / "parsed" / "runkeys.csv").exists())
            routes_state.CASE_STATES.clear()

    def test_cleanup_case_entries_never_deletes_disk(self) -> None:
        """Explicit cleanup_case_entries only removes in-memory state."""
        with TemporaryDirectory(prefix="aift-entry-disk-") as tmpdir:
            case_dir = Path(tmpdir) / "cases" / "entry-disk-test"
            case_dir.mkdir(parents=True)
            (case_dir / "audit.jsonl").write_text("{}\n", encoding="utf-8")
            (case_dir / "reports").mkdir()
            (case_dir / "reports" / "report.html").write_text("<html/>", encoding="utf-8")

            routes_state.CASE_STATES["entry-disk-test"] = {
                "status": "completed",
                "case_dir": str(case_dir),
            }
            routes_state.PARSE_PROGRESS["entry-disk-test"] = routes_state.new_progress()
            routes_state.ANALYSIS_PROGRESS["entry-disk-test"] = routes_state.new_progress()
            routes_state.CHAT_PROGRESS["entry-disk-test"] = routes_state.new_progress()

            routes_state.cleanup_case_entries("entry-disk-test")

            self.assertNotIn("entry-disk-test", routes_state.CASE_STATES)
            self.assertTrue(case_dir.exists())
            self.assertTrue((case_dir / "reports" / "report.html").exists())


    def test_cleanup_progress_store_marks_drained_not_removed(self) -> None:
        """_cleanup_progress_store marks terminal entries as drained, not removed."""
        store: dict[str, dict] = {
            "case1": routes_state.new_progress(status="completed"),
        }
        routes_state._cleanup_progress_store(store, "case1")
        self.assertIn("case1", store, "Terminal entry should still be in store")
        self.assertTrue(store["case1"].get("_drained"))

    def test_cleanup_progress_store_ignores_non_terminal(self) -> None:
        """_cleanup_progress_store does nothing for non-terminal entries."""
        store: dict[str, dict] = {
            "case1": routes_state.new_progress(status="running"),
        }
        routes_state._cleanup_progress_store(store, "case1")
        self.assertIn("case1", store)
        self.assertNotIn("_drained", store["case1"])

    def test_stream_sse_reconnect_after_completion_emits_complete(self) -> None:
        """Reconnecting to SSE after progress is cleaned up emits 'complete', not 'error'."""
        from flask import Flask
        app = Flask(__name__)
        case_id = "reconnect-case"
        store: dict[str, dict] = {}
        # Case exists in CASE_STATES but progress store is empty (already drained/cleaned).
        with routes_state.STATE_LOCK:
            routes_state.CASE_STATES[case_id] = {"status": "completed"}
        try:
            with app.test_request_context():
                resp = routes_state.stream_sse(store, case_id)
                data = resp.get_data(as_text=True)
                self.assertIn('"type":"complete"', data)
                self.assertIn("Already completed", data)
                self.assertNotIn("Case not found", data)
        finally:
            with routes_state.STATE_LOCK:
                routes_state.CASE_STATES.pop(case_id, None)

    def test_stream_sse_truly_missing_case_emits_error(self) -> None:
        """SSE for a case absent from both progress and CASE_STATES emits 'error'."""
        from flask import Flask
        app = Flask(__name__)
        store: dict[str, dict] = {}
        with app.test_request_context():
            resp = routes_state.stream_sse(store, "truly-missing")
            data = resp.get_data(as_text=True)
            self.assertIn("Case not found", data)
            self.assertNotIn('"type":"complete"', data)


class EvidenceHelperTests(unittest.TestCase):
    """Tests for helper functions in app.routes.evidence."""

    def test_build_csv_map_successful_results(self) -> None:
        results = [
            {"artifact_key": "runkeys", "success": True, "csv_path": "/path/runkeys.csv"},
            {"artifact_key": "tasks", "success": False, "csv_path": "/path/tasks.csv"},
            {"artifact_key": "amcache", "success": True, "csv_path": ""},
            {"artifact_key": "multi", "success": True, "csv_paths": ["/path/multi_1.csv", "/path/multi_2.csv"]},
        ]
        mapping = routes_evidence.build_csv_map(results)
        self.assertEqual(mapping["runkeys"], "/path/runkeys.csv")
        self.assertNotIn("tasks", mapping)
        self.assertNotIn("amcache", mapping)
        self.assertEqual(mapping["multi"], ["/path/multi_1.csv", "/path/multi_2.csv"])

    def test_build_csv_map_empty_results(self) -> None:
        self.assertEqual(routes_evidence.build_csv_map([]), {})

    def test_build_csv_map_single_csv_paths_collapses_to_string(self) -> None:
        """A csv_paths list with exactly one entry should collapse to a plain string."""
        results = [
            {"artifact_key": "evtx", "success": True, "csv_paths": ["/path/evtx_Security.csv"]},
        ]
        mapping = routes_evidence.build_csv_map(results)
        self.assertEqual(mapping["evtx"], "/path/evtx_Security.csv")

    def test_build_csv_map_split_artifact_preserves_all_paths(self) -> None:
        """Split artifacts with multiple csv_paths are stored as a list."""
        results = [
            {"artifact_key": "evtx", "success": True, "csv_paths": [
                "/path/evtx_Security.csv", "/path/evtx_System.csv", "/path/evtx_Application.csv",
            ]},
        ]
        mapping = routes_evidence.build_csv_map(results)
        self.assertIsInstance(mapping["evtx"], list)
        self.assertEqual(len(mapping["evtx"]), 3)

    def test_build_csv_map_csv_path_preferred_over_empty_csv_paths(self) -> None:
        """When csv_paths is empty, csv_path should still be used."""
        results = [
            {"artifact_key": "runkeys", "success": True, "csv_path": "/path/runkeys.csv", "csv_paths": []},
        ]
        mapping = routes_evidence.build_csv_map(results)
        self.assertEqual(mapping["runkeys"], "/path/runkeys.csv")

    def test_collect_case_csv_paths_handles_list_values(self) -> None:
        """collect_case_csv_paths should collect all paths from list-valued entries."""
        with TemporaryDirectory() as tmpdir:
            csv1 = Path(tmpdir) / "evtx_Security.csv"
            csv2 = Path(tmpdir) / "evtx_System.csv"
            csv1.write_text("col\n1\n", encoding="utf-8")
            csv2.write_text("col\n2\n", encoding="utf-8")
            case = {
                "case_dir": tmpdir,
                "artifact_csv_paths": {"evtx": [str(csv1), str(csv2)]},
                "parse_results": [],
            }
            result = routes_evidence.collect_case_csv_paths(case)
            resolved = {p.name for p in result}
            self.assertIn("evtx_Security.csv", resolved)
            self.assertIn("evtx_System.csv", resolved)

    def test_read_audit_entries_missing_file(self) -> None:
        with TemporaryDirectory() as tmpdir:
            result = routes_evidence.read_audit_entries(Path(tmpdir))
        self.assertEqual(result, [])

    def test_read_audit_entries_valid_file(self) -> None:
        with TemporaryDirectory() as tmpdir:
            audit_path = Path(tmpdir) / "audit.jsonl"
            audit_path.write_text(
                '{"action": "test", "timestamp": "2025-01-01T00:00:00Z"}\n'
                'invalid json line\n'
                '{"action": "test2"}\n',
                encoding="utf-8",
            )
            result = routes_evidence.read_audit_entries(Path(tmpdir))
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["action"], "test")
        self.assertEqual(result[1]["action"], "test2")

    def test_resolve_hash_verification_path_source(self) -> None:
        case = {"source_path": "/evidence/disk.E01", "evidence_path": "/case/extracted/disk.E01"}
        result = routes_evidence.resolve_hash_verification_path(case)
        self.assertEqual(result, Path("/evidence/disk.E01"))

    def test_resolve_hash_verification_path_evidence_fallback(self) -> None:
        case = {"source_path": "", "evidence_path": "/case/extracted/disk.E01"}
        result = routes_evidence.resolve_hash_verification_path(case)
        self.assertEqual(result, Path("/case/extracted/disk.E01"))

    def test_resolve_hash_verification_path_none(self) -> None:
        case = {"source_path": "", "evidence_path": ""}
        result = routes_evidence.resolve_hash_verification_path(case)
        self.assertIsNone(result)

    def test_resolve_case_csv_output_dir_default(self) -> None:
        with TemporaryDirectory() as tmpdir:
            case_dir = Path(tmpdir) / "case1"
            case_dir.mkdir()
            case = {"case_dir": case_dir, "case_id": "case1"}
            result = routes_evidence.resolve_case_csv_output_dir(case, {})
        self.assertEqual(result, case_dir / "parsed")

    def test_resolve_case_csv_output_dir_configured(self) -> None:
        with TemporaryDirectory() as tmpdir:
            case_dir = Path(tmpdir) / "case1"
            case_dir.mkdir()
            output_root = Path(tmpdir) / "custom_output"
            case = {"case_dir": case_dir, "case_id": "case1"}
            config = {"evidence": {"csv_output_dir": str(output_root)}}
            result = routes_evidence.resolve_case_csv_output_dir(case, config)
        self.assertEqual(result, output_root / "case1" / "parsed")

    def test_collect_case_csv_paths_from_artifact_csv_paths(self) -> None:
        with TemporaryDirectory() as tmpdir:
            case_dir = Path(tmpdir)
            csv_path = case_dir / "parsed" / "runkeys.csv"
            csv_path.parent.mkdir(parents=True, exist_ok=True)
            csv_path.write_text("data", encoding="utf-8")
            case = {
                "case_dir": case_dir,
                "artifact_csv_paths": {"runkeys": str(csv_path)},
                "parse_results": [],
            }
            result = routes_evidence.collect_case_csv_paths(case)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], csv_path)

    def test_collect_case_csv_paths_fallback_to_parsed_dir(self) -> None:
        with TemporaryDirectory() as tmpdir:
            case_dir = Path(tmpdir)
            parsed_dir = case_dir / "parsed"
            parsed_dir.mkdir()
            (parsed_dir / "test.csv").write_text("data", encoding="utf-8")
            case = {"case_dir": case_dir, "artifact_csv_paths": {}, "parse_results": []}
            result = routes_evidence.collect_case_csv_paths(case)
        self.assertEqual(len(result), 1)


class ArtifactHelperTests(unittest.TestCase):
    """Tests for helper functions in app.routes.artifacts."""

    def test_normalize_artifact_mode_defaults(self) -> None:
        self.assertEqual(routes_artifacts.normalize_artifact_mode("parse_and_ai"), "parse_and_ai")
        self.assertEqual(routes_artifacts.normalize_artifact_mode("parse_only"), "parse_only")
        self.assertEqual(routes_artifacts.normalize_artifact_mode(""), "parse_and_ai")
        self.assertEqual(routes_artifacts.normalize_artifact_mode(None), "parse_and_ai")
        self.assertEqual(routes_artifacts.normalize_artifact_mode("invalid"), "parse_and_ai")
        self.assertEqual(
            routes_artifacts.normalize_artifact_mode("invalid", default_mode="parse_only"),
            "parse_only",
        )

    def test_normalize_artifact_options_string_list(self) -> None:
        result = routes_artifacts.normalize_artifact_options(["runkeys", "mft", "runkeys"])
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["artifact_key"], "runkeys")
        self.assertEqual(result[0]["mode"], "parse_and_ai")

    def test_normalize_artifact_options_dict_list(self) -> None:
        result = routes_artifacts.normalize_artifact_options([
            {"artifact_key": "runkeys", "mode": "parse_only"},
            {"key": "mft", "ai_enabled": False},
        ])
        self.assertEqual(result[0]["mode"], "parse_only")
        self.assertEqual(result[1]["artifact_key"], "mft")
        self.assertEqual(result[1]["mode"], "parse_only")

    def test_normalize_artifact_options_rejects_non_list(self) -> None:
        with self.assertRaises(ValueError):
            routes_artifacts.normalize_artifact_options("not a list")

    def test_normalize_artifact_options_skips_non_string_non_dict(self) -> None:
        result = routes_artifacts.normalize_artifact_options(["runkeys", 42, None])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["artifact_key"], "runkeys")

    def test_artifact_options_to_lists(self) -> None:
        options = [
            {"artifact_key": "runkeys", "mode": "parse_and_ai"},
            {"artifact_key": "mft", "mode": "parse_only"},
            {"artifact_key": "evtx", "mode": "parse_and_ai"},
        ]
        parse, analysis = routes_artifacts.artifact_options_to_lists(options)
        self.assertEqual(parse, ["runkeys", "mft", "evtx"])
        self.assertEqual(analysis, ["runkeys", "evtx"])

    def test_extract_parse_selection_payload_new_format(self) -> None:
        payload = {
            "artifact_options": [
                {"artifact_key": "runkeys", "mode": "parse_and_ai"},
                {"artifact_key": "mft", "mode": "parse_only"},
            ]
        }
        options, parse_list, analysis_list = routes_artifacts.extract_parse_selection_payload(payload)
        self.assertEqual(len(options), 2)
        self.assertEqual(parse_list, ["runkeys", "mft"])
        self.assertEqual(analysis_list, ["runkeys"])

    def test_extract_parse_selection_payload_legacy_format(self) -> None:
        payload = {
            "artifacts": ["runkeys", "mft"],
            "ai_artifacts": ["runkeys"],
        }
        options, parse_list, analysis_list = routes_artifacts.extract_parse_selection_payload(payload)
        self.assertEqual(parse_list, ["runkeys", "mft"])
        self.assertEqual(analysis_list, ["runkeys"])

    def test_extract_parse_selection_payload_legacy_no_ai_artifacts(self) -> None:
        payload = {"artifacts": ["runkeys", "mft"]}
        options, parse_list, analysis_list = routes_artifacts.extract_parse_selection_payload(payload)
        self.assertEqual(parse_list, ["runkeys", "mft"])
        self.assertEqual(analysis_list, ["runkeys", "mft"])

    def test_extract_parse_selection_payload_invalid_artifacts(self) -> None:
        with self.assertRaises(ValueError):
            routes_artifacts.extract_parse_selection_payload({"artifacts": "not a list"})

    def test_extract_parse_selection_payload_invalid_ai_artifacts(self) -> None:
        with self.assertRaises(ValueError):
            routes_artifacts.extract_parse_selection_payload(
                {"artifacts": ["runkeys"], "ai_artifacts": "not a list"}
            )

    def test_validate_analysis_date_range_valid(self) -> None:
        result = routes_artifacts.validate_analysis_date_range(
            {"start_date": "2025-01-01", "end_date": "2025-01-31"}
        )
        self.assertEqual(result["start_date"], "2025-01-01")
        self.assertEqual(result["end_date"], "2025-01-31")

    def test_validate_analysis_date_range_none(self) -> None:
        self.assertIsNone(routes_artifacts.validate_analysis_date_range(None))

    def test_validate_analysis_date_range_empty(self) -> None:
        self.assertIsNone(
            routes_artifacts.validate_analysis_date_range({"start_date": "", "end_date": ""})
        )

    def test_validate_analysis_date_range_partial(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            routes_artifacts.validate_analysis_date_range({"start_date": "2025-01-01"})
        self.assertIn("Provide both", str(ctx.exception))

    def test_validate_analysis_date_range_invalid_format(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            routes_artifacts.validate_analysis_date_range(
                {"start_date": "01-01-2025", "end_date": "01-31-2025"}
            )
        self.assertIn("YYYY-MM-DD", str(ctx.exception))

    def test_validate_analysis_date_range_reversed(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            routes_artifacts.validate_analysis_date_range(
                {"start_date": "2025-02-01", "end_date": "2025-01-01"}
            )
        self.assertIn("earlier", str(ctx.exception))

    def test_validate_analysis_date_range_non_dict(self) -> None:
        with self.assertRaises(ValueError):
            routes_artifacts.validate_analysis_date_range("not a dict")

    def test_extract_parse_progress_dict_arg(self) -> None:
        key, count = routes_artifacts.extract_parse_progress(
            "fallback", ({"artifact_key": "runkeys", "record_count": 42},)
        )
        self.assertEqual(key, "runkeys")
        self.assertEqual(count, 42)

    def test_extract_parse_progress_positional_args(self) -> None:
        key, count = routes_artifacts.extract_parse_progress("fallback", ("mft", 100))
        self.assertEqual(key, "mft")
        self.assertEqual(count, 100)

    def test_extract_parse_progress_single_arg(self) -> None:
        key, count = routes_artifacts.extract_parse_progress("fallback", (50,))
        self.assertEqual(key, "fallback")
        self.assertEqual(count, 50)

    def test_extract_parse_progress_no_args(self) -> None:
        key, count = routes_artifacts.extract_parse_progress("fallback", ())
        self.assertEqual(key, "fallback")
        self.assertEqual(count, 0)

    def test_sanitize_prompt_short(self) -> None:
        result = routes_artifacts.sanitize_prompt("  hello   world  ")
        self.assertEqual(result, "hello world")

    def test_sanitize_prompt_truncation(self) -> None:
        long_prompt = "a" * 3000
        result = routes_artifacts.sanitize_prompt(long_prompt, max_chars=100)
        self.assertTrue(result.endswith("... [truncated]"))
        self.assertTrue(len(result) < 200)

    def test_normalize_profile_name_valid(self) -> None:
        self.assertEqual(routes_artifacts.normalize_profile_name("My Profile"), "My Profile")

    def test_normalize_profile_name_empty(self) -> None:
        with self.assertRaises(ValueError):
            routes_artifacts.normalize_profile_name("")

    def test_normalize_profile_name_reserved(self) -> None:
        with self.assertRaises(ValueError):
            routes_artifacts.normalize_profile_name("recommended")

    def test_normalize_profile_name_invalid_chars(self) -> None:
        with self.assertRaises(ValueError):
            routes_artifacts.normalize_profile_name("!@#$%")

    def test_profile_path_for_new_name(self) -> None:
        with TemporaryDirectory() as tmpdir:
            profiles_root = Path(tmpdir)
            path = routes_artifacts.profile_path_for_new_name(profiles_root, "My Profile")
            self.assertEqual(path, profiles_root / "my_profile.json")

    def test_profile_path_for_new_name_collision(self) -> None:
        with TemporaryDirectory() as tmpdir:
            profiles_root = Path(tmpdir)
            (profiles_root / "my_profile.json").write_text("{}", encoding="utf-8")
            path = routes_artifacts.profile_path_for_new_name(profiles_root, "My Profile")
            self.assertEqual(path, profiles_root / "my_profile_1.json")


class TaskHelperTests(unittest.TestCase):
    """Tests for helper functions in app.routes.tasks."""

    def test_load_case_analysis_results_from_memory(self) -> None:
        case = {
            "case_dir": "/tmp/fake",
            "analysis_results": {"summary": "test", "per_artifact": []},
        }
        result = routes_tasks.load_case_analysis_results(case)
        self.assertEqual(result["summary"], "test")

    def test_load_case_analysis_results_empty_dict_no_file(self) -> None:
        with TemporaryDirectory() as tmpdir:
            case = {"case_dir": tmpdir, "analysis_results": {}}
            result = routes_tasks.load_case_analysis_results(case)
        # Empty dict in memory with no file on disk returns empty dict (not None)
        self.assertEqual(result, {})

    def test_load_case_analysis_results_none_no_file(self) -> None:
        with TemporaryDirectory() as tmpdir:
            case = {"case_dir": tmpdir, "analysis_results": None}
            result = routes_tasks.load_case_analysis_results(case)
        self.assertIsNone(result)

    def test_load_case_analysis_results_from_disk(self) -> None:
        with TemporaryDirectory() as tmpdir:
            results_path = Path(tmpdir) / "analysis_results.json"
            results_path.write_text(
                json.dumps({"summary": "disk_result", "per_artifact": []}),
                encoding="utf-8",
            )
            case = {"case_dir": tmpdir, "analysis_results": {}}
            result = routes_tasks.load_case_analysis_results(case)
        self.assertEqual(result["summary"], "disk_result")

    def test_load_case_analysis_results_missing_file(self) -> None:
        with TemporaryDirectory() as tmpdir:
            case = {"case_dir": tmpdir, "analysis_results": None}
            result = routes_tasks.load_case_analysis_results(case)
        self.assertIsNone(result)

    def test_resolve_case_investigation_context_from_memory(self) -> None:
        case = {"case_dir": "/tmp/fake", "investigation_context": "memory context"}
        result = routes_tasks.resolve_case_investigation_context(case)
        self.assertEqual(result, "memory context")

    def test_resolve_case_investigation_context_from_disk(self) -> None:
        with TemporaryDirectory() as tmpdir:
            prompt_path = Path(tmpdir) / "prompt.txt"
            prompt_path.write_text("disk context", encoding="utf-8")
            case = {"case_dir": tmpdir, "investigation_context": ""}
            result = routes_tasks.resolve_case_investigation_context(case)
        self.assertEqual(result, "disk context")

    def test_resolve_case_investigation_context_empty(self) -> None:
        with TemporaryDirectory() as tmpdir:
            case = {"case_dir": tmpdir, "investigation_context": ""}
            result = routes_tasks.resolve_case_investigation_context(case)
        self.assertEqual(result, "")

    def test_resolve_case_parsed_dir_from_csv_output_dir(self) -> None:
        case = {"case_dir": "/tmp/fake", "csv_output_dir": "/custom/output", "artifact_csv_paths": {}, "parse_results": []}
        result = routes_tasks.resolve_case_parsed_dir(case)
        self.assertEqual(result, Path("/custom/output"))

    def test_resolve_case_parsed_dir_default(self) -> None:
        with TemporaryDirectory() as tmpdir:
            case = {"case_dir": tmpdir, "csv_output_dir": "", "artifact_csv_paths": {}, "parse_results": []}
            result = routes_tasks.resolve_case_parsed_dir(case)
        self.assertEqual(result, Path(tmpdir) / "parsed")

    def test_run_task_with_case_log_context_calls_function(self) -> None:
        called_args: list = []

        def task_fn(*args: object) -> None:
            called_args.extend(args)

        routes_tasks.run_task_with_case_log_context("fake-case", task_fn, "a", "b")
        self.assertEqual(called_args, ["a", "b"])

    def test_run_parse_case_not_found(self) -> None:
        routes_state.CASE_STATES.clear()
        routes_state.PARSE_PROGRESS.clear()
        routes_tasks.run_parse("missing-id", ["runkeys"], ["runkeys"], [], {})
        self.assertEqual(routes_state.PARSE_PROGRESS["missing-id"]["status"], "failed")
        routes_state.PARSE_PROGRESS.clear()

    def test_run_analysis_case_not_found(self) -> None:
        routes_state.CASE_STATES.clear()
        routes_state.ANALYSIS_PROGRESS.clear()
        routes_tasks.run_analysis("missing-id", "prompt", {})
        self.assertEqual(routes_state.ANALYSIS_PROGRESS["missing-id"]["status"], "failed")
        routes_state.ANALYSIS_PROGRESS.clear()

    def test_run_chat_case_not_found(self) -> None:
        routes_state.CASE_STATES.clear()
        routes_state.CHAT_PROGRESS.clear()
        routes_tasks.run_chat("missing-id", "hello", {})
        self.assertEqual(routes_state.CHAT_PROGRESS["missing-id"]["status"], "failed")
        routes_state.CHAT_PROGRESS.clear()

    def test_run_parse_no_evidence(self) -> None:
        routes_state.CASE_STATES.clear()
        routes_state.PARSE_PROGRESS.clear()
        audit = MagicMock()
        routes_state.CASE_STATES["test-id"] = {
            "case_dir": "/tmp/fake",
            "evidence_path": "",
            "audit": audit,
        }
        routes_tasks.run_parse("test-id", ["runkeys"], ["runkeys"], [], {})
        self.assertEqual(routes_state.PARSE_PROGRESS["test-id"]["status"], "failed")
        self.assertEqual(routes_state.CASE_STATES["test-id"]["status"], "failed")
        routes_state.CASE_STATES.clear()
        routes_state.PARSE_PROGRESS.clear()



if __name__ == "__main__":
    unittest.main()
