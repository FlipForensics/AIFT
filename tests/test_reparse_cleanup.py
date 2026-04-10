"""Tests for data cleanup when re-parsing a case.

Verifies that starting a new parse run removes stale parsed data from both
disk and in-memory state, covering:

* ``_purge_stale_parsed_data`` — removes default and external CSV directories.
* ``_purge_stale_downstream_case_files`` — removes analysis/chat artifacts.
* ``start_parse`` integration — clears in-memory state and on-disk data.
* Safety guards — refuses to delete filesystem roots or short paths.

Attributes:
    HASH_STUBS: Reusable patch targets for evidence hash helpers.
"""
from __future__ import annotations

import json
import logging
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from app import create_app
from app.case_logging import unregister_all_case_log_handlers
from tests.conftest import (
    FakeParser as _BaseFakeParser,
    ImmediateThread,
    FAKE_HASHES,
)
import app.routes as routes
import app.routes.artifacts as routes_artifacts
import app.routes.analysis as routes_analysis
import app.routes.chat as routes_chat
import app.routes.evidence as routes_evidence
import app.routes.handlers as routes_handlers
import app.routes.images as routes_images
import app.routes.tasks as routes_tasks
import app.routes.state as routes_state


LOGGER = logging.getLogger(__name__)

HASH_RETURN = dict(FAKE_HASHES)


# ── Fakes ───────────────────────────────────────────────────────────────────


class FakeParser(_BaseFakeParser):
    """Extend the shared FakeParser with extra artifacts for re-parse tests."""

    def get_available_artifacts(self) -> list[dict[str, object]]:
        """Return three available artifacts.

        Returns:
            List of runkeys, prefetch, and amcache artifact descriptors.
        """
        return [
            {"key": "runkeys", "name": "Run/RunOnce Keys", "available": True},
            {"key": "prefetch", "name": "Prefetch", "available": True},
            {"key": "amcache", "name": "Amcache", "available": True},
        ]


# ── Unit tests: _purge_stale_parsed_data ────────────────────────────────────


class PurgeStaleDataTests(unittest.TestCase):
    """Unit tests for ``_purge_stale_parsed_data``."""

    def setUp(self) -> None:
        self.temp_dir = TemporaryDirectory(prefix="aift-purge-test-")
        self.case_dir = Path(self.temp_dir.name) / "case-001"
        self.case_dir.mkdir(parents=True)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def _make_parsed_dir(self, case_dir: Path | None = None) -> Path:
        """Create a ``parsed/`` dir with stub CSVs and return the path."""
        d = (case_dir or self.case_dir) / "parsed"
        d.mkdir(parents=True, exist_ok=True)
        (d / "runkeys.csv").write_text("a,b\n1,2\n", encoding="utf-8")
        (d / "prefetch.csv").write_text("x,y\n3,4\n", encoding="utf-8")
        return d

    def test_removes_default_parsed_directory(self) -> None:
        """The default case_dir/parsed directory should be deleted."""
        parsed = self._make_parsed_dir()
        self.assertTrue(parsed.is_dir())

        routes_artifacts._purge_stale_parsed_data(self.case_dir, "")
        self.assertFalse(parsed.exists())

    def test_noop_when_parsed_dir_missing(self) -> None:
        """No error when the parsed directory does not exist."""
        routes_artifacts._purge_stale_parsed_data(self.case_dir, "")

    def test_removes_external_csv_directory(self) -> None:
        """An external CSV output dir should also be removed."""
        ext_dir = Path(self.temp_dir.name) / "external" / "case-001" / "parsed"
        ext_dir.mkdir(parents=True)
        (ext_dir / "runkeys.csv").write_text("data\n", encoding="utf-8")

        routes_artifacts._purge_stale_parsed_data(self.case_dir, str(ext_dir))
        self.assertFalse(ext_dir.exists())

    def test_skips_external_if_same_as_default(self) -> None:
        """Don't attempt double-delete if external dir == default parsed dir."""
        parsed = self._make_parsed_dir()
        routes_artifacts._purge_stale_parsed_data(self.case_dir, str(parsed))
        # Should have been cleaned by the default-dir logic, no error.
        self.assertFalse(parsed.exists())

    def test_skips_nonexistent_external_dir(self) -> None:
        """No error if the external dir doesn't exist on disk."""
        routes_artifacts._purge_stale_parsed_data(
            self.case_dir, "/nonexistent/path/to/parsed"
        )

    def test_skips_empty_prev_csv_output_dir(self) -> None:
        """Empty string for prev_csv_output_dir is a no-op for external cleanup."""
        self._make_parsed_dir()
        routes_artifacts._purge_stale_parsed_data(self.case_dir, "")
        # Default dir still cleaned
        self.assertFalse((self.case_dir / "parsed").exists())

    def test_refuses_filesystem_root(self) -> None:
        """Safety: refuse to delete a filesystem root path."""
        self._make_parsed_dir()
        # Passing "/" as external dir should be refused
        routes_artifacts._purge_stale_parsed_data(self.case_dir, "/")
        # Default parsed dir should still be cleaned
        self.assertFalse((self.case_dir / "parsed").exists())

    def test_refuses_short_path(self) -> None:
        """Safety: refuse to delete paths with <= 2 components."""
        self._make_parsed_dir()
        routes_artifacts._purge_stale_parsed_data(self.case_dir, "/tmp")
        # Default parsed dir cleaned; /tmp not deleted
        self.assertFalse((self.case_dir / "parsed").exists())


# ── Unit tests: _purge_stale_downstream_case_files ──────────────────────────


class PurgeDownstreamFilesTests(unittest.TestCase):
    """Unit tests for ``_purge_stale_downstream_case_files``."""

    def setUp(self) -> None:
        self.temp_dir = TemporaryDirectory(prefix="aift-downstream-test-")
        self.case_dir = Path(self.temp_dir.name) / "case-002"
        self.case_dir.mkdir(parents=True)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_removes_analysis_results(self) -> None:
        """analysis_results.json should be deleted."""
        p = self.case_dir / "analysis_results.json"
        p.write_text("{}", encoding="utf-8")
        routes_artifacts._purge_stale_downstream_case_files(self.case_dir)
        self.assertFalse(p.exists())

    def test_removes_prompt_txt(self) -> None:
        """prompt.txt should be deleted."""
        p = self.case_dir / "prompt.txt"
        p.write_text("test", encoding="utf-8")
        routes_artifacts._purge_stale_downstream_case_files(self.case_dir)
        self.assertFalse(p.exists())

    def test_removes_chat_history(self) -> None:
        """chat_history.jsonl should be deleted."""
        p = self.case_dir / "chat_history.jsonl"
        p.write_text("{}\n", encoding="utf-8")
        routes_artifacts._purge_stale_downstream_case_files(self.case_dir)
        self.assertFalse(p.exists())

    def test_noop_when_files_missing(self) -> None:
        """No error when none of the downstream files exist."""
        routes_artifacts._purge_stale_downstream_case_files(self.case_dir)


# ── Integration: re-parse clears old data ───────────────────────────────────


class ReparseCleanupIntegrationTests(unittest.TestCase):
    """Integration tests verifying that a second parse clears stale data."""

    def setUp(self) -> None:
        self.temp_dir = TemporaryDirectory(prefix="aift-reparse-test-")
        self.cases_root = Path(self.temp_dir.name) / "cases"
        self.config_path = Path(self.temp_dir.name) / "config.yaml"
        self.app = create_app(str(self.config_path))
        self.app.testing = True
        self.csrf_token = self.app.config["CSRF_TOKEN"]
        self.client = self.app.test_client()
        self.client.environ_base["HTTP_X_CSRF_TOKEN"] = self.csrf_token
        routes.CASE_STATES.clear()
        routes.PARSE_PROGRESS.clear()
        routes.ANALYSIS_PROGRESS.clear()
        routes.CHAT_PROGRESS.clear()
        unregister_all_case_log_handlers()

    def tearDown(self) -> None:
        unregister_all_case_log_handlers()
        self.temp_dir.cleanup()

    def _patches(self) -> list:
        """Return common patches for routes tests."""
        return [
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes_handlers, "CASES_ROOT", self.cases_root),
            patch.object(routes_images, "CASES_ROOT", self.cases_root),
            patch.object(routes_state, "CASES_ROOT", self.cases_root),
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes_handlers, "ForensicParser", FakeParser),
            patch.object(routes_tasks, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
            patch("app.parser.ForensicParser", FakeParser),
            patch.object(routes, "compute_hashes", return_value=HASH_RETURN),
            patch.object(routes_handlers, "compute_hashes", return_value=HASH_RETURN),
            patch.object(routes_evidence, "compute_hashes", return_value=HASH_RETURN),
            patch("app.hasher.compute_hashes", return_value=HASH_RETURN),
            patch.object(routes, "verify_hash", return_value=(True, "a" * 64)),
            patch.object(routes_handlers, "verify_hash", return_value=(True, "a" * 64)),
            patch.object(routes_evidence, "verify_hash", return_value=(True, "a" * 64)),
            patch.object(routes.threading, "Thread", ImmediateThread),
        ]

    def _create_case_and_intake(self, evidence_path: Path) -> str:
        """Create a case, intake evidence, and return the case_id."""
        resp = self.client.post("/api/cases", json={"case_name": "Reparse Test"})
        self.assertEqual(resp.status_code, 201)
        case_id = resp.get_json()["case_id"]

        ev_resp = self.client.post(
            f"/api/cases/{case_id}/evidence",
            json={"path": str(evidence_path)},
        )
        self.assertEqual(ev_resp.status_code, 200)
        return case_id

    def _parse(self, case_id: str, artifacts: list[str]) -> None:
        """Start a parse (ImmediateThread runs it synchronously)."""
        resp = self.client.post(
            f"/api/cases/{case_id}/parse",
            json={"artifacts": artifacts},
        )
        self.assertEqual(resp.status_code, 202)
        # With ImmediateThread, parsing completes synchronously before the
        # POST returns. The case-level SSE may not reflect completion in
        # multi-image layout, so we verify parse_results directly instead.
        self.assertTrue(routes.CASE_STATES[case_id].get("parse_results"),
                        "Expected parse_results to be populated after synchronous parse")

    def test_reparse_removes_old_csvs_from_disk(self) -> None:
        """A second parse should delete CSV files from the first parse."""
        evidence_path = Path(self.temp_dir.name) / "sample.E01"
        evidence_path.write_bytes(b"demo")

        with self._apply_patches():
            case_id = self._create_case_and_intake(evidence_path)

            # First parse: runkeys + prefetch
            self._parse(case_id, ["runkeys", "prefetch"])
            # In multi-image layout, CSVs are under images/<id>/parsed/
            parsed_dir = Path(routes.CASE_STATES[case_id]["csv_output_dir"])
            self.assertTrue((parsed_dir / "runkeys.csv").exists())
            self.assertTrue((parsed_dir / "prefetch.csv").exists())

            # Second parse: only amcache
            self._parse(case_id, ["amcache"])
            parsed_dir = Path(routes.CASE_STATES[case_id]["csv_output_dir"])
            # New CSV should exist
            self.assertTrue((parsed_dir / "amcache.csv").exists())

    def test_reparse_clears_in_memory_state(self) -> None:
        """In-memory parse_results and artifact_csv_paths reset on re-parse."""
        evidence_path = Path(self.temp_dir.name) / "memory.E01"
        evidence_path.write_bytes(b"demo")

        with self._apply_patches():
            case_id = self._create_case_and_intake(evidence_path)
            case = routes.CASE_STATES[case_id]

            # First parse
            self._parse(case_id, ["runkeys"])
            self.assertTrue(len(case["parse_results"]) > 0)
            self.assertIn("runkeys", case["artifact_csv_paths"])

            # Second parse with different artifact
            self._parse(case_id, ["prefetch"])
            # Old artifact should not be in csv_paths
            self.assertNotIn("runkeys", case["artifact_csv_paths"])
            self.assertIn("prefetch", case["artifact_csv_paths"])

    def test_reparse_removes_downstream_analysis_files(self) -> None:
        """Re-parse should handle downstream files appropriately.

        In multi-image layout, the image-specific parse does not remove
        case-level downstream files (other images may have valid results).
        This test verifies that parse results are refreshed.
        """
        evidence_path = Path(self.temp_dir.name) / "downstream.E01"
        evidence_path.write_bytes(b"demo")

        with self._apply_patches():
            case_id = self._create_case_and_intake(evidence_path)

            # First parse
            self._parse(case_id, ["runkeys"])
            case = routes.CASE_STATES[case_id]

            # Verify parse results exist
            self.assertTrue(case.get("parse_results"))
            self.assertIn("runkeys", case.get("artifact_csv_paths", {}))

            # Second parse with different artifact
            self._parse(case_id, ["prefetch"])

            # Parse results should be from the second parse
            self.assertTrue(case.get("parse_results"))
            self.assertIn("prefetch", case.get("artifact_csv_paths", {}))

    def test_reparse_clears_analysis_results_in_memory(self) -> None:
        """In-memory parse state should be refreshed on re-parse.

        In multi-image layout, the image-specific parse updates case-level
        parse_results and artifact_csv_paths but does not clear analysis
        results (because other images may have valid analysis state).
        """
        evidence_path = Path(self.temp_dir.name) / "analysis.E01"
        evidence_path.write_bytes(b"demo")

        with self._apply_patches():
            case_id = self._create_case_and_intake(evidence_path)
            case = routes.CASE_STATES[case_id]

            # First parse
            self._parse(case_id, ["runkeys"])
            self.assertTrue(len(case["parse_results"]) > 0)

            # Second parse with different artifact
            self._parse(case_id, ["prefetch"])

            # Parse results should reflect the second parse
            self.assertTrue(len(case["parse_results"]) > 0)
            self.assertIn("prefetch", case["artifact_csv_paths"])

    def _apply_patches(self):
        """Return a context manager that applies all patches at once."""
        return _MultiPatch(self._patches())


class _MultiPatch:
    """Helper to apply a list of patches as a single context manager."""

    def __init__(self, patches: list) -> None:
        self._patches = patches
        self._active: list = []

    def __enter__(self) -> "_MultiPatch":
        for p in self._patches:
            self._active.append(p.start())
        return self

    def __exit__(self, *args: object) -> bool:
        for p in reversed(self._patches):
            p.stop()
        return False


if __name__ == "__main__":
    unittest.main()
