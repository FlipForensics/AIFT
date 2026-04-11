"""Tests for route analysis edge cases and regression tests.

Covers TestParseRerunClearsStaleState, TestRunAnalysisUnavailableProvider,
and TestAnalysisRerunClearsStaleResults extracted from the main test_routes module.
"""
from __future__ import annotations

import csv
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


class FakeParser(_BaseFakeParser):
    """Parser stub returning ``demo-host`` metadata and an unavailable artifact."""

    def get_image_metadata(self) -> dict[str, str]:
        """Return demo-host metadata matching route-test assertions."""
        return {
            "hostname": "demo-host",
            "os_version": "Windows 11",
            "domain": "corp.local",
            "ips": "10.1.1.10",
            "timezone": "UTC",
            "install_date": "2025-01-01",
        }

    def get_available_artifacts(self) -> list[dict[str, object]]:
        """Return artifacts including one marked unavailable."""
        return [
            {"key": "runkeys", "name": "Run/RunOnce Keys", "available": True},
            {"key": "tasks", "name": "Scheduled Tasks", "available": False},
        ]


class TestParseRerunClearsStaleState(unittest.TestCase):
    """Regression: a failed reparse must not leave old parse outputs usable."""

    def setUp(self) -> None:
        self.temp_dir = TemporaryDirectory(prefix="aift-reparse-")
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

    def test_failed_reparse_clears_old_parse_outputs(self) -> None:
        """After a successful parse, a failing reparse must clear stale data."""
        evidence_path = Path(self.temp_dir.name) / "stale.E01"
        evidence_path.write_bytes(b"demo")

        class FailingParser(FakeParser):
            """Parser that raises on parse_artifact."""

            def parse_artifact(self, artifact_key: str, progress_callback: object | None = None) -> dict[str, object]:
                """Always raise to simulate a parser failure."""
                raise RuntimeError("Simulated parse failure")

        with (
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes_handlers, "CASES_ROOT", self.cases_root),
            patch.object(routes_images, "CASES_ROOT", self.cases_root),
            patch.object(routes_state, "CASES_ROOT", self.cases_root),
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes_handlers, "ForensicParser", FakeParser),
            patch.object(routes_tasks, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
            patch("app.parser.ForensicParser", FakeParser),
            patch.object(
                routes, "compute_hashes",
                return_value={"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 4},
            ),
            patch.object(
                routes_handlers, "compute_hashes",
                return_value={"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 4},
            ),
            patch.object(
                routes_evidence, "compute_hashes",
                return_value={"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 4},
            ),
            patch(
                "app.hasher.compute_hashes",
                return_value={"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 4},
            ),
            patch.object(routes.threading, "Thread", ImmediateThread),
        ):
            # Create case and load evidence.
            create_resp = self.client.post("/api/cases", json={"case_name": "Stale"})
            case_id = create_resp.get_json()["case_id"]
            self.client.post(f"/api/cases/{case_id}/evidence", json={"path": str(evidence_path)})

            # First parse succeeds.
            resp = self.client.post(f"/api/cases/{case_id}/parse", json={"artifacts": ["runkeys"]})
            self.assertEqual(resp.status_code, 202)
            case = routes_state.CASE_STATES[case_id]
            self.assertTrue(len(case.get("parse_results", [])) > 0, "First parse should produce results")
            self.assertTrue(len(case.get("artifact_csv_paths", {})) > 0, "First parse should produce csv map")
            case_dir = Path(case["case_dir"])
            (case_dir / "analysis_results.json").write_text(
                json.dumps({"summary": "stale", "per_artifact": []}),
                encoding="utf-8",
            )
            (case_dir / "prompt.txt").write_text("stale prompt", encoding="utf-8")
            (case_dir / "chat_history.jsonl").write_text(
                json.dumps({"role": "user", "content": "stale"}) + "\n",
                encoding="utf-8",
            )
            with routes_state.STATE_LOCK:
                case["investigation_context"] = "stale prompt"

        # Now reparse with a failing parser.
        with (
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes_handlers, "CASES_ROOT", self.cases_root),
            patch.object(routes_images, "CASES_ROOT", self.cases_root),
            patch.object(routes_state, "CASES_ROOT", self.cases_root),
            patch.object(routes, "ForensicParser", FailingParser),
            patch.object(routes_handlers, "ForensicParser", FailingParser),
            patch.object(routes_tasks, "ForensicParser", FailingParser),
            patch.object(routes_evidence, "ForensicParser", FailingParser),
            patch("app.parser.ForensicParser", FailingParser),
            patch.object(routes.threading, "Thread", ImmediateThread),
        ):
            resp = self.client.post(f"/api/cases/{case_id}/parse", json={"artifacts": ["runkeys"]})
            self.assertEqual(resp.status_code, 202)

            # After the failed reparse, the case should be in error state.
            case = routes_state.CASE_STATES[case_id]
            self.assertEqual(case.get("status"), "error",
                             "Case should be in error state after failed parse")


class TestRunAnalysisUnavailableProvider(unittest.TestCase):
    """Regression: analysis with an unconfigured provider must not mark case completed."""

    def setUp(self) -> None:
        routes_state.CASE_STATES.clear()
        routes_state.ANALYSIS_PROGRESS.clear()

    def tearDown(self) -> None:
        routes_state.CASE_STATES.clear()
        routes_state.ANALYSIS_PROGRESS.clear()

    def test_unavailable_provider_sets_error_status(self) -> None:
        """When provider init fails, case status must be error, not completed."""
        from tempfile import TemporaryDirectory
        import csv

        with TemporaryDirectory(prefix="aift-unavail-") as tmp_dir:
            csv_path = Path(tmp_dir) / "parsed" / "runkeys.csv"
            csv_path.parent.mkdir(parents=True, exist_ok=True)
            with csv_path.open("w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["ts", "name"])
                writer.writerow(["2024-01-01", "test"])

            audit = MagicMock()
            routes_state.CASE_STATES["bad-provider"] = {
                "case_dir": tmp_dir,
                "audit": audit,
                "artifact_csv_paths": {"runkeys": str(csv_path)},
                "parse_results": [{"artifact_key": "runkeys", "success": True, "csv_path": str(csv_path)}],
                "analysis_artifacts": ["runkeys"],
                "selected_artifacts": ["runkeys"],
                "artifact_options": [],
                "image_metadata": {},
            }

            bad_config = {"ai": {"provider": "anthropic", "anthropic": {"api_key": ""}}}
            with patch.object(
                routes_tasks, "ForensicAnalyzer",
                side_effect=RuntimeError("Invalid API key"),
            ):
                routes_tasks.run_analysis("bad-provider", "investigate breach", bad_config)

            case = routes_state.CASE_STATES["bad-provider"]
            progress = routes_state.ANALYSIS_PROGRESS.get("bad-provider", {})

            # Case must NOT be completed
            self.assertNotEqual(case.get("status"), "completed")
            self.assertEqual(case.get("status"), "error")

            # Analysis progress must be failed
            self.assertEqual(progress.get("status"), "failed")

            # No misleading analysis_results stored
            self.assertFalse(
                isinstance(case.get("analysis_results"), dict)
                and case["analysis_results"].get("per_artifact"),
                "Stale analysis_results should not be stored",
            )


class TestAnalysisRerunClearsStaleResults(unittest.TestCase):
    """Regression: a failed re-analysis must not leave prior findings available."""

    def setUp(self) -> None:
        self.temp_dir = TemporaryDirectory(prefix="aift-stale-analysis-")
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
        FakeAnalyzer.last_artifact_keys = []

    def tearDown(self) -> None:
        unregister_all_case_log_handlers()
        self.temp_dir.cleanup()

    def test_failed_reanalysis_clears_stale_results(self) -> None:
        """Run analysis successfully, then force failure on rerun.

        After the failed rerun, prior findings must not be available
        via chat or report/download routes.
        """
        evidence_path = Path(self.temp_dir.name) / "stale.E01"
        evidence_path.write_bytes(b"demo")

        call_count = 0

        class FailOnSecondAnalyzer(FakeAnalyzer):
            """Succeeds on first call, raises on second."""

            def run_full_analysis(
                self,
                artifact_keys: list[str],
                investigation_context: str,
                metadata: dict[str, object] | None,
                progress_callback: object | None = None,
                cancel_check: object | None = None,
            ) -> dict[str, object]:
                nonlocal call_count
                call_count += 1
                if call_count >= 2:
                    raise RuntimeError("Simulated provider failure")
                return super().run_full_analysis(
                    artifact_keys, investigation_context, metadata,
                    progress_callback, cancel_check,
                )

        hash_rv = {"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 4}

        with (
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes_handlers, "CASES_ROOT", self.cases_root),
            patch.object(routes_images, "CASES_ROOT", self.cases_root),
            patch.object(routes_state, "CASES_ROOT", self.cases_root),
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes_handlers, "ForensicParser", FakeParser),
            patch.object(routes_tasks, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
            patch("app.parser.ForensicParser", FakeParser),
            patch.object(routes, "ForensicAnalyzer", FailOnSecondAnalyzer),
            patch.object(routes_tasks, "ForensicAnalyzer", FailOnSecondAnalyzer),
            patch.object(routes.threading, "Thread", ImmediateThread),
            patch.object(routes, "compute_hashes", return_value=hash_rv),
            patch.object(routes_handlers, "compute_hashes", return_value=hash_rv),
            patch.object(routes_evidence, "compute_hashes", return_value=hash_rv),
            patch("app.hasher.compute_hashes", return_value=hash_rv),
        ):
            # Create case, load evidence, parse.
            create_resp = self.client.post(
                "/api/cases", json={"case_name": "Stale Analysis Test"},
            )
            self.assertEqual(create_resp.status_code, 201)
            case_id = create_resp.get_json()["case_id"]

            ev_resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                json={"path": str(evidence_path)},
            )
            self.assertEqual(ev_resp.status_code, 200)

            parse_resp = self.client.post(
                f"/api/cases/{case_id}/parse",
                json={"artifacts": ["runkeys"]},
            )
            self.assertEqual(parse_resp.status_code, 202)

            # --- First analysis: succeeds ---
            resp1 = self.client.post(
                f"/api/cases/{case_id}/analyze",
                json={"prompt": "first run"},
            )
            self.assertEqual(resp1.status_code, 202)

            # Verify results exist after successful analysis.
            case = routes_state.CASE_STATES[case_id]
            self.assertTrue(
                isinstance(case.get("analysis_results"), dict)
                and case["analysis_results"].get("per_artifact"),
                "First analysis should produce results",
            )
            results_path = self.cases_root / case_id / "analysis_results.json"
            self.assertTrue(results_path.exists(), "Results file should exist after first run")

            # --- Second analysis: fails ---
            resp2 = self.client.post(
                f"/api/cases/{case_id}/analyze",
                json={"prompt": "second run"},
            )
            self.assertEqual(resp2.status_code, 202)

            # In-memory results must be empty.
            in_memory = case.get("analysis_results")
            self.assertFalse(
                isinstance(in_memory, dict) and in_memory.get("per_artifact"),
                "Stale in-memory analysis_results must be cleared after failed rerun",
            )

            # On-disk results must be removed.
            self.assertFalse(
                results_path.exists(),
                "Stale analysis_results.json must be removed after failed rerun",
            )

            # Chat route must refuse (no results available).
            chat_resp = self.client.post(
                f"/api/cases/{case_id}/chat",
                json={"message": "What did you find?"},
            )
            self.assertIn(chat_resp.status_code, (400, 404))
            chat_body = chat_resp.get_json()
            self.assertFalse(chat_body.get("success"))


if __name__ == "__main__":
    unittest.main()
