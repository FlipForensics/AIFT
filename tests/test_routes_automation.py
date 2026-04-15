"""Tests for the automation REST API endpoints in app/routes/automation.py.

Covers request validation, CSRF exemption, concurrency limiting,
status tracking, cancellation, report download, and run listing.
"""

from __future__ import annotations

import json
import threading
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch

from app import create_app
from app.automation.engine import AutomationResult
import app.routes.automation as automation_mod


def _make_successful_result(case_id: str = "test-case-123") -> AutomationResult:
    """Build a successful AutomationResult for mocking.

    Args:
        case_id: Case ID to embed in the result.

    Returns:
        A populated AutomationResult with success=True.
    """
    return AutomationResult(
        success=True,
        case_id=case_id,
        html_report_path=None,
        json_report_path=None,
        evidence_files=[Path("/fake/evidence.E01")],
        errors=[],
        warnings=["minor warning"],
        duration_seconds=42.0,
    )


def _make_failed_result(case_id: str = "test-case-456") -> AutomationResult:
    """Build a failed AutomationResult for mocking.

    Args:
        case_id: Case ID to embed in the result.

    Returns:
        A populated AutomationResult with success=False.
    """
    return AutomationResult(
        success=False,
        case_id=case_id,
        errors=["Evidence path does not exist"],
        duration_seconds=1.0,
    )


class AutomationRoutesTestBase(unittest.TestCase):
    """Base class for automation route tests with app and client setup."""

    def setUp(self) -> None:
        """Set up Flask test client and clear automation run state."""
        self.temp_dir = TemporaryDirectory(prefix="aift-auto-test-")
        self.config_path = Path(self.temp_dir.name) / "config.yaml"
        self.app = create_app(str(self.config_path))
        self.app.testing = True
        self.client = self.app.test_client()
        # Clear global state between tests.
        automation_mod.AUTOMATION_RUNS.clear()

    def tearDown(self) -> None:
        """Clean up temp directory."""
        self.temp_dir.cleanup()

    def _post_json(self, url: str, data: dict) -> object:
        """POST JSON without CSRF token (automation endpoints are exempt).

        Args:
            url: Request URL path.
            data: JSON-serialisable dict.

        Returns:
            Flask test response.
        """
        return self.client.post(
            url,
            data=json.dumps(data),
            content_type="application/json",
        )


class TestStartRunValidation(AutomationRoutesTestBase):
    """Tests for POST /api/automation/run input validation."""

    def test_missing_evidence_path(self) -> None:
        """Return 400 when evidence_path is missing."""
        resp = self._post_json("/api/automation/run", {"prompt": "test"})
        self.assertEqual(resp.status_code, 400)
        body = resp.get_json()
        self.assertIn("evidence_path", body["error"])

    def test_empty_evidence_path(self) -> None:
        """Return 400 when evidence_path is empty string."""
        resp = self._post_json(
            "/api/automation/run",
            {"evidence_path": "  ", "prompt": "test"},
        )
        self.assertEqual(resp.status_code, 400)

    def test_missing_prompt(self) -> None:
        """Return 400 when prompt is missing."""
        resp = self._post_json(
            "/api/automation/run",
            {"evidence_path": "/fake/path"},
        )
        self.assertEqual(resp.status_code, 400)
        body = resp.get_json()
        self.assertIn("prompt", body["error"])

    def test_invalid_date_range_format(self) -> None:
        """Return 400 when date_range has invalid date format."""
        resp = self._post_json(
            "/api/automation/run",
            {
                "evidence_path": "/fake/path",
                "prompt": "test",
                "date_range": {"start_date": "not-a-date", "end_date": "2026-04-15"},
            },
        )
        self.assertEqual(resp.status_code, 400)
        body = resp.get_json()
        self.assertIn("date_range", body["error"])

    def test_invalid_date_range_missing_end(self) -> None:
        """Return 400 when date_range has start but no end."""
        resp = self._post_json(
            "/api/automation/run",
            {
                "evidence_path": "/fake/path",
                "prompt": "test",
                "date_range": {"start_date": "2026-04-01"},
            },
        )
        self.assertEqual(resp.status_code, 400)

    def test_non_json_body(self) -> None:
        """Return 400 when body is not valid JSON."""
        resp = self.client.post(
            "/api/automation/run",
            data="not json",
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)


class TestCsrfExemption(AutomationRoutesTestBase):
    """Verify that automation endpoints do not require CSRF tokens."""

    @patch("app.routes.automation.run_automation")
    def test_post_without_csrf_returns_202(self, mock_run: MagicMock) -> None:
        """POST to /api/automation/run without CSRF token should succeed."""
        mock_run.return_value = _make_successful_result()
        resp = self._post_json(
            "/api/automation/run",
            {"evidence_path": "/fake/path.E01", "prompt": "test"},
        )
        # Should not get 403 CSRF error.
        self.assertNotEqual(resp.status_code, 403)
        self.assertIn(resp.status_code, (200, 202))

    def test_cancel_without_csrf(self) -> None:
        """POST to cancel endpoint without CSRF should not return 403."""
        resp = self._post_json("/api/automation/run/nonexistent/cancel", {})
        # 404 because run doesn't exist, but NOT 403.
        self.assertEqual(resp.status_code, 404)


class TestStartRunSuccess(AutomationRoutesTestBase):
    """Tests for successful run initiation."""

    @patch("app.routes.automation.run_automation")
    def test_start_returns_202_with_run_id(self, mock_run: MagicMock) -> None:
        """Successful start returns 202 with run_id and status_url."""
        mock_run.return_value = _make_successful_result()
        resp = self._post_json(
            "/api/automation/run",
            {"evidence_path": "/fake/path.E01", "prompt": "Investigate this"},
        )
        self.assertEqual(resp.status_code, 202)
        body = resp.get_json()
        self.assertTrue(body["success"])
        self.assertIn("run_id", body)
        self.assertEqual(body["status"], "started")
        self.assertIn("status_url", body)
        self.assertIn(body["run_id"], body["status_url"])

    @patch("app.routes.automation.run_automation")
    def test_run_registered_in_state(self, mock_run: MagicMock) -> None:
        """Starting a run registers it in AUTOMATION_RUNS."""
        mock_run.return_value = _make_successful_result()
        resp = self._post_json(
            "/api/automation/run",
            {"evidence_path": "/fake/path.E01", "prompt": "test"},
        )
        body = resp.get_json()
        run_id = body["run_id"]
        # Give thread time to register.
        time.sleep(0.1)
        self.assertIn(run_id, automation_mod.AUTOMATION_RUNS)


class TestConcurrencyLimit(AutomationRoutesTestBase):
    """Tests for the single-concurrent-run limit."""

    def test_second_run_returns_409(self) -> None:
        """Starting a second run while one is active returns 409."""
        # Manually inject a running run.
        with automation_mod.RUNS_LOCK:
            automation_mod.AUTOMATION_RUNS["fake-run"] = {
                "run_id": "fake-run",
                "status": "running",
                "phase": "parsing",
                "message": "busy",
                "percentage": 50.0,
                "started_at": "2026-04-15T10:00:00Z",
                "evidence_path": "/fake",
                "_started_mono": time.monotonic(),
            }

        resp = self._post_json(
            "/api/automation/run",
            {"evidence_path": "/other/path.E01", "prompt": "test"},
        )
        self.assertEqual(resp.status_code, 409)
        body = resp.get_json()
        self.assertIn("already in progress", body["error"])


class TestGetRunStatus(AutomationRoutesTestBase):
    """Tests for GET /api/automation/run/<run_id>/status."""

    def test_not_found(self) -> None:
        """Return 404 for unknown run_id."""
        resp = self.client.get("/api/automation/run/nonexistent/status")
        self.assertEqual(resp.status_code, 404)

    def test_running_status(self) -> None:
        """Return running status with phase and percentage."""
        mono = time.monotonic()
        with automation_mod.RUNS_LOCK:
            automation_mod.AUTOMATION_RUNS["run-1"] = {
                "run_id": "run-1",
                "case_id": "case-abc",
                "status": "running",
                "phase": "parsing",
                "message": "Parsing shimcache",
                "percentage": 45.0,
                "started_at": "2026-04-15T10:30:00Z",
                "completed_at": None,
                "elapsed_seconds": 0.0,
                "evidence_path": "/fake",
                "_started_mono": mono,
            }

        resp = self.client.get("/api/automation/run/run-1/status")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body["success"])
        self.assertEqual(body["status"], "running")
        self.assertEqual(body["phase"], "parsing")
        self.assertEqual(body["percentage"], 45.0)
        self.assertGreaterEqual(body["elapsed_seconds"], 0.0)

    def test_completed_status_includes_result(self) -> None:
        """Completed runs include the result block."""
        with automation_mod.RUNS_LOCK:
            automation_mod.AUTOMATION_RUNS["run-2"] = {
                "run_id": "run-2",
                "case_id": "case-xyz",
                "status": "completed",
                "phase": "done",
                "message": "Automation run completed successfully",
                "percentage": 100.0,
                "started_at": "2026-04-15T10:30:00Z",
                "completed_at": "2026-04-15T10:45:00Z",
                "elapsed_seconds": 900.0,
                "evidence_path": "/fake",
                "_started_mono": time.monotonic() - 900,
                "result": {
                    "html_report_path": "/output/report.html",
                    "json_report_path": "/output/report.json",
                    "evidence_files_processed": 2,
                    "warnings": [],
                },
            }

        resp = self.client.get("/api/automation/run/run-2/status")
        body = resp.get_json()
        self.assertEqual(body["status"], "completed")
        self.assertIsNotNone(body.get("result"))
        self.assertEqual(body["result"]["evidence_files_processed"], 2)
        self.assertEqual(body["completed_at"], "2026-04-15T10:45:00Z")

    def test_failed_status_includes_errors(self) -> None:
        """Failed runs include the errors list."""
        with automation_mod.RUNS_LOCK:
            automation_mod.AUTOMATION_RUNS["run-3"] = {
                "run_id": "run-3",
                "case_id": "case-fail",
                "status": "failed",
                "phase": "analysis",
                "message": "API key invalid",
                "percentage": 30.0,
                "started_at": "2026-04-15T10:30:00Z",
                "elapsed_seconds": 60.0,
                "evidence_path": "/fake",
                "errors": ["API key invalid"],
                "_started_mono": time.monotonic() - 60,
            }

        resp = self.client.get("/api/automation/run/run-3/status")
        body = resp.get_json()
        self.assertEqual(body["status"], "failed")
        self.assertIn("API key invalid", body["errors"])


class TestListRuns(AutomationRoutesTestBase):
    """Tests for GET /api/automation/runs."""

    def test_empty_list(self) -> None:
        """Return empty runs list when no runs exist."""
        resp = self.client.get("/api/automation/runs")
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body["success"])
        self.assertEqual(body["runs"], [])

    def test_lists_all_runs(self) -> None:
        """Return all registered runs."""
        with automation_mod.RUNS_LOCK:
            for i in range(3):
                automation_mod.AUTOMATION_RUNS[f"run-{i}"] = {
                    "run_id": f"run-{i}",
                    "case_id": f"case-{i}",
                    "status": "completed",
                    "started_at": "2026-04-15T10:00:00Z",
                    "evidence_path": f"/path/{i}",
                    "_finished_mono": time.monotonic(),
                }

        resp = self.client.get("/api/automation/runs")
        body = resp.get_json()
        self.assertEqual(len(body["runs"]), 3)


class TestCancelRun(AutomationRoutesTestBase):
    """Tests for POST /api/automation/run/<run_id>/cancel."""

    def test_cancel_not_found(self) -> None:
        """Return 404 for unknown run_id."""
        resp = self._post_json("/api/automation/run/no-such-run/cancel", {})
        self.assertEqual(resp.status_code, 404)

    def test_cancel_running_run(self) -> None:
        """Cancel a running run returns success."""
        cancel_event = threading.Event()
        with automation_mod.RUNS_LOCK:
            automation_mod.AUTOMATION_RUNS["run-cancel"] = {
                "run_id": "run-cancel",
                "case_id": "case-c",
                "status": "running",
                "phase": "parsing",
                "message": "busy",
                "percentage": 50.0,
                "started_at": "2026-04-15T10:00:00Z",
                "evidence_path": "/fake",
                "cancel_event": cancel_event,
                "_started_mono": time.monotonic(),
            }

        resp = self._post_json("/api/automation/run/run-cancel/cancel", {})
        self.assertEqual(resp.status_code, 200)
        body = resp.get_json()
        self.assertTrue(body["success"])
        self.assertIn("cancelled", body.get("message", "").lower())

        # Verify state updated.
        run = automation_mod.AUTOMATION_RUNS["run-cancel"]
        self.assertEqual(run["status"], "cancelled")
        self.assertTrue(cancel_event.is_set())

    def test_cancel_completed_run_returns_409(self) -> None:
        """Cannot cancel a completed run."""
        with automation_mod.RUNS_LOCK:
            automation_mod.AUTOMATION_RUNS["run-done"] = {
                "run_id": "run-done",
                "status": "completed",
                "phase": "done",
                "message": "done",
                "percentage": 100.0,
                "started_at": "2026-04-15T10:00:00Z",
                "evidence_path": "/fake",
                "_started_mono": time.monotonic(),
            }

        resp = self._post_json("/api/automation/run/run-done/cancel", {})
        self.assertEqual(resp.status_code, 409)


class TestReportDownload(AutomationRoutesTestBase):
    """Tests for GET /api/automation/run/<run_id>/report/{html,json}."""

    def test_html_report_not_found_for_unknown_run(self) -> None:
        """Return 404 for unknown run_id."""
        resp = self.client.get("/api/automation/run/no-run/report/html")
        self.assertEqual(resp.status_code, 404)

    def test_html_report_not_available_if_not_completed(self) -> None:
        """Return 404 if run is still running."""
        with automation_mod.RUNS_LOCK:
            automation_mod.AUTOMATION_RUNS["run-r"] = {
                "run_id": "run-r",
                "status": "running",
                "phase": "parsing",
                "message": "",
                "percentage": 0,
                "started_at": "",
                "evidence_path": "/fake",
                "_started_mono": time.monotonic(),
            }

        resp = self.client.get("/api/automation/run/run-r/report/html")
        self.assertEqual(resp.status_code, 404)

    def test_html_report_download(self) -> None:
        """Download HTML report when run is completed and file exists."""
        html_file = Path(self.temp_dir.name) / "report.html"
        html_file.write_text("<html><body>Report</body></html>", encoding="utf-8")

        with automation_mod.RUNS_LOCK:
            automation_mod.AUTOMATION_RUNS["run-ok"] = {
                "run_id": "run-ok",
                "status": "completed",
                "phase": "done",
                "message": "",
                "percentage": 100,
                "started_at": "",
                "evidence_path": "/fake",
                "_started_mono": time.monotonic(),
                "result": {
                    "html_report_path": str(html_file),
                    "json_report_path": None,
                    "evidence_files_processed": 1,
                    "warnings": [],
                },
            }

        resp = self.client.get("/api/automation/run/run-ok/report/html")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Report", resp.data)

    def test_json_report_download(self) -> None:
        """Download JSON report when run is completed and file exists."""
        json_file = Path(self.temp_dir.name) / "report.json"
        json_file.write_text('{"case_id": "test"}', encoding="utf-8")

        with automation_mod.RUNS_LOCK:
            automation_mod.AUTOMATION_RUNS["run-j"] = {
                "run_id": "run-j",
                "status": "completed",
                "phase": "done",
                "message": "",
                "percentage": 100,
                "started_at": "",
                "evidence_path": "/fake",
                "_started_mono": time.monotonic(),
                "result": {
                    "html_report_path": None,
                    "json_report_path": str(json_file),
                    "evidence_files_processed": 1,
                    "warnings": [],
                },
            }

        resp = self.client.get("/api/automation/run/run-j/report/json")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"case_id", resp.data)

    def test_json_report_file_missing_on_disk(self) -> None:
        """Return 404 when the report file doesn't exist on disk."""
        with automation_mod.RUNS_LOCK:
            automation_mod.AUTOMATION_RUNS["run-miss"] = {
                "run_id": "run-miss",
                "status": "completed",
                "phase": "done",
                "message": "",
                "percentage": 100,
                "started_at": "",
                "evidence_path": "/fake",
                "_started_mono": time.monotonic(),
                "result": {
                    "html_report_path": None,
                    "json_report_path": "/nonexistent/path/report.json",
                    "evidence_files_processed": 1,
                    "warnings": [],
                },
            }

        resp = self.client.get("/api/automation/run/run-miss/report/json")
        self.assertEqual(resp.status_code, 404)


class TestRunCleanup(AutomationRoutesTestBase):
    """Tests for expired-run eviction."""

    def test_expired_runs_are_evicted(self) -> None:
        """Completed runs older than RUN_TTL_SECONDS are removed."""
        old_mono = time.monotonic() - automation_mod.RUN_TTL_SECONDS - 10
        with automation_mod.RUNS_LOCK:
            automation_mod.AUTOMATION_RUNS["old-run"] = {
                "run_id": "old-run",
                "status": "completed",
                "phase": "done",
                "message": "",
                "started_at": "",
                "evidence_path": "/fake",
                "_finished_mono": old_mono,
                "_started_mono": old_mono,
            }
            automation_mod.AUTOMATION_RUNS["new-run"] = {
                "run_id": "new-run",
                "status": "completed",
                "phase": "done",
                "message": "",
                "started_at": "",
                "evidence_path": "/fake",
                "_finished_mono": time.monotonic(),
                "_started_mono": time.monotonic(),
            }

        automation_mod._cleanup_expired_runs()

        self.assertNotIn("old-run", automation_mod.AUTOMATION_RUNS)
        self.assertIn("new-run", automation_mod.AUTOMATION_RUNS)

    def test_running_runs_not_evicted(self) -> None:
        """Running runs are never evicted regardless of age."""
        old_mono = time.monotonic() - automation_mod.RUN_TTL_SECONDS - 100
        with automation_mod.RUNS_LOCK:
            automation_mod.AUTOMATION_RUNS["active-run"] = {
                "run_id": "active-run",
                "status": "running",
                "phase": "parsing",
                "message": "",
                "started_at": "",
                "evidence_path": "/fake",
                "_started_mono": old_mono,
            }

        automation_mod._cleanup_expired_runs()
        self.assertIn("active-run", automation_mod.AUTOMATION_RUNS)


class TestBackgroundThread(AutomationRoutesTestBase):
    """Tests for the background automation thread behaviour."""

    @patch("app.routes.automation.run_automation")
    def test_successful_run_updates_state(self, mock_run: MagicMock) -> None:
        """Background thread updates state to completed on success."""
        result = _make_successful_result("case-bg-ok")
        mock_run.return_value = result

        resp = self._post_json(
            "/api/automation/run",
            {"evidence_path": "/fake/path.E01", "prompt": "test"},
        )
        self.assertEqual(resp.status_code, 202)
        run_id = resp.get_json()["run_id"]

        # Wait for the background thread to finish.
        time.sleep(0.5)

        run = automation_mod.AUTOMATION_RUNS.get(run_id)
        self.assertIsNotNone(run)
        self.assertEqual(run["status"], "completed")
        self.assertEqual(run["case_id"], "case-bg-ok")
        self.assertIsNotNone(run["result"])
        self.assertEqual(run["result"]["evidence_files_processed"], 1)

    @patch("app.routes.automation.run_automation")
    def test_failed_run_updates_state(self, mock_run: MagicMock) -> None:
        """Background thread updates state to failed on engine failure."""
        result = _make_failed_result("case-bg-fail")
        mock_run.return_value = result

        resp = self._post_json(
            "/api/automation/run",
            {"evidence_path": "/fake/path.E01", "prompt": "test"},
        )
        run_id = resp.get_json()["run_id"]

        time.sleep(0.5)

        run = automation_mod.AUTOMATION_RUNS.get(run_id)
        self.assertIsNotNone(run)
        self.assertEqual(run["status"], "failed")
        self.assertIn("Evidence path does not exist", run["errors"])

    @patch("app.routes.automation.run_automation")
    def test_exception_in_run_marks_failed(self, mock_run: MagicMock) -> None:
        """Background thread marks run as failed if engine raises."""
        mock_run.side_effect = RuntimeError("boom")

        resp = self._post_json(
            "/api/automation/run",
            {"evidence_path": "/fake/path.E01", "prompt": "test"},
        )
        run_id = resp.get_json()["run_id"]

        time.sleep(0.5)

        run = automation_mod.AUTOMATION_RUNS.get(run_id)
        self.assertIsNotNone(run)
        self.assertEqual(run["status"], "failed")
        self.assertIn("boom", run["errors"][0])

    @patch("app.routes.automation.run_automation")
    def test_cancelled_run_not_overwritten(self, mock_run: MagicMock) -> None:
        """If user cancels before engine finishes, status stays cancelled."""

        def _slow_run(req, progress_callback=None):
            """Simulate a slow run that checks for cancel."""
            time.sleep(0.3)
            return _make_successful_result()

        mock_run.side_effect = _slow_run

        resp = self._post_json(
            "/api/automation/run",
            {"evidence_path": "/fake/path.E01", "prompt": "test"},
        )
        run_id = resp.get_json()["run_id"]

        # Cancel immediately.
        time.sleep(0.05)
        cancel_resp = self._post_json(f"/api/automation/run/{run_id}/cancel", {})
        self.assertEqual(cancel_resp.status_code, 200)

        # Wait for engine to finish.
        time.sleep(0.5)

        run = automation_mod.AUTOMATION_RUNS.get(run_id)
        self.assertEqual(run["status"], "cancelled")


class TestProgressCallback(AutomationRoutesTestBase):
    """Tests for progress callback updating run state."""

    @patch("app.routes.automation.run_automation")
    def test_progress_callback_updates_phase(self, mock_run: MagicMock) -> None:
        """Progress callback updates phase, message, and percentage."""
        callback_holder: list = []

        def _capture_run(req, progress_callback=None):
            """Capture and invoke the progress callback."""
            if progress_callback:
                callback_holder.append(progress_callback)
                progress_callback("hashing", "Hashing evidence.E01", 50.0)
            return _make_successful_result()

        mock_run.side_effect = _capture_run

        resp = self._post_json(
            "/api/automation/run",
            {"evidence_path": "/fake/path.E01", "prompt": "test"},
        )
        run_id = resp.get_json()["run_id"]

        time.sleep(0.5)

        # The run should have been updated by the callback at some point.
        # Since it completed, status is now "completed", but we can verify
        # the callback was invoked.
        self.assertEqual(len(callback_holder), 1)


class TestValidDateRange(AutomationRoutesTestBase):
    """Tests for valid date range handling."""

    @patch("app.routes.automation.run_automation")
    def test_valid_date_range_accepted(self, mock_run: MagicMock) -> None:
        """Valid date range is accepted and passed to the engine."""
        mock_run.return_value = _make_successful_result()

        resp = self._post_json(
            "/api/automation/run",
            {
                "evidence_path": "/fake/path.E01",
                "prompt": "test",
                "date_range": {
                    "start_date": "2026-04-01",
                    "end_date": "2026-04-15",
                },
            },
        )
        self.assertEqual(resp.status_code, 202)

        time.sleep(0.3)

        # Verify the engine was called with the date range.
        call_args = mock_run.call_args
        req = call_args[0][0]
        self.assertEqual(req.date_range, ("2026-04-01", "2026-04-15"))

    @patch("app.routes.automation.run_automation")
    def test_null_date_range_accepted(self, mock_run: MagicMock) -> None:
        """Null date_range is accepted (no filtering)."""
        mock_run.return_value = _make_successful_result()

        resp = self._post_json(
            "/api/automation/run",
            {
                "evidence_path": "/fake/path.E01",
                "prompt": "test",
                "date_range": None,
            },
        )
        self.assertEqual(resp.status_code, 202)


if __name__ == "__main__":
    unittest.main()
