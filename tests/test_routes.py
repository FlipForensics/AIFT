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


class FakeParser(_BaseFakeParser):
    """Parser stub returning ``demo-host`` metadata and an unavailable artifact."""

    def get_image_metadata(self) -> dict[str, str]:
        """Return demo-host metadata matching route-test assertions.

        Returns:
            Dict with ``demo-host`` hostname and extended metadata fields.
        """
        return {
            "hostname": "demo-host",
            "os_version": "Windows 11",
            "domain": "corp.local",
            "ips": "10.1.1.10",
            "timezone": "UTC",
            "install_date": "2025-01-01",
        }

    def get_available_artifacts(self) -> list[dict[str, object]]:
        """Return artifacts including one marked unavailable.

        Returns:
            List with ``runkeys`` (available) and ``tasks`` (unavailable).
        """
        return [
            {"key": "runkeys", "name": "Run/RunOnce Keys", "available": True},
            {"key": "tasks", "name": "Scheduled Tasks", "available": False},
        ]


class RoutesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = TemporaryDirectory(prefix="aift-routes-test-")
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

    def _evidence_patches(
        self,
        parser_cls: type = None,
        analyzer_cls: type = None,
        report_cls: type = None,
        hash_rv: dict | None = None,
        verify_rv: tuple | None = None,
        thread_cls: type | None = None,
        create_prov: object | None = None,
    ):
        """Return an ExitStack with common evidence-related patches.

        Args:
            parser_cls: Fake parser class (default FakeParser).
            analyzer_cls: Fake analyzer class (optional).
            report_cls: Fake report generator class (optional).
            hash_rv: Return value for compute_hashes (default standard).
            verify_rv: Return value for verify_hash (optional).
            thread_cls: Thread replacement class (optional, e.g. ImmediateThread).
            create_prov: Fake provider instance for create_provider (optional).

        Returns:
            A contextlib.ExitStack with all patches applied.
        """
        from contextlib import ExitStack

        if parser_cls is None:
            parser_cls = FakeParser
        if hash_rv is None:
            hash_rv = {"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 4}

        stack = ExitStack()
        # CASES_ROOT
        for mod in (routes, routes_handlers, routes_images, routes_state):
            stack.enter_context(patch.object(mod, "CASES_ROOT", self.cases_root))
        # ForensicParser
        for mod in (routes, routes_handlers, routes_tasks, routes_evidence):
            stack.enter_context(patch.object(mod, "ForensicParser", parser_cls))
        stack.enter_context(patch("app.parser.ForensicParser", parser_cls))
        # ForensicAnalyzer
        if analyzer_cls is not None:
            for mod in (routes, routes_tasks):
                stack.enter_context(patch.object(mod, "ForensicAnalyzer", analyzer_cls))
        # ReportGenerator
        if report_cls is not None:
            for mod in (routes, routes_handlers, routes_evidence):
                stack.enter_context(patch.object(mod, "ReportGenerator", report_cls))
        # compute_hashes
        for mod in (routes, routes_handlers, routes_evidence):
            stack.enter_context(patch.object(mod, "compute_hashes", return_value=dict(hash_rv)))
        stack.enter_context(patch("app.hasher.compute_hashes", return_value=dict(hash_rv)))
        # verify_hash
        if verify_rv is not None:
            for mod in (routes, routes_handlers, routes_evidence):
                stack.enter_context(patch.object(mod, "verify_hash", return_value=verify_rv))
        # threading
        if thread_cls is not None:
            stack.enter_context(patch.object(routes.threading, "Thread", thread_cls))
        # create_provider
        if create_prov is not None:
            for mod in (routes, routes_handlers, routes_tasks_chat):
                stack.enter_context(patch.object(mod, "create_provider", return_value=create_prov))
        return stack

    def test_full_route_flow(self) -> None:
        evidence_path = Path(self.temp_dir.name) / "sample.E01"
        evidence_path.write_bytes(b"demo")

        with self._evidence_patches(
            analyzer_cls=FakeAnalyzer,
            report_cls=FakeReportGenerator,
            verify_rv=(True, "a" * 64),
            thread_cls=ImmediateThread,
        ):
            create_resp = self.client.post("/api/cases", json={"case_name": "Demo Case"})
            self.assertEqual(create_resp.status_code, 201)
            case_id = create_resp.get_json()["case_id"]

            evidence_resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                json={"path": str(evidence_path)},
            )
            self.assertEqual(evidence_resp.status_code, 200)
            self.assertEqual(evidence_resp.get_json()["metadata"]["hostname"], "demo-host")

            parse_resp = self.client.post(
                f"/api/cases/{case_id}/parse",
                json={"artifacts": ["runkeys"]},
            )
            self.assertEqual(parse_resp.status_code, 202)

            # With ImmediateThread, parsing completes synchronously.
            # Verify parse results directly rather than consuming SSE.
            self.assertTrue(routes.CASE_STATES[case_id].get("parse_results"))

            analyze_resp = self.client.post(
                f"/api/cases/{case_id}/analyze",
                json={"prompt": "Investigate persistence"},
            )
            self.assertEqual(analyze_resp.status_code, 202)
            # Verify analysis results directly.
            self.assertTrue(routes.CASE_STATES[case_id].get("analysis_results"))

            csv_resp = self.client.get(f"/api/cases/{case_id}/csvs")
            self.assertEqual(csv_resp.status_code, 200)
            self.assertEqual(csv_resp.mimetype, "application/zip")

            report_resp = self.client.get(f"/api/cases/{case_id}/report")
            self.assertEqual(report_resp.status_code, 200)
            self.assertEqual(report_resp.mimetype, "text/html")
            # Case must remain accessible after report download so that
            # CSV downloads and chat still work on the Results screen.
            self.assertIn(case_id, routes.CASE_STATES)
            self.assertEqual(routes.CASE_STATES[case_id]["status"], "completed")

    def test_case_persists_after_report_download(self) -> None:
        """Report download must NOT destroy the active case so CSV and chat still work."""
        evidence_path = Path(self.temp_dir.name) / "cleanup-check.E01"
        evidence_path.write_bytes(b"demo")

        with self._evidence_patches(
            analyzer_cls=FakeAnalyzer,
            report_cls=FakeReportGenerator,
            verify_rv=(True, "a" * 64),
            thread_cls=ImmediateThread,
        ):
            create_resp = self.client.post("/api/cases", json={"case_name": "Cleanup On Completion"})
            self.assertEqual(create_resp.status_code, 201)
            case_id = create_resp.get_json()["case_id"]

            evidence_resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                json={"path": str(evidence_path)},
            )
            self.assertEqual(evidence_resp.status_code, 200)

            parse_resp = self.client.post(
                f"/api/cases/{case_id}/parse",
                json={"artifacts": ["runkeys"]},
            )
            self.assertEqual(parse_resp.status_code, 202)

            analyze_resp = self.client.post(
                f"/api/cases/{case_id}/analyze",
                json={"prompt": "Investigate persistence"},
            )
            self.assertEqual(analyze_resp.status_code, 202)

            self.assertIn(case_id, routes.CASE_STATES)

            report_resp = self.client.get(f"/api/cases/{case_id}/report")
            self.assertEqual(report_resp.status_code, 200)

            # Case must still be in memory after report download.
            self.assertIn(case_id, routes.CASE_STATES)
            self.assertEqual(routes.CASE_STATES[case_id]["status"], "completed")

            # CSV download must still work after report download.
            csv_resp = self.client.get(f"/api/cases/{case_id}/csvs")
            self.assertEqual(csv_resp.status_code, 200)
            self.assertEqual(csv_resp.mimetype, "application/zip")

            # Chat history endpoint must still work after report download.
            history_resp = self.client.get(f"/api/cases/{case_id}/chat/history")
            self.assertEqual(history_resp.status_code, 200)

    def test_parse_progress_sse_waits_before_emitting_idle(self) -> None:
        with (
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes_handlers, "CASES_ROOT", self.cases_root),
            patch.object(routes_state, "SSE_INITIAL_IDLE_GRACE_SECONDS", 0.4),
        ):
            create_resp = self.client.post("/api/cases", json={"case_name": "SSE Wait Case"})
            self.assertEqual(create_resp.status_code, 201)
            case_id = create_resp.get_json()["case_id"]

            def mark_parse_running() -> None:
                time.sleep(0.05)
                routes.set_progress_status(routes.PARSE_PROGRESS, case_id, "running")
                routes.emit_progress(routes.PARSE_PROGRESS, case_id, {"type": "parse_started"})
                routes.set_progress_status(routes.PARSE_PROGRESS, case_id, "completed")
                routes.emit_progress(routes.PARSE_PROGRESS, case_id, {"type": "parse_completed"})

            worker = threading.Thread(target=mark_parse_running, daemon=True)
            worker.start()

            parse_sse = self.client.get(f"/api/cases/{case_id}/parse/progress")
            self.assertEqual(parse_sse.status_code, 200)
            payload = parse_sse.get_data(as_text=True)
            self.assertIn("parse_started", payload)
            self.assertIn("parse_completed", payload)
            self.assertNotIn('"type":"idle"', payload)

    def test_create_case_preserves_recent_terminal_cases(self) -> None:
        """Creating a new case must NOT evict recently-completed cases."""
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root), patch.object(routes_images, "CASES_ROOT", self.cases_root), patch.object(routes_state, "CASES_ROOT", self.cases_root):
            with routes.STATE_LOCK:
                routes.CASE_STATES["terminal-completed"] = {
                    "status": "completed",
                    "_terminal_since": time.monotonic(),
                }
                routes.PARSE_PROGRESS["terminal-completed"] = routes.new_progress(status="completed")
                routes.ANALYSIS_PROGRESS["terminal-completed"] = routes.new_progress(status="completed")
                routes.CHAT_PROGRESS["terminal-completed"] = routes.new_progress(status="completed")

                routes.CASE_STATES["terminal-failed"] = {
                    "status": "failed",
                    "_terminal_since": time.monotonic(),
                }
                routes.PARSE_PROGRESS["terminal-failed"] = routes.new_progress(status="failed")
                routes.ANALYSIS_PROGRESS["terminal-failed"] = routes.new_progress(status="idle")
                routes.CHAT_PROGRESS["terminal-failed"] = routes.new_progress(status="failed")

                routes.CASE_STATES["active-case"] = {"status": "running"}
                routes.PARSE_PROGRESS["active-case"] = routes.new_progress(status="running")
                routes.ANALYSIS_PROGRESS["active-case"] = routes.new_progress(status="idle")
                routes.CHAT_PROGRESS["active-case"] = routes.new_progress(status="idle")

            create_resp = self.client.post("/api/cases", json={"case_name": "Cleanup Trigger Case"})
            self.assertEqual(create_resp.status_code, 201)
            new_case_id = create_resp.get_json()["case_id"]

            # Recent terminal cases must survive
            self.assertIn("terminal-completed", routes.CASE_STATES)
            self.assertIn("terminal-failed", routes.CASE_STATES)
            self.assertIn("active-case", routes.CASE_STATES)
            self.assertIn(new_case_id, routes.CASE_STATES)
            self.assertIn(new_case_id, routes.PARSE_PROGRESS)
            self.assertIn(new_case_id, routes.ANALYSIS_PROGRESS)
            self.assertIn(new_case_id, routes.CHAT_PROGRESS)

    def test_create_case_cleans_up_expired_terminal_cases(self) -> None:
        """Terminal cases whose TTL has expired are evicted on new case creation."""
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root), patch.object(routes_images, "CASES_ROOT", self.cases_root), patch.object(routes_state, "CASES_ROOT", self.cases_root):
            expired_time = time.monotonic() - routes_state.CASE_TTL_SECONDS - 1
            with routes.STATE_LOCK:
                routes.CASE_STATES["expired-completed"] = {
                    "status": "completed",
                    "_terminal_since": expired_time,
                }
                routes.PARSE_PROGRESS["expired-completed"] = routes.new_progress(status="completed")

                routes.CASE_STATES["expired-error"] = {
                    "status": "error",
                    "_terminal_since": expired_time,
                }
                routes.PARSE_PROGRESS["expired-error"] = routes.new_progress(status="error")

                routes.CASE_STATES["recent-completed"] = {
                    "status": "completed",
                    "_terminal_since": time.monotonic(),
                }
                routes.PARSE_PROGRESS["recent-completed"] = routes.new_progress(status="completed")

            create_resp = self.client.post("/api/cases", json={"case_name": "Expire Test"})
            self.assertEqual(create_resp.status_code, 201)

            self.assertNotIn("expired-completed", routes.CASE_STATES)
            self.assertNotIn("expired-completed", routes.PARSE_PROGRESS)
            self.assertNotIn("expired-error", routes.CASE_STATES)
            self.assertNotIn("expired-error", routes.PARSE_PROGRESS)
            # Recent terminal case must survive
            self.assertIn("recent-completed", routes.CASE_STATES)

    def test_completed_case_usable_after_new_case_created(self) -> None:
        """Complete case 1, create case 2, verify case 1 still serves chat/report/csv."""
        evidence_path = Path(self.temp_dir.name) / "lifecycle.E01"
        evidence_path.write_bytes(b"demo")

        with self._evidence_patches(
            analyzer_cls=FakeAnalyzer,
            report_cls=FakeReportGenerator,
            verify_rv=(True, "a" * 64),
            thread_cls=ImmediateThread,
        ):
            # --- Case 1: full workflow to completion ---
            resp1 = self.client.post("/api/cases", json={"case_name": "Case One"})
            self.assertEqual(resp1.status_code, 201)
            case1_id = resp1.get_json()["case_id"]

            self.client.post(f"/api/cases/{case1_id}/evidence", json={"path": str(evidence_path)})
            self.client.post(f"/api/cases/{case1_id}/parse", json={"artifacts": ["runkeys"]})
            self.client.post(f"/api/cases/{case1_id}/analyze", json={"prompt": "Investigate"})

            self.assertEqual(routes.CASE_STATES[case1_id]["status"], "completed")

            # --- Case 2: creating it must NOT strand case 1 ---
            resp2 = self.client.post("/api/cases", json={"case_name": "Case Two"})
            self.assertEqual(resp2.status_code, 201)

            # Case 1 must still be in memory
            self.assertIn(case1_id, routes.CASE_STATES)

            # Post-analysis endpoints must still work for case 1
            report_resp = self.client.get(f"/api/cases/{case1_id}/report")
            self.assertEqual(report_resp.status_code, 200)

            csv_resp = self.client.get(f"/api/cases/{case1_id}/csvs")
            self.assertEqual(csv_resp.status_code, 200)

            history_resp = self.client.get(f"/api/cases/{case1_id}/chat/history")
            self.assertEqual(history_resp.status_code, 200)

    def test_evidence_upload_includes_split_ewf_segments(self) -> None:
        class CapturingParser(FakeParser):
            opened_paths: list[str] = []

            def __init__(self, evidence_path: str | Path, case_dir: str | Path, audit_logger: object) -> None:
                CapturingParser.opened_paths.append(str(evidence_path))
                super().__init__(evidence_path, case_dir, audit_logger)

        with (
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes_handlers, "CASES_ROOT", self.cases_root),
            patch.object(routes_images, "CASES_ROOT", self.cases_root),
            patch.object(routes_state, "CASES_ROOT", self.cases_root),
            patch.object(routes, "ForensicParser", CapturingParser),
            patch.object(routes_handlers, "ForensicParser", CapturingParser),
            patch.object(routes_tasks, "ForensicParser", CapturingParser),
            patch.object(routes_evidence, "ForensicParser", CapturingParser),
            patch("app.parser.ForensicParser", CapturingParser),
            patch.object(
                routes,
                "compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 12,
                },
            ),
            patch.object(
                routes_handlers,
                "compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 12,
                },
            ),
            patch.object(
                routes_evidence,
                "compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 12,
                },
            ),
            patch(
                "app.hasher.compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 12,
                },
            ),
        ):
            create_resp = self.client.post("/api/cases", json={"case_name": "Split EWF Upload"})
            self.assertEqual(create_resp.status_code, 201)
            case_id = create_resp.get_json()["case_id"]

            upload_resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                data={
                    "evidence_file": [
                        (BytesIO(b"seg1"), "Disk.E01"),
                        (BytesIO(b"seg2"), "Disk.E02"),
                        (BytesIO(b"seg3"), "Disk.E03"),
                    ]
                },
                content_type="multipart/form-data",
            )
            self.assertEqual(upload_resp.status_code, 200)

            payload = upload_resp.get_json()
            self.assertTrue(str(payload["evidence_path"]).endswith("Disk.E01"))
            self.assertEqual(len(payload.get("uploaded_files", [])), 3)

            # Evidence files are stored under images/<image_id>/evidence/
            # after the migration to multi-image layout.
            images_dir = self.cases_root / case_id / "images"
            image_dirs = [d for d in images_dir.iterdir() if d.is_dir()]
            self.assertTrue(image_dirs, "Expected at least one image directory")
            evidence_dir = image_dirs[0] / "evidence"
            self.assertTrue((evidence_dir / "Disk.E01").exists())
            self.assertTrue((evidence_dir / "Disk.E02").exists())
            self.assertTrue((evidence_dir / "Disk.E03").exists())
            self.assertTrue(CapturingParser.opened_paths)
            self.assertTrue(CapturingParser.opened_paths[-1].endswith("Disk.E01"))

    def test_evidence_upload_linux_returns_os_type(self) -> None:
        """Evidence intake with a Linux image should return os_type='linux'."""
        class LinuxParser(FakeParser):
            def __init__(self, evidence_path: str | Path, case_dir: str | Path, audit_logger: object) -> None:
                super().__init__(evidence_path, case_dir, audit_logger)
                self.os_type = "linux"

            def get_image_metadata(self) -> dict[str, str]:
                return {
                    "hostname": "linux-host",
                    "os_version": "Ubuntu 22.04",
                    "domain": "-",
                    "ips": "10.1.1.20",
                    "timezone": "UTC",
                    "install_date": "2025-01-01",
                }

            def get_available_artifacts(self) -> list[dict[str, object]]:
                return [
                    {"key": "bash_history", "name": "Bash History", "available": True},
                    {"key": "syslog", "name": "Syslog", "available": True},
                ]

        with (
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes_handlers, "CASES_ROOT", self.cases_root),
            patch.object(routes_images, "CASES_ROOT", self.cases_root),
            patch.object(routes_state, "CASES_ROOT", self.cases_root),
            patch.object(routes, "ForensicParser", LinuxParser),
            patch.object(routes_handlers, "ForensicParser", LinuxParser),
            patch.object(routes_tasks, "ForensicParser", LinuxParser),
            patch.object(routes_evidence, "ForensicParser", LinuxParser),
            patch("app.parser.ForensicParser", LinuxParser),
            patch.object(
                routes_evidence,
                "compute_hashes",
                return_value={"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 12},
            ),
            patch(
                "app.hasher.compute_hashes",
                return_value={"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 12},
            ),
        ):
            create_resp = self.client.post("/api/cases", json={"case_name": "Linux Case"})
            case_id = create_resp.get_json()["case_id"]

            upload_resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                data={"evidence_file": (BytesIO(b"linux-image"), "disk.E01")},
                content_type="multipart/form-data",
            )
            self.assertEqual(upload_resp.status_code, 200)
            payload = upload_resp.get_json()
            self.assertEqual(payload.get("os_type"), "linux")
            self.assertNotIn("os_warning", payload)

            # Returned artifact keys should come from the Linux registry.
            from app.parser import LINUX_ARTIFACT_REGISTRY
            returned_keys = {
                str(a["key"]) for a in payload.get("available_artifacts", [])
            }
            linux_keys = set(LINUX_ARTIFACT_REGISTRY.keys())
            self.assertTrue(
                returned_keys.issubset(linux_keys),
                f"Returned keys {returned_keys - linux_keys} are not in Linux registry",
            )

    def test_evidence_upload_unknown_os_returns_warning(self) -> None:
        """Evidence intake with unknown OS should include os_warning."""
        class UnknownOsParser(FakeParser):
            def __init__(self, evidence_path: str | Path, case_dir: str | Path, audit_logger: object) -> None:
                super().__init__(evidence_path, case_dir, audit_logger)
                self.os_type = "unknown"

        with (
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes_handlers, "CASES_ROOT", self.cases_root),
            patch.object(routes_images, "CASES_ROOT", self.cases_root),
            patch.object(routes_state, "CASES_ROOT", self.cases_root),
            patch.object(routes, "ForensicParser", UnknownOsParser),
            patch.object(routes_handlers, "ForensicParser", UnknownOsParser),
            patch.object(routes_tasks, "ForensicParser", UnknownOsParser),
            patch.object(routes_evidence, "ForensicParser", UnknownOsParser),
            patch("app.parser.ForensicParser", UnknownOsParser),
            patch.object(
                routes_evidence,
                "compute_hashes",
                return_value={"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 12},
            ),
            patch(
                "app.hasher.compute_hashes",
                return_value={"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 12},
            ),
        ):
            create_resp = self.client.post("/api/cases", json={"case_name": "Unknown OS"})
            case_id = create_resp.get_json()["case_id"]

            upload_resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                data={"evidence_file": (BytesIO(b"mystery"), "disk.E01")},
                content_type="multipart/form-data",
            )
            self.assertEqual(upload_resp.status_code, 200)
            payload = upload_resp.get_json()
            self.assertEqual(payload.get("os_type"), "unknown")
            self.assertIn("os_warning", payload)
            self.assertIn("Could not detect", payload["os_warning"])

    def test_settings_endpoints_mask_api_keys(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root), patch.object(routes_images, "CASES_ROOT", self.cases_root), patch.object(routes_state, "CASES_ROOT", self.cases_root):
            update_resp = self.client.post(
                "/api/settings",
                json={"ai": {"openai": {"api_key": "secret-key", "model": "gpt-test"}}},
            )
            self.assertEqual(update_resp.status_code, 200)
            self.assertEqual(update_resp.get_json()["ai"]["openai"]["api_key"], "********")

            get_resp = self.client.get("/api/settings")
            self.assertEqual(get_resp.status_code, 200)
            self.assertEqual(get_resp.get_json()["ai"]["openai"]["api_key"], "********")

    def test_index_prefers_white_text_logo_and_handles_spaces(self) -> None:
        images_dir = Path(self.temp_dir.name) / "images"
        images_dir.mkdir(parents=True, exist_ok=True)
        (images_dir / "AIFT Logo - White Text.png").write_bytes(b"\x89PNG\r\n\x1a\nwhite")
        (images_dir / "AIFT Logo Wide.png").write_bytes(b"\x89PNG\r\n\x1a\nwide")
        (images_dir / "AIFT_Logo.png").write_bytes(b"\x89PNG\r\n\x1a\nnormal")

        with patch.object(routes, "IMAGES_ROOT", images_dir), patch.object(routes_handlers, "IMAGES_ROOT", images_dir), patch.object(routes_state, "IMAGES_ROOT", images_dir):
            index_resp = self.client.get("/")
            self.assertEqual(index_resp.status_code, 200)
            html = index_resp.get_data(as_text=True)
            self.assertIn("AIFT%20Logo%20-%20White%20Text.png", html)
            self.assertIn("<title>AIFT | Flip Forensics</title>", html)
            self.assertIn(f"v{routes.TOOL_VERSION}", html)
            self.assertIn("©Flip Forensics", html)

            image_resp = self.client.get("/images/AIFT%20Logo%20-%20White%20Text.png")
            self.assertEqual(image_resp.status_code, 200)
            self.assertEqual(image_resp.get_data(), b"\x89PNG\r\n\x1a\nwhite")

            favicon_resp = self.client.get("/favicon.ico")
            self.assertEqual(favicon_resp.status_code, 200)
            self.assertEqual(favicon_resp.get_data(), b"\x89PNG\r\n\x1a\nwhite")

    def test_settings_test_connection_succeeds_without_active_case(self) -> None:
        captured_tokens: list[int] = []

        class FakeConnectionProvider:
            def analyze(
                self,
                system_prompt: str,
                user_prompt: str,
                max_tokens: int = 4096,
            ) -> str:
                del system_prompt, user_prompt
                captured_tokens.append(max_tokens)
                return "Connection OK"

            def get_model_info(self) -> dict[str, str]:
                return {"provider": "local", "model": "demo-model"}

        with patch.object(routes, "create_provider", return_value=FakeConnectionProvider()), patch.object(routes_handlers, "create_provider", return_value=FakeConnectionProvider()):
            response = self.client.post("/api/settings/test-connection")

        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["model_info"]["provider"], "local")
        self.assertEqual(payload["model_info"]["model"], "demo-model")
        self.assertIn("Connection OK", payload["response_preview"])
        self.assertEqual(captured_tokens[-1], 256)

    def test_settings_test_connection_uses_configured_connection_token_limit(self) -> None:
        class FakeConnectionProvider:
            def __init__(self) -> None:
                self.max_tokens_seen = 0

            def analyze(
                self,
                system_prompt: str,
                user_prompt: str,
                max_tokens: int = 4096,
            ) -> str:
                del system_prompt, user_prompt
                self.max_tokens_seen = max_tokens
                return "Connection OK"

            def get_model_info(self) -> dict[str, str]:
                return {"provider": "local", "model": "demo-model"}

        fake_provider = FakeConnectionProvider()
        with patch.object(routes, "create_provider", return_value=fake_provider), patch.object(routes_handlers, "create_provider", return_value=fake_provider):
            update_resp = self.client.post(
                "/api/settings",
                json={"analysis": {"connection_test_max_tokens": 777}},
            )
            self.assertEqual(update_resp.status_code, 200)
            response = self.client.post("/api/settings/test-connection")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(fake_provider.max_tokens_seen, 777)

    def test_settings_test_connection_returns_provider_error(self) -> None:
        class FailingConnectionProvider:
            def analyze(
                self,
                system_prompt: str,
                user_prompt: str,
                max_tokens: int = 4096,
            ) -> str:
                del system_prompt, user_prompt, max_tokens
                raise routes.AIProviderError("Unable to connect to local AI endpoint.")

            def get_model_info(self) -> dict[str, str]:
                return {"provider": "local", "model": "demo-model"}

        with patch.object(routes, "create_provider", return_value=FailingConnectionProvider()), patch.object(routes_handlers, "create_provider", return_value=FailingConnectionProvider()):
            response = self.client.post("/api/settings/test-connection")

        self.assertEqual(response.status_code, 502)
        self.assertIn("Unable to connect to local AI endpoint.", response.get_json()["error"])

    def test_settings_test_connection_returns_config_error(self) -> None:
        with patch.object(routes, "create_provider", side_effect=ValueError("Invalid configuration.")), patch.object(routes_handlers, "create_provider", side_effect=ValueError("Invalid configuration.")):
            response = self.client.post("/api/settings/test-connection")

        self.assertEqual(response.status_code, 400)
        self.assertIn("Invalid configuration.", response.get_json()["error"])

    @patch("openai.OpenAI")
    def test_settings_test_connection_rejects_empty_openai_api_key(self, mock_openai_cls) -> None:
        with patch.dict("os.environ", {"OPENAI_API_KEY": ""}):
            update_resp = self.client.post(
                "/api/settings",
                json={
                    "ai": {
                        "provider": "openai",
                        "openai": {"api_key": "", "model": "gpt-5.4"},
                    }
                },
            )
            self.assertEqual(update_resp.status_code, 200)

            response = self.client.post("/api/settings/test-connection")

        self.assertEqual(response.status_code, 502)
        self.assertIn("API key is not configured", response.get_json()["error"])
        mock_openai_cls.assert_not_called()

    def test_artifact_profiles_endpoints_persist_custom_profiles(self) -> None:
        profiles_dir = Path(self.temp_dir.name) / "profile"
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root), patch.object(routes_images, "CASES_ROOT", self.cases_root), patch.object(routes_state, "CASES_ROOT", self.cases_root):
            list_resp = self.client.get("/api/artifact-profiles")
            self.assertEqual(list_resp.status_code, 200)
            profiles = list_resp.get_json()["profiles"]
            self.assertTrue(any(profile["name"] == "recommended" for profile in profiles))

            save_resp = self.client.post(
                "/api/artifact-profiles",
                json={
                    "name": "IR Minimal",
                    "artifact_options": [
                        {"artifact_key": "runkeys", "mode": "parse_and_ai"},
                        {"artifact_key": "mft", "mode": "parse_only"},
                    ],
                },
            )
            self.assertEqual(save_resp.status_code, 200)
            saved = save_resp.get_json()["profile"]
            self.assertEqual(saved["name"], "IR Minimal")
            self.assertEqual(len(saved["artifact_options"]), 2)

            list_after_save = self.client.get("/api/artifact-profiles")
            self.assertEqual(list_after_save.status_code, 200)
            names = [profile["name"] for profile in list_after_save.get_json()["profiles"]]
            self.assertIn("recommended", names)
            self.assertIn("IR Minimal", names)

        recommended_profile_path = profiles_dir / "recommended.json"
        self.assertTrue(recommended_profile_path.exists())

        saved_profile_path = profiles_dir / "ir_minimal.json"
        self.assertTrue(saved_profile_path.exists())
        saved_payload = json.loads(saved_profile_path.read_text(encoding="utf-8"))
        self.assertEqual(saved_payload["name"], "IR Minimal")
        self.assertEqual(len(saved_payload["artifact_options"]), 2)

    def test_recommended_profile_includes_all_artifacts_except_excluded_defaults(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root), patch.object(routes_images, "CASES_ROOT", self.cases_root), patch.object(routes_state, "CASES_ROOT", self.cases_root):
            response = self.client.get("/api/artifact-profiles")
            self.assertEqual(response.status_code, 200)

        payload = response.get_json()
        profiles = payload["profiles"]
        recommended = next(
            profile for profile in profiles if str(profile.get("name", "")).strip().lower() == "recommended"
        )
        options = list(recommended.get("artifact_options", []))
        option_keys = [str(option.get("artifact_key", "")).strip() for option in options]

        # The recommended profile now includes both Windows and Linux
        # artifacts (minus the excluded set), so profiles work for any OS.
        from app.parser import LINUX_ARTIFACT_REGISTRY
        expected_keys: list[str] = []
        seen: set[str] = set()
        for registry in (routes.WINDOWS_ARTIFACT_REGISTRY, LINUX_ARTIFACT_REGISTRY):
            for artifact_key in registry:
                normalized = artifact_key.lower()
                if normalized in routes.RECOMMENDED_PROFILE_EXCLUDED_ARTIFACTS:
                    continue
                if normalized in seen:
                    continue
                seen.add(normalized)
                expected_keys.append(artifact_key)

        self.assertEqual(option_keys, expected_keys)
        self.assertNotIn("mft", option_keys)
        self.assertNotIn("usnjrnl", option_keys)
        self.assertNotIn("evtx", option_keys)
        self.assertNotIn("defender.evtx", option_keys)
        # Linux artifacts should now be present.
        self.assertIn("bash_history", option_keys)
        self.assertIn("syslog", option_keys)
        self.assertTrue(all(str(option.get("mode", "")) == "parse_and_ai" for option in options))

    def test_settings_update_persists_csv_output_dir(self) -> None:
        csv_output_dir = str((Path(self.temp_dir.name) / "csv output").resolve())
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root), patch.object(routes_images, "CASES_ROOT", self.cases_root), patch.object(routes_state, "CASES_ROOT", self.cases_root):
            update_resp = self.client.post(
                "/api/settings",
                json={"evidence": {"csv_output_dir": csv_output_dir}},
            )
            self.assertEqual(update_resp.status_code, 200)
            self.assertEqual(update_resp.get_json()["evidence"]["csv_output_dir"], csv_output_dir)

        persisted = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
        self.assertEqual(
            persisted.get("evidence", {}).get("csv_output_dir", ""),
            csv_output_dir,
        )

    def test_settings_update_persists_advanced_analysis_settings(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root), patch.object(routes_images, "CASES_ROOT", self.cases_root), patch.object(routes_state, "CASES_ROOT", self.cases_root):
            update_resp = self.client.post(
                "/api/settings",
                json={
                    "analysis": {
                        "ai_max_tokens": 2048,
                        "shortened_prompt_cutoff_tokens": 64000,
                        "artifact_deduplication_enabled": False,
                    },
                    "ai": {
                        "openai": {"attach_csv_as_file": False},
                        "local": {
                            "attach_csv_as_file": False,
                            "request_timeout_seconds": 5400,
                        },
                    },
                },
            )
            self.assertEqual(update_resp.status_code, 200)
            payload = update_resp.get_json()
            self.assertEqual(payload["analysis"]["ai_max_tokens"], 2048)
            self.assertEqual(payload["analysis"]["shortened_prompt_cutoff_tokens"], 64000)
            self.assertEqual(payload["analysis"]["artifact_deduplication_enabled"], False)
            self.assertFalse(payload["ai"]["openai"]["attach_csv_as_file"])
            self.assertFalse(payload["ai"]["local"]["attach_csv_as_file"])
            self.assertEqual(payload["ai"]["local"]["request_timeout_seconds"], 5400)

        persisted = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
        self.assertEqual(persisted.get("analysis", {}).get("ai_max_tokens"), 2048)
        self.assertEqual(persisted.get("analysis", {}).get("shortened_prompt_cutoff_tokens"), 64000)
        self.assertEqual(persisted.get("analysis", {}).get("artifact_deduplication_enabled"), False)
        self.assertEqual(persisted.get("ai", {}).get("openai", {}).get("attach_csv_as_file"), False)
        self.assertEqual(persisted.get("ai", {}).get("local", {}).get("attach_csv_as_file"), False)
        self.assertEqual(persisted.get("ai", {}).get("local", {}).get("request_timeout_seconds"), 5400)

    def test_evidence_path_strips_quotes(self) -> None:
        evidence_path = Path(self.temp_dir.name) / "quoted.E01"
        evidence_path.write_bytes(b"demo")

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
                routes,
                "compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 4,
                },
            ),
            patch.object(
                routes_handlers,
                "compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 4,
                },
            ),
            patch.object(
                routes_evidence,
                "compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 4,
                },
            ),
        ):
            create_resp = self.client.post("/api/cases", json={"case_name": "Quoted Path Case"})
            self.assertEqual(create_resp.status_code, 201)
            case_id = create_resp.get_json()["case_id"]

            quoted_path = f'"{evidence_path}"'
            evidence_resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                json={"path": quoted_path},
            )
            self.assertEqual(evidence_resp.status_code, 200)

            payload = evidence_resp.get_json()
            self.assertEqual(payload["source_mode"], "path")
            self.assertEqual(Path(payload["source_path"]), evidence_path)

    def test_parse_date_range_is_optional_but_still_validated(self) -> None:
        evidence_path = Path(self.temp_dir.name) / "windowed.E01"
        evidence_path.write_bytes(b"demo")

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
                routes,
                "compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 4,
                },
            ),
            patch.object(
                routes_handlers,
                "compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 4,
                },
            ),
            patch.object(
                routes_evidence,
                "compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 4,
                },
            ),
            patch(
                "app.hasher.compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 4,
                },
            ),
            patch.object(routes.threading, "Thread", ImmediateThread),
        ):
            create_resp = self.client.post("/api/cases", json={"case_name": "Date Filter Case"})
            self.assertEqual(create_resp.status_code, 201)
            case_id = create_resp.get_json()["case_id"]

            evidence_resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                json={"path": str(evidence_path)},
            )
            self.assertEqual(evidence_resp.status_code, 200)

            missing_range_resp = self.client.post(
                f"/api/cases/{case_id}/parse",
                json={"artifacts": ["mft"]},
            )
            self.assertEqual(missing_range_resp.status_code, 202)
            self.assertNotIn("analysis_date_range", missing_range_resp.get_json())

            partial_range_resp = self.client.post(
                f"/api/cases/{case_id}/parse",
                json={
                    "artifacts": ["evtx"],
                    "analysis_date_range": {"start_date": "2026-01-01"},
                },
            )
            self.assertEqual(partial_range_resp.status_code, 400)
            self.assertIn("Provide both", partial_range_resp.get_json()["error"])

            parse_only_resp = self.client.post(
                f"/api/cases/{case_id}/parse",
                json={"artifact_options": [{"artifact_key": "mft", "mode": "parse_only"}]},
            )
            self.assertEqual(parse_only_resp.status_code, 202)

            runkeys_resp = self.client.post(
                f"/api/cases/{case_id}/parse",
                json={"artifacts": ["runkeys"]},
            )
            self.assertEqual(runkeys_resp.status_code, 202)

    def test_parse_persists_analysis_date_range(self) -> None:
        evidence_path = Path(self.temp_dir.name) / "persist-range.E01"
        evidence_path.write_bytes(b"demo")

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
                routes,
                "compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 4,
                },
            ),
            patch.object(
                routes_handlers,
                "compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 4,
                },
            ),
            patch.object(
                routes_evidence,
                "compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 4,
                },
            ),
            patch(
                "app.hasher.compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 4,
                },
            ),
            patch.object(routes.threading, "Thread", ImmediateThread),
        ):
            create_resp = self.client.post("/api/cases", json={"case_name": "Persist Range Case"})
            self.assertEqual(create_resp.status_code, 201)
            case_id = create_resp.get_json()["case_id"]

            evidence_resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                json={"path": str(evidence_path)},
            )
            self.assertEqual(evidence_resp.status_code, 200)

            requested_range = {"start_date": "2026-01-01", "end_date": "2026-01-31"}
            parse_resp = self.client.post(
                f"/api/cases/{case_id}/parse",
                json={"artifacts": ["mft"], "analysis_date_range": requested_range},
            )
            self.assertEqual(parse_resp.status_code, 202)
            self.assertEqual(parse_resp.get_json()["analysis_date_range"], requested_range)
            self.assertEqual(
                routes.CASE_STATES[case_id]["analysis_date_range"],
                requested_range,
            )

    def test_parse_and_analyze_respects_parse_only_artifact_modes(self) -> None:
        evidence_path = Path(self.temp_dir.name) / "parse-only-flow.E01"
        evidence_path.write_bytes(b"demo")

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
            patch.object(routes, "ForensicAnalyzer", FakeAnalyzer),
            patch.object(routes_tasks, "ForensicAnalyzer", FakeAnalyzer),
            patch.object(
                routes,
                "compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 4,
                },
            ),
            patch.object(
                routes_handlers,
                "compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 4,
                },
            ),
            patch.object(
                routes_evidence,
                "compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 4,
                },
            ),
            patch(
                "app.hasher.compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 4,
                },
            ),
            patch.object(routes.threading, "Thread", ImmediateThread),
        ):
            create_resp = self.client.post("/api/cases", json={"case_name": "Parse Only Case"})
            self.assertEqual(create_resp.status_code, 201)
            case_id = create_resp.get_json()["case_id"]

            evidence_resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                json={"path": str(evidence_path)},
            )
            self.assertEqual(evidence_resp.status_code, 200)

            parse_resp = self.client.post(
                f"/api/cases/{case_id}/parse",
                json={
                    "artifact_options": [
                        {"artifact_key": "runkeys", "mode": "parse_and_ai"},
                        {"artifact_key": "tasks", "mode": "parse_only"},
                    ]
                },
            )
            self.assertEqual(parse_resp.status_code, 202)
            payload = parse_resp.get_json()
            self.assertEqual(payload["artifacts"], ["runkeys", "tasks"])
            self.assertEqual(payload["ai_artifacts"], ["runkeys"])

            analyze_resp = self.client.post(
                f"/api/cases/{case_id}/analyze",
                json={"prompt": "Investigate persistence"},
            )
            self.assertEqual(analyze_resp.status_code, 202)
            self.assertEqual(FakeAnalyzer.last_artifact_keys, ["runkeys"])

    def test_analysis_running_conflict_does_not_overwrite_prompt_file(self) -> None:
        evidence_path = Path(self.temp_dir.name) / "analysis-lock-conflict.E01"
        evidence_path.write_bytes(b"demo")

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
            patch.object(routes.threading, "Thread", ImmediateThread),
            patch.object(
                routes,
                "compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 4,
                },
            ),
            patch.object(
                routes_handlers,
                "compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 4,
                },
            ),
            patch.object(
                routes_evidence,
                "compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 4,
                },
            ),
        ):
            create_resp = self.client.post("/api/cases", json={"case_name": "Analysis Lock Case"})
            self.assertEqual(create_resp.status_code, 201)
            case_id = create_resp.get_json()["case_id"]

            evidence_resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                json={"path": str(evidence_path)},
            )
            self.assertEqual(evidence_resp.status_code, 200)

            parse_resp = self.client.post(
                f"/api/cases/{case_id}/parse",
                json={"artifacts": ["runkeys"]},
            )
            self.assertEqual(parse_resp.status_code, 202)

            case_state = routes.CASE_STATES[case_id]
            prompt_path = Path(case_state["case_dir"]) / "prompt.txt"
            prompt_path.write_text("existing prompt", encoding="utf-8")

            with routes.STATE_LOCK:
                routes.ANALYSIS_PROGRESS[case_id] = routes.new_progress(status="running")
                case_state["status"] = "running"

            analyze_resp = self.client.post(
                f"/api/cases/{case_id}/analyze",
                json={"prompt": "new prompt that should not be written"},
            )
            self.assertEqual(analyze_resp.status_code, 409)
            self.assertEqual(prompt_path.read_text(encoding="utf-8"), "existing prompt")

    def test_analysis_requires_ai_enabled_artifacts(self) -> None:
        evidence_path = Path(self.temp_dir.name) / "no-ai.E01"
        evidence_path.write_bytes(b"demo")

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
            patch.object(routes.threading, "Thread", ImmediateThread),
            patch.object(
                routes,
                "compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 4,
                },
            ),
            patch.object(
                routes_handlers,
                "compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 4,
                },
            ),
            patch.object(
                routes_evidence,
                "compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 4,
                },
            ),
        ):
            create_resp = self.client.post("/api/cases", json={"case_name": "No AI Artifacts Case"})
            self.assertEqual(create_resp.status_code, 201)
            case_id = create_resp.get_json()["case_id"]

            evidence_resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                json={"path": str(evidence_path)},
            )
            self.assertEqual(evidence_resp.status_code, 200)

            parse_resp = self.client.post(
                f"/api/cases/{case_id}/parse",
                json={"artifact_options": [{"artifact_key": "runkeys", "mode": "parse_only"}]},
            )
            self.assertEqual(parse_resp.status_code, 202)

            analyze_resp = self.client.post(
                f"/api/cases/{case_id}/analyze",
                json={"prompt": "Investigate"},
            )
            self.assertEqual(analyze_resp.status_code, 400)
            self.assertIn("Parse and use in AI", analyze_resp.get_json()["error"])

    def test_analyze_persists_analysis_results_json(self) -> None:
        evidence_path = Path(self.temp_dir.name) / "analysis-results.E01"
        evidence_path.write_bytes(b"demo")

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
            patch.object(routes, "ForensicAnalyzer", FakeAnalyzer),
            patch.object(routes_tasks, "ForensicAnalyzer", FakeAnalyzer),
            patch.object(routes.threading, "Thread", ImmediateThread),
            patch.object(
                routes,
                "compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 4,
                },
            ),
            patch.object(
                routes_handlers,
                "compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 4,
                },
            ),
            patch.object(
                routes_evidence,
                "compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 4,
                },
            ),
        ):
            create_resp = self.client.post("/api/cases", json={"case_name": "Persist Analysis Results Case"})
            self.assertEqual(create_resp.status_code, 201)
            case_id = create_resp.get_json()["case_id"]

            evidence_resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                json={"path": str(evidence_path)},
            )
            self.assertEqual(evidence_resp.status_code, 200)

            parse_resp = self.client.post(
                f"/api/cases/{case_id}/parse",
                json={"artifacts": ["runkeys"]},
            )
            self.assertEqual(parse_resp.status_code, 202)

            analyze_resp = self.client.post(
                f"/api/cases/{case_id}/analyze",
                json={"prompt": "Investigate persistence"},
            )
            self.assertEqual(analyze_resp.status_code, 202)

        analysis_results_path = self.cases_root / case_id / "analysis_results.json"
        self.assertTrue(analysis_results_path.exists())
        persisted_results = json.loads(analysis_results_path.read_text(encoding="utf-8"))
        self.assertEqual(persisted_results["summary"], "final summary")
        self.assertEqual(persisted_results["per_artifact"][0]["artifact_key"], "runkeys")

    def test_chat_endpoints_store_history_and_return_retrieval_details(self) -> None:
        evidence_path = Path(self.temp_dir.name) / "chat-endpoints.E01"
        evidence_path.write_bytes(b"demo")

        class FakeChatProvider:
            def __init__(self) -> None:
                self.calls: list[dict[str, object]] = []

            def analyze_stream(
                self,
                system_prompt: str,
                user_prompt: str,
                max_tokens: int = 4096,
            ) -> object:
                self.calls.append(
                    {
                        "system_prompt": system_prompt,
                        "user_prompt": user_prompt,
                        "max_tokens": max_tokens,
                    }
                )
                yield "Chat response "
                yield "from test provider."

            def get_model_info(self) -> dict[str, str]:
                return {"provider": "fake", "model": "fake-chat"}

        fake_provider = FakeChatProvider()

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
            patch.object(routes, "ForensicAnalyzer", FakeAnalyzer),
            patch.object(routes_tasks, "ForensicAnalyzer", FakeAnalyzer),
            patch.object(routes.threading, "Thread", ImmediateThread),
            patch.object(routes, "create_provider", return_value=fake_provider),
            patch.object(routes_handlers, "create_provider", return_value=fake_provider),
            patch.object(routes_tasks_chat, "create_provider", return_value=fake_provider),
            patch.object(
                routes,
                "compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 4,
                },
            ),
            patch.object(
                routes_handlers,
                "compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 4,
                },
            ),
            patch.object(
                routes_evidence,
                "compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 4,
                },
            ),
        ):
            settings_resp = self.client.post(
                "/api/settings",
                json={"analysis": {"ai_max_tokens": 2222}},
            )
            self.assertEqual(settings_resp.status_code, 200)

            create_resp = self.client.post("/api/cases", json={"case_name": "Chat Endpoints Case"})
            self.assertEqual(create_resp.status_code, 201)
            case_id = create_resp.get_json()["case_id"]

            evidence_resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                json={"path": str(evidence_path)},
            )
            self.assertEqual(evidence_resp.status_code, 200)

            parse_resp = self.client.post(
                f"/api/cases/{case_id}/parse",
                json={"artifacts": ["runkeys"]},
            )
            self.assertEqual(parse_resp.status_code, 202)

            analyze_resp = self.client.post(
                f"/api/cases/{case_id}/analyze",
                json={"prompt": "Investigate persistence"},
            )
            self.assertEqual(analyze_resp.status_code, 202)

            user_message = "Check the runkeys CSV and show me rows related to persistence."
            chat_resp = self.client.post(
                f"/api/cases/{case_id}/chat",
                json={"message": user_message},
            )
            self.assertEqual(chat_resp.status_code, 202)
            chat_payload = chat_resp.get_json()
            self.assertEqual(chat_payload["status"], "processing")

            chat_stream_resp = self.client.get(f"/api/cases/{case_id}/chat/stream")
            self.assertEqual(chat_stream_resp.status_code, 200)
            stream_payload = chat_stream_resp.get_data(as_text=True)
            self.assertIn('"type":"token"', stream_payload)
            self.assertIn('"type":"done"', stream_payload)
            self.assertIn("Chat response ", stream_payload)
            self.assertIn("from test provider.", stream_payload)
            self.assertIn('"data_retrieved":["runkeys.csv"]', stream_payload)

            history_resp = self.client.get(f"/api/cases/{case_id}/chat/history")
            self.assertEqual(history_resp.status_code, 200)
            history_data = history_resp.get_json()
            self.assertTrue(history_data["success"])
            history = history_data["messages"]
            self.assertEqual([entry["role"] for entry in history], ["user", "assistant"])
            self.assertEqual(history[0]["content"], user_message)
            self.assertEqual(history[1]["content"], "Chat response from test provider.")
            # After the SSE stream ends, the progress entry is marked drained
            # but retained so reconnecting clients get a proper completion signal.
            self.assertIn(case_id, routes.CHAT_PROGRESS)
            self.assertTrue(routes.CHAT_PROGRESS[case_id].get("_drained"))

            clear_history_resp = self.client.delete(f"/api/cases/{case_id}/chat/history")
            self.assertEqual(clear_history_resp.status_code, 200)
            clear_data = clear_history_resp.get_json()
            self.assertTrue(clear_data["success"])
            self.assertEqual(clear_data["status"], "cleared")

            history_after_clear_resp = self.client.get(f"/api/cases/{case_id}/chat/history")
            self.assertEqual(history_after_clear_resp.status_code, 200)
            after_clear_data = history_after_clear_resp.get_json()
            self.assertTrue(after_clear_data["success"])
            self.assertEqual(after_clear_data["messages"], [])

            self.assertTrue(fake_provider.calls)
            first_call = fake_provider.calls[0]
            self.assertIn("digital forensic analyst", str(first_call["system_prompt"]).lower())
            self.assertIn("Context Block:", str(first_call["user_prompt"]))
            self.assertIn("New User Question:", str(first_call["user_prompt"]))
            self.assertIn("Retrieved CSV data for this question", str(first_call["user_prompt"]))
            # 20% of ai_max_tokens (2222) is allocated for the AI response.
            self.assertEqual(first_call["max_tokens"], int(2222 * 0.2))

        audit_entries = routes.read_audit_entries(self.cases_root / case_id)
        audit_actions = {str(entry.get("action", "")) for entry in audit_entries}
        self.assertIn("chat_message_sent", audit_actions)
        self.assertIn("chat_response_received", audit_actions)
        self.assertIn("chat_data_retrieval", audit_actions)

    def test_parse_uses_configured_csv_output_directory(self) -> None:
        evidence_path = Path(self.temp_dir.name) / "configured-output.E01"
        evidence_path.write_bytes(b"demo")
        configured_output_root = Path(self.temp_dir.name) / "external csv output"

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
                routes,
                "compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 4,
                },
            ),
            patch.object(
                routes_handlers,
                "compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 4,
                },
            ),
            patch.object(
                routes_evidence,
                "compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 4,
                },
            ),
            patch(
                "app.hasher.compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 4,
                },
            ),
            patch.object(routes.threading, "Thread", ImmediateThread),
        ):
            settings_resp = self.client.post(
                "/api/settings",
                json={"evidence": {"csv_output_dir": str(configured_output_root)}},
            )
            self.assertEqual(settings_resp.status_code, 200)

            create_resp = self.client.post("/api/cases", json={"case_name": "Custom CSV Path Case"})
            self.assertEqual(create_resp.status_code, 201)
            case_id = create_resp.get_json()["case_id"]

            evidence_resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                json={"path": str(evidence_path)},
            )
            self.assertEqual(evidence_resp.status_code, 200)

            parse_resp = self.client.post(
                f"/api/cases/{case_id}/parse",
                json={"artifacts": ["runkeys"]},
            )
            self.assertEqual(parse_resp.status_code, 202)

            case_state = routes.CASE_STATES[case_id]
            # In multi-image layout, csv_output_dir is the image's parsed dir
            csv_output = Path(case_state["csv_output_dir"])
            self.assertTrue(csv_output.is_dir())
            csv_path = Path(case_state["artifact_csv_paths"]["runkeys"])
            self.assertTrue(csv_path.exists())
            self.assertEqual(csv_path.parent, csv_output)

            csv_bundle_resp = self.client.get(f"/api/cases/{case_id}/csvs")
            self.assertEqual(csv_bundle_resp.status_code, 200)
            self.assertEqual(csv_bundle_resp.mimetype, "application/zip")

    def test_report_hash_verification_uses_evidence_file_hashes_for_zip(self) -> None:
        zip_path = Path(self.temp_dir.name) / "sample.zip"
        with ZipFile(zip_path, "w") as archive:
            archive.writestr("sample.E01", b"demo")

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
            patch.object(routes, "ReportGenerator", FakeReportGenerator),
            patch.object(routes_handlers, "ReportGenerator", FakeReportGenerator),
            patch.object(routes_evidence, "ReportGenerator", FakeReportGenerator),
            patch.object(
                routes,
                "compute_hashes",
                return_value={"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 4},
            ),
            patch.object(
                routes_handlers,
                "compute_hashes",
                return_value={"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 4},
            ),
            patch.object(
                routes_evidence,
                "compute_hashes",
                return_value={"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 4},
            ),
            patch(
                "app.hasher.compute_hashes",
                return_value={"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 4},
            ),
            patch.object(routes, "verify_hash", return_value=(True, "a" * 64)),
            patch.object(routes_handlers, "verify_hash", return_value=(True, "a" * 64)),
            patch.object(routes_evidence, "verify_hash", return_value=(True, "a" * 64)) as verify_hash_mock,
        ):
            create_resp = self.client.post("/api/cases", json={"case_name": "ZIP Case"})
            self.assertEqual(create_resp.status_code, 201)
            case_id = create_resp.get_json()["case_id"]

            evidence_resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                json={"path": str(zip_path)},
            )
            self.assertEqual(evidence_resp.status_code, 200)
            self.assertTrue(evidence_resp.get_json()["evidence_path"].lower().endswith(".e01"))

            # Verify evidence_file_hashes was stored with the zip path.
            with routes.STATE_LOCK:
                file_hashes = routes.CASE_STATES[case_id].get("evidence_file_hashes", [])
            self.assertEqual(len(file_hashes), 1)
            self.assertEqual(file_hashes[0]["path"], str(zip_path))

            # Inject minimal analysis results so the report guard passes.
            with routes.STATE_LOCK:
                routes.CASE_STATES[case_id]["analysis_results"] = {"summary": "test", "per_artifact": []}

            report_resp = self.client.get(f"/api/cases/{case_id}/report")
            self.assertEqual(report_resp.status_code, 200)

            # verify_hash called with the zip path (from evidence_file_hashes).
            verify_hash_mock.assert_called_once()
            called_path = verify_hash_mock.call_args.args[0]
            self.assertEqual(str(called_path), str(zip_path))

            audit_path = self.cases_root / case_id / "audit.jsonl"
            audit_entries = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            hash_events = [entry for entry in audit_entries if entry.get("action") == "hash_verification"]
            self.assertTrue(hash_events)
            details = hash_events[-1].get("details", {})
            self.assertEqual(details.get("expected_sha256"), "a" * 64)
            self.assertTrue(details.get("match"))

    def test_extract_zip_without_image_returns_directory_target(self) -> None:
        zip_path = Path(self.temp_dir.name) / "triage.zip"
        destination = Path(self.temp_dir.name) / "triage_extract"
        with ZipFile(zip_path, "w") as archive:
            archive.writestr("Windows/System32/config/SAM", b"sam")
            archive.writestr("Users/Alice/NTUSER.DAT", b"profile")

        dissect_target = routes_evidence._extract_zip(zip_path, destination)

        self.assertEqual(dissect_target, destination)
        self.assertTrue(dissect_target.is_dir())

    def test_extract_zip_with_wrapper_directory_returns_wrapper_path(self) -> None:
        zip_path = Path(self.temp_dir.name) / "triage_wrapped.zip"
        destination = Path(self.temp_dir.name) / "triage_wrapped_extract"
        with ZipFile(zip_path, "w") as archive:
            archive.writestr("collection/Windows/System32/config/SAM", b"sam")
            archive.writestr("collection/Users/Alice/NTUSER.DAT", b"profile")

        dissect_target = routes_evidence._extract_zip(zip_path, destination)

        self.assertEqual(dissect_target, destination / "collection")
        self.assertTrue(dissect_target.is_dir())

    def test_evidence_intake_unexpected_error_returns_friendly_message(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root), patch.object(routes_images, "CASES_ROOT", self.cases_root), patch.object(routes_state, "CASES_ROOT", self.cases_root):
            create_resp = self.client.post("/api/cases", json={"case_name": "Friendly Error Case"})
            self.assertEqual(create_resp.status_code, 201)
            case_id = create_resp.get_json()["case_id"]

            with patch.object(routes, "resolve_evidence_payload", side_effect=RuntimeError("internal-boom")), patch.object(routes_evidence, "resolve_evidence_payload", side_effect=RuntimeError("internal-boom")):
                response = self.client.post(f"/api/cases/{case_id}/evidence", json={"path": "C:\\bad.E01"})

        self.assertEqual(response.status_code, 500)
        error_message = response.get_json()["error"]
        self.assertIn("Evidence intake failed due to an unexpected error", error_message)
        self.assertNotIn("internal-boom", error_message)

    def test_case_log_file_collects_module_logs_in_single_file(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root), patch.object(routes_images, "CASES_ROOT", self.cases_root), patch.object(routes_state, "CASES_ROOT", self.cases_root):
            create_resp = self.client.post("/api/cases", json={"case_name": "Unified Log Case"})
            self.assertEqual(create_resp.status_code, 201)
            case_id = str(create_resp.get_json()["case_id"])
            case_dir = self.cases_root / case_id

            with patch.object(routes, "resolve_evidence_payload", side_effect=RuntimeError("internal-boom")), patch.object(routes_evidence, "resolve_evidence_payload", side_effect=RuntimeError("internal-boom")):
                response = self.client.post(f"/api/cases/{case_id}/evidence", json={"path": "C:\\bad.E01"})
            self.assertEqual(response.status_code, 500)

            with routes.case_log_context(case_id):
                logging.getLogger("app.analyzer").warning("analyzer-log-marker")
                logging.getLogger("app.parser").warning("parser-log-marker")

            log_dir = case_dir / "logs"
            log_path = log_dir / "application.log"
            self.assertTrue(log_path.exists())
            self.assertEqual(sorted(path.name for path in log_dir.glob("*.log")), ["application.log"])
            log_contents = log_path.read_text(encoding="utf-8")

        self.assertIn("Initialized case logging", log_contents)
        self.assertIn("Evidence intake failed for case", log_contents)
        self.assertIn("analyzer-log-marker", log_contents)
        self.assertIn("parser-log-marker", log_contents)

    def test_settings_update_does_not_persist_env_api_keys(self) -> None:
        with (
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes_handlers, "CASES_ROOT", self.cases_root),
            patch.dict("os.environ", {"OPENAI_API_KEY": "env-only-secret"}, clear=False),
        ):
            update_resp = self.client.post(
                "/api/settings",
                json={"server": {"port": 5051}},
            )
            self.assertEqual(update_resp.status_code, 200)

        persisted = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
        persisted_key = persisted.get("ai", {}).get("openai", {}).get("api_key", "")
        self.assertEqual(persisted_key, "")

    def test_settings_update_writes_config_changed_audit_entries(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root), patch.object(routes_images, "CASES_ROOT", self.cases_root), patch.object(routes_state, "CASES_ROOT", self.cases_root):
            create_resp = self.client.post("/api/cases", json={"case_name": "Settings Audit Case"})
            self.assertEqual(create_resp.status_code, 201)
            case_id = create_resp.get_json()["case_id"]

            update_resp = self.client.post(
                "/api/settings",
                json={
                    "server": {"port": 5052},
                    "ai": {"openai": {"api_key": "new-secret"}},
                },
            )
            self.assertEqual(update_resp.status_code, 200)

            audit_path = self.cases_root / case_id / "audit.jsonl"
            self.assertTrue(audit_path.exists())
            audit_entries = [
                json.loads(line)
                for line in audit_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            config_events = [entry for entry in audit_entries if entry.get("action") == "config_changed"]
            self.assertTrue(config_events, "Expected at least one config_changed audit entry.")

            details = config_events[-1].get("details", {})
            changed_keys = details.get("changed_keys", [])
            self.assertIn("server.port", changed_keys)
            self.assertIn("ai.openai.api_key (redacted)", changed_keys)


    # ------------------------------------------------------------------
    # Route edge-case tests
    # ------------------------------------------------------------------

    def test_create_case_auto_generates_name_when_missing(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root), patch.object(routes_images, "CASES_ROOT", self.cases_root), patch.object(routes_state, "CASES_ROOT", self.cases_root):
            resp = self.client.post("/api/cases", json={})
            self.assertEqual(resp.status_code, 201)
            payload = resp.get_json()
            self.assertTrue(payload["success"])
            self.assertTrue(payload["case_name"].startswith("Case "))

    def test_create_case_auto_generates_name_when_blank(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root), patch.object(routes_images, "CASES_ROOT", self.cases_root), patch.object(routes_state, "CASES_ROOT", self.cases_root):
            resp = self.client.post("/api/cases", json={"case_name": "   "})
            self.assertEqual(resp.status_code, 201)
            self.assertTrue(resp.get_json()["case_name"].startswith("Case "))

    def test_favicon_returns_404_when_no_logo(self) -> None:
        missing_dir = Path(self.temp_dir.name) / "no_images"
        with patch.object(routes_state, "IMAGES_ROOT", missing_dir), patch.object(routes_handlers, "IMAGES_ROOT", missing_dir):
            resp = self.client.get("/favicon.ico")
            self.assertEqual(resp.status_code, 404)

    def test_image_asset_rejects_path_traversal(self) -> None:
        images_dir = Path(self.temp_dir.name) / "images"
        images_dir.mkdir(parents=True, exist_ok=True)
        with patch.object(routes_state, "IMAGES_ROOT", images_dir), patch.object(routes_handlers, "IMAGES_ROOT", images_dir):
            resp = self.client.get("/images/../config.yaml")
            self.assertEqual(resp.status_code, 400)
            self.assertIn("Invalid image filename", resp.get_json()["error"])

    def test_image_asset_returns_404_for_missing_file(self) -> None:
        images_dir = Path(self.temp_dir.name) / "images"
        images_dir.mkdir(parents=True, exist_ok=True)
        with patch.object(routes_state, "IMAGES_ROOT", images_dir), patch.object(routes_handlers, "IMAGES_ROOT", images_dir):
            resp = self.client.get("/images/nonexistent.png")
            self.assertEqual(resp.status_code, 404)
            self.assertIn("Image not found", resp.get_json()["error"])

    def test_image_asset_returns_404_when_images_dir_missing(self) -> None:
        missing_dir = Path(self.temp_dir.name) / "no_images_dir"
        with patch.object(routes_state, "IMAGES_ROOT", missing_dir), patch.object(routes_handlers, "IMAGES_ROOT", missing_dir):
            resp = self.client.get("/images/logo.png")
            self.assertEqual(resp.status_code, 404)
            self.assertIn("Image directory not found", resp.get_json()["error"])

    def test_evidence_intake_nonexistent_case(self) -> None:
        resp = self.client.post(
            "/api/cases/nonexistent-id/evidence",
            json={"path": "C:\\fake.E01"},
        )
        self.assertEqual(resp.status_code, 404)
        self.assertIn("Case not found", resp.get_json()["error"])

    def test_evidence_intake_missing_path_and_no_upload(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root), patch.object(routes_images, "CASES_ROOT", self.cases_root), patch.object(routes_state, "CASES_ROOT", self.cases_root):
            create_resp = self.client.post("/api/cases", json={"case_name": "No Evidence"})
            case_id = create_resp.get_json()["case_id"]
            resp = self.client.post(f"/api/cases/{case_id}/evidence", json={})
            self.assertEqual(resp.status_code, 400)
            self.assertIn("Provide evidence", resp.get_json()["error"])

    def test_evidence_intake_nonexistent_path(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root), patch.object(routes_images, "CASES_ROOT", self.cases_root), patch.object(routes_state, "CASES_ROOT", self.cases_root):
            create_resp = self.client.post("/api/cases", json={"case_name": "Missing Path"})
            case_id = create_resp.get_json()["case_id"]
            resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                json={"path": "C:\\does_not_exist\\fake.E01"},
            )
            self.assertEqual(resp.status_code, 400)
            self.assertIn("does not exist", resp.get_json()["error"])

    def test_parse_nonexistent_case(self) -> None:
        resp = self.client.post(
            "/api/cases/nonexistent-id/parse",
            json={"artifacts": ["runkeys"]},
        )
        self.assertEqual(resp.status_code, 404)

    def test_parse_no_evidence_loaded(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root), patch.object(routes_images, "CASES_ROOT", self.cases_root), patch.object(routes_state, "CASES_ROOT", self.cases_root):
            create_resp = self.client.post("/api/cases", json={"case_name": "No Evidence Parse"})
            case_id = create_resp.get_json()["case_id"]
            resp = self.client.post(
                f"/api/cases/{case_id}/parse",
                json={"artifacts": ["runkeys"]},
            )
            self.assertEqual(resp.status_code, 400)
            self.assertIn("No evidence loaded", resp.get_json()["error"])

    def test_parse_no_artifacts_provided(self) -> None:
        evidence_path = Path(self.temp_dir.name) / "no-artifacts.E01"
        evidence_path.write_bytes(b"demo")
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
                routes_evidence,
                "compute_hashes",
                return_value={"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 4},
            ),
            patch(
                "app.hasher.compute_hashes",
                return_value={"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 4},
            ),
        ):
            create_resp = self.client.post("/api/cases", json={"case_name": "Empty Artifacts"})
            case_id = create_resp.get_json()["case_id"]
            self.client.post(f"/api/cases/{case_id}/evidence", json={"path": str(evidence_path)})
            resp = self.client.post(f"/api/cases/{case_id}/parse", json={"artifacts": []})
            self.assertEqual(resp.status_code, 400)
            self.assertIn("at least one artifact", resp.get_json()["error"])

    def test_parse_already_running_returns_409(self) -> None:
        evidence_path = Path(self.temp_dir.name) / "already-parsing.E01"
        evidence_path.write_bytes(b"demo")
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
                routes_evidence,
                "compute_hashes",
                return_value={"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 4},
            ),
            patch(
                "app.hasher.compute_hashes",
                return_value={"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 4},
            ),
        ):
            create_resp = self.client.post("/api/cases", json={"case_name": "Already Running"})
            case_id = create_resp.get_json()["case_id"]
            self.client.post(f"/api/cases/{case_id}/evidence", json={"path": str(evidence_path)})
            with routes.STATE_LOCK:
                # Set progress for both case-level and image-level keys
                routes.PARSE_PROGRESS[case_id] = routes.new_progress(status="running")
                image_states = routes.CASE_STATES[case_id].get("image_states", {})
                for img_id in image_states:
                    routes.PARSE_PROGRESS[f"{case_id}::{img_id}"] = routes.new_progress(status="running")
            resp = self.client.post(
                f"/api/cases/{case_id}/parse",
                json={"artifacts": ["runkeys"]},
            )
            self.assertEqual(resp.status_code, 409)
            self.assertIn("already running", resp.get_json()["error"])

    def test_parse_progress_nonexistent_case(self) -> None:
        resp = self.client.get("/api/cases/nonexistent-id/parse/progress")
        self.assertEqual(resp.status_code, 404)

    def test_analyze_nonexistent_case(self) -> None:
        resp = self.client.post(
            "/api/cases/nonexistent-id/analyze",
            json={"prompt": "test"},
        )
        self.assertEqual(resp.status_code, 404)

    def test_analyze_no_parse_results(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root), patch.object(routes_images, "CASES_ROOT", self.cases_root), patch.object(routes_state, "CASES_ROOT", self.cases_root):
            create_resp = self.client.post("/api/cases", json={"case_name": "No Parse Results"})
            case_id = create_resp.get_json()["case_id"]
            resp = self.client.post(
                f"/api/cases/{case_id}/analyze",
                json={"prompt": "test"},
            )
            self.assertEqual(resp.status_code, 400)
            self.assertIn("No parsed artifacts", resp.get_json()["error"])

    def test_analyze_progress_nonexistent_case(self) -> None:
        resp = self.client.get("/api/cases/nonexistent-id/analyze/progress")
        self.assertEqual(resp.status_code, 404)

    def test_chat_nonexistent_case(self) -> None:
        resp = self.client.post(
            "/api/cases/nonexistent-id/chat",
            json={"message": "hello"},
        )
        self.assertEqual(resp.status_code, 404)

    def test_chat_missing_payload(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root), patch.object(routes_images, "CASES_ROOT", self.cases_root), patch.object(routes_state, "CASES_ROOT", self.cases_root):
            create_resp = self.client.post("/api/cases", json={"case_name": "Chat No Payload"})
            case_id = create_resp.get_json()["case_id"]
            resp = self.client.post(
                f"/api/cases/{case_id}/chat",
                data="not json",
                content_type="text/plain",
            )
            self.assertEqual(resp.status_code, 400)
            self.assertIn("JSON object", resp.get_json()["error"])

    def test_chat_empty_message(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root), patch.object(routes_images, "CASES_ROOT", self.cases_root), patch.object(routes_state, "CASES_ROOT", self.cases_root):
            create_resp = self.client.post("/api/cases", json={"case_name": "Chat Empty Message"})
            case_id = create_resp.get_json()["case_id"]
            resp = self.client.post(
                f"/api/cases/{case_id}/chat",
                json={"message": ""},
            )
            self.assertEqual(resp.status_code, 400)
            self.assertIn("message", resp.get_json()["error"])

    def test_chat_no_analysis_results(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root), patch.object(routes_images, "CASES_ROOT", self.cases_root), patch.object(routes_state, "CASES_ROOT", self.cases_root):
            create_resp = self.client.post("/api/cases", json={"case_name": "Chat No Analysis"})
            case_id = create_resp.get_json()["case_id"]
            resp = self.client.post(
                f"/api/cases/{case_id}/chat",
                json={"message": "What happened?"},
            )
            self.assertEqual(resp.status_code, 400)
            self.assertIn("No analysis results", resp.get_json()["error"])

    def test_chat_already_running_returns_409(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root), patch.object(routes_images, "CASES_ROOT", self.cases_root), patch.object(routes_state, "CASES_ROOT", self.cases_root):
            create_resp = self.client.post("/api/cases", json={"case_name": "Chat Running"})
            case_id = create_resp.get_json()["case_id"]
            # Set up analysis results so the check passes
            with routes.STATE_LOCK:
                routes.CASE_STATES[case_id]["analysis_results"] = {"summary": "done", "per_artifact": []}
                routes.CHAT_PROGRESS[case_id] = routes.new_progress(status="running")
            resp = self.client.post(
                f"/api/cases/{case_id}/chat",
                json={"message": "hello"},
            )
            self.assertEqual(resp.status_code, 409)
            self.assertIn("already running", resp.get_json()["error"])

    def test_chat_stream_nonexistent_case(self) -> None:
        resp = self.client.get("/api/cases/nonexistent-id/chat/stream")
        self.assertEqual(resp.status_code, 404)

    def test_chat_history_nonexistent_case(self) -> None:
        resp = self.client.get("/api/cases/nonexistent-id/chat/history")
        self.assertEqual(resp.status_code, 404)

    def test_clear_chat_history_nonexistent_case(self) -> None:
        resp = self.client.delete("/api/cases/nonexistent-id/chat/history")
        self.assertEqual(resp.status_code, 404)

    def test_report_nonexistent_case(self) -> None:
        resp = self.client.get("/api/cases/nonexistent-id/report")
        self.assertEqual(resp.status_code, 404)

    def test_report_rejected_without_analysis(self) -> None:
        """Report generation must fail when no analysis has been run."""
        evidence_path = Path(self.temp_dir.name) / "no-analysis.E01"
        evidence_path.write_bytes(b"demo")

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
            create_resp = self.client.post("/api/cases", json={"case_name": "No Analysis"})
            self.assertEqual(create_resp.status_code, 201)
            case_id = create_resp.get_json()["case_id"]

            # Upload evidence and parse, but skip analysis.
            evidence_resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                json={"path": str(evidence_path)},
            )
            self.assertEqual(evidence_resp.status_code, 200)

            parse_resp = self.client.post(
                f"/api/cases/{case_id}/parse",
                json={"artifacts": ["runkeys"]},
            )
            self.assertEqual(parse_resp.status_code, 202)

            # Attempt report without analysis — must be rejected.
            report_resp = self.client.get(f"/api/cases/{case_id}/report")
            self.assertEqual(report_resp.status_code, 400)
            body = report_resp.get_json()
            self.assertIn("Analysis has not been completed", body["error"])

            # Case must NOT be transitioned to completed.
            self.assertNotEqual(routes.CASE_STATES[case_id]["status"], "completed")

    def test_csv_bundle_nonexistent_case(self) -> None:
        resp = self.client.get("/api/cases/nonexistent-id/csvs")
        self.assertEqual(resp.status_code, 404)

    def test_csv_bundle_no_csv_files(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root), patch.object(routes_images, "CASES_ROOT", self.cases_root), patch.object(routes_state, "CASES_ROOT", self.cases_root):
            create_resp = self.client.post("/api/cases", json={"case_name": "No CSVs"})
            case_id = create_resp.get_json()["case_id"]
            resp = self.client.get(f"/api/cases/{case_id}/csvs")
            self.assertEqual(resp.status_code, 404)
            self.assertIn("No parsed CSV", resp.get_json()["error"])

    def test_settings_update_rejects_non_dict_payload(self) -> None:
        resp = self.client.post(
            "/api/settings",
            data=json.dumps([1, 2, 3]),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("JSON object", resp.get_json()["error"])

    def test_settings_test_connection_unexpected_error(self) -> None:
        with (
            patch.object(routes, "create_provider", side_effect=RuntimeError("boom")),
            patch.object(routes_handlers, "create_provider", side_effect=RuntimeError("boom")),
        ):
            resp = self.client.post("/api/settings/test-connection")
        self.assertEqual(resp.status_code, 500)
        self.assertIn("Unexpected error", resp.get_json()["error"])

    def test_settings_update_rejects_invalid_port(self) -> None:
        """Invalid settings must be rejected with 400 and NOT persisted."""
        original = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
        original_port = original.get("server", {}).get("port", 5000)

        resp = self.client.post(
            "/api/settings",
            json={"server": {"port": "not-a-number"}},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("server.port", resp.get_json()["error"])

        # Config on disk must be unchanged.
        persisted = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
        self.assertEqual(persisted.get("server", {}).get("port", 5000), original_port)

    def test_settings_update_rejects_invalid_provider(self) -> None:
        """An unknown AI provider must be rejected with 400."""
        resp = self.client.post(
            "/api/settings",
            json={"ai": {"provider": "doesnotexist"}},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("ai.provider", resp.get_json()["error"])

    def test_settings_update_preserves_valid_after_invalid_attempt(self) -> None:
        """After a rejected update, a valid update should still work."""
        # First: invalid
        resp = self.client.post(
            "/api/settings",
            json={"server": {"port": -1}},
        )
        self.assertEqual(resp.status_code, 400)

        # Then: valid
        resp = self.client.post(
            "/api/settings",
            json={"server": {"port": 9999}},
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["server"]["port"], 9999)

    def test_settings_test_connection_empty_reply(self) -> None:
        class EmptyReplyProvider:
            def analyze(self, system_prompt: str, user_prompt: str, max_tokens: int = 256) -> str:
                return ""
            def get_model_info(self) -> dict[str, str]:
                return {"provider": "fake", "model": "empty-model"}

        with (
            patch.object(routes, "create_provider", return_value=EmptyReplyProvider()),
            patch.object(routes_handlers, "create_provider", return_value=EmptyReplyProvider()),
        ):
            resp = self.client.post("/api/settings/test-connection")
        self.assertEqual(resp.status_code, 502)
        self.assertIn("empty response", resp.get_json()["error"])

    def test_profile_save_rejects_reserved_name(self) -> None:
        resp = self.client.post(
            "/api/artifact-profiles",
            json={
                "name": "recommended",
                "artifact_options": [{"artifact_key": "runkeys", "mode": "parse_and_ai"}],
            },
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("built-in", resp.get_json()["error"])

    def test_profile_save_rejects_empty_name(self) -> None:
        resp = self.client.post(
            "/api/artifact-profiles",
            json={
                "name": "",
                "artifact_options": [{"artifact_key": "runkeys", "mode": "parse_and_ai"}],
            },
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("required", resp.get_json()["error"])

    def test_profile_save_rejects_empty_options(self) -> None:
        resp = self.client.post(
            "/api/artifact-profiles",
            json={"name": "EmptyProfile", "artifact_options": []},
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("at least one", resp.get_json()["error"])

    def test_profile_save_rejects_non_dict_payload(self) -> None:
        resp = self.client.post(
            "/api/artifact-profiles",
            data=json.dumps("not a dict"),
            content_type="application/json",
        )
        self.assertEqual(resp.status_code, 400)
        self.assertIn("JSON object", resp.get_json()["error"])

    # ------------------------------------------------------------------
    # JSON body type validation (non-object payloads → 400)
    # ------------------------------------------------------------------

    def test_create_case_rejects_json_array(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root), patch.object(routes_images, "CASES_ROOT", self.cases_root), patch.object(routes_state, "CASES_ROOT", self.cases_root):
            resp = self.client.post(
                "/api/cases",
                data=json.dumps(["not", "an", "object"]),
                content_type="application/json",
            )
            self.assertEqual(resp.status_code, 400)
            self.assertIn("JSON object", resp.get_json()["error"])

    def test_create_case_rejects_json_scalar(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root), patch.object(routes_images, "CASES_ROOT", self.cases_root), patch.object(routes_state, "CASES_ROOT", self.cases_root):
            resp = self.client.post(
                "/api/cases",
                data=json.dumps("just a string"),
                content_type="application/json",
            )
            self.assertEqual(resp.status_code, 400)
            self.assertIn("JSON object", resp.get_json()["error"])

    def test_create_case_accepts_valid_object(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root), patch.object(routes_images, "CASES_ROOT", self.cases_root), patch.object(routes_state, "CASES_ROOT", self.cases_root):
            resp = self.client.post("/api/cases", json={"case_name": "Valid"})
            self.assertEqual(resp.status_code, 201)
            self.assertIn("case_id", resp.get_json())

    def test_start_parse_rejects_json_array(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root), patch.object(routes_images, "CASES_ROOT", self.cases_root), patch.object(routes_state, "CASES_ROOT", self.cases_root):
            create_resp = self.client.post("/api/cases", json={"case_name": "Parse Array"})
            case_id = create_resp.get_json()["case_id"]
            with routes.STATE_LOCK:
                routes.CASE_STATES[case_id]["evidence_path"] = "/fake/evidence.E01"
            resp = self.client.post(
                f"/api/cases/{case_id}/parse",
                data=json.dumps(["runkeys"]),
                content_type="application/json",
            )
            self.assertEqual(resp.status_code, 400)
            self.assertIn("JSON object", resp.get_json()["error"])

    def test_start_parse_rejects_json_scalar(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root), patch.object(routes_images, "CASES_ROOT", self.cases_root), patch.object(routes_state, "CASES_ROOT", self.cases_root):
            create_resp = self.client.post("/api/cases", json={"case_name": "Parse Scalar"})
            case_id = create_resp.get_json()["case_id"]
            with routes.STATE_LOCK:
                routes.CASE_STATES[case_id]["evidence_path"] = "/fake/evidence.E01"
            resp = self.client.post(
                f"/api/cases/{case_id}/parse",
                data=json.dumps(42),
                content_type="application/json",
            )
            self.assertEqual(resp.status_code, 400)
            self.assertIn("JSON object", resp.get_json()["error"])

    def test_start_analysis_rejects_json_array(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root), patch.object(routes_images, "CASES_ROOT", self.cases_root), patch.object(routes_state, "CASES_ROOT", self.cases_root):
            create_resp = self.client.post("/api/cases", json={"case_name": "Analysis Array"})
            case_id = create_resp.get_json()["case_id"]
            with routes.STATE_LOCK:
                routes.CASE_STATES[case_id]["parse_results"] = [{"success": True}]
                routes.CASE_STATES[case_id]["analysis_artifacts"] = ["runkeys"]
            resp = self.client.post(
                f"/api/cases/{case_id}/analyze",
                data=json.dumps(["prompt text"]),
                content_type="application/json",
            )
            self.assertEqual(resp.status_code, 400)
            self.assertIn("JSON object", resp.get_json()["error"])

    def test_start_analysis_rejects_json_scalar(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root), patch.object(routes_images, "CASES_ROOT", self.cases_root), patch.object(routes_state, "CASES_ROOT", self.cases_root):
            create_resp = self.client.post("/api/cases", json={"case_name": "Analysis Scalar"})
            case_id = create_resp.get_json()["case_id"]
            with routes.STATE_LOCK:
                routes.CASE_STATES[case_id]["parse_results"] = [{"success": True}]
                routes.CASE_STATES[case_id]["analysis_artifacts"] = ["runkeys"]
            resp = self.client.post(
                f"/api/cases/{case_id}/analyze",
                data=json.dumps(true if False else "a string"),
                content_type="application/json",
            )
            self.assertEqual(resp.status_code, 400)
            self.assertIn("JSON object", resp.get_json()["error"])

    def test_evidence_intake_rejects_json_array(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root), patch.object(routes_images, "CASES_ROOT", self.cases_root), patch.object(routes_state, "CASES_ROOT", self.cases_root):
            create_resp = self.client.post("/api/cases", json={"case_name": "Evidence Array"})
            case_id = create_resp.get_json()["case_id"]
            resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                data=json.dumps(["/some/path"]),
                content_type="application/json",
            )
            self.assertEqual(resp.status_code, 400)
            self.assertIn("JSON object", resp.get_json()["error"])

    def test_evidence_intake_rejects_json_scalar(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root), patch.object(routes_images, "CASES_ROOT", self.cases_root), patch.object(routes_state, "CASES_ROOT", self.cases_root):
            create_resp = self.client.post("/api/cases", json={"case_name": "Evidence Scalar"})
            case_id = create_resp.get_json()["case_id"]
            resp = self.client.post(
                f"/api/cases/{case_id}/evidence",
                data=json.dumps(12345),
                content_type="application/json",
            )
            self.assertEqual(resp.status_code, 400)
            self.assertIn("JSON object", resp.get_json()["error"])

    def test_report_missing_hash_context(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root), patch.object(routes_images, "CASES_ROOT", self.cases_root), patch.object(routes_state, "CASES_ROOT", self.cases_root):
            create_resp = self.client.post("/api/cases", json={"case_name": "No Hash"})
            case_id = create_resp.get_json()["case_id"]
            # Simulate parse results exist but no hash
            with routes.STATE_LOCK:
                routes.CASE_STATES[case_id]["evidence_hashes"] = {"sha256": "abc123"}
                routes.CASE_STATES[case_id]["source_path"] = ""
                routes.CASE_STATES[case_id]["evidence_path"] = ""
            resp = self.client.get(f"/api/cases/{case_id}/report")
            self.assertEqual(resp.status_code, 400)
            self.assertIn("integrity data is missing", resp.get_json()["error"])

    def test_replace_evidence_clears_stale_downstream_state(self) -> None:
        """Loading new evidence must invalidate parse, analysis, and chat state."""
        evidence_a = Path(self.temp_dir.name) / "disk_a.E01"
        evidence_a.write_bytes(b"disk-a")
        evidence_b = Path(self.temp_dir.name) / "disk_b.E01"
        evidence_b.write_bytes(b"disk-b")

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
            patch.object(routes, "ForensicAnalyzer", FakeAnalyzer),
            patch.object(routes_tasks, "ForensicAnalyzer", FakeAnalyzer),
            patch.object(
                routes, "compute_hashes",
                return_value={"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 6},
            ),
            patch.object(
                routes_handlers, "compute_hashes",
                return_value={"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 6},
            ),
            patch.object(
                routes_evidence, "compute_hashes",
                return_value={"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 6},
            ),
            patch(
                "app.hasher.compute_hashes",
                return_value={"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 6},
            ),
            patch.object(routes.threading, "Thread", ImmediateThread),
        ):
            # Create case, load evidence A, parse, and analyze.
            create_resp = self.client.post("/api/cases", json={"case_name": "Stale State"})
            self.assertEqual(create_resp.status_code, 201)
            case_id = create_resp.get_json()["case_id"]

            self.client.post(f"/api/cases/{case_id}/evidence", json={"path": str(evidence_a)})
            self.client.post(f"/api/cases/{case_id}/parse", json={"artifacts": ["runkeys"]})
            self.client.post(f"/api/cases/{case_id}/analyze", json={"prompt": "Investigate"})

            # Confirm downstream state is populated before replacement.
            with routes.STATE_LOCK:
                case = routes.CASE_STATES[case_id]
                self.assertTrue(case.get("parse_results"), "parse_results should exist after parsing")
                self.assertTrue(case.get("artifact_csv_paths"), "artifact_csv_paths should exist after parsing")
                self.assertTrue(case.get("analysis_results"), "analysis_results should exist after analysis")

            # Replace evidence with B.
            ev_resp = self.client.post(f"/api/cases/{case_id}/evidence", json={"path": str(evidence_b)})
            self.assertEqual(ev_resp.status_code, 200)

            # Verify all downstream state has been cleared.
            with routes.STATE_LOCK:
                case = routes.CASE_STATES[case_id]
                self.assertEqual(case.get("parse_results"), [])
                self.assertEqual(case.get("artifact_csv_paths"), {})
                self.assertEqual(case.get("analysis_results"), {})
                self.assertEqual(case.get("csv_output_dir"), "")
                self.assertEqual(case.get("selected_artifacts"), [])
                self.assertEqual(case.get("analysis_artifacts"), [])
                self.assertEqual(case.get("artifact_options"), [])
                self.assertIsNone(case.get("analysis_date_range"))
                self.assertEqual(case.get("investigation_context"), "")
                self.assertEqual(case.get("status"), "evidence_loaded")

            # Progress stores should be cleared.
            self.assertNotIn(case_id, routes.PARSE_PROGRESS)
            self.assertNotIn(case_id, routes.ANALYSIS_PROGRESS)
            self.assertNotIn(case_id, routes.CHAT_PROGRESS)

            # Evidence metadata should reflect the new evidence.
            with routes.STATE_LOCK:
                self.assertIn("disk_b", case.get("source_path", ""))

    def test_replace_evidence_blocks_analysis_until_reparsed(self) -> None:
        """After evidence replacement, analysis should fail (no parse results)."""
        evidence_a = Path(self.temp_dir.name) / "ev_a.E01"
        evidence_a.write_bytes(b"aaa")
        evidence_b = Path(self.temp_dir.name) / "ev_b.E01"
        evidence_b.write_bytes(b"bbb")

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
            patch.object(routes, "ForensicAnalyzer", FakeAnalyzer),
            patch.object(routes_tasks, "ForensicAnalyzer", FakeAnalyzer),
            patch.object(
                routes, "compute_hashes",
                return_value={"sha256": "c" * 64, "md5": "d" * 32, "size_bytes": 3},
            ),
            patch.object(
                routes_handlers, "compute_hashes",
                return_value={"sha256": "c" * 64, "md5": "d" * 32, "size_bytes": 3},
            ),
            patch.object(
                routes_evidence, "compute_hashes",
                return_value={"sha256": "c" * 64, "md5": "d" * 32, "size_bytes": 3},
            ),
            patch(
                "app.hasher.compute_hashes",
                return_value={"sha256": "c" * 64, "md5": "d" * 32, "size_bytes": 3},
            ),
            patch.object(routes.threading, "Thread", ImmediateThread),
        ):
            create_resp = self.client.post("/api/cases", json={"case_name": "Reparse"})
            case_id = create_resp.get_json()["case_id"]

            # Load A, parse, analyze.
            self.client.post(f"/api/cases/{case_id}/evidence", json={"path": str(evidence_a)})
            self.client.post(f"/api/cases/{case_id}/parse", json={"artifacts": ["runkeys"]})
            self.client.post(f"/api/cases/{case_id}/analyze", json={"prompt": "Check"})

            # Replace evidence with B.
            self.client.post(f"/api/cases/{case_id}/evidence", json={"path": str(evidence_b)})

            # Analysis should be rejected — no parse results from new evidence.
            analyze_resp = self.client.post(
                f"/api/cases/{case_id}/analyze", json={"prompt": "Check again"},
            )
            self.assertEqual(analyze_resp.status_code, 400)
            self.assertIn("parsing", analyze_resp.get_json()["error"].lower())

    def test_replace_evidence_blocks_chat_until_reanalyzed(self) -> None:
        """After evidence replacement, chat should fail (no analysis results)."""
        evidence_a = Path(self.temp_dir.name) / "chat_a.E01"
        evidence_a.write_bytes(b"aaa")
        evidence_b = Path(self.temp_dir.name) / "chat_b.E01"
        evidence_b.write_bytes(b"bbb")

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
            patch.object(routes, "ForensicAnalyzer", FakeAnalyzer),
            patch.object(routes_tasks, "ForensicAnalyzer", FakeAnalyzer),
            patch.object(
                routes, "compute_hashes",
                return_value={"sha256": "e" * 64, "md5": "f" * 32, "size_bytes": 3},
            ),
            patch.object(
                routes_handlers, "compute_hashes",
                return_value={"sha256": "e" * 64, "md5": "f" * 32, "size_bytes": 3},
            ),
            patch.object(
                routes_evidence, "compute_hashes",
                return_value={"sha256": "e" * 64, "md5": "f" * 32, "size_bytes": 3},
            ),
            patch(
                "app.hasher.compute_hashes",
                return_value={"sha256": "e" * 64, "md5": "f" * 32, "size_bytes": 3},
            ),
            patch.object(routes.threading, "Thread", ImmediateThread),
        ):
            create_resp = self.client.post("/api/cases", json={"case_name": "Chat Block"})
            case_id = create_resp.get_json()["case_id"]

            # Load A, parse, analyze.
            self.client.post(f"/api/cases/{case_id}/evidence", json={"path": str(evidence_a)})
            self.client.post(f"/api/cases/{case_id}/parse", json={"artifacts": ["runkeys"]})
            self.client.post(f"/api/cases/{case_id}/analyze", json={"prompt": "Investigate"})

            # Replace evidence with B.
            self.client.post(f"/api/cases/{case_id}/evidence", json={"path": str(evidence_b)})

            # Chat should be rejected — no analysis results from new evidence.
            chat_resp = self.client.post(
                f"/api/cases/{case_id}/chat", json={"message": "What happened?"},
            )
            self.assertEqual(chat_resp.status_code, 400)
            self.assertIn("analysis", chat_resp.get_json()["error"].lower())

    def test_replace_evidence_allows_clean_reparse(self) -> None:
        """After evidence replacement, a fresh parse should succeed cleanly."""
        evidence_a = Path(self.temp_dir.name) / "rp_a.E01"
        evidence_a.write_bytes(b"aaa")
        evidence_b = Path(self.temp_dir.name) / "rp_b.E01"
        evidence_b.write_bytes(b"bbb")

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
            patch.object(routes, "ForensicAnalyzer", FakeAnalyzer),
            patch.object(routes_tasks, "ForensicAnalyzer", FakeAnalyzer),
            patch.object(
                routes, "compute_hashes",
                return_value={"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 3},
            ),
            patch.object(
                routes_handlers, "compute_hashes",
                return_value={"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 3},
            ),
            patch.object(
                routes_evidence, "compute_hashes",
                return_value={"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 3},
            ),
            patch(
                "app.hasher.compute_hashes",
                return_value={"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 3},
            ),
            patch.object(routes.threading, "Thread", ImmediateThread),
        ):
            create_resp = self.client.post("/api/cases", json={"case_name": "Reparse OK"})
            case_id = create_resp.get_json()["case_id"]

            # Load A and parse.
            self.client.post(f"/api/cases/{case_id}/evidence", json={"path": str(evidence_a)})
            self.client.post(f"/api/cases/{case_id}/parse", json={"artifacts": ["runkeys"]})

            # Replace evidence with B.
            self.client.post(f"/api/cases/{case_id}/evidence", json={"path": str(evidence_b)})

            # Fresh parse on new evidence should succeed.
            parse_resp = self.client.post(
                f"/api/cases/{case_id}/parse", json={"artifacts": ["runkeys"]},
            )
            self.assertEqual(parse_resp.status_code, 202)

            # Verify parse results are populated from the new parse.
            with routes.STATE_LOCK:
                case = routes.CASE_STATES[case_id]
                self.assertTrue(case.get("parse_results"))
                self.assertTrue(case.get("artifact_csv_paths"))


    def test_replace_evidence_clears_stale_csvs_on_disk(self) -> None:
        """After evidence replacement, /csvs must not return old parsed CSVs."""
        evidence_a = Path(self.temp_dir.name) / "csv_a.E01"
        evidence_a.write_bytes(b"aaa")
        evidence_b = Path(self.temp_dir.name) / "csv_b.E01"
        evidence_b.write_bytes(b"bbb")

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
            patch.object(routes, "ForensicAnalyzer", FakeAnalyzer),
            patch.object(routes_tasks, "ForensicAnalyzer", FakeAnalyzer),
            patch.object(
                routes, "compute_hashes",
                return_value={"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 3},
            ),
            patch.object(
                routes_handlers, "compute_hashes",
                return_value={"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 3},
            ),
            patch.object(
                routes_evidence, "compute_hashes",
                return_value={"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 3},
            ),
            patch(
                "app.hasher.compute_hashes",
                return_value={"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 3},
            ),
            patch.object(routes.threading, "Thread", ImmediateThread),
        ):
            # Create case, load evidence A, parse it.
            create_resp = self.client.post("/api/cases", json={"case_name": "Stale CSV"})
            case_id = create_resp.get_json()["case_id"]

            self.client.post(f"/api/cases/{case_id}/evidence", json={"path": str(evidence_a)})
            self.client.post(f"/api/cases/{case_id}/parse", json={"artifacts": ["runkeys"]})

            # CSVs should be available after parsing evidence A.
            csv_resp = self.client.get(f"/api/cases/{case_id}/csvs")
            self.assertEqual(csv_resp.status_code, 200)
            self.assertEqual(csv_resp.mimetype, "application/zip")

            # Replace evidence with B (no reparse yet).
            ev_resp = self.client.post(
                f"/api/cases/{case_id}/evidence", json={"path": str(evidence_b)},
            )
            self.assertEqual(ev_resp.status_code, 200)

            # /csvs must NOT return stale CSVs from evidence A.
            csv_resp = self.client.get(f"/api/cases/{case_id}/csvs")
            self.assertEqual(csv_resp.status_code, 404)
            self.assertIn("No parsed CSV", csv_resp.get_json()["error"])

            # Stale parsed directory should be gone.
            with routes.STATE_LOCK:
                case = routes.CASE_STATES[case_id]
                parsed_dir = Path(case["case_dir"]) / "parsed"
            self.assertFalse(parsed_dir.exists())

            # Reparse evidence B.
            parse_resp = self.client.post(
                f"/api/cases/{case_id}/parse", json={"artifacts": ["runkeys"]},
            )
            self.assertEqual(parse_resp.status_code, 202)

            # /csvs should now return CSVs from the new parse.
            csv_resp = self.client.get(f"/api/cases/{case_id}/csvs")
            self.assertEqual(csv_resp.status_code, 200)
            self.assertEqual(csv_resp.mimetype, "application/zip")

    def test_replace_evidence_clears_external_csv_output_dir(self) -> None:
        """Replacing evidence must remove stale CSVs from an external csv_output_dir."""
        evidence_a = Path(self.temp_dir.name) / "ext_a.E01"
        evidence_a.write_bytes(b"aaa")
        evidence_b = Path(self.temp_dir.name) / "ext_b.E01"
        evidence_b.write_bytes(b"bbb")
        external_output_root = Path(self.temp_dir.name) / "external_parsed"

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
            patch.object(routes, "ForensicAnalyzer", FakeAnalyzer),
            patch.object(routes_tasks, "ForensicAnalyzer", FakeAnalyzer),
            patch.object(
                routes, "compute_hashes",
                return_value={"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 3},
            ),
            patch.object(
                routes_handlers, "compute_hashes",
                return_value={"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 3},
            ),
            patch.object(
                routes_evidence, "compute_hashes",
                return_value={"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 3},
            ),
            patch(
                "app.hasher.compute_hashes",
                return_value={"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 3},
            ),
            patch.object(routes.threading, "Thread", ImmediateThread),
        ):
            # Configure external csv_output_dir.
            settings_resp = self.client.post(
                "/api/settings",
                json={"evidence": {"csv_output_dir": str(external_output_root)}},
            )
            self.assertEqual(settings_resp.status_code, 200)

            # Create case, load evidence A, parse.
            create_resp = self.client.post("/api/cases", json={"case_name": "ExtCleanup"})
            self.assertEqual(create_resp.status_code, 201)
            case_id = create_resp.get_json()["case_id"]

            self.client.post(f"/api/cases/{case_id}/evidence", json={"path": str(evidence_a)})
            self.client.post(f"/api/cases/{case_id}/parse", json={"artifacts": ["runkeys"]})

            # Confirm parsed dir exists with CSVs.
            with routes.STATE_LOCK:
                case = routes.CASE_STATES[case_id]
                parsed_dir = Path(case["csv_output_dir"])
            self.assertTrue(parsed_dir.is_dir())
            self.assertTrue(any(parsed_dir.glob("*.csv")))

            # Replace evidence with B.
            ev_resp = self.client.post(
                f"/api/cases/{case_id}/evidence", json={"path": str(evidence_b)},
            )
            self.assertEqual(ev_resp.status_code, 200)

            # After evidence replacement, csv_output_dir should be cleared.
            with routes.STATE_LOCK:
                case = routes.CASE_STATES[case_id]
                self.assertEqual(case.get("csv_output_dir", ""), "")



if __name__ == "__main__":
    unittest.main()
