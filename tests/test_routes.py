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
import app.routes.tasks as routes_tasks
import app.routes.state as routes_state


class ImmediateThread:
    def __init__(
        self,
        group: object | None = None,
        target: object | None = None,
        name: str | None = None,
        args: tuple[object, ...] = (),
        kwargs: dict[str, object] | None = None,
        daemon: bool | None = None,
    ) -> None:
        del group, name, daemon
        self._target = target
        self._args = args
        self._kwargs = kwargs or {}

    def start(self) -> None:
        if callable(self._target):
            self._target(*self._args, **self._kwargs)


class FakeParser:
    def __init__(
        self,
        evidence_path: str | Path,
        case_dir: str | Path,
        audit_logger: object,
        parsed_dir: str | Path | None = None,
    ) -> None:
        del evidence_path, audit_logger
        self.case_dir = Path(case_dir)
        self.parsed_dir = Path(parsed_dir) if parsed_dir is not None else self.case_dir / "parsed"
        self.parsed_dir.mkdir(parents=True, exist_ok=True)

    def __enter__(self) -> "FakeParser":
        return self

    def __exit__(self, *args: object) -> bool:
        return False

    def close(self) -> None:
        pass

    def get_image_metadata(self) -> dict[str, str]:
        return {
            "hostname": "demo-host",
            "os_version": "Windows 11",
            "domain": "corp.local",
            "ips": "10.1.1.10",
            "timezone": "UTC",
            "install_date": "2025-01-01",
        }

    def get_available_artifacts(self) -> list[dict[str, object]]:
        return [
            {"key": "runkeys", "name": "Run/RunOnce Keys", "available": True},
            {"key": "tasks", "name": "Scheduled Tasks", "available": False},
        ]

    def parse_artifact(self, artifact_key: str, progress_callback: object | None = None) -> dict[str, object]:
        if callable(progress_callback):
            progress_callback({"artifact_key": artifact_key, "record_count": 1})

        csv_path = self.parsed_dir / f"{artifact_key}.csv"
        csv_path.write_text("name\nvalue\n", encoding="utf-8")
        return {
            "csv_path": str(csv_path),
            "record_count": 1,
            "duration_seconds": 0.01,
            "success": True,
            "error": None,
        }


class FakeAnalyzer:
    last_artifact_keys: list[str] = []

    def __init__(
        self,
        case_dir: str | Path,
        config: dict[str, object] | None,
        audit_logger: object,
        artifact_csv_paths: dict[str, str],
    ) -> None:
        del case_dir, config, audit_logger, artifact_csv_paths

    def run_full_analysis(
        self,
        artifact_keys: list[str],
        investigation_context: str,
        metadata: dict[str, object] | None,
        progress_callback: object | None = None,
        cancel_check: object | None = None,
    ) -> dict[str, object]:
        del investigation_context, metadata, cancel_check
        FakeAnalyzer.last_artifact_keys = list(artifact_keys)
        per_artifact: list[dict[str, str]] = []
        for artifact in artifact_keys:
            result = {
                "artifact_key": artifact,
                "artifact_name": artifact,
                "analysis": f"analysis for {artifact}",
                "model": "fake-model",
            }
            per_artifact.append(result)
            if callable(progress_callback):
                progress_callback(artifact, "complete", result)

        return {
            "per_artifact": per_artifact,
            "summary": "final summary",
            "model_info": {"provider": "fake", "model": "fake-model"},
        }


class FakeReportGenerator:
    def __init__(self, cases_root: str | Path | None = None, **_: object) -> None:
        self.cases_root = Path(cases_root) if cases_root is not None else Path(".")

    def generate(
        self,
        analysis_results: dict[str, object],
        image_metadata: dict[str, object],
        evidence_hashes: dict[str, object],
        investigation_context: str,
        audit_log_entries: list[dict[str, object]],
    ) -> Path:
        del image_metadata, evidence_hashes, investigation_context, audit_log_entries
        case_id = str(analysis_results["case_id"])
        reports_dir = self.cases_root / case_id / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)
        path = reports_dir / "report_test.html"
        path.write_text("<html><body>report</body></html>", encoding="utf-8")
        return path


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

    def test_full_route_flow(self) -> None:
        evidence_path = Path(self.temp_dir.name) / "sample.E01"
        evidence_path.write_bytes(b"demo")

        with (
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes_handlers, "CASES_ROOT", self.cases_root),
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes_handlers, "ForensicParser", FakeParser),
            patch.object(routes_tasks, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
            patch.object(routes, "ForensicAnalyzer", FakeAnalyzer),
            patch.object(routes_tasks, "ForensicAnalyzer", FakeAnalyzer),
            patch.object(routes, "ReportGenerator", FakeReportGenerator),
            patch.object(routes_handlers, "ReportGenerator", FakeReportGenerator),
            patch.object(routes_evidence, "ReportGenerator", FakeReportGenerator),
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
            patch.object(routes, "verify_hash", return_value=(True, "a" * 64)),
            patch.object(routes_handlers, "verify_hash", return_value=(True, "a" * 64)),
            patch.object(routes_evidence, "verify_hash", return_value=(True, "a" * 64)),
            patch.object(routes.threading, "Thread", ImmediateThread),
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

            parse_sse = self.client.get(f"/api/cases/{case_id}/parse/progress")
            self.assertEqual(parse_sse.status_code, 200)
            self.assertIn("parse_completed", parse_sse.get_data(as_text=True))

            analyze_resp = self.client.post(
                f"/api/cases/{case_id}/analyze",
                json={"prompt": "Investigate persistence"},
            )
            self.assertEqual(analyze_resp.status_code, 202)

            analysis_sse = self.client.get(f"/api/cases/{case_id}/analyze/progress")
            self.assertEqual(analysis_sse.status_code, 200)
            self.assertIn("analysis_summary", analysis_sse.get_data(as_text=True))

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

        with (
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes_handlers, "CASES_ROOT", self.cases_root),
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes_handlers, "ForensicParser", FakeParser),
            patch.object(routes_tasks, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
            patch.object(routes, "ForensicAnalyzer", FakeAnalyzer),
            patch.object(routes_tasks, "ForensicAnalyzer", FakeAnalyzer),
            patch.object(routes, "ReportGenerator", FakeReportGenerator),
            patch.object(routes_handlers, "ReportGenerator", FakeReportGenerator),
            patch.object(routes_evidence, "ReportGenerator", FakeReportGenerator),
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
            patch.object(routes, "verify_hash", return_value=(True, "a" * 64)),
            patch.object(routes_handlers, "verify_hash", return_value=(True, "a" * 64)),
            patch.object(routes_evidence, "verify_hash", return_value=(True, "a" * 64)),
            patch.object(routes.threading, "Thread", ImmediateThread),
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
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root):
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
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root):
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

        with (
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes_handlers, "CASES_ROOT", self.cases_root),
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes_handlers, "ForensicParser", FakeParser),
            patch.object(routes_tasks, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
            patch.object(routes, "ForensicAnalyzer", FakeAnalyzer),
            patch.object(routes_tasks, "ForensicAnalyzer", FakeAnalyzer),
            patch.object(routes, "ReportGenerator", FakeReportGenerator),
            patch.object(routes_handlers, "ReportGenerator", FakeReportGenerator),
            patch.object(routes_evidence, "ReportGenerator", FakeReportGenerator),
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
            patch.object(routes, "verify_hash", return_value=(True, "a" * 64)),
            patch.object(routes_handlers, "verify_hash", return_value=(True, "a" * 64)),
            patch.object(routes_evidence, "verify_hash", return_value=(True, "a" * 64)),
            patch.object(routes.threading, "Thread", ImmediateThread),
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
            patch.object(routes, "ForensicParser", CapturingParser),
            patch.object(routes_handlers, "ForensicParser", CapturingParser),
            patch.object(routes_tasks, "ForensicParser", CapturingParser),
            patch.object(routes_evidence, "ForensicParser", CapturingParser),
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

            evidence_dir = self.cases_root / case_id / "evidence"
            self.assertTrue((evidence_dir / "Disk.E01").exists())
            self.assertTrue((evidence_dir / "Disk.E02").exists())
            self.assertTrue((evidence_dir / "Disk.E03").exists())
            self.assertTrue(CapturingParser.opened_paths)
            self.assertTrue(CapturingParser.opened_paths[-1].endswith("Disk.E01"))

    def test_settings_endpoints_mask_api_keys(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root):
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
                        "openai": {"api_key": "", "model": "gpt-5.2"},
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
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root):
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
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root):
            response = self.client.get("/api/artifact-profiles")
            self.assertEqual(response.status_code, 200)

        payload = response.get_json()
        profiles = payload["profiles"]
        recommended = next(
            profile for profile in profiles if str(profile.get("name", "")).strip().lower() == "recommended"
        )
        options = list(recommended.get("artifact_options", []))
        option_keys = [str(option.get("artifact_key", "")).strip() for option in options]

        expected_keys = [
            artifact_key
            for artifact_key in routes.ARTIFACT_REGISTRY
            if artifact_key.lower() not in routes.RECOMMENDED_PROFILE_EXCLUDED_ARTIFACTS
        ]

        self.assertEqual(option_keys, expected_keys)
        self.assertNotIn("mft", option_keys)
        self.assertNotIn("usnjrnl", option_keys)
        self.assertNotIn("evtx", option_keys)
        self.assertNotIn("defender.evtx", option_keys)
        self.assertTrue(all(str(option.get("mode", "")) == "parse_and_ai" for option in options))

    def test_settings_update_persists_csv_output_dir(self) -> None:
        csv_output_dir = str((Path(self.temp_dir.name) / "csv output").resolve())
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root):
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
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root):
            update_resp = self.client.post(
                "/api/settings",
                json={
                    "analysis": {
                        "date_buffer_days": 3,
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
            self.assertEqual(payload["analysis"]["date_buffer_days"], 3)
            self.assertEqual(payload["analysis"]["ai_max_tokens"], 2048)
            self.assertEqual(payload["analysis"]["shortened_prompt_cutoff_tokens"], 64000)
            self.assertEqual(payload["analysis"]["artifact_deduplication_enabled"], False)
            self.assertFalse(payload["ai"]["openai"]["attach_csv_as_file"])
            self.assertFalse(payload["ai"]["local"]["attach_csv_as_file"])
            self.assertEqual(payload["ai"]["local"]["request_timeout_seconds"], 5400)

        persisted = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
        self.assertEqual(persisted.get("analysis", {}).get("date_buffer_days"), 3)
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
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes_handlers, "ForensicParser", FakeParser),
            patch.object(routes_tasks, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
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
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes_handlers, "ForensicParser", FakeParser),
            patch.object(routes_tasks, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
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
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes_handlers, "ForensicParser", FakeParser),
            patch.object(routes_tasks, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
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
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes_handlers, "ForensicParser", FakeParser),
            patch.object(routes_tasks, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
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
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes_handlers, "ForensicParser", FakeParser),
            patch.object(routes_tasks, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
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
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes_handlers, "ForensicParser", FakeParser),
            patch.object(routes_tasks, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
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
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes_handlers, "ForensicParser", FakeParser),
            patch.object(routes_tasks, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
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
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes_handlers, "ForensicParser", FakeParser),
            patch.object(routes_tasks, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
            patch.object(routes, "ForensicAnalyzer", FakeAnalyzer),
            patch.object(routes_tasks, "ForensicAnalyzer", FakeAnalyzer),
            patch.object(routes.threading, "Thread", ImmediateThread),
            patch.object(routes, "create_provider", return_value=fake_provider),
            patch.object(routes_handlers, "create_provider", return_value=fake_provider),
            patch.object(routes_tasks, "create_provider", return_value=fake_provider),
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
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes_handlers, "ForensicParser", FakeParser),
            patch.object(routes_tasks, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
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
            expected_dir = configured_output_root / case_id / "parsed"
            self.assertEqual(Path(case_state["csv_output_dir"]), expected_dir)
            csv_path = Path(case_state["artifact_csv_paths"]["runkeys"])
            self.assertTrue(csv_path.exists())
            self.assertEqual(csv_path.parent, expected_dir)

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
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes_handlers, "ForensicParser", FakeParser),
            patch.object(routes_tasks, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
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
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root):
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
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root):
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
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root):
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
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root):
            resp = self.client.post("/api/cases", json={})
            self.assertEqual(resp.status_code, 201)
            payload = resp.get_json()
            self.assertTrue(payload["success"])
            self.assertTrue(payload["case_name"].startswith("Case "))

    def test_create_case_auto_generates_name_when_blank(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root):
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
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root):
            create_resp = self.client.post("/api/cases", json={"case_name": "No Evidence"})
            case_id = create_resp.get_json()["case_id"]
            resp = self.client.post(f"/api/cases/{case_id}/evidence", json={})
            self.assertEqual(resp.status_code, 400)
            self.assertIn("Provide evidence", resp.get_json()["error"])

    def test_evidence_intake_nonexistent_path(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root):
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
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root):
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
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes_handlers, "ForensicParser", FakeParser),
            patch.object(routes_tasks, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
            patch.object(
                routes_evidence,
                "compute_hashes",
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
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes_handlers, "ForensicParser", FakeParser),
            patch.object(routes_tasks, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
            patch.object(
                routes_evidence,
                "compute_hashes",
                return_value={"sha256": "a" * 64, "md5": "b" * 32, "size_bytes": 4},
            ),
        ):
            create_resp = self.client.post("/api/cases", json={"case_name": "Already Running"})
            case_id = create_resp.get_json()["case_id"]
            self.client.post(f"/api/cases/{case_id}/evidence", json={"path": str(evidence_path)})
            with routes.STATE_LOCK:
                routes.PARSE_PROGRESS[case_id] = routes.new_progress(status="running")
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
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root):
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
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root):
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
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root):
            create_resp = self.client.post("/api/cases", json={"case_name": "Chat Empty Message"})
            case_id = create_resp.get_json()["case_id"]
            resp = self.client.post(
                f"/api/cases/{case_id}/chat",
                json={"message": ""},
            )
            self.assertEqual(resp.status_code, 400)
            self.assertIn("message", resp.get_json()["error"])

    def test_chat_no_analysis_results(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root):
            create_resp = self.client.post("/api/cases", json={"case_name": "Chat No Analysis"})
            case_id = create_resp.get_json()["case_id"]
            resp = self.client.post(
                f"/api/cases/{case_id}/chat",
                json={"message": "What happened?"},
            )
            self.assertEqual(resp.status_code, 400)
            self.assertIn("No analysis results", resp.get_json()["error"])

    def test_chat_already_running_returns_409(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root):
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
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes_handlers, "ForensicParser", FakeParser),
            patch.object(routes_tasks, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
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
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root):
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
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root):
            resp = self.client.post(
                "/api/cases",
                data=json.dumps(["not", "an", "object"]),
                content_type="application/json",
            )
            self.assertEqual(resp.status_code, 400)
            self.assertIn("JSON object", resp.get_json()["error"])

    def test_create_case_rejects_json_scalar(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root):
            resp = self.client.post(
                "/api/cases",
                data=json.dumps("just a string"),
                content_type="application/json",
            )
            self.assertEqual(resp.status_code, 400)
            self.assertIn("JSON object", resp.get_json()["error"])

    def test_create_case_accepts_valid_object(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root):
            resp = self.client.post("/api/cases", json={"case_name": "Valid"})
            self.assertEqual(resp.status_code, 201)
            self.assertIn("case_id", resp.get_json())

    def test_start_parse_rejects_json_array(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root):
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
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root):
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
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root):
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
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root):
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
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root):
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
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root):
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
        with patch.object(routes, "CASES_ROOT", self.cases_root), patch.object(routes_handlers, "CASES_ROOT", self.cases_root):
            create_resp = self.client.post("/api/cases", json={"case_name": "No Hash"})
            case_id = create_resp.get_json()["case_id"]
            # Simulate parse results exist but no hash
            with routes.STATE_LOCK:
                routes.CASE_STATES[case_id]["evidence_hashes"] = {"sha256": "abc123"}
                routes.CASE_STATES[case_id]["source_path"] = ""
                routes.CASE_STATES[case_id]["evidence_path"] = ""
            resp = self.client.get(f"/api/cases/{case_id}/report")
            self.assertEqual(resp.status_code, 400)
            self.assertIn("hash context", resp.get_json()["error"])

    def test_replace_evidence_clears_stale_downstream_state(self) -> None:
        """Loading new evidence must invalidate parse, analysis, and chat state."""
        evidence_a = Path(self.temp_dir.name) / "disk_a.E01"
        evidence_a.write_bytes(b"disk-a")
        evidence_b = Path(self.temp_dir.name) / "disk_b.E01"
        evidence_b.write_bytes(b"disk-b")

        with (
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes_handlers, "CASES_ROOT", self.cases_root),
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes_handlers, "ForensicParser", FakeParser),
            patch.object(routes_tasks, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
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
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes_handlers, "ForensicParser", FakeParser),
            patch.object(routes_tasks, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
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
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes_handlers, "ForensicParser", FakeParser),
            patch.object(routes_tasks, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
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
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes_handlers, "ForensicParser", FakeParser),
            patch.object(routes_tasks, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
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
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes_handlers, "ForensicParser", FakeParser),
            patch.object(routes_tasks, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
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
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes_handlers, "ForensicParser", FakeParser),
            patch.object(routes_tasks, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
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

            # Confirm external parsed dir exists with CSVs.
            with routes.STATE_LOCK:
                case = routes.CASE_STATES[case_id]
                ext_parsed_dir = Path(case["csv_output_dir"])
            self.assertTrue(ext_parsed_dir.is_dir())
            self.assertTrue(any(ext_parsed_dir.glob("*.csv")))
            # Verify it is outside the case directory.
            case_dir = Path(case["case_dir"])
            self.assertFalse(
                ext_parsed_dir.resolve().is_relative_to(case_dir.resolve()),
                "External parsed dir should be outside case_dir",
            )

            # Replace evidence with B.
            ev_resp = self.client.post(
                f"/api/cases/{case_id}/evidence", json={"path": str(evidence_b)},
            )
            self.assertEqual(ev_resp.status_code, 200)

            # The external parsed directory should have been cleaned up.
            self.assertFalse(
                ext_parsed_dir.exists(),
                "External csv_output_dir should be removed on evidence replacement",
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
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes_handlers, "ForensicParser", FakeParser),
            patch.object(routes_tasks, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
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

        # Now reparse with a failing parser.
        with (
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes_handlers, "CASES_ROOT", self.cases_root),
            patch.object(routes, "ForensicParser", FailingParser),
            patch.object(routes_handlers, "ForensicParser", FailingParser),
            patch.object(routes_tasks, "ForensicParser", FailingParser),
            patch.object(routes_evidence, "ForensicParser", FailingParser),
            patch.object(routes.threading, "Thread", ImmediateThread),
        ):
            resp = self.client.post(f"/api/cases/{case_id}/parse", json={"artifacts": ["runkeys"]})
            self.assertEqual(resp.status_code, 202)

            # After the failed reparse, stale outputs must be gone.
            case = routes_state.CASE_STATES[case_id]
            self.assertEqual(case.get("parse_results"), [], "Stale parse_results should be cleared")
            self.assertEqual(case.get("artifact_csv_paths"), {}, "Stale artifact_csv_paths should be cleared")
            self.assertEqual(case.get("analysis_results"), {}, "Stale analysis_results should be cleared")


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
            with patch(
                "app.routes.tasks.create_provider",
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
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes_handlers, "ForensicParser", FakeParser),
            patch.object(routes_tasks, "ForensicParser", FakeParser),
            patch.object(routes_evidence, "ForensicParser", FakeParser),
            patch.object(routes, "ForensicAnalyzer", FailOnSecondAnalyzer),
            patch.object(routes_tasks, "ForensicAnalyzer", FailOnSecondAnalyzer),
            patch.object(routes.threading, "Thread", ImmediateThread),
            patch.object(routes, "compute_hashes", return_value=hash_rv),
            patch.object(routes_handlers, "compute_hashes", return_value=hash_rv),
            patch.object(routes_evidence, "compute_hashes", return_value=hash_rv),
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
