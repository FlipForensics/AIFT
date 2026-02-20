from __future__ import annotations

import json
import logging
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
import threading
import time
import unittest
from unittest.mock import patch
from zipfile import ZipFile

import yaml

from app import create_app
from app.case_logging import unregister_all_case_log_handlers
import app.routes as routes


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
    ) -> dict[str, object]:
        del investigation_context, metadata
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
        self.client = self.app.test_client()
        routes.CASE_STATES.clear()
        routes.PARSE_PROGRESS.clear()
        routes.ANALYSIS_PROGRESS.clear()
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
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes, "ForensicAnalyzer", FakeAnalyzer),
            patch.object(routes, "ReportGenerator", FakeReportGenerator),
            patch.object(
                routes,
                "compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 4,
                },
            ),
            patch.object(routes, "verify_hash", return_value=(True, "a" * 64)),
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
            self.assertNotIn(case_id, routes.CASE_STATES)
            self.assertNotIn(case_id, routes.PARSE_PROGRESS)
            self.assertNotIn(case_id, routes.ANALYSIS_PROGRESS)

    def test_case_completion_cleans_global_case_entries(self) -> None:
        evidence_path = Path(self.temp_dir.name) / "cleanup-check.E01"
        evidence_path.write_bytes(b"demo")

        with (
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes, "ForensicAnalyzer", FakeAnalyzer),
            patch.object(routes, "ReportGenerator", FakeReportGenerator),
            patch.object(
                routes,
                "compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 4,
                },
            ),
            patch.object(routes, "verify_hash", return_value=(True, "a" * 64)),
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
            self.assertIn(case_id, routes.PARSE_PROGRESS)
            self.assertIn(case_id, routes.ANALYSIS_PROGRESS)

            report_resp = self.client.get(f"/api/cases/{case_id}/report")
            self.assertEqual(report_resp.status_code, 200)

            for store_name, store in (
                ("CASE_STATES", routes.CASE_STATES),
                ("PARSE_PROGRESS", routes.PARSE_PROGRESS),
                ("ANALYSIS_PROGRESS", routes.ANALYSIS_PROGRESS),
            ):
                with self.subTest(store=store_name):
                    self.assertNotIn(case_id, store)

    def test_parse_progress_sse_waits_before_emitting_idle(self) -> None:
        with (
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes, "SSE_INITIAL_IDLE_GRACE_SECONDS", 0.4),
        ):
            create_resp = self.client.post("/api/cases", json={"case_name": "SSE Wait Case"})
            self.assertEqual(create_resp.status_code, 201)
            case_id = create_resp.get_json()["case_id"]

            def mark_parse_running() -> None:
                time.sleep(0.05)
                routes._set_progress_status(routes.PARSE_PROGRESS, case_id, "running")
                routes._emit_progress(routes.PARSE_PROGRESS, case_id, {"type": "parse_started"})
                routes._set_progress_status(routes.PARSE_PROGRESS, case_id, "completed")
                routes._emit_progress(routes.PARSE_PROGRESS, case_id, {"type": "parse_completed"})

            worker = threading.Thread(target=mark_parse_running, daemon=True)
            worker.start()

            parse_sse = self.client.get(f"/api/cases/{case_id}/parse/progress")
            self.assertEqual(parse_sse.status_code, 200)
            payload = parse_sse.get_data(as_text=True)
            self.assertIn("parse_started", payload)
            self.assertIn("parse_completed", payload)
            self.assertNotIn('"type":"idle"', payload)

    def test_create_case_cleans_up_terminal_case_entries(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root):
            with routes.STATE_LOCK:
                routes.CASE_STATES["terminal-completed"] = {"status": "completed"}
                routes.PARSE_PROGRESS["terminal-completed"] = routes._new_progress(status="completed")
                routes.ANALYSIS_PROGRESS["terminal-completed"] = routes._new_progress(status="completed")

                routes.CASE_STATES["terminal-failed"] = {"status": "failed"}
                routes.PARSE_PROGRESS["terminal-failed"] = routes._new_progress(status="failed")
                routes.ANALYSIS_PROGRESS["terminal-failed"] = routes._new_progress(status="idle")

                routes.CASE_STATES["terminal-error"] = {"status": "error"}
                routes.PARSE_PROGRESS["terminal-error"] = routes._new_progress(status="error")
                routes.ANALYSIS_PROGRESS["terminal-error"] = routes._new_progress(status="idle")

                routes.CASE_STATES["active-case"] = {"status": "running"}
                routes.PARSE_PROGRESS["active-case"] = routes._new_progress(status="running")
                routes.ANALYSIS_PROGRESS["active-case"] = routes._new_progress(status="idle")

            create_resp = self.client.post("/api/cases", json={"case_name": "Cleanup Trigger Case"})
            self.assertEqual(create_resp.status_code, 201)
            new_case_id = create_resp.get_json()["case_id"]

            self.assertNotIn("terminal-completed", routes.CASE_STATES)
            self.assertNotIn("terminal-completed", routes.PARSE_PROGRESS)
            self.assertNotIn("terminal-completed", routes.ANALYSIS_PROGRESS)

            self.assertNotIn("terminal-failed", routes.CASE_STATES)
            self.assertNotIn("terminal-failed", routes.PARSE_PROGRESS)
            self.assertNotIn("terminal-failed", routes.ANALYSIS_PROGRESS)

            self.assertNotIn("terminal-error", routes.CASE_STATES)
            self.assertNotIn("terminal-error", routes.PARSE_PROGRESS)
            self.assertNotIn("terminal-error", routes.ANALYSIS_PROGRESS)

            self.assertIn("active-case", routes.CASE_STATES)
            self.assertIn(new_case_id, routes.CASE_STATES)
            self.assertIn(new_case_id, routes.PARSE_PROGRESS)
            self.assertIn(new_case_id, routes.ANALYSIS_PROGRESS)

    def test_evidence_upload_includes_split_ewf_segments(self) -> None:
        class CapturingParser(FakeParser):
            opened_paths: list[str] = []

            def __init__(self, evidence_path: str | Path, case_dir: str | Path, audit_logger: object) -> None:
                CapturingParser.opened_paths.append(str(evidence_path))
                super().__init__(evidence_path, case_dir, audit_logger)

        with (
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes, "ForensicParser", CapturingParser),
            patch.object(
                routes,
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
        with patch.object(routes, "CASES_ROOT", self.cases_root):
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

        with patch.object(routes, "IMAGES_ROOT", images_dir):
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

        with patch.object(routes, "create_provider", return_value=FakeConnectionProvider()):
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
        with patch.object(routes, "create_provider", return_value=fake_provider):
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

        with patch.object(routes, "create_provider", return_value=FailingConnectionProvider()):
            response = self.client.post("/api/settings/test-connection")

        self.assertEqual(response.status_code, 502)
        self.assertIn("Unable to connect to local AI endpoint.", response.get_json()["error"])

    def test_settings_test_connection_returns_config_error(self) -> None:
        with patch.object(routes, "create_provider", side_effect=ValueError("Invalid configuration.")):
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
        with patch.object(routes, "CASES_ROOT", self.cases_root):
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
        with patch.object(routes, "CASES_ROOT", self.cases_root):
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
        with patch.object(routes, "CASES_ROOT", self.cases_root):
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
        with patch.object(routes, "CASES_ROOT", self.cases_root):
            update_resp = self.client.post(
                "/api/settings",
                json={
                    "analysis": {
                        "date_buffer_days": 3,
                        "ai_max_tokens": 2048,
                        "artifact_deduplication_enabled": False,
                    },
                    "ai": {
                        "openai": {"attach_csv_as_file": False},
                        "local": {"attach_csv_as_file": False},
                    },
                },
            )
            self.assertEqual(update_resp.status_code, 200)
            payload = update_resp.get_json()
            self.assertEqual(payload["analysis"]["date_buffer_days"], 3)
            self.assertEqual(payload["analysis"]["ai_max_tokens"], 2048)
            self.assertEqual(payload["analysis"]["artifact_deduplication_enabled"], False)
            self.assertFalse(payload["ai"]["openai"]["attach_csv_as_file"])
            self.assertFalse(payload["ai"]["local"]["attach_csv_as_file"])

        persisted = yaml.safe_load(self.config_path.read_text(encoding="utf-8")) or {}
        self.assertEqual(persisted.get("analysis", {}).get("date_buffer_days"), 3)
        self.assertEqual(persisted.get("analysis", {}).get("ai_max_tokens"), 2048)
        self.assertEqual(persisted.get("analysis", {}).get("artifact_deduplication_enabled"), False)
        self.assertEqual(persisted.get("ai", {}).get("openai", {}).get("attach_csv_as_file"), False)
        self.assertEqual(persisted.get("ai", {}).get("local", {}).get("attach_csv_as_file"), False)

    def test_evidence_path_strips_quotes(self) -> None:
        evidence_path = Path(self.temp_dir.name) / "quoted.E01"
        evidence_path.write_bytes(b"demo")

        with (
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(
                routes,
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
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(
                routes,
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
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(
                routes,
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
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes, "ForensicAnalyzer", FakeAnalyzer),
            patch.object(
                routes,
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
            patch.object(routes, "ForensicParser", FakeParser),
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
                routes.ANALYSIS_PROGRESS[case_id] = routes._new_progress(status="running")
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
            patch.object(routes, "ForensicParser", FakeParser),
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

    def test_parse_uses_configured_csv_output_directory(self) -> None:
        evidence_path = Path(self.temp_dir.name) / "configured-output.E01"
        evidence_path.write_bytes(b"demo")
        configured_output_root = Path(self.temp_dir.name) / "external csv output"

        with (
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(
                routes,
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

    def test_report_hash_verification_uses_source_path_for_zip_evidence(self) -> None:
        zip_path = Path(self.temp_dir.name) / "sample.zip"
        with ZipFile(zip_path, "w") as archive:
            archive.writestr("sample.E01", b"demo")

        with (
            patch.object(routes, "CASES_ROOT", self.cases_root),
            patch.object(routes, "ForensicParser", FakeParser),
            patch.object(routes, "ReportGenerator", FakeReportGenerator),
            patch.object(
                routes,
                "compute_hashes",
                return_value={
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "size_bytes": 4,
                },
            ),
            patch.object(routes, "verify_hash", return_value=(True, "a" * 64)) as verify_hash_mock,
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

            report_resp = self.client.get(f"/api/cases/{case_id}/report")
            self.assertEqual(report_resp.status_code, 200)

            verify_hash_mock.assert_called_once()
            called_path, called_hash = verify_hash_mock.call_args.args
            self.assertEqual(Path(called_path), zip_path)
            self.assertEqual(called_hash, "a" * 64)

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
            self.assertEqual(len(str(details.get("computed_sha256", ""))), 64)
            self.assertTrue(details.get("match"))

    def test_extract_zip_without_image_returns_directory_target(self) -> None:
        zip_path = Path(self.temp_dir.name) / "triage.zip"
        destination = Path(self.temp_dir.name) / "triage_extract"
        with ZipFile(zip_path, "w") as archive:
            archive.writestr("Windows/System32/config/SAM", b"sam")
            archive.writestr("Users/Alice/NTUSER.DAT", b"profile")

        dissect_target = routes._extract_zip(zip_path, destination)

        self.assertEqual(dissect_target, destination)
        self.assertTrue(dissect_target.is_dir())

    def test_extract_zip_with_wrapper_directory_returns_wrapper_path(self) -> None:
        zip_path = Path(self.temp_dir.name) / "triage_wrapped.zip"
        destination = Path(self.temp_dir.name) / "triage_wrapped_extract"
        with ZipFile(zip_path, "w") as archive:
            archive.writestr("collection/Windows/System32/config/SAM", b"sam")
            archive.writestr("collection/Users/Alice/NTUSER.DAT", b"profile")

        dissect_target = routes._extract_zip(zip_path, destination)

        self.assertEqual(dissect_target, destination / "collection")
        self.assertTrue(dissect_target.is_dir())

    def test_evidence_intake_unexpected_error_returns_friendly_message(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root):
            create_resp = self.client.post("/api/cases", json={"case_name": "Friendly Error Case"})
            self.assertEqual(create_resp.status_code, 201)
            case_id = create_resp.get_json()["case_id"]

            with patch.object(routes, "_resolve_evidence_payload", side_effect=RuntimeError("internal-boom")):
                response = self.client.post(f"/api/cases/{case_id}/evidence", json={"path": "C:\\bad.E01"})

        self.assertEqual(response.status_code, 500)
        error_message = response.get_json()["error"]
        self.assertIn("Evidence intake failed due to an unexpected error", error_message)
        self.assertNotIn("internal-boom", error_message)

    def test_case_log_file_collects_module_logs_in_single_file(self) -> None:
        with patch.object(routes, "CASES_ROOT", self.cases_root):
            create_resp = self.client.post("/api/cases", json={"case_name": "Unified Log Case"})
            self.assertEqual(create_resp.status_code, 201)
            case_id = str(create_resp.get_json()["case_id"])
            case_dir = self.cases_root / case_id

            with patch.object(routes, "_resolve_evidence_payload", side_effect=RuntimeError("internal-boom")):
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
        with patch.object(routes, "CASES_ROOT", self.cases_root):
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


if __name__ == "__main__":
    unittest.main()
