from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from app.analyzer import ForensicAnalyzer
from app.audit import AuditLogger
from app.hasher import compute_hashes, verify_hash
from app.parser import ForensicParser
from app.reporter import ReportGenerator


class FakeTarget:
    hostname = "LAB-WS01"
    os_version = "Windows 11 Pro"
    domain = "lab.local"
    ips = ["192.168.56.10", "10.10.10.12"]

    def __init__(self) -> None:
        self.closed = False

    def runkeys(self) -> list[dict[str, str]]:
        return [
            {
                "ts": "2026-01-15T10:11:00Z",
                "name": "UserUpdater",
                "command": r"C:\Users\Public\updater.exe",
                "key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            },
            {
                "ts": "2026-01-15T10:20:00Z",
                "name": "OneDrive",
                "command": r"C:\Program Files\Microsoft OneDrive\OneDrive.exe",
                "key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            },
        ]

    def tasks(self) -> list[dict[str, str]]:
        return [
            {
                "ts": "2026-01-15T10:14:00Z",
                "task_name": r"\Microsoft\Windows\UpdateOrchestrator\UpdateTask",
                "action": r"C:\Users\Public\updater.exe /silent",
                "author": "SYSTEM",
            }
        ]

    def close(self) -> None:
        self.closed = True


class FakeProvider:
    def __init__(self, responses: list[str]) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, str]] = []
        self._index = 0

    def analyze(self, system_prompt: str, user_prompt: str, max_tokens: int = 4096) -> str:
        self.calls.append(
            {
                "system_prompt": system_prompt,
                "user_prompt": user_prompt,
                "max_tokens": str(max_tokens),
            }
        )
        if self._index < len(self.responses):
            response = self.responses[self._index]
            self._index += 1
            return response
        return self.responses[-1]

    def get_model_info(self) -> dict[str, str]:
        return {"provider": "fake", "model": "fake-model-1"}


class PipelineTests(unittest.TestCase):
    @staticmethod
    def _read_audit_entries(audit_path: Path) -> list[dict[str, object]]:
        return [
            json.loads(line)
            for line in audit_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    def test_parse_analyze_report_pipeline_generates_expected_report_sections(self) -> None:
        with TemporaryDirectory(prefix="aift-pipeline-test-") as temp_dir:
            root = Path(temp_dir)
            case_id = "case-pipeline-001"
            case_dir = root / "cases" / case_id
            case_dir.mkdir(parents=True, exist_ok=True)
            evidence_path = case_dir / "evidence" / "mock_image.E01"
            evidence_path.parent.mkdir(parents=True, exist_ok=True)
            evidence_path.write_bytes(b"mock evidence bytes for pipeline integration test")

            audit_logger = AuditLogger(case_dir)
            fake_target = FakeTarget()

            with patch("app.parser.Target.open", return_value=fake_target):
                parser = ForensicParser(
                    evidence_path=evidence_path,
                    case_dir=case_dir,
                    audit_logger=audit_logger,
                )
                image_metadata = parser.get_image_metadata()
                runkeys_result = parser.parse_artifact("runkeys")
                tasks_result = parser.parse_artifact("tasks")
                parser.close()

            self.assertTrue(runkeys_result["success"])
            self.assertTrue(tasks_result["success"])
            self.assertTrue(Path(str(runkeys_result["csv_path"])).exists())
            self.assertTrue(Path(str(tasks_result["csv_path"])).exists())
            self.assertTrue(fake_target.closed)

            provider = FakeProvider(
                responses=[
                    "Confidence HIGH suspicious autorun command from user-writable path.",
                    "Confidence MEDIUM scheduled task executes suspicious command.",
                    "Executive Summary\n- Cross-artifact synthesis points to persistence.",
                ]
            )
            with patch("app.analyzer.create_provider", return_value=provider):
                analyzer = ForensicAnalyzer(
                    case_dir=case_dir,
                    audit_logger=audit_logger,
                )
                analysis_results = analyzer.run_full_analysis(
                    artifact_keys=["runkeys", "tasks"],
                    investigation_context="Investigate persistence around 2026-01-15.",
                    metadata=image_metadata,
                )

            self.assertEqual(len(provider.calls), 3)

            analysis_results["case_id"] = case_id
            analysis_results["case_name"] = "Pipeline Integration Case"

            intake_hashes = compute_hashes(evidence_path)
            hash_ok, computed_sha256 = verify_hash(
                evidence_path,
                intake_hashes["sha256"],
                return_computed=True,
            )
            audit_logger.log(
                "hash_verification",
                {
                    "expected_sha256": intake_hashes["sha256"],
                    "computed_sha256": computed_sha256,
                    "match": hash_ok,
                    "verification_path": str(evidence_path),
                },
            )

            evidence_hashes = {
                "filename": evidence_path.name,
                "sha256": intake_hashes["sha256"],
                "md5": intake_hashes["md5"],
                "size_bytes": intake_hashes["size_bytes"],
                "expected_sha256": intake_hashes["sha256"],
                "reverified_sha256": computed_sha256,
                "hash_verified": hash_ok,
                "case_id": case_id,
            }

            audit_path = case_dir / "audit.jsonl"
            audit_entries_for_report = self._read_audit_entries(audit_path)

            reporter = ReportGenerator(cases_root=root / "cases")
            report_path = reporter.generate(
                analysis_results=analysis_results,
                image_metadata=image_metadata,
                evidence_hashes=evidence_hashes,
                investigation_context="Investigate persistence and scheduled task abuse.",
                audit_log_entries=audit_entries_for_report,
            )
            audit_logger.log(
                "report_generated",
                {"report_filename": report_path.name, "hash_verified": hash_ok},
            )

            html = report_path.read_text(encoding="utf-8")
            self.assertTrue(report_path.exists())
            self.assertIn("Evidence Summary", html)
            self.assertIn("Hash Verification Result", html)
            self.assertIn("Per-Artifact Findings", html)
            self.assertIn("Audit Trail", html)
            self.assertIn("Run/RunOnce Keys", html)
            self.assertIn("Scheduled Tasks", html)
            self.assertIn("Cross-artifact synthesis points to persistence.", html)
            self.assertIn('class="hash-status pass"', html)
            self.assertIn("parsing_started", html)
            self.assertIn("analysis_completed", html)
            self.assertIn("hash_verification", html)

            audit_entries = self._read_audit_entries(audit_path)
            recorded_actions = {str(entry.get("action")) for entry in audit_entries}
            expected_actions = {
                "parsing_started",
                "parsing_completed",
                "analysis_started",
                "analysis_completed",
                "hash_verification",
                "report_generated",
            }
            self.assertTrue(expected_actions.issubset(recorded_actions))


if __name__ == "__main__":
    unittest.main()
