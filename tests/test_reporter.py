from __future__ import annotations

from pathlib import Path
import re
from tempfile import TemporaryDirectory
import unittest

from app.reporter import ReportGenerator


class ReporterTests(unittest.TestCase):
    def _create_report_generator(self, cases_root: Path) -> ReportGenerator:
        project_root = Path(__file__).resolve().parents[1]
        templates_dir = project_root / "templates"
        return ReportGenerator(templates_dir=templates_dir, cases_root=cases_root)

    def test_generate_creates_report_with_required_sections(self) -> None:
        with TemporaryDirectory(prefix="aift-reporter-test-") as temp_dir:
            cases_root = Path(temp_dir) / "cases"
            reporter = self._create_report_generator(cases_root)

            analysis_results = {
                "case_id": "case-123",
                "case_name": "Credential Theft Investigation",
                "tool_version": "1.2.3",
                "model_info": {"provider": "openai", "model": "gpt-4o"},
                "summary": (
                    "Executive Summary\n"
                    "- Unauthorized tool execution was observed.\n\n"
                    "Correlated Timeline\n"
                    "- 2026-01-15T09:30:00Z - Suspicious binary executed.\n\n"
                    "Recommendations\n"
                    "- Acquire volatile memory for follow-up.\n"
                ),
                "per_artifact": [
                    {
                        "artifact_key": "runkeys",
                        "artifact_name": "Run/RunOnce Keys",
                        "analysis": "Confidence HIGH that persistence was configured via HKCU Run key.",
                        "record_count": 17,
                        "time_range_start": "2026-01-15T09:20:00Z",
                        "time_range_end": "2026-01-15T09:40:00Z",
                        "key_data_points": [
                            {
                                "timestamp": "2026-01-15T09:31:00Z",
                                "value": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                            }
                        ],
                    }
                ],
            }
            image_metadata = {
                "hostname": "ws-13",
                "os_version": "Windows 11 Pro",
                "domain": "corp.local",
                "ips": ["10.1.1.45", "172.16.1.20"],
            }
            evidence_hashes = {
                "filename": "disk-image.E01",
                "sha256": "a" * 64,
                "md5": "b" * 32,
                "size_bytes": 1024,
                "expected_sha256": "c" * 64,
                "reverified_sha256": "c" * 64,
            }
            investigation_context = (
                "Investigate potential credential theft and persistence "
                "between 2026-01-15 and 2026-01-16."
            )
            audit_entries = [
                {
                    "timestamp": "2026-01-15T10:00:00Z",
                    "action": "analysis_completed",
                    "details": {"artifact_key": "runkeys", "status": "success"},
                    "tool_version": "1.2.3",
                }
            ]

            report_path = reporter.generate(
                analysis_results=analysis_results,
                image_metadata=image_metadata,
                evidence_hashes=evidence_hashes,
                investigation_context=investigation_context,
                audit_log_entries=audit_entries,
            )
            html = report_path.read_text(encoding="utf-8")
            self.assertTrue(report_path.exists())
            self.assertEqual(report_path.parent, cases_root / "case-123" / "reports")
            self.assertRegex(report_path.name, r"^report_\d{8}_\d{6}\.html$")
            self.assertIn("<style>", html)
            self.assertNotIn("<link rel=", html)
            self.assertNotIn("http://", html)
            self.assertNotIn("https://", html)
            self.assertIn("Credential Theft Investigation", html)
            self.assertIn("case-123", html)
            self.assertIn("AI Provider", html)
            self.assertIn("Evidence Summary", html)
            self.assertIn("Hash Verification Result", html)
            self.assertIn("Executive Summary", html)
            self.assertNotIn("<h2>Correlated Timeline</h2>", html)
            self.assertIn("Per-Artifact Findings", html)
            self.assertNotIn("<h2>Recommendations</h2>", html)
            self.assertIn("Audit Trail", html)
            self.assertIn('class="hash-status pass"', html)
            self.assertRegex(html, r'class="hash-status pass">\s*PASS\s*</div>')
            project_root = Path(__file__).resolve().parents[1]
            images_dir = project_root / "images"
            if images_dir.exists() and any(images_dir.glob("*.png")):
                self.assertIn("data:image/png;base64,", html)
            self.assertIn("confidence-high", html)
            self.assertIn("<details class=\"artifact-card\" open>", html)
            self.assertIn(
                (
                    "This report was generated with AI assistance. "
                    "All findings should be independently verified by a qualified forensic examiner "
                    "before being used in any legal or formal proceeding."
                ),
                html,
            )
            self.assertIn("©Flip Forensics", html)

    def test_generate_marks_hash_verification_fail_on_mismatch(self) -> None:
        with TemporaryDirectory(prefix="aift-reporter-test-") as temp_dir:
            cases_root = Path(temp_dir) / "cases"
            reporter = self._create_report_generator(cases_root)

            report_path = reporter.generate(
                analysis_results={
                    "case_id": "case-hash-fail",
                    "case_name": "Hash Mismatch Investigation",
                    "summary": "Executive Summary\n- Hash mismatch detected.\n",
                    "per_artifact": [],
                },
                image_metadata={"hostname": "host-fail"},
                evidence_hashes={
                    "filename": "bad.E01",
                    "expected_sha256": "1" * 64,
                    "reverified_sha256": "2" * 64,
                },
                investigation_context="Confirm hash mismatch handling.",
                audit_log_entries=[],
            )
            html = report_path.read_text(encoding="utf-8")

        self.assertEqual(report_path.parent, cases_root / "case-hash-fail" / "reports")
        self.assertIn('class="hash-status fail"', html)
        self.assertRegex(html, r'class="hash-status fail">\s*FAIL\s*</div>')
        self.assertIn("does not match intake hash", html)

    def test_generate_accepts_mapping_style_per_artifact_findings(self) -> None:
        with TemporaryDirectory(prefix="aift-reporter-test-") as temp_dir:
            cases_root = Path(temp_dir) / "cases"
            reporter = self._create_report_generator(cases_root)

            report_path = reporter.generate(
                analysis_results={
                    "case_id": "case-map",
                    "summary": "Executive Summary\n- Mapping test.\n",
                    "per_artifact": {
                        "runkeys": {
                            "analysis": "Confidence LOW for persistence.",
                            "confidence": "critical",
                            "record_count": 1,
                            "time_range": {"start": "2026-01-01T00:00:00Z", "end": "2026-01-01T00:00:00Z"},
                            "key_data_points": [
                                {
                                    "timestamp": "2026-01-01T00:00:00Z",
                                    "value": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
                                }
                            ],
                        },
                        "shimcache": "No notable activity.",
                    },
                },
                image_metadata={"hostname": "map-host"},
                evidence_hashes={"hash_verified": True},
                investigation_context="Check mapping support.",
                audit_log_entries=[],
            )
            html = report_path.read_text(encoding="utf-8")

        self.assertEqual(html.count('class="artifact-card"'), 2)
        self.assertIn("runkeys (runkeys)", html)
        self.assertIn("shimcache (shimcache)", html)
        self.assertIn("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", html)
        self.assertIn("class=\"mono\">HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", html)
        self.assertIn('class="pill confidence-critical">CRITICAL</span>', html)
        self.assertIn("details:not([open]) > *:not(summary)", html)

    def test_generate_renders_markdown_in_summary_and_artifact_findings(self) -> None:
        with TemporaryDirectory(prefix="aift-reporter-test-") as temp_dir:
            cases_root = Path(temp_dir) / "cases"
            reporter = self._create_report_generator(cases_root)

            report_path = reporter.generate(
                analysis_results={
                    "case_id": "case-markdown",
                    "summary": (
                        "Executive Summary\n"
                        "### Cross-Artifact forensic synthesis\n"
                        "1. **Host and Domain**: `DESKTOP-23PS6ES`\n"
                        "2. **Key Users/Accounts**: `alice`\n"
                    ),
                    "per_artifact": [
                        {
                            "artifact_key": "runkeys",
                            "artifact_name": "Run/RunOnce Keys",
                            "analysis": (
                                "### Baseline Profile (Cross-Artifact)\n"
                                "- severity: CRITICAL\n"
                                "- **Host and Domain**: `DESKTOP-23PS6ES`\n"
                                "- confidence: HIGH\n"
                            ),
                        }
                    ],
                },
                image_metadata={"hostname": "md-host"},
                evidence_hashes={"hash_verified": True},
                investigation_context="### Scope\n- Parse baseline activity.",
                audit_log_entries=[],
            )
            html = report_path.read_text(encoding="utf-8")

        self.assertIn('<div class="content-block markdown-output">', html)
        self.assertIn("<h3>Cross-Artifact forensic synthesis</h3>", html)
        self.assertIn("<strong>Host and Domain</strong>: <code>DESKTOP-23PS6ES</code>", html)
        self.assertIn("<h3>Baseline Profile (Cross-Artifact)</h3>", html)
        self.assertIn("confidence-inline confidence-critical", html)
        self.assertIn("confidence-inline confidence-high", html)
        self.assertIn("<h3>Scope</h3>", html)

    def test_generate_keeps_full_summary_text_in_executive_summary_block(self) -> None:
        with TemporaryDirectory(prefix="aift-reporter-test-") as temp_dir:
            cases_root = Path(temp_dir) / "cases"
            reporter = self._create_report_generator(cases_root)

            summary_text = (
                "Executive Summary\n"
                "Cross-Artifact Incident Assessment\n"
                "This is the summary preface.\n\n"
                "---\n\n"
                "Timeline\n"
                "| Timestamp (UTC) | Source Artifact(s) | Event | Confidence |\n"
                "|---|---|---|---|\n"
                "| 2024-02-05T00:00:00Z | Browser Downloads | Test event | HIGH |\n"
            )

            report_path = reporter.generate(
                analysis_results={
                    "case_id": "case-full-summary",
                    "summary": summary_text,
                    "per_artifact": [],
                },
                image_metadata={"hostname": "summary-host"},
                evidence_hashes={"hash_verified": True},
                investigation_context="Validate summary rendering.",
                audit_log_entries=[],
            )
            html = report_path.read_text(encoding="utf-8")

        self.assertIn("This is the summary preface.", html)
        self.assertIn("<table>", html)
        self.assertIn("<th>Timestamp (UTC)</th>", html)
        self.assertIn("<th>Source Artifact(s)</th>", html)
        self.assertIn("<th>Event</th>", html)
        self.assertIn("<th>Confidence</th>", html)
        self.assertIn("<td>2024-02-05T00:00:00Z</td>", html)
        self.assertIn("<td>Browser Downloads</td>", html)
        self.assertIn("<td>Test event</td>", html)
        self.assertNotIn("| Timestamp (UTC) | Source Artifact(s) | Event | Confidence |", html)
        self.assertIn("confidence-inline confidence-high", html)


if __name__ == "__main__":
    unittest.main()
