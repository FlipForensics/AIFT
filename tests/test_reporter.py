from __future__ import annotations

import base64
import json
from pathlib import Path
import re
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch
import unittest

from markupsafe import Markup

from app.reporter import ReportGenerator
from app.reporter.markdown import (
    CONFIDENCE_CLASS_MAP,
    CONFIDENCE_PATTERN,
    _is_table_separator_row,
    _normalize_table_row_cells,
    _render_table_html,
    _split_table_row,
    _stringify as md_stringify,
    format_block,
    format_markdown_block,
    highlight_confidence_tokens,
    markdown_to_html,
    render_inline_markdown,
)


# ---------------------------------------------------------------------------
# Helper to build a ReportGenerator with real templates
# ---------------------------------------------------------------------------


def _create_report_generator(cases_root: Path) -> ReportGenerator:
    project_root = Path(__file__).resolve().parents[1]
    templates_dir = project_root / "templates"
    return ReportGenerator(templates_dir=templates_dir, cases_root=cases_root)


# ===================================================================
# Tests for app.reporter.__init__ re-export
# ===================================================================


class TestReporterInit(unittest.TestCase):
    """Verify the __init__.py re-export works."""

    def test_report_generator_importable_from_package(self) -> None:
        from app.reporter import ReportGenerator as RG

        self.assertIs(RG, ReportGenerator)


# ===================================================================
# Tests for ReportGenerator (generator.py)
# ===================================================================


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


# ===================================================================
# Tests for ReportGenerator private/static helpers
# ===================================================================


class TestFileToDataUri(unittest.TestCase):
    """Tests for ReportGenerator._file_to_data_uri."""

    def test_png_file(self) -> None:
        with TemporaryDirectory() as td:
            p = Path(td) / "logo.png"
            p.write_bytes(b"\x89PNG_FAKE")
            result = ReportGenerator._file_to_data_uri(p)
            encoded = base64.b64encode(b"\x89PNG_FAKE").decode("ascii")
            self.assertEqual(result, f"data:image/png;base64,{encoded}")

    def test_jpeg_file(self) -> None:
        with TemporaryDirectory() as td:
            p = Path(td) / "logo.jpg"
            p.write_bytes(b"\xff\xd8")
            result = ReportGenerator._file_to_data_uri(p)
            self.assertTrue(result.startswith("data:image/jpeg;base64,"))

    def test_svg_file(self) -> None:
        with TemporaryDirectory() as td:
            p = Path(td) / "logo.svg"
            p.write_bytes(b"<svg></svg>")
            result = ReportGenerator._file_to_data_uri(p)
            self.assertTrue(result.startswith("data:image/svg+xml;base64,"))

    def test_webp_file(self) -> None:
        with TemporaryDirectory() as td:
            p = Path(td) / "logo.webp"
            p.write_bytes(b"WEBP_DATA")
            result = ReportGenerator._file_to_data_uri(p)
            self.assertTrue(result.startswith("data:image/webp;base64,"))

    def test_unknown_extension(self) -> None:
        with TemporaryDirectory() as td:
            p = Path(td) / "logo.bmp"
            p.write_bytes(b"BMP_DATA")
            result = ReportGenerator._file_to_data_uri(p)
            self.assertTrue(result.startswith("data:application/octet-stream;base64,"))


class TestResolveCaseId(unittest.TestCase):
    """Tests for ReportGenerator._resolve_case_id."""

    def setUp(self) -> None:
        with TemporaryDirectory() as td:
            self.gen = _create_report_generator(Path(td))

    def test_case_id_from_analysis(self) -> None:
        result = self.gen._resolve_case_id({"case_id": "abc-123"}, {}, {})
        self.assertEqual(result, "abc-123")

    def test_case_id_from_analysis_id(self) -> None:
        result = self.gen._resolve_case_id({"id": "from-id"}, {}, {})
        self.assertEqual(result, "from-id")

    def test_case_id_from_hashes(self) -> None:
        result = self.gen._resolve_case_id({}, {}, {"case_id": "hash-case"})
        self.assertEqual(result, "hash-case")

    def test_case_id_from_metadata(self) -> None:
        result = self.gen._resolve_case_id({}, {"case_id": "meta-case"}, {})
        self.assertEqual(result, "meta-case")

    def test_case_id_from_nested_case(self) -> None:
        result = self.gen._resolve_case_id({"case": {"id": "nested-id"}}, {}, {})
        self.assertEqual(result, "nested-id")

    def test_case_id_from_nested_case_case_id(self) -> None:
        result = self.gen._resolve_case_id({"case": {"case_id": "nested-cid"}}, {}, {})
        self.assertEqual(result, "nested-cid")

    def test_case_id_sanitized(self) -> None:
        result = self.gen._resolve_case_id({"case_id": "foo bar/baz"}, {}, {})
        self.assertEqual(result, "foo_bar_baz")

    def test_raises_when_no_case_id(self) -> None:
        with self.assertRaises(ValueError):
            self.gen._resolve_case_id({}, {}, {})

    def test_raises_when_all_empty_strings(self) -> None:
        with self.assertRaises(ValueError):
            self.gen._resolve_case_id({"case_id": "", "id": ""}, {"case_id": ""}, {"case_id": ""})


class TestResolveCaseName(unittest.TestCase):
    """Tests for ReportGenerator._resolve_case_name."""

    def setUp(self) -> None:
        with TemporaryDirectory() as td:
            self.gen = _create_report_generator(Path(td))

    def test_name_from_nested_case(self) -> None:
        result = self.gen._resolve_case_name({"case": {"name": "My Case"}})
        self.assertEqual(result, "My Case")

    def test_name_from_case_name_key(self) -> None:
        result = self.gen._resolve_case_name({"case_name": "Direct Name"})
        self.assertEqual(result, "Direct Name")

    def test_default_when_no_name(self) -> None:
        result = self.gen._resolve_case_name({})
        self.assertEqual(result, "Untitled Investigation")

    def test_nested_case_not_mapping(self) -> None:
        result = self.gen._resolve_case_name({"case": "not-a-dict", "case_name": "Fallback"})
        self.assertEqual(result, "Fallback")

    def test_nested_case_empty_name(self) -> None:
        result = self.gen._resolve_case_name({"case": {"name": ""}, "case_name": "Alt"})
        self.assertEqual(result, "Alt")


class TestResolveToolVersion(unittest.TestCase):
    """Tests for ReportGenerator._resolve_tool_version."""

    def setUp(self) -> None:
        with TemporaryDirectory() as td:
            self.gen = _create_report_generator(Path(td))

    def test_explicit_version_in_analysis(self) -> None:
        result = self.gen._resolve_tool_version({"tool_version": "2.0.0"}, [])
        self.assertEqual(result, "2.0.0")

    def test_version_from_audit_entries(self) -> None:
        entries = [
            {"tool_version": "1.0.0"},
            {"tool_version": "1.1.0"},
        ]
        result = self.gen._resolve_tool_version({}, entries)
        self.assertEqual(result, "1.1.0")  # last entry wins

    def test_default_version_when_none_found(self) -> None:
        from app.version import TOOL_VERSION

        result = self.gen._resolve_tool_version({}, [])
        self.assertEqual(result, TOOL_VERSION)


class TestResolveAiProvider(unittest.TestCase):
    """Tests for ReportGenerator._resolve_ai_provider."""

    def setUp(self) -> None:
        with TemporaryDirectory() as td:
            self.gen = _create_report_generator(Path(td))

    def test_explicit_provider(self) -> None:
        result = self.gen._resolve_ai_provider({"ai_provider": "Anthropic Claude"})
        self.assertEqual(result, "Anthropic Claude")

    def test_model_info_with_provider_and_model(self) -> None:
        result = self.gen._resolve_ai_provider(
            {"model_info": {"provider": "openai", "model": "gpt-4o"}}
        )
        self.assertEqual(result, "openai (gpt-4o)")

    def test_model_info_provider_only(self) -> None:
        result = self.gen._resolve_ai_provider(
            {"model_info": {"provider": "anthropic"}}
        )
        self.assertEqual(result, "anthropic")

    def test_model_info_no_provider(self) -> None:
        result = self.gen._resolve_ai_provider({"model_info": {"model": "llama"}})
        self.assertEqual(result, "unknown (llama)")

    def test_default_when_nothing(self) -> None:
        result = self.gen._resolve_ai_provider({})
        self.assertEqual(result, "unknown")

    def test_model_info_not_mapping(self) -> None:
        result = self.gen._resolve_ai_provider({"model_info": "just a string"})
        self.assertEqual(result, "unknown")


class TestBuildEvidenceSummary(unittest.TestCase):
    """Tests for ReportGenerator._build_evidence_summary."""

    def setUp(self) -> None:
        with TemporaryDirectory() as td:
            self.gen = _create_report_generator(Path(td))

    def test_full_metadata_and_hashes(self) -> None:
        result = self.gen._build_evidence_summary(
            {"hostname": "ws-1", "os_version": "Win10", "domain": "corp", "ips": ["10.0.0.1"]},
            {"filename": "disk.E01", "sha256": "abc", "md5": "def", "size_bytes": 2048},
        )
        self.assertEqual(result["hostname"], "ws-1")
        self.assertEqual(result["os_version"], "Win10")
        self.assertEqual(result["domain"], "corp")
        self.assertEqual(result["filename"], "disk.E01")
        self.assertEqual(result["sha256"], "abc")
        self.assertEqual(result["md5"], "def")
        self.assertIn("2048", result["file_size"])

    def test_alternate_field_names(self) -> None:
        result = self.gen._build_evidence_summary(
            {"os": "Win11", "ip_addresses": ["1.1.1.1", "2.2.2.2"]},
            {"file_name": "alt.E01", "file_size_bytes": 1024},
        )
        self.assertEqual(result["os_version"], "Win11")
        self.assertEqual(result["filename"], "alt.E01")
        self.assertIn("1.1.1.1", result["ips"])
        self.assertIn("2.2.2.2", result["ips"])

    def test_defaults_when_empty(self) -> None:
        result = self.gen._build_evidence_summary({}, {})
        self.assertEqual(result["hostname"], "Unknown")
        self.assertEqual(result["os_version"], "Unknown")
        self.assertEqual(result["domain"], "Unknown")
        self.assertEqual(result["ips"], "Unknown")
        self.assertEqual(result["filename"], "Unknown")
        self.assertEqual(result["sha256"], "N/A")
        self.assertEqual(result["md5"], "N/A")
        self.assertEqual(result["file_size"], "N/A")


class TestResolveHashVerification(unittest.TestCase):
    """Tests for ReportGenerator._resolve_hash_verification."""

    def setUp(self) -> None:
        with TemporaryDirectory() as td:
            self.gen = _create_report_generator(Path(td))

    def test_explicit_bool_true(self) -> None:
        result = self.gen._resolve_hash_verification({"hash_verified": True})
        self.assertTrue(result["passed"])
        self.assertEqual(result["label"], "PASS")

    def test_explicit_bool_false(self) -> None:
        result = self.gen._resolve_hash_verification({"hash_verified": False})
        self.assertFalse(result["passed"])
        self.assertEqual(result["label"], "FAIL")

    def test_verification_passed_key(self) -> None:
        result = self.gen._resolve_hash_verification({"verification_passed": True})
        self.assertTrue(result["passed"])

    def test_verified_key(self) -> None:
        result = self.gen._resolve_hash_verification({"verified": False})
        self.assertFalse(result["passed"])

    def test_string_pass_variants(self) -> None:
        for val in ["true", "pass", "PASSED", "ok", "yes"]:
            result = self.gen._resolve_hash_verification({"hash_verified": val})
            self.assertTrue(result["passed"], f"Failed for value: {val}")
            self.assertEqual(result["label"], "PASS")

    def test_string_fail_variants(self) -> None:
        for val in ["false", "fail", "FAILED", "no"]:
            result = self.gen._resolve_hash_verification({"hash_verified": val})
            self.assertFalse(result["passed"], f"Failed for value: {val}")
            self.assertEqual(result["label"], "FAIL")

    def test_matching_sha256(self) -> None:
        result = self.gen._resolve_hash_verification({
            "expected_sha256": "a" * 64,
            "reverified_sha256": "a" * 64,
        })
        self.assertTrue(result["passed"])
        self.assertIn("matches", result["detail"])

    def test_mismatching_sha256(self) -> None:
        result = self.gen._resolve_hash_verification({
            "intake_sha256": "a" * 64,
            "current_sha256": "b" * 64,
        })
        self.assertFalse(result["passed"])
        self.assertIn("does not match", result["detail"])

    def test_insufficient_data(self) -> None:
        result = self.gen._resolve_hash_verification({})
        self.assertFalse(result["passed"])
        self.assertEqual(result["label"], "FAIL")
        self.assertIn("Insufficient", result["detail"])

    def test_unrecognized_string_falls_through_to_sha_check(self) -> None:
        result = self.gen._resolve_hash_verification({
            "hash_verified": "maybe",
            "original_sha256": "a" * 64,
            "computed_sha256": "a" * 64,
        })
        self.assertTrue(result["passed"])


class TestNormalizePerArtifactFindings(unittest.TestCase):
    """Tests for ReportGenerator._normalize_per_artifact_findings."""

    def setUp(self) -> None:
        with TemporaryDirectory() as td:
            self.gen = _create_report_generator(Path(td))

    def test_list_input(self) -> None:
        analysis = {
            "per_artifact": [
                {"artifact_name": "evtx", "analysis": "Found events."}
            ]
        }
        result = self.gen._normalize_per_artifact_findings(analysis)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["artifact_name"], "evtx")
        self.assertEqual(result[0]["analysis"], "Found events.")

    def test_non_mapping_items_skipped(self) -> None:
        analysis = {"per_artifact": ["not a dict", 42, None]}
        result = self.gen._normalize_per_artifact_findings(analysis)
        self.assertEqual(len(result), 0)

    def test_default_artifact_name(self) -> None:
        analysis = {"per_artifact": [{"analysis": "Some text."}]}
        result = self.gen._normalize_per_artifact_findings(analysis)
        self.assertEqual(result[0]["artifact_name"], "Artifact 1")

    def test_per_artifact_findings_key(self) -> None:
        analysis = {"per_artifact_findings": [{"name": "mft", "text": "MFT data."}]}
        result = self.gen._normalize_per_artifact_findings(analysis)
        self.assertEqual(result[0]["artifact_name"], "mft")
        self.assertEqual(result[0]["analysis"], "MFT data.")

    def test_none_returns_empty(self) -> None:
        result = self.gen._normalize_per_artifact_findings({})
        self.assertEqual(result, [])

    def test_nested_time_range(self) -> None:
        analysis = {
            "per_artifact": [
                {
                    "artifact_name": "evtx",
                    "analysis": "Events.",
                    "time_range": {"start": "2026-01-01", "end": "2026-01-02"},
                }
            ]
        }
        result = self.gen._normalize_per_artifact_findings(analysis)
        self.assertEqual(result[0]["time_range_start"], "2026-01-01")
        self.assertEqual(result[0]["time_range_end"], "2026-01-02")


class TestCoercePerArtifactIterable(unittest.TestCase):
    """Tests for ReportGenerator._coerce_per_artifact_iterable."""

    def setUp(self) -> None:
        with TemporaryDirectory() as td:
            self.gen = _create_report_generator(Path(td))

    def test_list_passed_through(self) -> None:
        items = [{"artifact_name": "a"}]
        result = self.gen._coerce_per_artifact_iterable(items)
        self.assertEqual(result, items)

    def test_string_returns_empty(self) -> None:
        result = self.gen._coerce_per_artifact_iterable("just a string")
        self.assertEqual(result, [])

    def test_none_returns_empty(self) -> None:
        result = self.gen._coerce_per_artifact_iterable(None)
        self.assertEqual(result, [])

    def test_single_finding_dict(self) -> None:
        finding = {"artifact_name": "evtx", "analysis": "text"}
        result = self.gen._coerce_per_artifact_iterable(finding)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], finding)

    def test_dict_keyed_by_artifact_with_mapping_values(self) -> None:
        raw = {"evtx": {"analysis": "Events."}, "mft": {"analysis": "MFT."}}
        result = self.gen._coerce_per_artifact_iterable(raw)
        self.assertEqual(len(result), 2)
        names = {r["artifact_name"] for r in result}
        self.assertIn("evtx", names)
        self.assertIn("mft", names)

    def test_dict_keyed_by_artifact_with_string_values(self) -> None:
        raw = {"evtx": "Event analysis text."}
        result = self.gen._coerce_per_artifact_iterable(raw)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["artifact_name"], "evtx")
        self.assertEqual(result[0]["analysis"], "Event analysis text.")

    def test_dict_with_empty_string_value_skipped(self) -> None:
        raw = {"evtx": ""}
        result = self.gen._coerce_per_artifact_iterable(raw)
        self.assertEqual(len(result), 0)

    def test_bytes_returns_empty(self) -> None:
        result = self.gen._coerce_per_artifact_iterable(b"bytes data")
        self.assertEqual(result, [])


class TestLooksLikeSingleFinding(unittest.TestCase):
    """Tests for ReportGenerator._looks_like_single_finding."""

    def test_true_with_finding_keys(self) -> None:
        self.assertTrue(ReportGenerator._looks_like_single_finding({"artifact_name": "x"}))
        self.assertTrue(ReportGenerator._looks_like_single_finding({"analysis": "text"}))
        self.assertTrue(ReportGenerator._looks_like_single_finding({"confidence": "HIGH"}))
        self.assertTrue(ReportGenerator._looks_like_single_finding({"record_count": 5}))

    def test_false_without_finding_keys(self) -> None:
        self.assertFalse(ReportGenerator._looks_like_single_finding({"evtx": "data", "mft": "data"}))


class TestNormalizeKeyDataPoints(unittest.TestCase):
    """Tests for ReportGenerator._normalize_key_data_points."""

    def setUp(self) -> None:
        with TemporaryDirectory() as td:
            self.gen = _create_report_generator(Path(td))

    def test_list_of_mappings(self) -> None:
        raw = [{"timestamp": "2026-01-01", "value": "event1"}]
        result = self.gen._normalize_key_data_points(raw)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["timestamp"], "2026-01-01")
        self.assertEqual(result[0]["value"], "event1")

    def test_mapping_without_value_key_uses_kv_text(self) -> None:
        raw = [{"timestamp": "2026-01-01", "source": "evtx", "action": "login"}]
        result = self.gen._normalize_key_data_points(raw)
        self.assertIn("source=evtx", result[0]["value"])
        self.assertIn("action=login", result[0]["value"])

    def test_list_of_strings(self) -> None:
        raw = ["point 1", "point 2"]
        result = self.gen._normalize_key_data_points(raw)
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["value"], "point 1")
        self.assertEqual(result[0]["timestamp"], "")

    def test_list_with_empty_strings_included(self) -> None:
        raw = ["valid", ""]
        result = self.gen._normalize_key_data_points(raw)
        # Empty string items are skipped
        self.assertEqual(len(result), 1)

    def test_mapping_input(self) -> None:
        raw = {"source": "evtx", "count": 5}
        result = self.gen._normalize_key_data_points(raw)
        self.assertEqual(len(result), 1)
        self.assertIn("source=evtx", result[0]["value"])

    def test_none_input(self) -> None:
        result = self.gen._normalize_key_data_points(None)
        self.assertEqual(result, [])

    def test_string_input(self) -> None:
        result = self.gen._normalize_key_data_points("single data point")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["value"], "single data point")

    def test_empty_string_input(self) -> None:
        result = self.gen._normalize_key_data_points("")
        self.assertEqual(result, [])

    def test_alternate_time_keys(self) -> None:
        raw = [{"time": "10:00", "data": "event"}]
        result = self.gen._normalize_key_data_points(raw)
        self.assertEqual(result[0]["timestamp"], "10:00")
        self.assertEqual(result[0]["value"], "event")

    def test_alternate_ts_and_detail_keys(self) -> None:
        raw = [{"ts": "11:00", "detail": "detail text"}]
        result = self.gen._normalize_key_data_points(raw)
        self.assertEqual(result[0]["timestamp"], "11:00")
        self.assertEqual(result[0]["value"], "detail text")

    def test_event_key(self) -> None:
        raw = [{"date": "2026-01-01", "event": "logon"}]
        result = self.gen._normalize_key_data_points(raw)
        self.assertEqual(result[0]["timestamp"], "2026-01-01")
        self.assertEqual(result[0]["value"], "logon")


class TestNormalizeAuditEntries(unittest.TestCase):
    """Tests for ReportGenerator._normalize_audit_entries."""

    def setUp(self) -> None:
        with TemporaryDirectory() as td:
            self.gen = _create_report_generator(Path(td))

    def test_none_returns_empty(self) -> None:
        result = self.gen._normalize_audit_entries(None)
        self.assertEqual(result, [])

    def test_dict_entries(self) -> None:
        entries = [
            {"timestamp": "2026-01-01T00:00:00Z", "action": "upload", "details": "file.E01"}
        ]
        result = self.gen._normalize_audit_entries(entries)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["timestamp"], "2026-01-01T00:00:00Z")
        self.assertEqual(result[0]["action"], "upload")
        self.assertEqual(result[0]["details"], "file.E01")

    def test_json_string_entries(self) -> None:
        entries = ['{"timestamp": "2026-01-01", "action": "parse"}']
        result = self.gen._normalize_audit_entries(entries)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["action"], "parse")

    def test_invalid_json_string_skipped(self) -> None:
        entries = ["not valid json"]
        result = self.gen._normalize_audit_entries(entries)
        self.assertEqual(len(result), 0)

    def test_empty_string_skipped(self) -> None:
        entries = [""]
        result = self.gen._normalize_audit_entries(entries)
        self.assertEqual(len(result), 0)

    def test_mapping_details_serialized_to_json(self) -> None:
        entries = [{"timestamp": "t", "action": "a", "details": {"key": "val"}}]
        result = self.gen._normalize_audit_entries(entries)
        self.assertIn('"key"', result[0]["details"])

    def test_sequence_details_serialized_to_json(self) -> None:
        entries = [{"timestamp": "t", "action": "a", "details": ["a", "b"]}]
        result = self.gen._normalize_audit_entries(entries)
        parsed = json.loads(result[0]["details"])
        self.assertEqual(parsed, ["a", "b"])

    def test_non_coercible_entries_skipped(self) -> None:
        entries = [42, None, True]
        result = self.gen._normalize_audit_entries(entries)
        self.assertEqual(len(result), 0)

    def test_defaults_for_missing_fields(self) -> None:
        entries = [{}]
        result = self.gen._normalize_audit_entries(entries)
        self.assertEqual(result[0]["timestamp"], "N/A")
        self.assertEqual(result[0]["action"], "unknown")
        self.assertEqual(result[0]["details"], "")
        self.assertEqual(result[0]["tool_version"], "")


class TestResolveConfidence(unittest.TestCase):
    """Tests for ReportGenerator._resolve_confidence."""

    def test_explicit_high(self) -> None:
        label, cls = ReportGenerator._resolve_confidence("HIGH", "")
        self.assertEqual(label, "HIGH")
        self.assertEqual(cls, "confidence-high")

    def test_explicit_critical_case_insensitive(self) -> None:
        label, cls = ReportGenerator._resolve_confidence("critical", "")
        self.assertEqual(label, "CRITICAL")
        self.assertEqual(cls, "confidence-critical")

    def test_from_text_pattern(self) -> None:
        label, cls = ReportGenerator._resolve_confidence("", "Confidence is MEDIUM here.")
        self.assertEqual(label, "MEDIUM")
        self.assertEqual(cls, "confidence-medium")

    def test_unspecified(self) -> None:
        label, cls = ReportGenerator._resolve_confidence("", "No severity mentioned.")
        self.assertEqual(label, "UNSPECIFIED")
        self.assertEqual(cls, "confidence-unknown")

    def test_explicit_invalid_falls_to_text(self) -> None:
        label, cls = ReportGenerator._resolve_confidence("UNKNOWN_LEVEL", "LOW risk found.")
        self.assertEqual(label, "LOW")
        self.assertEqual(cls, "confidence-low")


class TestNestedLookup(unittest.TestCase):
    """Tests for ReportGenerator._nested_lookup."""

    def test_valid_path(self) -> None:
        result = ReportGenerator._nested_lookup({"a": {"b": "value"}}, ("a", "b"))
        self.assertEqual(result, "value")

    def test_missing_key(self) -> None:
        result = ReportGenerator._nested_lookup({"a": {}}, ("a", "b"))
        self.assertIsNone(result)

    def test_intermediate_not_mapping(self) -> None:
        result = ReportGenerator._nested_lookup({"a": "string"}, ("a", "b"))
        self.assertIsNone(result)

    def test_top_level_missing(self) -> None:
        result = ReportGenerator._nested_lookup({}, ("a", "b"))
        self.assertIsNone(result)


class TestCoerceMapping(unittest.TestCase):
    """Tests for ReportGenerator._coerce_mapping."""

    def test_dict_input(self) -> None:
        result = ReportGenerator._coerce_mapping({"a": 1})
        self.assertEqual(result, {"a": 1})

    def test_valid_json_string(self) -> None:
        result = ReportGenerator._coerce_mapping('{"a": 1}')
        self.assertEqual(result, {"a": 1})

    def test_invalid_json_string(self) -> None:
        result = ReportGenerator._coerce_mapping("not json")
        self.assertIsNone(result)

    def test_empty_string(self) -> None:
        result = ReportGenerator._coerce_mapping("")
        self.assertIsNone(result)

    def test_whitespace_only(self) -> None:
        result = ReportGenerator._coerce_mapping("   ")
        self.assertIsNone(result)

    def test_non_mapping_json(self) -> None:
        result = ReportGenerator._coerce_mapping("[1, 2, 3]")
        self.assertIsNone(result)

    def test_integer_input(self) -> None:
        result = ReportGenerator._coerce_mapping(42)
        self.assertIsNone(result)

    def test_none_input(self) -> None:
        result = ReportGenerator._coerce_mapping(None)
        self.assertIsNone(result)


class TestFormatFileSize(unittest.TestCase):
    """Tests for ReportGenerator._format_file_size."""

    def test_none_returns_na(self) -> None:
        self.assertEqual(ReportGenerator._format_file_size(None), "N/A")

    def test_bytes(self) -> None:
        result = ReportGenerator._format_file_size(500)
        self.assertEqual(result, "500 B")

    def test_kilobytes(self) -> None:
        result = ReportGenerator._format_file_size(2048)
        self.assertIn("KB", result)
        self.assertIn("2048 bytes", result)

    def test_megabytes(self) -> None:
        result = ReportGenerator._format_file_size(5 * 1024 * 1024)
        self.assertIn("MB", result)

    def test_gigabytes(self) -> None:
        result = ReportGenerator._format_file_size(2 * 1024 ** 3)
        self.assertIn("GB", result)

    def test_terabytes(self) -> None:
        result = ReportGenerator._format_file_size(3 * 1024 ** 4)
        self.assertIn("TB", result)

    def test_string_number(self) -> None:
        result = ReportGenerator._format_file_size("1024")
        self.assertIn("KB", result)

    def test_invalid_value(self) -> None:
        result = ReportGenerator._format_file_size("not_a_number")
        self.assertEqual(result, "not_a_number")

    def test_zero_bytes(self) -> None:
        result = ReportGenerator._format_file_size(0)
        self.assertEqual(result, "0 B")


class TestStringifyIps(unittest.TestCase):
    """Tests for ReportGenerator._stringify_ips."""

    def test_list_of_ips(self) -> None:
        result = ReportGenerator._stringify_ips(["10.0.0.1", "10.0.0.2"])
        self.assertEqual(result, "10.0.0.1, 10.0.0.2")

    def test_empty_list(self) -> None:
        result = ReportGenerator._stringify_ips([])
        self.assertEqual(result, "Unknown")

    def test_list_with_empty_strings(self) -> None:
        result = ReportGenerator._stringify_ips(["10.0.0.1", "", "  "])
        self.assertEqual(result, "10.0.0.1")

    def test_string_value(self) -> None:
        result = ReportGenerator._stringify_ips("192.168.1.1")
        self.assertEqual(result, "192.168.1.1")

    def test_none_value(self) -> None:
        result = ReportGenerator._stringify_ips(None)
        self.assertEqual(result, "Unknown")

    def test_empty_string(self) -> None:
        result = ReportGenerator._stringify_ips("")
        self.assertEqual(result, "Unknown")


class TestMappingToKvText(unittest.TestCase):
    """Tests for ReportGenerator._mapping_to_kv_text."""

    def test_basic_mapping(self) -> None:
        result = ReportGenerator._mapping_to_kv_text({"a": 1, "b": "two"})
        self.assertIn("a=1", result)
        self.assertIn("b=two", result)
        self.assertIn("; ", result)

    def test_none_and_empty_values_skipped(self) -> None:
        result = ReportGenerator._mapping_to_kv_text({"a": 1, "b": None, "c": ""})
        self.assertIn("a=1", result)
        self.assertNotIn("b=", result)
        self.assertNotIn("c=", result)

    def test_empty_mapping(self) -> None:
        result = ReportGenerator._mapping_to_kv_text({})
        self.assertEqual(result, "")


class TestStringify(unittest.TestCase):
    """Tests for ReportGenerator._stringify."""

    def test_none_returns_default(self) -> None:
        self.assertEqual(ReportGenerator._stringify(None, default="fallback"), "fallback")

    def test_empty_string_returns_default(self) -> None:
        self.assertEqual(ReportGenerator._stringify("", default="fallback"), "fallback")

    def test_whitespace_returns_default(self) -> None:
        self.assertEqual(ReportGenerator._stringify("   ", default="fallback"), "fallback")

    def test_normal_string(self) -> None:
        self.assertEqual(ReportGenerator._stringify("  hello  "), "hello")

    def test_integer_converted(self) -> None:
        self.assertEqual(ReportGenerator._stringify(42), "42")

    def test_default_is_empty_string(self) -> None:
        self.assertEqual(ReportGenerator._stringify(None), "")


class TestResolveLogoDataUri(unittest.TestCase):
    """Tests for ReportGenerator._resolve_logo_data_uri."""

    def setUp(self) -> None:
        with TemporaryDirectory() as td:
            self.gen = _create_report_generator(Path(td))

    def test_returns_string(self) -> None:
        # The real project may or may not have an images directory,
        # but the method should always return a string.
        result = self.gen._resolve_logo_data_uri()
        self.assertIsInstance(result, str)

    @patch("app.reporter.generator.Path.is_dir", return_value=False)
    def test_returns_empty_when_no_images_dir(self, mock_is_dir: MagicMock) -> None:
        result = self.gen._resolve_logo_data_uri()
        self.assertEqual(result, "")


# ===================================================================
# Tests for markdown.py functions
# ===================================================================


class TestMdStringify(unittest.TestCase):
    """Tests for markdown._stringify."""

    def test_none_returns_default(self) -> None:
        self.assertEqual(md_stringify(None, default="x"), "x")

    def test_empty_returns_default(self) -> None:
        self.assertEqual(md_stringify("", default="x"), "x")

    def test_whitespace_returns_default(self) -> None:
        self.assertEqual(md_stringify("  ", default="x"), "x")

    def test_normal_value(self) -> None:
        self.assertEqual(md_stringify("  hello  "), "hello")

    def test_integer(self) -> None:
        self.assertEqual(md_stringify(42), "42")


class MarkdownToHtmlTests(unittest.TestCase):
    """Direct unit tests for markdown_to_html."""

    def test_bold_with_double_stars(self) -> None:
        result = markdown_to_html("This is **bold** text.")
        self.assertIn("<strong>bold</strong>", result)

    def test_bold_with_double_underscores(self) -> None:
        result = markdown_to_html("This is __bold__ text.")
        self.assertIn("<strong>bold</strong>", result)

    def test_italic_with_single_star(self) -> None:
        result = markdown_to_html("This is *italic* text.")
        self.assertIn("<em>italic</em>", result)

    def test_italic_with_single_underscore(self) -> None:
        result = markdown_to_html("This is _italic_ text.")
        self.assertIn("<em>italic</em>", result)

    def test_inline_code(self) -> None:
        result = markdown_to_html("Run `cmd.exe` to test.")
        self.assertIn("<code>cmd.exe</code>", result)

    def test_fenced_code_block(self) -> None:
        md = "```\nsome code\nmore code\n```"
        result = markdown_to_html(md)
        self.assertIn("<pre><code>", result)
        self.assertIn("some code", result)
        self.assertIn("more code", result)
        self.assertIn("</code></pre>", result)

    def test_headings_h1_through_h3(self) -> None:
        for level in range(1, 4):
            hashes = "#" * level
            md = f"{hashes} Heading Level {level}"
            result = markdown_to_html(md)
            self.assertIn(f"<h{level}>Heading Level {level}</h{level}>", result)

    def test_headings_h4_through_h6(self) -> None:
        for level in range(4, 7):
            hashes = "#" * level
            md = f"{hashes} Heading Level {level}"
            result = markdown_to_html(md)
            self.assertIn(f"<h{level}>Heading Level {level}</h{level}>", result)

    def test_unordered_list(self) -> None:
        md = "- Item one\n- Item two\n- Item three"
        result = markdown_to_html(md)
        self.assertIn("<ul>", result)
        self.assertIn("<li>Item one</li>", result)
        self.assertIn("<li>Item two</li>", result)
        self.assertIn("<li>Item three</li>", result)
        self.assertIn("</ul>", result)

    def test_unordered_list_with_star_marker(self) -> None:
        md = "* Alpha\n* Beta"
        result = markdown_to_html(md)
        self.assertIn("<ul>", result)
        self.assertIn("<li>Alpha</li>", result)
        self.assertIn("<li>Beta</li>", result)

    def test_ordered_list(self) -> None:
        md = "1. First\n2. Second\n3. Third"
        result = markdown_to_html(md)
        self.assertIn("<ol>", result)
        self.assertIn("<li>First</li>", result)
        self.assertIn("<li>Third</li>", result)
        self.assertIn("</ol>", result)

    def test_table_rendering(self) -> None:
        md = "| Header1 | Header2 |\n|---|---|\n| cell1 | cell2 |"
        result = markdown_to_html(md)
        self.assertIn("<table>", result)
        self.assertIn("<th>Header1</th>", result)
        self.assertIn("<td>cell1</td>", result)
        self.assertIn("</table>", result)

    def test_empty_string(self) -> None:
        result = markdown_to_html("")
        self.assertEqual(result, "")

    def test_multiple_paragraphs(self) -> None:
        md = "First paragraph.\n\nSecond paragraph."
        result = markdown_to_html(md)
        self.assertIn("<p>First paragraph.</p>", result)
        self.assertIn("<p>Second paragraph.</p>", result)

    def test_paragraph_with_line_breaks(self) -> None:
        md = "Line one\nLine two"
        result = markdown_to_html(md)
        self.assertIn("<br>", result)

    def test_unclosed_fenced_code_block(self) -> None:
        md = "```\nsome code\nno closing fence"
        result = markdown_to_html(md)
        self.assertIn("<pre><code>", result)
        self.assertIn("some code", result)

    def test_mixed_list_types_flushed(self) -> None:
        md = "- unordered item\n\n1. ordered item"
        result = markdown_to_html(md)
        self.assertIn("<ul>", result)
        self.assertIn("<ol>", result)

    def test_table_without_body_rows(self) -> None:
        md = "| H1 | H2 |\n|---|---|"
        result = markdown_to_html(md)
        self.assertIn("<table>", result)
        self.assertIn("<th>H1</th>", result)
        self.assertNotIn("<tbody>", result)

    def test_carriage_return_normalization(self) -> None:
        md = "Line one\r\nLine two\rLine three"
        result = markdown_to_html(md)
        # Should not contain raw \r
        self.assertNotIn("\r", result)


class TestRenderInlineMarkdown(unittest.TestCase):
    """Tests for render_inline_markdown."""

    def test_empty_string(self) -> None:
        self.assertEqual(render_inline_markdown(""), "")

    def test_none_value(self) -> None:
        self.assertEqual(render_inline_markdown(None), "")

    def test_code_span(self) -> None:
        result = render_inline_markdown("`hello`")
        self.assertEqual(result, "<code>hello</code>")

    def test_bold_stars(self) -> None:
        result = render_inline_markdown("**bold**")
        self.assertIn("<strong>bold</strong>", result)

    def test_bold_underscores(self) -> None:
        result = render_inline_markdown("__bold__")
        self.assertIn("<strong>bold</strong>", result)

    def test_italic_star(self) -> None:
        result = render_inline_markdown("*italic*")
        self.assertIn("<em>italic</em>", result)

    def test_italic_underscore(self) -> None:
        result = render_inline_markdown("_italic_")
        self.assertIn("<em>italic</em>", result)

    def test_confidence_highlighted(self) -> None:
        result = render_inline_markdown("severity: CRITICAL")
        self.assertIn("confidence-critical", result)

    def test_mixed_code_and_formatting(self) -> None:
        result = render_inline_markdown("Run `cmd` with **admin** rights")
        self.assertIn("<code>cmd</code>", result)
        self.assertIn("<strong>admin</strong>", result)


class TestSplitTableRow(unittest.TestCase):
    """Tests for _split_table_row."""

    def test_no_pipe(self) -> None:
        self.assertEqual(_split_table_row("no pipes here"), [])

    def test_basic_row(self) -> None:
        result = _split_table_row("| a | b | c |")
        self.assertEqual(result, ["a", "b", "c"])

    def test_row_without_leading_trailing_pipes(self) -> None:
        result = _split_table_row("a | b | c")
        self.assertEqual(result, ["a", "b", "c"])

    def test_empty_input(self) -> None:
        self.assertEqual(_split_table_row(""), [])

    def test_none_input(self) -> None:
        self.assertEqual(_split_table_row(None), [])

    def test_only_pipe(self) -> None:
        result = _split_table_row("|")
        # After stripping leading and trailing pipe, empty string, split gives [""]
        self.assertEqual(result, [""])


class TestIsTableSeparatorRow(unittest.TestCase):
    """Tests for _is_table_separator_row."""

    def test_valid_separator(self) -> None:
        self.assertTrue(_is_table_separator_row(["---", "---", "---"]))

    def test_separator_with_colons(self) -> None:
        self.assertTrue(_is_table_separator_row([":---", "---:", ":---:"]))

    def test_empty_cells(self) -> None:
        self.assertFalse(_is_table_separator_row([]))

    def test_non_separator(self) -> None:
        self.assertFalse(_is_table_separator_row(["Header1", "Header2"]))

    def test_mixed_valid_and_invalid(self) -> None:
        self.assertFalse(_is_table_separator_row(["---", "text"]))

    def test_short_dashes_invalid(self) -> None:
        self.assertFalse(_is_table_separator_row(["--"]))


class TestNormalizeTableRowCells(unittest.TestCase):
    """Tests for _normalize_table_row_cells."""

    def test_exact_count(self) -> None:
        result = _normalize_table_row_cells(["a", "b", "c"], 3)
        self.assertEqual(result, ["a", "b", "c"])

    def test_padding(self) -> None:
        result = _normalize_table_row_cells(["a"], 3)
        self.assertEqual(result, ["a", "", ""])

    def test_truncation(self) -> None:
        result = _normalize_table_row_cells(["a", "b", "c", "d"], 2)
        self.assertEqual(result, ["a", "b"])

    def test_strips_whitespace(self) -> None:
        result = _normalize_table_row_cells(["  a  ", " b "], 2)
        self.assertEqual(result, ["a", "b"])


class TestRenderTableHtml(unittest.TestCase):
    """Tests for _render_table_html."""

    def test_basic_table(self) -> None:
        result = _render_table_html(["H1", "H2"], [["c1", "c2"]])
        self.assertIn("<table>", result)
        self.assertIn("<th>H1</th>", result)
        self.assertIn("<td>c1</td>", result)
        self.assertIn("</table>", result)

    def test_no_body_rows(self) -> None:
        result = _render_table_html(["H1", "H2"], [])
        self.assertIn("<thead>", result)
        self.assertNotIn("<tbody>", result)

    def test_inline_formatting_in_cells(self) -> None:
        result = _render_table_html(["**Bold Header**"], [["*italic*"]])
        self.assertIn("<strong>Bold Header</strong>", result)
        self.assertIn("<em>italic</em>", result)


class HtmlEscapingTests(unittest.TestCase):
    """Test that HTML special characters are escaped to prevent XSS."""

    def test_script_tag_is_escaped(self) -> None:
        result = markdown_to_html("<script>alert('xss')</script>")
        self.assertNotIn("<script>", result)
        self.assertIn("&lt;script&gt;", result)

    def test_angle_brackets_escaped_in_inline_text(self) -> None:
        result = markdown_to_html("Value <img onerror=alert(1)> test")
        self.assertNotIn("<img", result)
        self.assertIn("&lt;img", result)

    def test_ampersand_is_escaped(self) -> None:
        result = markdown_to_html("A & B")
        self.assertIn("&amp;", result)

    def test_quotes_are_escaped(self) -> None:
        result = markdown_to_html('He said "hello"')
        self.assertIn("&quot;", result)


class ConfidenceHighlightingTests(unittest.TestCase):
    """Test confidence token highlighting in _highlight_confidence_tokens."""

    def test_critical_token_highlighted(self) -> None:
        result = highlight_confidence_tokens("Severity: CRITICAL")
        self.assertIn("confidence-critical", result)
        self.assertIn("CRITICAL", result)

    def test_high_token_highlighted(self) -> None:
        result = highlight_confidence_tokens("Confidence HIGH")
        self.assertIn("confidence-high", result)

    def test_medium_token_highlighted(self) -> None:
        result = highlight_confidence_tokens("Risk level: MEDIUM")
        self.assertIn("confidence-medium", result)

    def test_low_token_highlighted(self) -> None:
        result = highlight_confidence_tokens("Priority: LOW")
        self.assertIn("confidence-low", result)

    def test_case_insensitive_matching(self) -> None:
        result = highlight_confidence_tokens("confidence high here")
        self.assertIn("confidence-high", result)

    def test_multiple_tokens_highlighted(self) -> None:
        result = highlight_confidence_tokens("CRITICAL and LOW findings")
        self.assertIn("confidence-critical", result)
        self.assertIn("confidence-low", result)

    def test_no_tokens_returns_unchanged(self) -> None:
        text = "No severity tokens here"
        result = highlight_confidence_tokens(text)
        self.assertEqual(result, text)

    def test_markdown_to_html_highlights_confidence_inline(self) -> None:
        result = markdown_to_html("- severity: CRITICAL\n- confidence: HIGH")
        self.assertIn("confidence-inline confidence-critical", result)
        self.assertIn("confidence-inline confidence-high", result)

    def test_span_structure(self) -> None:
        result = highlight_confidence_tokens("CRITICAL")
        self.assertIn('<span class="confidence-inline confidence-critical">CRITICAL</span>', result)


class TestFormatBlock(unittest.TestCase):
    """Tests for format_block Jinja2 filter."""

    def test_empty_returns_na_markup(self) -> None:
        result = format_block("")
        self.assertIsInstance(result, Markup)
        self.assertIn("N/A", str(result))

    def test_none_returns_na_markup(self) -> None:
        result = format_block(None)
        self.assertIn("N/A", str(result))

    def test_plain_text(self) -> None:
        result = format_block("Hello world")
        self.assertIsInstance(result, Markup)
        self.assertIn("Hello world", str(result))

    def test_newlines_converted_to_br(self) -> None:
        result = format_block("line1\nline2")
        self.assertIn("<br>", str(result))

    def test_confidence_tokens_highlighted(self) -> None:
        result = format_block("Risk: HIGH")
        self.assertIn("confidence-high", str(result))

    def test_html_escaped(self) -> None:
        result = format_block("<script>alert(1)</script>")
        self.assertNotIn("<script>", str(result))
        self.assertIn("&lt;script&gt;", str(result))

    def test_carriage_return_normalized(self) -> None:
        result = format_block("line1\r\nline2")
        self.assertIn("<br>", str(result))


class TestFormatMarkdownBlock(unittest.TestCase):
    """Tests for format_markdown_block Jinja2 filter."""

    def test_empty_returns_na_markup(self) -> None:
        result = format_markdown_block("")
        self.assertIsInstance(result, Markup)
        self.assertIn("N/A", str(result))

    def test_none_returns_na_markup(self) -> None:
        result = format_markdown_block(None)
        self.assertIn("N/A", str(result))

    def test_markdown_rendered(self) -> None:
        result = format_markdown_block("## Heading")
        self.assertIsInstance(result, Markup)
        self.assertIn("<h2>Heading</h2>", str(result))

    def test_bold_rendered(self) -> None:
        result = format_markdown_block("This is **bold** text.")
        self.assertIn("<strong>bold</strong>", str(result))

    def test_list_rendered(self) -> None:
        result = format_markdown_block("- item1\n- item2")
        self.assertIn("<ul>", str(result))
        self.assertIn("<li>item1</li>", str(result))


# ===================================================================
# Tests for constants and patterns
# ===================================================================


class TestConfidenceConstants(unittest.TestCase):
    """Tests for confidence-related constants."""

    def test_confidence_class_map_keys(self) -> None:
        self.assertEqual(
            set(CONFIDENCE_CLASS_MAP.keys()),
            {"CRITICAL", "HIGH", "MEDIUM", "LOW"},
        )

    def test_confidence_pattern_matches_all_levels(self) -> None:
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            self.assertIsNotNone(CONFIDENCE_PATTERN.search(level))

    def test_confidence_pattern_case_insensitive(self) -> None:
        self.assertIsNotNone(CONFIDENCE_PATTERN.search("critical"))
        self.assertIsNotNone(CONFIDENCE_PATTERN.search("High"))


# ===================================================================
# Edge case: generate with None/empty inputs
# ===================================================================


class TestGenerateEdgeCases(unittest.TestCase):
    """Edge cases for ReportGenerator.generate."""

    def test_generate_with_none_analysis_results(self) -> None:
        """generate should handle None analysis_results by raising ValueError (no case_id)."""
        with TemporaryDirectory() as td:
            gen = _create_report_generator(Path(td))
            with self.assertRaises(ValueError):
                gen.generate(
                    analysis_results=None,
                    image_metadata=None,
                    evidence_hashes=None,
                    investigation_context="",
                    audit_log_entries=None,
                )

    def test_generate_uses_executive_summary_over_summary(self) -> None:
        with TemporaryDirectory() as td:
            cases_root = Path(td) / "cases"
            gen = _create_report_generator(cases_root)
            report_path = gen.generate(
                analysis_results={
                    "case_id": "exec-sum",
                    "summary": "Fallback summary.",
                    "executive_summary": "Primary executive summary.",
                    "per_artifact": [],
                },
                image_metadata={},
                evidence_hashes={"hash_verified": True},
                investigation_context="Test.",
                audit_log_entries=[],
            )
            html = report_path.read_text(encoding="utf-8")
            self.assertIn("Primary executive summary.", html)

    def test_generate_empty_investigation_context(self) -> None:
        with TemporaryDirectory() as td:
            cases_root = Path(td) / "cases"
            gen = _create_report_generator(cases_root)
            report_path = gen.generate(
                analysis_results={
                    "case_id": "empty-ctx",
                    "summary": "Summary.",
                    "per_artifact": [],
                },
                image_metadata={},
                evidence_hashes={"hash_verified": True},
                investigation_context="",
                audit_log_entries=[],
            )
            html = report_path.read_text(encoding="utf-8")
            self.assertIn("No investigation context provided.", html)


if __name__ == "__main__":
    unittest.main()
