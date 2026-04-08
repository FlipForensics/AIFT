"""Tests for multi-image report generation.

Validates that the ReportGenerator correctly handles:
- V1 single-image format (backward compatibility)
- Multi-image format with per-image sections
- Cross-system analysis section rendering
- Evidence summary table with multiple images
- Automatic V1-to-multi-image format conversion
"""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from app.reporter import ReportGenerator


def _create_report_generator(cases_root: Path) -> ReportGenerator:
    """Create a ReportGenerator pointing at the real templates directory.

    Args:
        cases_root: Temporary directory for case output.

    Returns:
        A configured ReportGenerator instance.
    """
    project_root = Path(__file__).resolve().parents[1]
    templates_dir = project_root / "templates"
    return ReportGenerator(templates_dir=templates_dir, cases_root=cases_root)


def _v1_analysis_results() -> dict:
    """Build a V1-format analysis_results dict for testing.

    Returns:
        A dict in V1 format with case_id, summary, per_artifact, etc.
    """
    return {
        "case_id": "case-v1-compat",
        "case_name": "V1 Backward Compat Test",
        "tool_version": "1.4.0",
        "model_info": {"provider": "openai", "model": "gpt-4o"},
        "summary": "Executive summary for single image analysis.",
        "per_artifact": [
            {
                "artifact_key": "runkeys",
                "artifact_name": "Run/RunOnce Keys",
                "analysis": "Confidence HIGH that persistence was found.",
                "record_count": 10,
                "time_range_start": "2026-01-15T09:00:00Z",
                "time_range_end": "2026-01-15T10:00:00Z",
            }
        ],
    }


def _multi_image_analysis_results() -> dict:
    """Build a multi-image analysis_results dict for testing.

    Returns:
        A dict with ``images``, ``cross_image_summary``, and ``model_info``.
    """
    return {
        "case_id": "case-multi-img",
        "case_name": "Multi-Image Investigation",
        "tool_version": "1.4.1",
        "images": {
            "img-001": {
                "label": "Workstation-PC01 (Windows 10)",
                "per_artifact": [
                    {
                        "artifact_key": "runkeys",
                        "artifact_name": "Run/RunOnce Keys",
                        "analysis": "Confidence MEDIUM that auto-start entries exist.",
                        "record_count": 5,
                        "time_range_start": "2026-02-10T08:00:00Z",
                        "time_range_end": "2026-02-10T12:00:00Z",
                    }
                ],
                "summary": "Workstation-PC01 shows signs of persistence via registry keys.",
            },
            "img-002": {
                "label": "Server-DC01 (Windows Server 2022)",
                "per_artifact": [
                    {
                        "artifact_key": "evtx",
                        "artifact_name": "Event Logs",
                        "analysis": "Confidence HIGH that lateral movement occurred.",
                        "record_count": 120,
                        "time_range_start": "2026-02-10T07:00:00Z",
                        "time_range_end": "2026-02-10T14:00:00Z",
                    },
                    {
                        "artifact_key": "prefetch",
                        "artifact_name": "Prefetch Files",
                        "analysis": "Confidence LOW for suspicious execution.",
                        "record_count": 30,
                        "time_range_start": "2026-02-10T09:00:00Z",
                        "time_range_end": "2026-02-10T11:00:00Z",
                    },
                ],
                "summary": "Server-DC01 experienced lateral movement via RDP.",
            },
        },
        "cross_image_summary": (
            "Cross-system analysis reveals a coordinated attack: "
            "initial persistence on PC01 followed by lateral movement to DC01."
        ),
        "model_info": {"provider": "anthropic", "model": "claude-sonnet-4-20250514"},
    }


def _multi_image_metadata() -> list[dict]:
    """Build a list of image metadata dicts for multi-image testing.

    Returns:
        A list of two metadata dicts.
    """
    return [
        {
            "hostname": "PC01",
            "os_version": "Windows 10 Pro",
            "domain": "corp.local",
            "ips": ["10.1.1.10"],
            "label": "Workstation-PC01",
        },
        {
            "hostname": "DC01",
            "os_version": "Windows Server 2022",
            "domain": "corp.local",
            "ips": ["10.1.1.1"],
            "label": "Server-DC01",
        },
    ]


def _multi_image_hashes() -> list[dict]:
    """Build a list of evidence hash dicts for multi-image testing.

    Returns:
        A list of two hash dicts with filenames and hashes.
    """
    return [
        {
            "filename": "pc01-image.E01",
            "sha256": "a" * 64,
            "md5": "b" * 32,
            "expected_sha256": "a" * 64,
            "reverified_sha256": "a" * 64,
        },
        {
            "filename": "dc01-image.E01",
            "sha256": "c" * 64,
            "md5": "d" * 32,
            "expected_sha256": "c" * 64,
            "reverified_sha256": "c" * 64,
        },
    ]


class TestSingleImageBackwardCompat(unittest.TestCase):
    """Verify that V1 single-image reports render identically to before."""

    def test_v1_report_renders_correctly(self) -> None:
        """Single-image V1 format produces a valid report with all sections."""
        with TemporaryDirectory(prefix="aift-mi-test-") as temp_dir:
            cases_root = Path(temp_dir) / "cases"
            reporter = _create_report_generator(cases_root)

            analysis = _v1_analysis_results()
            metadata = {
                "hostname": "ws-13",
                "os_version": "Windows 11 Pro",
                "domain": "corp.local",
                "ips": ["10.1.1.45"],
            }
            hashes = {
                "filename": "disk-image.E01",
                "sha256": "a" * 64,
                "md5": "b" * 32,
                "size_bytes": 1024,
                "expected_sha256": "c" * 64,
                "reverified_sha256": "c" * 64,
            }

            report_path = reporter.generate(
                analysis_results=analysis,
                image_metadata=metadata,
                evidence_hashes=hashes,
                investigation_context="Investigate credential theft.",
                audit_log_entries=[],
            )

            html = report_path.read_text(encoding="utf-8")

            # V1 sections present
            self.assertIn("Evidence Summary", html)
            self.assertIn("Hash Verification Result", html)
            self.assertIn("Executive Summary", html)
            self.assertIn("Per-Artifact Findings", html)
            self.assertIn("Audit Trail", html)

            # V1 key-value evidence table (not multi-image table)
            self.assertIn("kv-table", html)
            self.assertIn("disk-image.E01", html)
            self.assertIn("ws-13", html)

            # Single hash status (not per-image rows)
            self.assertIn('class="hash-status pass"', html)

            # No multi-image sections
            self.assertNotIn("Cross-System Analysis", html)
            self.assertNotIn('class="image-section"', html)

            # Artifact findings present
            self.assertIn("Run/RunOnce Keys", html)
            self.assertIn("confidence-high", html)

    def test_v1_format_auto_converted(self) -> None:
        """V1 analysis_results without 'images' key are auto-wrapped."""
        with TemporaryDirectory(prefix="aift-mi-test-") as temp_dir:
            cases_root = Path(temp_dir) / "cases"
            reporter = _create_report_generator(cases_root)

            analysis = _v1_analysis_results()
            # Confirm no "images" key
            self.assertNotIn("images", analysis)

            report_path = reporter.generate(
                analysis_results=analysis,
                image_metadata={"hostname": "test-host"},
                evidence_hashes={"filename": "test.E01", "sha256": "x" * 64, "md5": "y" * 32},
                investigation_context="Test context.",
                audit_log_entries=[],
            )

            html = report_path.read_text(encoding="utf-8")
            # Should render as single-image (no cross-system section)
            self.assertNotIn("Cross-System Analysis", html)
            self.assertNotIn('class="image-section"', html)
            # Should have executive summary
            self.assertIn("Executive Summary", html)
            self.assertIn("Executive summary for single image analysis", html)


class TestMultiImageReport(unittest.TestCase):
    """Verify multi-image report structure and content."""

    def test_multi_image_has_cross_system_section(self) -> None:
        """Multi-image report includes the cross-system analysis section."""
        with TemporaryDirectory(prefix="aift-mi-test-") as temp_dir:
            cases_root = Path(temp_dir) / "cases"
            reporter = _create_report_generator(cases_root)

            report_path = reporter.generate(
                analysis_results=_multi_image_analysis_results(),
                image_metadata=_multi_image_metadata(),
                evidence_hashes=_multi_image_hashes(),
                investigation_context="Multi-image investigation.",
                audit_log_entries=[],
            )

            html = report_path.read_text(encoding="utf-8")
            self.assertIn("Cross-System Analysis", html)
            self.assertIn("cross-system-panel", html)
            self.assertIn("coordinated attack", html)
            self.assertIn("lateral movement to DC01", html)

    def test_multi_image_has_per_image_sections(self) -> None:
        """Multi-image report has collapsible sections for each image."""
        with TemporaryDirectory(prefix="aift-mi-test-") as temp_dir:
            cases_root = Path(temp_dir) / "cases"
            reporter = _create_report_generator(cases_root)

            report_path = reporter.generate(
                analysis_results=_multi_image_analysis_results(),
                image_metadata=_multi_image_metadata(),
                evidence_hashes=_multi_image_hashes(),
                investigation_context="Multi-image investigation.",
                audit_log_entries=[],
            )

            html = report_path.read_text(encoding="utf-8")

            # Both image labels in section headers
            self.assertIn("Workstation-PC01 (Windows 10)", html)
            self.assertIn("Server-DC01 (Windows Server 2022)", html)

            # Image section HTML elements
            self.assertIn('class="image-section"', html)

            # Per-image summaries
            self.assertIn("persistence via registry keys", html)
            self.assertIn("lateral movement via RDP", html)

            # Per-image artifact findings
            self.assertIn("Run/RunOnce Keys", html)
            self.assertIn("Event Logs", html)
            self.assertIn("Prefetch Files", html)

    def test_evidence_summary_table_has_rows_for_each_image(self) -> None:
        """Evidence summary uses a multi-column table with one row per image."""
        with TemporaryDirectory(prefix="aift-mi-test-") as temp_dir:
            cases_root = Path(temp_dir) / "cases"
            reporter = _create_report_generator(cases_root)

            report_path = reporter.generate(
                analysis_results=_multi_image_analysis_results(),
                image_metadata=_multi_image_metadata(),
                evidence_hashes=_multi_image_hashes(),
                investigation_context="Multi-image investigation.",
                audit_log_entries=[],
            )

            html = report_path.read_text(encoding="utf-8")

            # Multi-image evidence table
            self.assertIn("evidence-multi-table", html)

            # Both filenames in the table
            self.assertIn("pc01-image.E01", html)
            self.assertIn("dc01-image.E01", html)

            # Both hostnames
            self.assertIn("PC01", html)
            self.assertIn("DC01", html)

            # Hash values
            self.assertIn("a" * 64, html)
            self.assertIn("c" * 64, html)

    def test_multi_image_hash_verification_per_image(self) -> None:
        """Hash verification shows per-image PASS/FAIL status."""
        with TemporaryDirectory(prefix="aift-mi-test-") as temp_dir:
            cases_root = Path(temp_dir) / "cases"
            reporter = _create_report_generator(cases_root)

            # One pass, one fail
            hashes = [
                {
                    "filename": "img1.E01",
                    "sha256": "a" * 64,
                    "md5": "b" * 32,
                    "expected_sha256": "a" * 64,
                    "reverified_sha256": "a" * 64,
                },
                {
                    "filename": "img2.E01",
                    "sha256": "c" * 64,
                    "md5": "d" * 32,
                    "expected_sha256": "c" * 64,
                    "reverified_sha256": "e" * 64,  # mismatch
                },
            ]

            report_path = reporter.generate(
                analysis_results=_multi_image_analysis_results(),
                image_metadata=_multi_image_metadata(),
                evidence_hashes=hashes,
                investigation_context="Hash verification test.",
                audit_log_entries=[],
            )

            html = report_path.read_text(encoding="utf-8")

            # Both pass and fail present
            self.assertIn('class="hash-status pass"', html)
            self.assertIn('class="hash-status fail"', html)

    def test_multi_image_no_cross_system_when_none(self) -> None:
        """Cross-System Analysis section is omitted when summary is None."""
        with TemporaryDirectory(prefix="aift-mi-test-") as temp_dir:
            cases_root = Path(temp_dir) / "cases"
            reporter = _create_report_generator(cases_root)

            analysis = _multi_image_analysis_results()
            analysis["cross_image_summary"] = None

            report_path = reporter.generate(
                analysis_results=analysis,
                image_metadata=_multi_image_metadata(),
                evidence_hashes=_multi_image_hashes(),
                investigation_context="No cross-system summary.",
                audit_log_entries=[],
            )

            html = report_path.read_text(encoding="utf-8")
            self.assertNotIn("Cross-System Analysis", html)

    def test_single_image_in_multi_format(self) -> None:
        """A single image in multi-image format renders as single-image."""
        with TemporaryDirectory(prefix="aift-mi-test-") as temp_dir:
            cases_root = Path(temp_dir) / "cases"
            reporter = _create_report_generator(cases_root)

            analysis = {
                "case_id": "case-single-multi",
                "case_name": "Single in Multi Format",
                "images": {
                    "img-only": {
                        "label": "Only Image",
                        "per_artifact": [
                            {
                                "artifact_key": "amcache",
                                "artifact_name": "Amcache",
                                "analysis": "No suspicious entries found. Confidence LOW.",
                                "record_count": 50,
                            }
                        ],
                        "summary": "No significant findings.",
                    }
                },
                "cross_image_summary": None,
                "model_info": {"provider": "openai", "model": "gpt-4o"},
            }

            report_path = reporter.generate(
                analysis_results=analysis,
                image_metadata={"hostname": "single-host"},
                evidence_hashes={"filename": "single.E01", "sha256": "f" * 64, "md5": "0" * 32},
                investigation_context="Single image test.",
                audit_log_entries=[],
            )

            html = report_path.read_text(encoding="utf-8")

            # Should render as single image (V1 layout)
            self.assertNotIn("Cross-System Analysis", html)
            self.assertNotIn('class="image-section"', html)
            self.assertIn("Executive Summary", html)
            self.assertIn("kv-table", html)


class TestReportGeneratorHelpers(unittest.TestCase):
    """Test internal helper methods for multi-image support."""

    def test_convert_v1_to_multi_image(self) -> None:
        """_convert_v1_to_multi_image wraps V1 data correctly."""
        reporter = ReportGenerator.__new__(ReportGenerator)
        v1 = _v1_analysis_results()
        result = reporter._convert_v1_to_multi_image(v1)

        self.assertIn("images", result)
        self.assertIn("default", result["images"])
        self.assertIsNone(result["cross_image_summary"])
        self.assertEqual(result["images"]["default"]["label"], "V1 Backward Compat Test")
        self.assertEqual(len(result["images"]["default"]["per_artifact"]), 1)

    def test_normalize_to_list_single_dict(self) -> None:
        """_normalize_to_list converts a single dict to a one-element list."""
        result = ReportGenerator._normalize_to_list({"key": "value"})
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["key"], "value")

    def test_normalize_to_list_already_list(self) -> None:
        """_normalize_to_list passes a list through unchanged."""
        input_list = [{"a": 1}, {"b": 2}]
        result = ReportGenerator._normalize_to_list(input_list)
        self.assertEqual(len(result), 2)

    def test_normalize_to_list_none(self) -> None:
        """_normalize_to_list returns [{}] for None input."""
        result = ReportGenerator._normalize_to_list(None)
        self.assertEqual(result, [{}])


if __name__ == "__main__":
    unittest.main()
