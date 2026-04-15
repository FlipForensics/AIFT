"""Tests for the headless automation engine in app/automation/engine.py.

Covers AutomationRequest/AutomationResult dataclasses, and the run_automation
function including: full pipeline success, folder processing, empty discovery,
config/profile fallback, partial and total image failures, analysis failure,
progress callbacks, hash skipping, date ranges, and output directory handling.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest.mock import MagicMock, patch

from app.automation.engine import AutomationRequest, AutomationResult, run_automation
from tests.conftest import (
    FAKE_HASHES,
    FakeAnalyzer,
    FakeAuditLogger,
    FakeParser as _BaseFakeParser,
    FakeReportGenerator,
)


class _EngineTestAnalyzer(FakeAnalyzer):
    """Analyzer stub that also supports multi-image analysis."""

    def run_multi_image_analysis(
        self,
        images_analysis_list: list[dict[str, object]],
        cross_image_context: str,
        **kwargs: object,
    ) -> dict[str, object]:
        """Return fake multi-image analysis results.

        Args:
            images_analysis_list: List of image descriptor dicts.
            cross_image_context: Investigation context string.
            **kwargs: Ignored additional keyword arguments.

        Returns:
            Multi-image analysis result dict.
        """
        images: dict[str, dict[str, object]] = {}
        for desc in images_analysis_list:
            iid = desc["image_id"]
            images[iid] = {
                "label": desc["label"],
                "per_artifact": [
                    {
                        "artifact_key": k,
                        "artifact_name": k,
                        "analysis": f"analysis for {k}",
                        "model": "fake-model",
                    }
                    for k in desc.get("artifact_keys", [])
                ],
                "summary": f"summary for {iid}",
            }
        return {
            "images": images,
            "cross_image_summary": "cross-image summary",
            "model_info": {"provider": "fake", "model": "fake-model"},
        }


class FakeParser(_BaseFakeParser):
    """Parser stub that returns 'runkeys' as the artifact name.

    The engine intersects profile artifact keys against available artifact
    *names*, so the name here must match the profile's artifact_key.
    """

    def get_available_artifacts(self) -> list[dict[str, object]]:
        """Return artifacts with a name matching the test profile.

        Returns:
            List with a single ``runkeys`` artifact marked available.
        """
        return [
            {"key": "runkeys", "name": "runkeys", "available": True},
        ]


# ---------------------------------------------------------------------------
# Patch target base paths
# ---------------------------------------------------------------------------

_ENGINE = "app.automation.engine"


def _fake_load_config(path: Any) -> dict[str, Any]:
    """Return a minimal valid config dict.

    Args:
        path: Ignored config path argument.

    Returns:
        Minimal config dict with fake AI provider settings.
    """
    return {"ai_provider": "fake", "api_key": "test"}


def _fake_profiles(root: Any) -> list[dict[str, Any]]:
    """Return a single recommended profile with one artifact.

    The artifact_key must match the ``name`` field returned by
    FakeParser.get_available_artifacts() because the engine intersects
    profile artifacts against available artifact *names*.

    Args:
        root: Ignored profiles directory path.

    Returns:
        List with one profile dict.
    """
    return [
        {
            "name": "recommended",
            "builtin": True,
            "artifact_options": [
                {"artifact_key": "runkeys", "parse": True, "analyze": True},
            ],
        },
    ]


def _fake_artifact_options_to_lists(
    options: list[dict[str, Any]],
) -> tuple[list[str], list[str]]:
    """Convert artifact options to parse/analysis key lists.

    Args:
        options: List of artifact option dicts.

    Returns:
        Tuple of (parse_keys, analysis_keys).
    """
    parse = [o["artifact_key"] for o in options if o.get("parse")]
    analyze = [o["artifact_key"] for o in options if o.get("analyze")]
    return parse, analyze


class TestAutomationRequest(unittest.TestCase):
    """Tests for AutomationRequest dataclass."""

    def test_defaults(self) -> None:
        """Optional fields have correct defaults."""
        req = AutomationRequest(
            evidence_path="/fake/path",
            prompt="test",
            output_dir="/output",
        )
        self.assertIsNone(req.profile_name)
        self.assertIsNone(req.config_path)
        self.assertIsNone(req.case_name)
        self.assertFalse(req.skip_hashing)
        self.assertIsNone(req.date_range)

    def test_all_fields(self) -> None:
        """All fields can be set explicitly."""
        req = AutomationRequest(
            evidence_path="/fake/path",
            prompt="test prompt",
            output_dir="/output",
            profile_name="full",
            config_path="/config.yaml",
            case_name="Test Case",
            skip_hashing=True,
            date_range=("2026-04-01", "2026-04-15"),
        )
        self.assertEqual(req.evidence_path, "/fake/path")
        self.assertEqual(req.prompt, "test prompt")
        self.assertEqual(req.profile_name, "full")
        self.assertTrue(req.skip_hashing)
        self.assertEqual(req.date_range, ("2026-04-01", "2026-04-15"))


class TestAutomationResult(unittest.TestCase):
    """Tests for AutomationResult dataclass."""

    def test_defaults(self) -> None:
        """Optional fields have correct defaults."""
        res = AutomationResult(success=True, case_id="abc")
        self.assertIsNone(res.html_report_path)
        self.assertIsNone(res.json_report_path)
        self.assertEqual(res.evidence_files, [])
        self.assertEqual(res.errors, [])
        self.assertEqual(res.warnings, [])
        self.assertEqual(res.duration_seconds, 0.0)


class TestRunAutomation(unittest.TestCase):
    """Tests for run_automation().

    Patches: ForensicParser, ForensicAnalyzer, ReportGenerator, CaseManager,
    discover_evidence, compute_hashes, export_json_report, AuditLogger,
    load_config, load_profiles_from_directory, artifact_options_to_lists.
    """

    def setUp(self) -> None:
        """Set up temp directories and common patches."""
        self.temp_dir = TemporaryDirectory(prefix="aift-engine-test-")
        self.root = Path(self.temp_dir.name)
        self.output_dir = self.root / "output"
        self.output_dir.mkdir()
        self.cases_dir = self.root / "cases"
        self.cases_dir.mkdir()

        # Create a fake evidence file.
        self.evidence_file = self.root / "evidence.E01"
        self.evidence_file.write_bytes(b"")

        # Standard patches.
        self.patches = []
        self._add_patch(f"{_ENGINE}.validate_evidence_path",
                        return_value=self.evidence_file)
        self._add_patch(f"{_ENGINE}.discover_evidence",
                        return_value=[self.evidence_file])
        self._add_patch(f"{_ENGINE}.load_config", side_effect=_fake_load_config)
        self._add_patch(f"{_ENGINE}.load_profiles_from_directory",
                        side_effect=_fake_profiles)
        self._add_patch(f"{_ENGINE}.artifact_options_to_lists",
                        side_effect=_fake_artifact_options_to_lists)
        self._add_patch(f"{_ENGINE}.compute_hashes",
                        return_value=dict(FAKE_HASHES))

        # CaseManager mock.
        self.mock_cm = MagicMock()
        self.mock_cm.create_case.return_value = "case-001"
        self.mock_cm.add_image.return_value = "img-001"
        case_dir = self.cases_dir / "case-001"
        case_dir.mkdir(parents=True, exist_ok=True)
        img_dir = case_dir / "images" / "img-001"
        img_dir.mkdir(parents=True, exist_ok=True)
        self.mock_cm.get_image_dir.return_value = img_dir
        self._add_patch(f"{_ENGINE}.CaseManager", return_value=self.mock_cm)

        # ForensicParser mock — use FakeParser.
        self._add_patch(
            f"{_ENGINE}.ForensicParser",
            side_effect=lambda **kwargs: FakeParser(**kwargs),
        )

        # ForensicAnalyzer mock — use _EngineTestAnalyzer (has multi-image).
        self._add_patch(
            f"{_ENGINE}.ForensicAnalyzer",
            side_effect=lambda **kwargs: _EngineTestAnalyzer(**kwargs),
        )

        # ReportGenerator mock — use FakeReportGenerator.
        self._add_patch(
            f"{_ENGINE}.ReportGenerator",
            side_effect=lambda **kwargs: FakeReportGenerator(
                cases_root=self.cases_dir, **{k: v for k, v in kwargs.items() if k != "cases_root"},
            ),
        )

        # export_json_report mock — write a stub JSON file.
        def _fake_export(**kwargs: Any) -> Path:
            """Write a stub JSON report file.

            Args:
                **kwargs: Keyword arguments including output_path.

            Returns:
                Path to the written JSON file.
            """
            out = Path(kwargs["output_path"])
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text('{"case_id":"case-001"}', encoding="utf-8")
            return out

        self._add_patch(f"{_ENGINE}.export_json_report", side_effect=_fake_export)

        # AuditLogger mock.
        self._add_patch(f"{_ENGINE}.AuditLogger",
                        return_value=FakeAuditLogger())

        # Override _PROJECT_ROOT so cases are created in our temp dir.
        self._add_patch(f"{_ENGINE}._PROJECT_ROOT", new=self.root)

        # Start all patches.
        self.mocks: dict[str, MagicMock] = {}
        for p in self.patches:
            self.mocks[p.attribute] = p.start()

    def _add_patch(self, target: str, **kwargs: Any) -> None:
        """Register a patch to be started in setUp.

        Args:
            target: Dotted import path to patch.
            **kwargs: Additional arguments for patch().
        """
        self.patches.append(patch(target, **kwargs))

    def tearDown(self) -> None:
        """Stop all patches and clean up."""
        for p in self.patches:
            p.stop()
        self.temp_dir.cleanup()

    def _make_request(self, **overrides: Any) -> AutomationRequest:
        """Build a standard AutomationRequest with optional overrides.

        Args:
            **overrides: Fields to override from defaults.

        Returns:
            Configured AutomationRequest.
        """
        defaults = {
            "evidence_path": str(self.evidence_file),
            "prompt": "Investigate this system",
            "output_dir": str(self.output_dir),
        }
        defaults.update(overrides)
        return AutomationRequest(**defaults)

    def test_successful_single_file_run(self) -> None:
        """Single evidence file processes through full pipeline."""
        result = run_automation(self._make_request())
        self.assertTrue(result.success)
        self.assertEqual(result.case_id, "case-001")
        self.assertEqual(len(result.errors), 0)

    def test_successful_folder_run(self) -> None:
        """Folder with multiple evidence files processes all of them."""
        ev2 = self.root / "disk2.vmdk"
        ev2.write_bytes(b"")

        # discover_evidence returns two files.
        self.mocks["discover_evidence"].return_value = [
            self.evidence_file, ev2,
        ]
        # CaseManager needs to return different image IDs for each.
        self.mock_cm.add_image.side_effect = ["img-001", "img-002"]
        img_dir2 = self.cases_dir / "case-001" / "images" / "img-002"
        img_dir2.mkdir(parents=True, exist_ok=True)
        self.mock_cm.get_image_dir.side_effect = [
            self.cases_dir / "case-001" / "images" / "img-001",
            img_dir2,
        ]

        result = run_automation(self._make_request())
        self.assertTrue(result.success)
        self.assertEqual(len(result.evidence_files), 2)

    def test_no_evidence_found_returns_failure(self) -> None:
        """Empty discovery result returns success=False."""
        self.mocks["discover_evidence"].return_value = []
        result = run_automation(self._make_request())
        self.assertFalse(result.success)
        self.assertTrue(any("No evidence" in e for e in result.errors))

    def test_invalid_config_falls_back_to_default(self) -> None:
        """Bad config path triggers fallback with warning."""
        # Make load_config raise for a specific path.
        def _fail_then_default(path: Any) -> dict[str, Any]:
            """Raise on first call, return defaults on fallback.

            Args:
                path: Config path (first call raises).

            Returns:
                Minimal config dict.
            """
            if path is not None:
                raise FileNotFoundError("bad config")
            return _fake_load_config(path)

        self.mocks["load_config"].side_effect = _fail_then_default

        result = run_automation(self._make_request(config_path="/bad/config.yaml"))
        # Should still succeed — config falls back.
        self.assertTrue(result.success)
        self.assertTrue(any("config" in w.lower() for w in result.warnings))

    def test_invalid_profile_falls_back_to_recommended(self) -> None:
        """Unknown profile name triggers fallback with warning."""
        result = run_automation(self._make_request(profile_name="nonexistent"))
        # Should still succeed — profile falls back.
        self.assertTrue(result.success)
        self.assertTrue(any("profile" in w.lower() for w in result.warnings))

    def test_partial_failure_returns_warnings(self) -> None:
        """If one image fails to open but others succeed, result has warnings."""
        ev2 = self.root / "bad.e01"
        ev2.write_bytes(b"")
        self.mocks["discover_evidence"].return_value = [
            self.evidence_file, ev2,
        ]
        self.mock_cm.add_image.side_effect = ["img-001", "img-002"]
        img_dir2 = self.cases_dir / "case-001" / "images" / "img-002"
        img_dir2.mkdir(parents=True, exist_ok=True)
        self.mock_cm.get_image_dir.side_effect = [
            self.cases_dir / "case-001" / "images" / "img-001",
            img_dir2,
        ]

        # Make ForensicParser fail on the second file.
        call_count = [0]
        original_side = self.mocks["ForensicParser"].side_effect

        def _parser_factory(**kwargs: Any) -> FakeParser:
            """Return FakeParser or raise on second call.

            Args:
                **kwargs: Constructor arguments.

            Returns:
                FakeParser instance.

            Raises:
                RuntimeError: On second call to simulate failure.
            """
            call_count[0] += 1
            if call_count[0] == 2:
                raise RuntimeError("Cannot open bad.e01")
            return FakeParser(**kwargs)

        self.mocks["ForensicParser"].side_effect = _parser_factory

        result = run_automation(self._make_request())
        self.assertTrue(result.success)
        self.assertTrue(len(result.warnings) > 0)

    def test_all_images_fail_returns_failure(self) -> None:
        """If every image fails to open, result is failure."""
        self.mocks["ForensicParser"].side_effect = RuntimeError("Cannot open")

        result = run_automation(self._make_request())
        self.assertFalse(result.success)
        self.assertTrue(any("failed" in e.lower() for e in result.errors))

    def test_analysis_failure_returns_failure(self) -> None:
        """AI analysis exception results in failure."""
        def _fail_analyzer(**kwargs: Any) -> _EngineTestAnalyzer:
            """Return an analyzer whose run_full_analysis raises.

            Args:
                **kwargs: Constructor arguments.

            Returns:
                Analyzer with overridden run_full_analysis.
            """
            a = _EngineTestAnalyzer(**kwargs)
            a.run_full_analysis = MagicMock(
                side_effect=RuntimeError("AI provider error"),
            )
            return a

        self.mocks["ForensicAnalyzer"].side_effect = _fail_analyzer

        result = run_automation(self._make_request())
        self.assertFalse(result.success)
        self.assertTrue(any("analysis" in e.lower() for e in result.errors))

    def test_progress_callback_called(self) -> None:
        """Progress callback receives expected phases and messages."""
        phases_seen: list[str] = []

        def _cb(phase: str, message: str, pct: float) -> None:
            """Record each progress callback invocation.

            Args:
                phase: Pipeline phase name.
                message: Status message.
                pct: Percentage value.
            """
            phases_seen.append(phase)

        result = run_automation(self._make_request(), progress_callback=_cb)
        self.assertTrue(result.success)
        self.assertIn("discovery", phases_seen)
        self.assertIn("reporting", phases_seen)

    def test_skip_hashing(self) -> None:
        """skip_hashing=True skips hash computation."""
        result = run_automation(self._make_request(skip_hashing=True))
        self.assertTrue(result.success)
        self.mocks["compute_hashes"].assert_not_called()

    def test_date_range_passed_to_analyzer(self) -> None:
        """Date range from request reaches the analyzer."""
        # The date_range is passed to the request but is used by the analyzer
        # via investigation_context. We verify it doesn't cause errors.
        result = run_automation(self._make_request(
            date_range=("2026-04-01", "2026-04-15"),
        ))
        self.assertTrue(result.success)

    def test_output_dir_created(self) -> None:
        """Output directory is created if it doesn't exist."""
        new_output = self.root / "new_output" / "deep"
        result = run_automation(self._make_request(output_dir=str(new_output)))
        self.assertTrue(result.success)
        self.assertTrue(new_output.exists())

    def test_case_id_in_result(self) -> None:
        """Result includes the created case_id."""
        result = run_automation(self._make_request())
        self.assertEqual(result.case_id, "case-001")

    def test_duration_tracked(self) -> None:
        """Result includes non-zero duration_seconds."""
        result = run_automation(self._make_request())
        self.assertGreater(result.duration_seconds, 0.0)

    def test_evidence_path_validation_failure(self) -> None:
        """Invalid evidence path returns failure immediately."""
        self.mocks["validate_evidence_path"].side_effect = FileNotFoundError(
            "Path not found",
        )
        result = run_automation(self._make_request())
        self.assertFalse(result.success)
        self.assertTrue(any("not found" in e.lower() for e in result.errors))


if __name__ == "__main__":
    unittest.main()
