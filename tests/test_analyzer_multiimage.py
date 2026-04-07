"""Tests for multi-image analysis orchestration.

Validates the three-phase multi-image analysis pipeline:
single-image cases (Phase 3 skipped), multi-image cases
(full cross-image correlation), progress callback invocation,
and prompt construction.
"""

from __future__ import annotations

import csv
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest.mock import patch

import pytest

from app.analyzer import ForensicAnalyzer
from app.analyzer.multi_image import build_cross_image_prompt, run_multi_image_analysis


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

class FakeAuditLogger:
    """Collects audit log entries for assertions."""

    def __init__(self) -> None:
        self.entries: list[tuple[str, dict]] = []

    def log(self, action: str, details: dict) -> None:
        """Record an audit entry."""
        self.entries.append((action, details))


class FakeProvider:
    """Mock AI provider that returns canned responses."""

    def __init__(self, responses: list[str] | None = None) -> None:
        self.responses = list(responses or ["stub-response"])
        self.calls: list[dict[str, str]] = []
        self.call_count = 0

    def analyze(self, system_prompt: str, user_prompt: str, max_tokens: int = 4096) -> str:
        """Return the next canned response."""
        idx = self.call_count
        self.call_count += 1
        self.calls.append({
            "system_prompt": system_prompt,
            "user_prompt": user_prompt,
            "max_tokens": str(max_tokens),
        })
        if idx < len(self.responses):
            return self.responses[idx]
        return self.responses[-1]

    def get_model_info(self) -> dict[str, str]:
        """Return fake model info."""
        return {"provider": "fake", "model": "fake-model-1"}


def _write_artifact_csv(parsed_dir: Path, artifact_key: str, rows: list[dict[str, str]]) -> Path:
    """Write a small artifact CSV for testing."""
    csv_path = parsed_dir / f"{artifact_key}.csv"
    if not rows:
        rows = [{"ts": "2025-01-01T00:00:00Z", "event": "test-event"}]
    columns = list(rows[0].keys())
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return csv_path


def _make_image(
    tmpdir: Path,
    image_id: str,
    label: str,
    artifact_keys: list[str],
    metadata: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Create an image descriptor with a parsed directory containing CSVs."""
    parsed_dir = tmpdir / "images" / image_id / "parsed"
    parsed_dir.mkdir(parents=True, exist_ok=True)
    for key in artifact_keys:
        _write_artifact_csv(parsed_dir, key, [
            {"ts": "2025-01-15T10:00:00Z", "event": f"{key}-event-on-{image_id}"},
        ])
    return {
        "image_id": image_id,
        "label": label,
        "metadata": metadata or {"hostname": label, "os_version": "Windows 10", "domain": "CORP"},
        "artifact_keys": artifact_keys,
        "parsed_dir": str(parsed_dir),
    }


def _build_analyzer(tmpdir: Path, responses: list[str] | None = None) -> ForensicAnalyzer:
    """Build a ForensicAnalyzer with a fake AI provider."""
    config = {
        "ai": {"provider": "local", "local": {"base_url": "http://localhost/v1", "model": "test", "api_key": "x"}},
        "analysis": {"ai_max_tokens": 128000},
    }
    audit = FakeAuditLogger()
    analyzer = ForensicAnalyzer(
        case_dir=str(tmpdir),
        config=config,
        audit_logger=audit,
        prompts_dir=str(Path(__file__).resolve().parents[1] / "prompts"),
    )
    provider = FakeProvider(responses=responses or ["artifact-analysis-result", "per-image-summary", "cross-image-correlation"])
    analyzer.ai_provider = provider
    analyzer.model_info = provider.get_model_info()
    return analyzer


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestSingleImageAnalysis:
    """Tests for single-image cases (Phase 3 skipped)."""

    def test_single_image_returns_correct_structure(self, tmp_path: Path) -> None:
        """Single-image analysis produces images dict with null cross_image_summary."""
        analyzer = _build_analyzer(tmp_path, responses=[
            "artifact-analysis-1",  # per-artifact
            "single-image-summary",  # per-image summary
        ])
        image = _make_image(tmp_path, "img1", "Workstation-PC01", ["runkeys"])

        result = analyzer.run_multi_image_analysis(
            images=[image],
            investigation_context="Test investigation",
        )

        assert "images" in result
        assert "img1" in result["images"]
        assert result["cross_image_summary"] is None
        assert result["model_info"]["provider"] == "fake"

        img_data = result["images"]["img1"]
        assert img_data["label"] == "Workstation-PC01"
        assert isinstance(img_data["per_artifact"], list)
        assert len(img_data["per_artifact"]) == 1
        assert isinstance(img_data["summary"], str)
        assert img_data["summary"] != ""

    def test_single_image_skips_phase3(self, tmp_path: Path) -> None:
        """Phase 3 is not invoked for single-image cases."""
        provider = FakeProvider(responses=[
            "artifact-result",
            "image-summary",
        ])
        analyzer = _build_analyzer(tmp_path)
        analyzer.ai_provider = provider

        image = _make_image(tmp_path, "img1", "Server-DC01", ["services"])

        result = analyzer.run_multi_image_analysis(
            images=[image],
            investigation_context="Single system check",
        )

        # Only 2 AI calls: 1 artifact + 1 summary (no cross-image call)
        assert provider.call_count == 2
        assert result["cross_image_summary"] is None


class TestMultiImageAnalysis:
    """Tests for multi-image cases (all three phases)."""

    def test_multi_image_produces_cross_image_summary(self, tmp_path: Path) -> None:
        """Multi-image analysis produces a non-null cross_image_summary."""
        provider = FakeProvider(responses=[
            "artifact-A1",  # image 1, artifact 1
            "artifact-A2",  # image 2, artifact 1
            "summary-img1",  # summary for image 1
            "summary-img2",  # summary for image 2
            "cross-image-correlation-result",  # Phase 3
        ])
        analyzer = _build_analyzer(tmp_path)
        analyzer.ai_provider = provider

        img1 = _make_image(tmp_path, "img1", "Workstation", ["runkeys"])
        img2 = _make_image(tmp_path, "img2", "Server", ["services"])

        result = analyzer.run_multi_image_analysis(
            images=[img1, img2],
            investigation_context="Investigate lateral movement",
        )

        assert "images" in result
        assert "img1" in result["images"]
        assert "img2" in result["images"]
        assert result["cross_image_summary"] is not None
        assert result["cross_image_summary"] == "cross-image-correlation-result"
        # 2 artifacts + 2 summaries + 1 cross-image = 5 AI calls
        assert provider.call_count == 5

    def test_multi_image_labels_in_context(self, tmp_path: Path) -> None:
        """Image labels are included in the investigation context sent to AI."""
        provider = FakeProvider(responses=["resp"] * 10)
        analyzer = _build_analyzer(tmp_path)
        analyzer.ai_provider = provider

        img1 = _make_image(tmp_path, "img1", "WS-PC01 (Windows 10)", ["runkeys"])
        img2 = _make_image(tmp_path, "img2", "DC-01 (Windows Server)", ["services"])

        analyzer.run_multi_image_analysis(
            images=[img1, img2],
            investigation_context="Check for compromise",
        )

        # The first AI call (artifact analysis for img1) should contain the label
        first_call_prompt = provider.calls[0]["user_prompt"]
        assert "WS-PC01" in first_call_prompt


class TestProgressCallback:
    """Tests for progress callback invocation."""

    def test_progress_callback_called_for_each_artifact(self, tmp_path: Path) -> None:
        """Progress callback is invoked for each image and artifact."""
        provider = FakeProvider(responses=["resp"] * 10)
        analyzer = _build_analyzer(tmp_path)
        analyzer.ai_provider = provider

        img1 = _make_image(tmp_path, "img1", "WS01", ["runkeys", "services"])

        events: list[tuple[str, str, dict]] = []

        def progress_cb(key: str, status: str, payload: dict) -> None:
            """Collect progress events."""
            events.append((key, status, payload))

        analyzer.run_multi_image_analysis(
            images=[img1],
            investigation_context="Test",
            progress_callback=progress_cb,
        )

        # Should have started + complete events for each artifact,
        # plus summary events
        artifact_complete_events = [e for e in events if e[1] == "complete" and e[0] in ("runkeys", "services")]
        assert len(artifact_complete_events) == 2

    def test_multi_image_progress_includes_cross_image(self, tmp_path: Path) -> None:
        """Progress callback includes cross-image correlation events for multi-image."""
        provider = FakeProvider(responses=["resp"] * 10)
        analyzer = _build_analyzer(tmp_path)
        analyzer.ai_provider = provider

        img1 = _make_image(tmp_path, "img1", "WS01", ["runkeys"])
        img2 = _make_image(tmp_path, "img2", "SRV01", ["services"])

        events: list[tuple[str, str, dict]] = []

        def progress_cb(key: str, status: str, payload: dict) -> None:
            """Collect progress events."""
            events.append((key, status, payload))

        analyzer.run_multi_image_analysis(
            images=[img1, img2],
            investigation_context="Test",
            progress_callback=progress_cb,
        )

        cross_events = [e for e in events if "cross_image" in e[0]]
        assert len(cross_events) >= 1


class TestCancelCheck:
    """Tests for cancellation during multi-image analysis."""

    def test_cancel_stops_analysis(self, tmp_path: Path) -> None:
        """Analysis raises AnalysisCancelledError when cancel_check returns True."""
        from app.analyzer.core import AnalysisCancelledError

        provider = FakeProvider(responses=["resp"] * 10)
        analyzer = _build_analyzer(tmp_path)
        analyzer.ai_provider = provider

        img1 = _make_image(tmp_path, "img1", "WS01", ["runkeys"])
        img2 = _make_image(tmp_path, "img2", "SRV01", ["services"])

        call_count = 0

        def cancel_after_first() -> bool:
            """Cancel after the first image starts."""
            nonlocal call_count
            call_count += 1
            return call_count > 1

        with pytest.raises(AnalysisCancelledError):
            analyzer.run_multi_image_analysis(
                images=[img1, img2],
                investigation_context="Test",
                cancel_check=cancel_after_first,
            )


class TestBuildCrossImagePrompt:
    """Tests for the cross-image prompt construction."""

    def test_prompt_contains_all_images(self) -> None:
        """Cross-image prompt includes metadata for all images."""
        images = [
            {"image_id": "a", "label": "WS01", "metadata": {"hostname": "WS01", "os_version": "Win10", "domain": "CORP"}},
            {"image_id": "b", "label": "DC01", "metadata": {"hostname": "DC01", "os_version": "WinSrv2019", "domain": "CORP"}},
        ]
        summaries = {
            "a": {"label": "WS01", "summary": "WS01 had suspicious activity."},
            "b": {"label": "DC01", "summary": "DC01 showed lateral movement signs."},
        }
        template = "Context: {{investigation_context}}\nMetadata:\n{{image_metadata_table}}\nSummaries:\n{{per_image_summaries}}"

        result = build_cross_image_prompt(
            template=template,
            investigation_context="Investigate breach",
            images=images,
            image_summaries=summaries,
        )

        assert "WS01" in result
        assert "DC01" in result
        assert "Investigate breach" in result
        assert "suspicious activity" in result
        assert "lateral movement" in result

    def test_prompt_with_empty_summaries(self) -> None:
        """Cross-image prompt handles empty summaries gracefully."""
        result = build_cross_image_prompt(
            template="{{per_image_summaries}}",
            investigation_context="test",
            images=[],
            image_summaries={},
        )
        assert "No per-image summaries" in result


class TestModelInfoInResult:
    """Tests for model_info propagation."""

    def test_model_info_present(self, tmp_path: Path) -> None:
        """Result includes model_info from the analyzer."""
        analyzer = _build_analyzer(tmp_path, responses=["resp", "summary"])
        image = _make_image(tmp_path, "img1", "WS01", ["runkeys"])

        result = analyzer.run_multi_image_analysis(
            images=[image],
            investigation_context="Test",
        )

        assert "model_info" in result
        assert result["model_info"]["provider"] == "fake"
        assert result["model_info"]["model"] == "fake-model-1"
