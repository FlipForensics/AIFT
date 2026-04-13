"""Tests for multi-image analysis orchestration.

Validates the three-phase multi-image analysis pipeline:
single-image cases (Phase 3 skipped), multi-image cases
(full cross-image correlation), progress callback invocation,
and prompt construction.
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

import pytest

from app.analyzer import ForensicAnalyzer
from app.analyzer.multi_image import (
    _build_image_metadata_table,
    _build_per_image_summaries_text,
    _register_image_csv_paths,
    _wrap_image_progress_callback,
    build_cross_image_prompt,
    run_multi_image_analysis,
)


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

from conftest import FakeAuditLogger, FakeProvider


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

    def test_multi_image_host_metadata_in_artifact_prompts(self, tmp_path: Path) -> None:
        """Per-image host metadata (hostname, domain, IPs) appears in artifact prompts."""
        provider = FakeProvider(responses=["resp"] * 10)
        analyzer = _build_analyzer(tmp_path)
        analyzer.ai_provider = provider

        img1 = _make_image(
            tmp_path, "img1", "WS01", ["runkeys"],
            metadata={
                "hostname": "WS01",
                "os_version": "Windows 10",
                "domain": "CORP.LOCAL",
                "ips": "10.0.0.5",
            },
        )
        img2 = _make_image(
            tmp_path, "img2", "DC01", ["services"],
            metadata={
                "hostname": "DC01",
                "os_version": "Windows Server 2019",
                "domain": "CORP.LOCAL",
                "ips": "10.0.0.1, 10.0.0.2",
            },
        )

        analyzer.run_multi_image_analysis(
            images=[img1, img2],
            investigation_context="Investigate breach",
        )

        # First call = img1 artifact prompt, should have img1's metadata
        img1_prompt = provider.calls[0]["user_prompt"]
        assert "WS01" in img1_prompt
        assert "10.0.0.5" in img1_prompt

        # Second call = img2 artifact prompt, should have img2's metadata
        img2_prompt = provider.calls[1]["user_prompt"]
        assert "DC01" in img2_prompt
        assert "10.0.0.1, 10.0.0.2" in img2_prompt


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

    def test_prompt_includes_ips_in_metadata_table(self) -> None:
        """Cross-image prompt metadata table includes IPs for each image."""
        images = [
            {
                "image_id": "a",
                "label": "WS01",
                "metadata": {
                    "hostname": "WS01",
                    "os_version": "Win10",
                    "domain": "CORP",
                    "ips": "10.0.0.5",
                },
            },
            {
                "image_id": "b",
                "label": "DC01",
                "metadata": {
                    "hostname": "DC01",
                    "os_version": "WinSrv2019",
                    "domain": "CORP",
                    "ips": "10.0.0.1, 10.0.0.2",
                },
            },
        ]
        summaries = {
            "a": {"label": "WS01", "summary": "Clean."},
            "b": {"label": "DC01", "summary": "Suspicious."},
        }
        template = "{{image_metadata_table}}\n{{per_image_summaries}}"

        result = build_cross_image_prompt(
            template=template,
            investigation_context="Test",
            images=images,
            image_summaries=summaries,
        )

        assert "10.0.0.5" in result
        assert "10.0.0.1, 10.0.0.2" in result

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


class TestBuildImageMetadataTable:
    """Tests for the _build_image_metadata_table helper."""

    def test_empty_images(self) -> None:
        """Empty images list produces a header-only table."""
        result = _build_image_metadata_table([])
        assert "| # |" in result
        # Only header + separator, no data rows
        assert result.count("\n") == 1

    def test_missing_metadata(self) -> None:
        """Images without metadata default to 'Unknown' for all fields."""
        images = [{"image_id": "x", "label": "TestImg"}]
        result = _build_image_metadata_table(images)
        assert "Unknown" in result
        assert "TestImg" in result

    def test_os_type_fallback(self) -> None:
        """os_type is used when os_version is absent."""
        images = [{"image_id": "z", "label": "L", "metadata": {"os_type": "Linux"}}]
        result = _build_image_metadata_table(images)
        assert "Linux" in result

    def test_ips_column_present_in_header(self) -> None:
        """Metadata table header includes the IP(s) column."""
        result = _build_image_metadata_table([])
        assert "IP(s)" in result

    def test_ips_rendered_from_metadata(self) -> None:
        """IPs from image metadata appear in the table row."""
        images = [
            {
                "image_id": "a",
                "label": "WS01",
                "metadata": {
                    "hostname": "WS01",
                    "os_version": "Win10",
                    "domain": "CORP",
                    "ips": "10.0.0.5, 192.168.1.10",
                },
            }
        ]
        result = _build_image_metadata_table(images)
        assert "10.0.0.5, 192.168.1.10" in result

    def test_ips_defaults_to_unknown(self) -> None:
        """IPs column defaults to Unknown when not in metadata."""
        images = [
            {
                "image_id": "b",
                "label": "DC01",
                "metadata": {"hostname": "DC01", "os_version": "WinSrv"},
            }
        ]
        result = _build_image_metadata_table(images)
        # The row should contain "Unknown" for the IPs column
        lines = result.strip().split("\n")
        data_row = lines[-1]
        # Hostname and OS are set, so the Unknown must be from IPs (or domain)
        assert data_row.count("Unknown") >= 1
        assert "DC01" in data_row


class TestBuildPerImageSummariesText:
    """Tests for the _build_per_image_summaries_text helper."""

    def test_empty_summaries(self) -> None:
        """Empty dict returns fallback text."""
        result = _build_per_image_summaries_text({})
        assert "No per-image summaries available" in result

    def test_single_summary(self) -> None:
        """Single summary is rendered without separator."""
        summaries = {"img1": {"label": "WS01", "summary": "Found malware."}}
        result = _build_per_image_summaries_text(summaries)
        assert "WS01" in result
        assert "Found malware." in result
        assert "---" not in result

    def test_multiple_summaries_separated(self) -> None:
        """Multiple summaries are separated by horizontal rules."""
        summaries = {
            "a": {"label": "A", "summary": "Summary A"},
            "b": {"label": "B", "summary": "Summary B"},
        }
        result = _build_per_image_summaries_text(summaries)
        assert "---" in result
        assert "Summary A" in result
        assert "Summary B" in result


class TestRegisterImageCsvPaths:
    """Tests for _register_image_csv_paths."""

    def test_empty_parsed_dir(self, tmp_path: Path) -> None:
        """Empty parsed_dir string is a no-op."""
        analyzer = _build_analyzer(tmp_path)
        analyzer.artifact_csv_paths.clear()
        _register_image_csv_paths(analyzer, ["runkeys"], "")
        assert len(analyzer.artifact_csv_paths) == 0

    def test_nonexistent_directory(self, tmp_path: Path) -> None:
        """Non-existent directory logs a warning and is a no-op."""
        analyzer = _build_analyzer(tmp_path)
        analyzer.artifact_csv_paths.clear()
        _register_image_csv_paths(analyzer, ["runkeys"], str(tmp_path / "nope"))
        assert len(analyzer.artifact_csv_paths) == 0

    def test_exact_csv_match(self, tmp_path: Path) -> None:
        """Exact CSV filename match registers the path."""
        parsed_dir = tmp_path / "parsed"
        parsed_dir.mkdir()
        csv_path = parsed_dir / "runkeys.csv"
        csv_path.write_text("col\nval\n", encoding="utf-8")

        analyzer = _build_analyzer(tmp_path)
        analyzer.artifact_csv_paths.clear()
        _register_image_csv_paths(analyzer, ["runkeys"], str(parsed_dir))
        assert "runkeys" in analyzer.artifact_csv_paths
        assert analyzer.artifact_csv_paths["runkeys"] == csv_path

    def test_prefixed_csv_match(self, tmp_path: Path) -> None:
        """Prefixed CSV files are found via glob."""
        parsed_dir = tmp_path / "parsed"
        parsed_dir.mkdir()
        (parsed_dir / "services_sub1.csv").write_text("c\nv\n", encoding="utf-8")
        (parsed_dir / "services_sub2.csv").write_text("c\nv\n", encoding="utf-8")

        analyzer = _build_analyzer(tmp_path)
        analyzer.artifact_csv_paths.clear()
        _register_image_csv_paths(analyzer, ["services"], str(parsed_dir))
        assert "services" in analyzer.artifact_csv_paths
        # Multiple matches should be stored as a list
        assert isinstance(analyzer.artifact_csv_paths["services"], list)
        assert len(analyzer.artifact_csv_paths["services"]) == 2

    def test_no_matching_csv(self, tmp_path: Path) -> None:
        """No matching CSV files leaves artifact_csv_paths unchanged."""
        parsed_dir = tmp_path / "parsed"
        parsed_dir.mkdir()
        (parsed_dir / "unrelated.csv").write_text("c\nv\n", encoding="utf-8")

        analyzer = _build_analyzer(tmp_path)
        analyzer.artifact_csv_paths.clear()
        _register_image_csv_paths(analyzer, ["runkeys"], str(parsed_dir))
        assert "runkeys" not in analyzer.artifact_csv_paths


class TestEmptyImagesListAnalysis:
    """Tests for edge case of empty images list."""

    def test_empty_images_returns_empty_result(self, tmp_path: Path) -> None:
        """An empty images list produces an empty result with no cross-image summary."""
        analyzer = _build_analyzer(tmp_path, responses=["resp"])
        result = analyzer.run_multi_image_analysis(
            images=[],
            investigation_context="Test",
        )
        assert result["images"] == {}
        assert result["cross_image_summary"] is None


class TestCrossImageCorrelationFailure:
    """Tests for Phase 3 error handling when AI call fails."""

    def test_ai_failure_returns_error_message(self, tmp_path: Path) -> None:
        """When AI call fails in Phase 3, the error is captured in the summary."""
        # Track how many successful (non-cross-image) calls we expect:
        # 2 artifact analyses + 2 summaries = 4 successful calls, then all
        # subsequent calls (the cross-image retries) should fail.
        call_idx = 0

        class FailOnCrossImageProvider(FakeProvider):
            """Provider that fails on all cross-image correlation calls."""

            def analyze(self, system_prompt: str, user_prompt: str, max_tokens: int = 4096) -> str:
                """Succeed for the first 4 calls, fail on all subsequent."""
                nonlocal call_idx
                call_idx += 1
                if call_idx > 4:
                    raise RuntimeError("AI service unavailable")
                return f"resp-{call_idx}"

        analyzer = _build_analyzer(tmp_path)
        analyzer.ai_provider = FailOnCrossImageProvider()

        img1 = _make_image(tmp_path, "img1", "WS01", ["runkeys"])
        img2 = _make_image(tmp_path, "img2", "SRV01", ["services"])

        result = analyzer.run_multi_image_analysis(
            images=[img1, img2],
            investigation_context="Test",
        )

        # Phase 3 failed, so the error message should appear in cross_image_summary
        assert result["cross_image_summary"] is not None
        assert "Cross-image correlation failed" in result["cross_image_summary"]
        assert "AI service unavailable" in result["cross_image_summary"]


class TestPerImageSummaryProgressPayload:
    """Regression test: per-image summary completion events must carry the
    ``summary`` key so the frontend can display the text.

    Before the fix, the frontend ``upsertAnalysis`` only checked ``analysis``
    and ``result`` keys, but per-image summary events used ``summary``.
    """

    def test_summary_complete_event_includes_summary_key(self, tmp_path: Path) -> None:
        """The 'complete' progress event for a per-image summary carries a non-empty summary."""
        provider = FakeProvider(responses=[
            "artifact-analysis-1",
            "per-image-summary-text",
        ])
        analyzer = _build_analyzer(tmp_path)
        analyzer.ai_provider = provider

        image = _make_image(tmp_path, "img1", "WS-PC01", ["runkeys"])

        events: list[tuple[str, str, dict]] = []

        def progress_cb(key: str, status: str, payload: dict) -> None:
            """Collect progress events."""
            events.append((key, status, payload))

        analyzer.run_multi_image_analysis(
            images=[image],
            investigation_context="Test summary payload",
            progress_callback=progress_cb,
        )

        summary_complete = [
            e for e in events
            if e[0].startswith("summary_") and e[1] == "complete"
        ]
        assert len(summary_complete) == 1, (
            f"Expected exactly 1 summary complete event, got {len(summary_complete)}"
        )

        _key, _status, payload = summary_complete[0]
        assert "summary" in payload, (
            f"Summary complete event payload missing 'summary' key: {payload}"
        )
        assert payload["summary"] != "", "Summary text should not be empty"
        assert payload["summary"] == "per-image-summary-text"

    def test_summary_complete_event_includes_image_context(self, tmp_path: Path) -> None:
        """Summary completion events include image_id, image_label, and artifact_name."""
        provider = FakeProvider(responses=["resp"] * 10)
        analyzer = _build_analyzer(tmp_path)
        analyzer.ai_provider = provider

        image = _make_image(tmp_path, "img1", "Server-DC01", ["services"])

        events: list[tuple[str, str, dict]] = []

        def progress_cb(key: str, status: str, payload: dict) -> None:
            events.append((key, status, payload))

        analyzer.run_multi_image_analysis(
            images=[image],
            investigation_context="Test",
            progress_callback=progress_cb,
        )

        summary_complete = [
            e for e in events
            if e[0].startswith("summary_") and e[1] == "complete"
        ]
        assert len(summary_complete) == 1

        _key, _status, payload = summary_complete[0]
        assert payload.get("image_id") == "img1"
        assert payload.get("image_label") == "Server-DC01"
        assert "Summary:" in payload.get("artifact_name", ""), (
            f"artifact_name should contain 'Summary:', got: {payload.get('artifact_name')}"
        )

    def test_multi_image_summary_events_carry_correct_image_ids(self, tmp_path: Path) -> None:
        """With two images, each summary completion event has the correct image_id."""
        provider = FakeProvider(responses=["resp"] * 10)
        analyzer = _build_analyzer(tmp_path)
        analyzer.ai_provider = provider

        img1 = _make_image(tmp_path, "img1", "WS01", ["runkeys"])
        img2 = _make_image(tmp_path, "img2", "SRV01", ["services"])

        events: list[tuple[str, str, dict]] = []

        def progress_cb(key: str, status: str, payload: dict) -> None:
            events.append((key, status, payload))

        analyzer.run_multi_image_analysis(
            images=[img1, img2],
            investigation_context="Test",
            progress_callback=progress_cb,
        )

        summary_complete = [
            e for e in events
            if e[0].startswith("summary_") and e[1] == "complete"
        ]
        assert len(summary_complete) == 2

        image_ids = {e[2].get("image_id") for e in summary_complete}
        assert image_ids == {"img1", "img2"}, (
            f"Expected summary events for img1 and img2, got {image_ids}"
        )

        for _key, _status, payload in summary_complete:
            assert payload.get("summary", "") != "", (
                f"Summary text empty for image {payload.get('image_id')}"
            )


class TestBuildCrossImagePromptEdgeCases:
    """Additional edge case tests for build_cross_image_prompt."""

    def test_empty_investigation_context(self) -> None:
        """Empty investigation context is replaced with a fallback message."""
        result = build_cross_image_prompt(
            template="{{investigation_context}}",
            investigation_context="",
            images=[],
            image_summaries={},
        )
        assert "No investigation context provided" in result

    def test_whitespace_only_investigation_context(self) -> None:
        """Whitespace-only investigation context is replaced with fallback."""
        result = build_cross_image_prompt(
            template="{{investigation_context}}",
            investigation_context="   \n\t  ",
            images=[],
            image_summaries={},
        )
        assert "No investigation context provided" in result


class TestArtifactCsvPathsClearedBetweenImages:
    """Regression test for stale CSV paths leaking across image iterations.

    Before the fix in commit 943849a, ``artifact_csv_paths`` was not cleared
    between images in ``run_multi_image_analysis``.  If two images shared the
    same artifact key, the second image's analysis would use CSV data from the
    first image.
    """

    def test_csv_paths_are_not_shared_between_images(self, tmp_path: Path) -> None:
        """Each image's artifact analysis uses its own CSV data, not stale paths."""
        img1 = _make_image(tmp_path, "img1", "WS01", ["runkeys"])
        img2 = _make_image(tmp_path, "img2", "SRV01", ["runkeys"])

        # Write distinct data so we can verify which CSV was used.
        parsed1 = Path(img1["parsed_dir"])
        parsed2 = Path(img2["parsed_dir"])
        (parsed1 / "runkeys.csv").write_text(
            "ts,event\n2025-01-15T10:00:00Z,img1-specific-event\n", encoding="utf-8",
        )
        (parsed2 / "runkeys.csv").write_text(
            "ts,event\n2025-01-15T10:00:00Z,img2-specific-event\n", encoding="utf-8",
        )

        calls_with_paths: list[Path | None] = []

        class PathTrackingProvider(FakeProvider):
            """Provider that records artifact_csv_paths at each call."""

            def analyze(self, system_prompt: str, user_prompt: str, max_tokens: int = 4096) -> str:
                """Track the CSV paths the analyzer has registered."""
                calls_with_paths.append(
                    analyzer.artifact_csv_paths.get("runkeys")
                )
                return super().analyze(system_prompt, user_prompt, max_tokens)

        provider = PathTrackingProvider(responses=["resp"] * 10)
        analyzer = _build_analyzer(tmp_path)
        analyzer.ai_provider = provider

        analyzer.run_multi_image_analysis(
            images=[img1, img2],
            investigation_context="Test CSV path isolation",
        )

        # Calls: img1-artifact, img2-artifact, img1-summary, img2-summary, cross-image
        # (Phase 1 processes all image artifacts, then Phase 2 generates summaries)
        assert calls_with_paths[0] is not None, "img1 should have registered runkeys path"
        assert calls_with_paths[1] is not None, "img2 should have registered runkeys path"

        path1 = calls_with_paths[0]
        path2 = calls_with_paths[1]
        if isinstance(path1, list):
            path1 = path1[0]
        if isinstance(path2, list):
            path2 = path2[0]
        assert str(path1) != str(path2), (
            f"img2 used the same CSV path as img1: {path1}"
        )


class TestWrapImageProgressCallback:
    """Tests for _wrap_image_progress_callback helper.

    Verifies that the wrapper injects image_id and image_label into
    progress payloads for both three-arg and single-dict calling
    conventions, preventing the frontend from falling back to
    ``__single__`` grouping.
    """

    def test_three_arg_convention_injects_fields(self) -> None:
        """Three-arg callback receives image_id/image_label in the payload."""
        captured: list[tuple[str, str, dict]] = []

        def raw_cb(key: str, status: str, payload: dict) -> None:
            """Capture call arguments."""
            captured.append((key, status, payload))

        wrapped = _wrap_image_progress_callback(raw_cb, "img-42", "Server-DC01")
        wrapped("prefetch", "started", {"artifact_key": "prefetch", "model": "test"})

        assert len(captured) == 1
        key, status, payload = captured[0]
        assert key == "prefetch"
        assert status == "started"
        assert payload["image_id"] == "img-42"
        assert payload["image_label"] == "Server-DC01"
        # Original fields preserved
        assert payload["artifact_key"] == "prefetch"
        assert payload["model"] == "test"

    def test_three_arg_does_not_overwrite_existing_image_id(self) -> None:
        """Wrapper overwrites payload image_id with the wrapped value."""
        captured: list[tuple[str, str, dict]] = []

        def raw_cb(key: str, status: str, payload: dict) -> None:
            captured.append((key, status, payload))

        wrapped = _wrap_image_progress_callback(raw_cb, "img-new", "NewLabel")
        wrapped("evtx", "complete", {"image_id": "old-id", "image_label": "OldLabel"})

        payload = captured[0][2]
        assert payload["image_id"] == "img-new"
        assert payload["image_label"] == "NewLabel"

    def test_single_dict_convention_injects_fields(self) -> None:
        """Single-dict callback receives image_id/image_label inside result."""
        captured: list[dict] = []

        def raw_cb(event: dict) -> None:
            captured.append(event)

        # _wrap_image_progress_callback checks len(args): a single dict
        # arg goes through the single-dict branch.
        wrapped = _wrap_image_progress_callback(raw_cb, "img-99", "WS-PC01")
        wrapped({
            "artifact_key": "runkeys",
            "status": "started",
            "result": {"artifact_key": "runkeys", "model": "test"},
        })

        assert len(captured) == 1
        result = captured[0]["result"]
        assert result["image_id"] == "img-99"
        assert result["image_label"] == "WS-PC01"
        assert result["artifact_key"] == "runkeys"

    def test_passthrough_for_unknown_convention(self) -> None:
        """Non-standard call signatures are forwarded unchanged."""
        captured: list[tuple] = []

        def raw_cb(*args: Any) -> None:
            captured.append(args)

        wrapped = _wrap_image_progress_callback(raw_cb, "img-1", "Label")
        wrapped("solo-string")

        assert len(captured) == 1
        assert captured[0] == ("solo-string",)

    def test_non_dict_payload_forwarded(self) -> None:
        """Three-arg call with non-dict payload is forwarded as-is."""
        captured: list[tuple] = []

        def raw_cb(key: str, status: str, payload: Any) -> None:
            captured.append((key, status, payload))

        wrapped = _wrap_image_progress_callback(raw_cb, "img-1", "L")
        wrapped("key", "started", "not-a-dict")

        assert len(captured) == 1
        assert captured[0][2] == "not-a-dict"


class TestProgressEventsIncludeImageContext:
    """End-to-end test: all progress events carry image_id and artifact_key.

    Regression test for the bugs where "started" events from
    analyze_artifact() lacked image_id (causing __single__ grouping)
    and summary events lacked artifact_key (causing artifact_N labels).
    """

    def test_all_started_events_have_image_id(self, tmp_path: Path) -> None:
        """Every 'started' progress event must include image_id."""
        provider = FakeProvider(responses=["resp"] * 10)
        analyzer = _build_analyzer(tmp_path)
        analyzer.ai_provider = provider

        img1 = _make_image(tmp_path, "img1", "WS01", ["runkeys"])

        events: list[tuple[str, str, dict]] = []

        def progress_cb(key: str, status: str, payload: dict) -> None:
            events.append((key, status, payload))

        analyzer.run_multi_image_analysis(
            images=[img1],
            investigation_context="Test",
            progress_callback=progress_cb,
        )

        started_events = [e for e in events if e[1] == "started"]
        assert len(started_events) >= 1, "Expected at least one 'started' event"

        for key, status, payload in started_events:
            # Artifact-level started events (not summary/cross) should
            # have image_id injected by the wrapper.
            if not key.startswith("summary_") and key != "cross_image_correlation":
                assert payload.get("image_id") == "img1", (
                    f"'started' event for {key!r} missing image_id: {payload}"
                )

    def test_all_started_events_have_image_label(self, tmp_path: Path) -> None:
        """Every artifact 'started' event must include image_label."""
        provider = FakeProvider(responses=["resp"] * 10)
        analyzer = _build_analyzer(tmp_path)
        analyzer.ai_provider = provider

        img1 = _make_image(tmp_path, "img1", "WorkStation-01", ["services"])

        events: list[tuple[str, str, dict]] = []

        def progress_cb(key: str, status: str, payload: dict) -> None:
            events.append((key, status, payload))

        analyzer.run_multi_image_analysis(
            images=[img1],
            investigation_context="Test",
            progress_callback=progress_cb,
        )

        artifact_started = [
            e for e in events
            if e[1] == "started" and not e[0].startswith("summary_") and e[0] != "cross_image_correlation"
        ]
        for key, status, payload in artifact_started:
            assert payload.get("image_label") == "WorkStation-01", (
                f"'started' event for {key!r} missing image_label: {payload}"
            )

    def test_summary_events_have_artifact_key(self, tmp_path: Path) -> None:
        """Summary progress events must include artifact_key in their payload."""
        provider = FakeProvider(responses=["resp"] * 10)
        analyzer = _build_analyzer(tmp_path)
        analyzer.ai_provider = provider

        img1 = _make_image(tmp_path, "img1", "WS01", ["runkeys"])

        events: list[tuple[str, str, dict]] = []

        def progress_cb(key: str, status: str, payload: dict) -> None:
            events.append((key, status, payload))

        analyzer.run_multi_image_analysis(
            images=[img1],
            investigation_context="Test",
            progress_callback=progress_cb,
        )

        summary_events = [e for e in events if e[0].startswith("summary_")]
        assert len(summary_events) >= 1, "Expected at least one summary event"

        for key, status, payload in summary_events:
            assert "artifact_key" in payload, (
                f"Summary event {key!r} ({status}) missing artifact_key: {payload}"
            )
            assert "artifact_name" in payload, (
                f"Summary event {key!r} ({status}) missing artifact_name: {payload}"
            )

    def test_cross_image_events_have_artifact_key(self, tmp_path: Path) -> None:
        """Cross-image correlation events must include artifact_key in payload."""
        provider = FakeProvider(responses=["resp"] * 10)
        analyzer = _build_analyzer(tmp_path)
        analyzer.ai_provider = provider

        img1 = _make_image(tmp_path, "img1", "WS01", ["runkeys"])
        img2 = _make_image(tmp_path, "img2", "SRV01", ["services"])

        events: list[tuple[str, str, dict]] = []

        def progress_cb(key: str, status: str, payload: dict) -> None:
            events.append((key, status, payload))

        analyzer.run_multi_image_analysis(
            images=[img1, img2],
            investigation_context="Test",
            progress_callback=progress_cb,
        )

        cross_events = [e for e in events if e[0] == "cross_image_correlation"]
        assert len(cross_events) >= 1, "Expected cross-image correlation events"

        for key, status, payload in cross_events:
            assert "artifact_key" in payload, (
                f"Cross-image event ({status}) missing artifact_key: {payload}"
            )
            assert payload["artifact_key"] == "cross_image_correlation"

    def test_multi_image_started_events_have_correct_image_ids(self, tmp_path: Path) -> None:
        """With two images, each artifact's started event has the correct image_id."""
        provider = FakeProvider(responses=["resp"] * 10)
        analyzer = _build_analyzer(tmp_path)
        analyzer.ai_provider = provider

        img1 = _make_image(tmp_path, "img1", "WS01", ["runkeys"])
        img2 = _make_image(tmp_path, "img2", "SRV01", ["runkeys"])

        events: list[tuple[str, str, dict]] = []

        def progress_cb(key: str, status: str, payload: dict) -> None:
            events.append((key, status, payload))

        analyzer.run_multi_image_analysis(
            images=[img1, img2],
            investigation_context="Test",
            progress_callback=progress_cb,
        )

        # Collect all "started" events for the "runkeys" artifact.
        runkey_started = [
            e for e in events
            if e[0] == "runkeys" and e[1] == "started"
        ]
        assert len(runkey_started) == 2, (
            f"Expected 2 started events for runkeys across 2 images, got {len(runkey_started)}"
        )

        image_ids = {e[2].get("image_id") for e in runkey_started}
        assert image_ids == {"img1", "img2"}, (
            f"Expected started events for img1 and img2, got {image_ids}"
        )
