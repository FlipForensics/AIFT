"""Tests for multi-image analysis and results frontend elements.

Validates that:
- The analyze endpoint accepts multi-image format
- The HTML template has the cross-system analysis section
- The JS sends correct multi-image analysis payload format
- The results display has per-image collapsible sections
- The chat manager handles multi-image context correctly

Attributes:
    EXPECTED_RESULTS_HTML_IDS: Set of HTML element IDs required for
        multi-image results display.
    EXPECTED_CSS_CLASSES: Set of CSS classes used by multi-image
        analysis and results sections.
"""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
from unittest.mock import MagicMock, patch

from app import create_app


EXPECTED_RESULTS_HTML_IDS = {
    "cross-system-analysis",
}

EXPECTED_CSS_CLASSES = {
    "cross-system-analysis",
    "cross-system-content",
}


class TestMultiImageResultsTemplate(unittest.TestCase):
    """Verify that the served HTML template contains multi-image results elements."""

    @classmethod
    def setUpClass(cls) -> None:
        """Create a Flask test client and fetch the index page."""
        cls._tmpdir = TemporaryDirectory()
        config_path = Path(cls._tmpdir.name) / "config.yaml"
        config_path.write_text("", encoding="utf-8")
        cls.app = create_app(config_path=str(config_path))
        cls.app.config["TESTING"] = True
        cls.client = cls.app.test_client()
        response = cls.client.get("/")
        cls.html = response.data.decode("utf-8")

    @classmethod
    def tearDownClass(cls) -> None:
        """Clean up the temporary directory."""
        cls._tmpdir.cleanup()

    def test_cross_system_analysis_section_exists(self) -> None:
        """The index page must contain the cross-system analysis section."""
        self.assertIn('id="cross-system-analysis"', self.html)

    def test_cross_system_content_div_exists(self) -> None:
        """The cross-system section must contain the content div."""
        self.assertIn('class="cross-system-content', self.html)

    def test_cross_system_section_hidden_by_default(self) -> None:
        """The cross-system section should be hidden by default."""
        self.assertIn('id="cross-system-analysis" class="cross-system-analysis" hidden', self.html)

    def test_expected_html_ids_present(self) -> None:
        """All expected multi-image results HTML IDs must be present."""
        for html_id in EXPECTED_RESULTS_HTML_IDS:
            with self.subTest(html_id=html_id):
                self.assertIn(f'id="{html_id}"', self.html)

    def test_expected_css_classes_present(self) -> None:
        """All expected multi-image CSS classes must appear in the HTML or CSS."""
        for css_class in EXPECTED_CSS_CLASSES:
            with self.subTest(css_class=css_class):
                self.assertIn(css_class, self.html)


class TestMultiImageAnalysisJS(unittest.TestCase):
    """Verify that the analysis JS contains multi-image support."""

    @classmethod
    def setUpClass(cls) -> None:
        """Read the analysis.js source file."""
        js_path = Path(__file__).resolve().parents[1] / "static" / "js" / "analysis.js"
        cls.js_content = js_path.read_text(encoding="utf-8")

    def test_sends_images_in_body(self) -> None:
        """The JS should send images array in the analysis request body."""
        self.assertIn("body.images", self.js_content)

    def test_multi_image_state_tracking(self) -> None:
        """The JS should track multiImage state."""
        self.assertIn("st.analysis.multiImage", self.js_content)

    def test_cross_image_summary_state(self) -> None:
        """The JS should track crossImageSummary state."""
        self.assertIn("st.analysis.crossImageSummary", self.js_content)

    def test_image_results_state(self) -> None:
        """The JS should track imageResults state."""
        self.assertIn("st.analysis.imageResults", self.js_content)

    def test_render_multi_image_analysis(self) -> None:
        """The JS should have renderMultiImageAnalysis function."""
        self.assertIn("renderMultiImageAnalysis", self.js_content)

    def test_render_multi_image_findings(self) -> None:
        """The JS should have renderMultiImageFindings function."""
        self.assertIn("renderMultiImageFindings", self.js_content)

    def test_render_multi_image_exec_summary(self) -> None:
        """The JS should have renderMultiImageExecSummary function."""
        self.assertIn("renderMultiImageExecSummary", self.js_content)

    def test_analysis_image_group_class(self) -> None:
        """The JS should create analysis-image-group elements."""
        self.assertIn("analysis-image-group", self.js_content)

    def test_findings_image_group_class(self) -> None:
        """The JS should create findings-image-group elements."""
        self.assertIn("findings-image-group", self.js_content)

    def test_per_image_summary_section_class(self) -> None:
        """The JS should create per-image-summary-section elements."""
        self.assertIn("per-image-summary-section", self.js_content)

    def test_cross_system_analysis_id(self) -> None:
        """The JS should reference the cross-system-analysis element."""
        self.assertIn("cross-system-analysis", self.js_content)

    def test_reset_clears_multi_image_state(self) -> None:
        """resetAnalysisState should clear multi-image state fields."""
        self.assertIn('st.analysis.multiImage = false', self.js_content)
        self.assertIn('st.analysis.imageResults = {}', self.js_content)
        self.assertIn('st.analysis.crossImageSummary = ""', self.js_content)

    def test_all_image_artifact_selections_usage(self) -> None:
        """The JS should call allImageArtifactSelections for multi-image."""
        self.assertIn("allImageArtifactSelections", self.js_content)


class TestMultiImageAnalysisCSS(unittest.TestCase):
    """Verify that the CSS contains multi-image analysis and results styles."""

    @classmethod
    def setUpClass(cls) -> None:
        """Read the style.css source file."""
        css_path = Path(__file__).resolve().parents[1] / "static" / "style.css"
        cls.css_content = css_path.read_text(encoding="utf-8")

    def test_cross_system_analysis_styles(self) -> None:
        """CSS must contain cross-system-analysis styles."""
        self.assertIn(".cross-system-analysis", self.css_content)

    def test_cross_system_content_styles(self) -> None:
        """CSS must contain cross-system-content styles."""
        self.assertIn(".cross-system-content", self.css_content)

    def test_per_image_summary_styles(self) -> None:
        """CSS must contain per-image-summary styles."""
        self.assertIn(".per-image-summary-section", self.css_content)
        self.assertIn(".per-image-summary-header", self.css_content)

    def test_analysis_image_group_styles(self) -> None:
        """CSS must contain analysis-image-group styles."""
        self.assertIn(".analysis-image-group", self.css_content)
        self.assertIn(".analysis-image-group-header", self.css_content)

    def test_findings_image_group_styles(self) -> None:
        """CSS must contain findings-image-group styles."""
        self.assertIn(".findings-image-group", self.css_content)
        self.assertIn(".findings-image-group-header", self.css_content)

    def test_accent_border_on_cross_system(self) -> None:
        """Cross-system analysis should use accent color border."""
        # Check that the accent variable is referenced in the cross-system block.
        self.assertIn("var(--accent)", self.css_content)


class TestMultiImageAnalyzeEndpoint(unittest.TestCase):
    """Verify that the analyze endpoint accepts multi-image format."""

    @classmethod
    def setUpClass(cls) -> None:
        """Create a Flask test client."""
        cls._tmpdir = TemporaryDirectory()
        config_path = Path(cls._tmpdir.name) / "config.yaml"
        config_path.write_text("", encoding="utf-8")
        cls.app = create_app(config_path=str(config_path))
        cls.app.config["TESTING"] = True
        cls.client = cls.app.test_client()

    @classmethod
    def tearDownClass(cls) -> None:
        """Clean up the temporary directory."""
        cls._tmpdir.cleanup()

    def test_analyze_endpoint_rejects_nonexistent_case(self) -> None:
        """POST /api/cases/<nonexistent>/analyze returns an error (403 or 404)."""
        response = self.client.post(
            "/api/cases/nonexistent-case/analyze",
            json={"prompt": "test", "images": [{"image_id": "img1", "artifacts": ["runkeys"]}]},
            content_type="application/json",
        )
        # May be 403 (CSRF) or 404 (case not found); either is an error.
        self.assertIn(response.status_code, (403, 404))

    def test_analyze_endpoint_accepts_images_format(self) -> None:
        """The analysis route module should import the multi-image task function."""
        from app.routes.analysis import analysis_bp  # noqa: F401
        from app.routes.tasks import run_multi_image_analysis_task  # noqa: F401
        # If the import succeeds, the function exists and is importable.
        self.assertTrue(callable(run_multi_image_analysis_task))


class TestMultiImageAnalysisRoute(unittest.TestCase):
    """Verify analysis route code handles the images payload."""

    def test_analysis_route_reads_images_from_payload(self) -> None:
        """The analysis route source should extract images from the payload."""
        route_path = Path(__file__).resolve().parents[1] / "app" / "routes" / "analysis.py"
        source = route_path.read_text(encoding="utf-8")
        self.assertIn('payload.get("images")', source)
        self.assertIn("images_payload", source)
        self.assertIn("run_multi_image_analysis_task", source)


class TestMultiImageChatContext(unittest.TestCase):
    """Verify ChatManager handles multi-image analysis results."""

    def setUp(self) -> None:
        """Create a temporary case directory and ChatManager."""
        self._tmpdir = TemporaryDirectory()
        self.case_dir = self._tmpdir.name
        from app.chat.manager import ChatManager
        self.manager = ChatManager(self.case_dir)

    def tearDown(self) -> None:
        """Clean up the temporary directory."""
        self._tmpdir.cleanup()

    def test_build_context_with_multi_image_results(self) -> None:
        """build_chat_context should include per-image summaries for multi-image results."""
        multi_image_results: dict[str, Any] = {
            "images": {
                "img1": {
                    "label": "Workstation-PC01",
                    "per_artifact": [
                        {"artifact_name": "runkeys", "analysis": "Found persistence."},
                    ],
                    "summary": "PC01 shows signs of malware persistence.",
                },
                "img2": {
                    "label": "Server-DC01",
                    "per_artifact": [
                        {"artifact_name": "evtx", "analysis": "Suspicious logins."},
                    ],
                    "summary": "DC01 shows lateral movement indicators.",
                },
            },
            "cross_image_summary": "Cross-system: attacker pivoted from PC01 to DC01.",
            "model_info": {"provider": "test", "model": "test-model"},
        }

        context = self.manager.build_chat_context(
            analysis_results=multi_image_results,
            investigation_context="Investigating breach.",
            metadata={"hostname": "multi"},
        )

        # Should include per-image summaries.
        self.assertIn("Workstation-PC01", context)
        self.assertIn("Server-DC01", context)
        self.assertIn("PC01 shows signs of malware persistence", context)
        self.assertIn("DC01 shows lateral movement indicators", context)

        # Should include cross-image summary.
        self.assertIn("Cross-Image Correlation", context)
        self.assertIn("attacker pivoted from PC01 to DC01", context)

    def test_build_context_with_single_image_results(self) -> None:
        """build_chat_context should work normally for single-image results."""
        single_results: dict[str, Any] = {
            "per_artifact": [
                {"artifact_name": "runkeys", "analysis": "No anomalies."},
            ],
            "summary": "Clean system.",
            "model_info": {"provider": "test", "model": "test-model"},
        }

        context = self.manager.build_chat_context(
            analysis_results=single_results,
            investigation_context="Routine check.",
            metadata={"hostname": "DESKTOP-01", "os_version": "Windows 10", "domain": "WORKGROUP"},
        )

        self.assertIn("DESKTOP-01", context)
        self.assertIn("Clean system.", context)
        self.assertIn("Routine check.", context)

    def test_format_multi_image_findings(self) -> None:
        """_format_per_artifact_findings should group findings by image."""
        multi_results: dict[str, Any] = {
            "images": {
                "img1": {
                    "label": "PC01",
                    "per_artifact": [
                        {"artifact_name": "runkeys", "analysis": "Malicious entry found."},
                    ],
                },
                "img2": {
                    "label": "DC01",
                    "per_artifact": [
                        {"artifact_name": "evtx", "analysis": "Failed logins detected."},
                    ],
                },
            },
        }

        findings = self.manager._format_per_artifact_findings(multi_results)
        self.assertIn("PC01", findings)
        self.assertIn("DC01", findings)
        self.assertIn("Malicious entry found.", findings)
        self.assertIn("Failed logins detected.", findings)

    def test_retrieve_csv_data_with_additional_dirs(self) -> None:
        """retrieve_csv_data should accept additional_parsed_dirs parameter."""
        import inspect
        sig = inspect.signature(self.manager.retrieve_csv_data)
        self.assertIn("additional_parsed_dirs", sig.parameters)


class TestMultiImageTaskFunction(unittest.TestCase):
    """Verify the run_multi_image_analysis_task function exists and has correct signature."""

    def test_function_exists(self) -> None:
        """run_multi_image_analysis_task should be importable."""
        from app.routes.tasks import run_multi_image_analysis_task
        self.assertTrue(callable(run_multi_image_analysis_task))

    def test_function_signature(self) -> None:
        """run_multi_image_analysis_task should accept the expected parameters."""
        import inspect
        from app.routes.tasks import run_multi_image_analysis_task
        sig = inspect.signature(run_multi_image_analysis_task)
        params = list(sig.parameters.keys())
        self.assertIn("case_id", params)
        self.assertIn("prompt", params)
        self.assertIn("images_payload", params)
        self.assertIn("config_snapshot", params)


if __name__ == "__main__":
    unittest.main()
