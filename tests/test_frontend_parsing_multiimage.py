"""Tests for multi-image artifact selection and parsing frontend elements.

Validates that the Flask-served template includes the tabbed artifact
selection UI for multi-image cases, grouped parsing progress containers,
and that the JS and CSS modules expose the expected functions and styles.

Attributes:
    EXPECTED_ARTIFACT_TAB_IDS: Set of HTML element IDs required for the
        multi-image artifact tab interface.
    EXPECTED_PARSE_SECTION_IDS: Set of HTML element IDs required for the
        multi-image parse progress view.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from app import create_app


EXPECTED_ARTIFACT_TAB_IDS = {
    "artifact-image-tabs",
    "artifact-image-panels",
    "artifact-selection-content",
}

EXPECTED_PARSE_SECTION_IDS = {
    "parse-image-sections",
    "parse-single-table",
    "parse-overall-progress",
    "parse-progress-rows",
    "parse-error-message",
    "cancel-parse",
}


class TestMultiImageArtifactTabsTemplate(unittest.TestCase):
    """Verify that the served HTML template contains tabbed artifact selection elements."""

    @classmethod
    def setUpClass(cls) -> None:
        """Create a Flask test client and fetch the index page."""
        cls._tmpdir = TemporaryDirectory()
        config_path = Path(cls._tmpdir.name) / "config.yaml"
        config_path.write_text("", encoding="utf-8")
        cls.app = create_app(config_path=str(config_path))
        cls.app.config["TESTING"] = True
        cls.client = cls.app.test_client()
        with cls.app.app_context():
            resp = cls.client.get("/")
        cls.html = resp.data.decode("utf-8")

    @classmethod
    def tearDownClass(cls) -> None:
        """Clean up temporary directory."""
        cls._tmpdir.cleanup()

    def test_artifact_image_tabs_container_exists(self) -> None:
        """The artifact-image-tabs container should be present (hidden by default)."""
        self.assertIn('id="artifact-image-tabs"', self.html)

    def test_artifact_image_tabs_hidden_by_default(self) -> None:
        """The tab container should be hidden by default (single-image mode)."""
        self.assertIn('id="artifact-image-tabs"', self.html)
        # It should have the 'hidden' attribute in the HTML
        self.assertIn('class="artifact-image-tabs" hidden', self.html)

    def test_artifact_tab_bar_exists(self) -> None:
        """The tab bar with role=tablist should be present."""
        self.assertIn('role="tablist"', self.html)
        self.assertIn('class="artifact-tab-bar"', self.html)

    def test_artifact_image_panels_container_exists(self) -> None:
        """The artifact-image-panels container should be present."""
        self.assertIn('id="artifact-image-panels"', self.html)

    def test_artifact_selection_content_wrapper_exists(self) -> None:
        """The artifact-selection-content wrapper should be present."""
        self.assertIn('id="artifact-selection-content"', self.html)

    def test_preset_buttons_still_present(self) -> None:
        """The Quick Triage and Clear All buttons should still exist."""
        self.assertIn('id="preset-quick-triage"', self.html)
        self.assertIn('id="preset-clear-all"', self.html)

    def test_parse_selected_button_still_present(self) -> None:
        """The Parse Selected button should still be present."""
        self.assertIn('id="parse-selected"', self.html)

    def test_all_artifact_tab_ids_present(self) -> None:
        """All expected HTML element IDs for artifact tabs should be in the template."""
        for element_id in EXPECTED_ARTIFACT_TAB_IDS:
            with self.subTest(element_id=element_id):
                self.assertIn(f'id="{element_id}"', self.html)


class TestMultiImageParseProgressTemplate(unittest.TestCase):
    """Verify that the served HTML template contains grouped parsing progress elements."""

    @classmethod
    def setUpClass(cls) -> None:
        """Create a Flask test client and fetch the index page."""
        cls._tmpdir = TemporaryDirectory()
        config_path = Path(cls._tmpdir.name) / "config.yaml"
        config_path.write_text("", encoding="utf-8")
        cls.app = create_app(config_path=str(config_path))
        cls.app.config["TESTING"] = True
        cls.client = cls.app.test_client()
        with cls.app.app_context():
            resp = cls.client.get("/")
        cls.html = resp.data.decode("utf-8")

    @classmethod
    def tearDownClass(cls) -> None:
        """Clean up temporary directory."""
        cls._tmpdir.cleanup()

    def test_parse_image_sections_container_exists(self) -> None:
        """The parse-image-sections container for multi-image progress should be present."""
        self.assertIn('id="parse-image-sections"', self.html)

    def test_parse_single_table_exists(self) -> None:
        """The single-image parse table should be present (V1 compatibility)."""
        self.assertIn('id="parse-single-table"', self.html)

    def test_overall_progress_bar_exists(self) -> None:
        """The overall progress bar should be present."""
        self.assertIn('id="parse-overall-progress"', self.html)

    def test_parse_progress_rows_exists(self) -> None:
        """The parse progress rows tbody should be present."""
        self.assertIn('id="parse-progress-rows"', self.html)

    def test_parse_error_message_exists(self) -> None:
        """The parse error message element should be present."""
        self.assertIn('id="parse-error-message"', self.html)

    def test_cancel_parse_button_exists(self) -> None:
        """The cancel parse button should be present."""
        self.assertIn('id="cancel-parse"', self.html)

    def test_all_parse_section_ids_present(self) -> None:
        """All expected HTML element IDs for parse progress should be in the template."""
        for element_id in EXPECTED_PARSE_SECTION_IDS:
            with self.subTest(element_id=element_id):
                self.assertIn(f'id="{element_id}"', self.html)

    def test_single_table_and_multi_sections_coexist(self) -> None:
        """Both single-image table and multi-image sections container should coexist."""
        self.assertIn('id="parse-single-table"', self.html)
        self.assertIn('id="parse-image-sections"', self.html)

    def test_parse_step_has_correct_step_number(self) -> None:
        """The parsing step should be step 3."""
        self.assertIn('data-step="3"', self.html)
        self.assertIn('id="step-parsing"', self.html)


class TestMultiImageParsingJsExports(unittest.TestCase):
    """Verify that the JS parsing module exposes multi-image parsing functions."""

    @classmethod
    def setUpClass(cls) -> None:
        """Read the parsing.js file content."""
        js_path = Path(__file__).resolve().parent.parent / "static" / "js" / "parsing.js"
        cls.js_content = js_path.read_text(encoding="utf-8")

    def test_submit_parse_exported(self) -> None:
        """The submitParse function should be exported on the AIFT namespace."""
        self.assertIn("A.submitParse", self.js_content)

    def test_cancel_parse_exported(self) -> None:
        """The cancelParse function should be exported."""
        self.assertIn("A.cancelParse", self.js_content)

    def test_close_parse_sse_exported(self) -> None:
        """The closeParseSse function should be exported."""
        self.assertIn("A.closeParseSse", self.js_content)

    def test_reset_parse_state_exported(self) -> None:
        """The resetParseState function should be exported."""
        self.assertIn("A.resetParseState", self.js_content)

    def test_render_parse_placeholder_exported(self) -> None:
        """The renderParsePlaceholder function should be exported."""
        self.assertIn("A.renderParsePlaceholder", self.js_content)

    def test_image_parse_state_initialized(self) -> None:
        """The st.imageParse object should be initialized."""
        self.assertIn("st.imageParse", self.js_content)

    def test_multi_image_parse_function_exists(self) -> None:
        """The submitMultiImageParse function should be defined."""
        self.assertIn("submitMultiImageParse", self.js_content)

    def test_start_image_parse_function_exists(self) -> None:
        """The startImageParse function should be defined."""
        self.assertIn("startImageParse", self.js_content)

    def test_build_multi_image_parse_sections_exists(self) -> None:
        """The buildMultiImageParseSections function should be defined."""
        self.assertIn("buildMultiImageParseSections", self.js_content)

    def test_start_image_parse_sse_exists(self) -> None:
        """The startImageParseSse function should be defined."""
        self.assertIn("startImageParseSse", self.js_content)

    def test_on_image_parse_event_exists(self) -> None:
        """The onImageParseEvent function should be defined."""
        self.assertIn("onImageParseEvent", self.js_content)

    def test_check_multi_image_completion_exists(self) -> None:
        """The checkMultiImageCompletion function should be defined."""
        self.assertIn("checkMultiImageCompletion", self.js_content)

    def test_set_image_parse_row_exists(self) -> None:
        """The setImageParseRow function should be defined."""
        self.assertIn("setImageParseRow", self.js_content)

    def test_update_multi_image_parse_progress_exists(self) -> None:
        """The updateMultiImageParseProgress function should be defined."""
        self.assertIn("updateMultiImageParseProgress", self.js_content)

    def test_per_image_parse_api_endpoint_used(self) -> None:
        """The JS should call per-image parse API endpoints."""
        self.assertIn("/images/", self.js_content)
        self.assertIn("/parse", self.js_content)

    def test_per_image_sse_endpoint_used(self) -> None:
        """The JS should connect to per-image parse progress SSE endpoints."""
        self.assertIn("/parse/progress", self.js_content)

    def test_is_multi_image_check_in_submit(self) -> None:
        """The submitParse function should check isMultiImage for branching."""
        self.assertIn("isMultiImage()", self.js_content)

    def test_show_single_image_parse_table_exists(self) -> None:
        """The showSingleImageParseTable function should be defined."""
        self.assertIn("showSingleImageParseTable", self.js_content)


class TestMultiImageArtifactTabsJsExports(unittest.TestCase):
    """Verify that the JS evidence module exposes multi-image artifact tab functions."""

    @classmethod
    def setUpClass(cls) -> None:
        """Read the evidence.js file content."""
        js_path = Path(__file__).resolve().parent.parent / "static" / "js" / "evidence.js"
        cls.js_content = js_path.read_text(encoding="utf-8")

    def test_build_multi_image_artifact_tabs_exported(self) -> None:
        """The buildMultiImageArtifactTabs function should be exported."""
        self.assertIn("A.buildMultiImageArtifactTabs", self.js_content)

    def test_switch_artifact_tab_exported(self) -> None:
        """The switchArtifactTab function should be exported."""
        self.assertIn("A.switchArtifactTab", self.js_content)

    def test_active_artifact_tab_image_id_exported(self) -> None:
        """The activeArtifactTabImageId function should be exported."""
        self.assertIn("A.activeArtifactTabImageId", self.js_content)

    def test_selected_artifact_options_for_image_exported(self) -> None:
        """The selectedArtifactOptionsForImage function should be exported."""
        self.assertIn("A.selectedArtifactOptionsForImage", self.js_content)

    def test_all_image_artifact_selections_exported(self) -> None:
        """The allImageArtifactSelections function should be exported."""
        self.assertIn("A.allImageArtifactSelections", self.js_content)

    def test_is_multi_image_exported(self) -> None:
        """The isMultiImage function should be exported."""
        self.assertIn("A.isMultiImage", self.js_content)

    def test_apply_preset_multi_aware_exported(self) -> None:
        """The applyPresetMultiAware function should be exported."""
        self.assertIn("A.applyPresetMultiAware", self.js_content)

    def test_preset_applies_to_active_tab(self) -> None:
        """The preset logic should call applyPresetMultiAware for multi-image mode."""
        self.assertIn("applyPresetMultiAware", self.js_content)
        # The recommended button handler should check isMultiImage
        self.assertIn('isMultiImage()', self.js_content)

    def test_active_tab_panel_selection_uses_image_id(self) -> None:
        """The artifact selection should use image_id to scope to the right panel."""
        self.assertIn("data-image-id", self.js_content)

    def test_clone_fieldsets_for_per_image_panels(self) -> None:
        """The tab builder should clone fieldsets from the main form."""
        self.assertIn("cloneNode", self.js_content)


class TestMultiImageParsingCss(unittest.TestCase):
    """Verify that the CSS includes styles for multi-image artifact tabs and parse progress."""

    @classmethod
    def setUpClass(cls) -> None:
        """Read the style.css file content."""
        css_path = Path(__file__).resolve().parent.parent / "static" / "style.css"
        cls.css_content = css_path.read_text(encoding="utf-8")

    def test_artifact_tab_bar_styled(self) -> None:
        """The .artifact-tab-bar class should be styled."""
        self.assertIn(".artifact-tab-bar", self.css_content)

    def test_artifact_tab_bar_button_styled(self) -> None:
        """The tab bar buttons should be styled."""
        self.assertIn(".artifact-tab-bar button", self.css_content)

    def test_artifact_tab_active_state_styled(self) -> None:
        """The active tab state should be styled with accent color."""
        self.assertIn(".artifact-tab-bar button.is-active", self.css_content)

    def test_artifact_image_panel_styled(self) -> None:
        """The .artifact-image-panel class should be styled."""
        self.assertIn(".artifact-image-panel", self.css_content)

    def test_artifact_image_panel_active_state(self) -> None:
        """The active panel state should display the panel."""
        self.assertIn(".artifact-image-panel.is-active", self.css_content)

    def test_artifact_image_tabs_container_styled(self) -> None:
        """The .artifact-image-tabs container should be styled."""
        self.assertIn(".artifact-image-tabs", self.css_content)

    def test_parse_image_section_styled(self) -> None:
        """The .parse-image-section class should be styled."""
        self.assertIn(".parse-image-section", self.css_content)

    def test_parse_image_section_header_styled(self) -> None:
        """The .parse-image-section-header class should be styled."""
        self.assertIn(".parse-image-section-header", self.css_content)

    def test_parse_image_section_header_h4_styled(self) -> None:
        """The h4 in parse section header should be styled with accent color."""
        self.assertIn(".parse-image-section-header h4", self.css_content)

    def test_parse_image_status_styled(self) -> None:
        """The .parse-image-status element should be styled."""
        self.assertIn(".parse-image-status", self.css_content)

    def test_parse_image_status_completed_styled(self) -> None:
        """The completed status should use the success color."""
        self.assertIn('.parse-image-status[data-status="completed"]', self.css_content)

    def test_parse_image_status_failed_styled(self) -> None:
        """The failed status should use the danger color."""
        self.assertIn('.parse-image-status[data-status="failed"]', self.css_content)

    def test_parse_image_section_table_styled(self) -> None:
        """The table within parse sections should be styled."""
        self.assertIn(".parse-image-section table", self.css_content)

    def test_parse_image_error_styled(self) -> None:
        """The .parse-image-error class should be styled."""
        self.assertIn(".parse-image-error", self.css_content)


if __name__ == "__main__":
    unittest.main()
