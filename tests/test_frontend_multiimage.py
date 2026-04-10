"""Tests for multi-image evidence intake frontend elements.

Validates that the Flask-served template includes the new multi-image
UI elements (Add Image button, image forms container, etc.) and that
the JS modules expose the expected functions.

Attributes:
    EXPECTED_HTML_IDS: Set of HTML element IDs required for multi-image
        evidence intake.
    EXPECTED_CSS_CLASSES: Set of CSS classes used by image form cards.
"""

from __future__ import annotations

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from app import create_app


EXPECTED_HTML_IDS = {
    "image-forms-container",
    "add-image-btn",
    "evidence-summaries-container",
    "evidence-summaries-list",
    "evidence-intake-status",
}

EXPECTED_CSS_CLASSES = {
    "image-form-card",
    "image-form-header",
    "image-form-title",
    "image-remove-btn",
    "image-label-input",
    "image-mode-upload",
    "image-mode-path",
    "image-upload-panel",
    "image-path-panel",
    "image-dropzone",
    "image-dropzone-help",
    "image-file-input",
    "image-path-input",
    "image-metadata-card",
    "image-status-msg",
}


class TestMultiImageTemplate(unittest.TestCase):
    """Verify that the served HTML template contains multi-image elements."""

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

    def test_add_image_button_exists(self) -> None:
        """The 'Add Image' button should be present in the rendered HTML."""
        self.assertIn('id="add-image-btn"', self.html)
        self.assertIn("Add Image", self.html)

    def test_image_forms_container_exists(self) -> None:
        """The image forms container should be present."""
        self.assertIn('id="image-forms-container"', self.html)

    def test_first_image_form_card_exists(self) -> None:
        """At least one image-form-card should be rendered by default."""
        self.assertIn('class="image-form-card"', self.html)

    def test_image_label_input_exists(self) -> None:
        """The image label input should be present in the first card."""
        self.assertIn('class="image-label-input"', self.html)

    def test_image_mode_toggle_exists(self) -> None:
        """Upload and path radio buttons should exist in the image card."""
        self.assertIn('class="image-mode-upload"', self.html)
        self.assertIn('class="image-mode-path"', self.html)

    def test_image_dropzone_exists(self) -> None:
        """The image dropzone label should be present."""
        self.assertIn('class="image-dropzone"', self.html)

    def test_image_path_input_exists(self) -> None:
        """The image path input should be present."""
        self.assertIn('class="image-path-input"', self.html)

    def test_image_metadata_card_exists(self) -> None:
        """The per-image metadata card should be present (hidden by default)."""
        self.assertIn('class="image-metadata-card summary-card"', self.html)

    def test_evidence_summaries_container_exists(self) -> None:
        """The evidence summaries container for Step 2 should be present."""
        self.assertIn('id="evidence-summaries-container"', self.html)
        self.assertIn('id="evidence-summaries-list"', self.html)

    def test_intake_status_element_exists(self) -> None:
        """The intake status paragraph should be present for progress display."""
        self.assertIn('id="evidence-intake-status"', self.html)

    def test_all_expected_ids_present(self) -> None:
        """All expected HTML element IDs should be in the template."""
        for element_id in EXPECTED_HTML_IDS:
            with self.subTest(element_id=element_id):
                self.assertIn(f'id="{element_id}"', self.html)

    def test_all_expected_classes_present(self) -> None:
        """All expected CSS classes should appear in the template."""
        for css_class in EXPECTED_CSS_CLASSES:
            with self.subTest(css_class=css_class):
                self.assertIn(css_class, self.html)

    def test_case_name_input_still_present(self) -> None:
        """The case name input should still be present (backward compat)."""
        self.assertIn('id="case-name"', self.html)

    def test_submit_button_still_present(self) -> None:
        """The submit evidence button should still be present."""
        self.assertIn('id="submit-evidence"', self.html)

    def test_remove_button_hidden_on_first_card(self) -> None:
        """The remove button on the first card should be hidden."""
        self.assertIn('class="image-remove-btn" data-image-index="0" hidden', self.html)


class TestMultiImageJsExports(unittest.TestCase):
    """Verify that the JS modules expose multi-image management functions."""

    @classmethod
    def setUpClass(cls) -> None:
        """Read the evidence JS files content."""
        js_dir = Path(__file__).resolve().parent.parent / "static" / "js"
        cls.js_content = (js_dir / "evidence.js").read_text(encoding="utf-8")
        cls.js_multi_content = (js_dir / "evidence_multi.js").read_text(encoding="utf-8")

    def test_get_image_forms_exported(self) -> None:
        """The getImageForms function should be exported on the AIFT namespace."""
        self.assertIn("A.getImageForms", self.js_content)

    def test_add_image_form_exported(self) -> None:
        """The addImageForm function should be exported."""
        self.assertIn("A.addImageForm", self.js_multi_content)

    def test_remove_image_form_exported(self) -> None:
        """The removeImageForm function should be exported."""
        self.assertIn("A.removeImageForm", self.js_multi_content)

    def test_render_image_summaries_exported(self) -> None:
        """The renderImageSummaries function should be exported."""
        self.assertIn("A.renderImageSummaries", self.js_multi_content)

    def test_images_state_initialized(self) -> None:
        """The st.images array should be initialized."""
        self.assertIn("st.images", self.js_content)

    def test_multi_image_api_endpoints_used(self) -> None:
        """The JS should call the multi-image API endpoints."""
        self.assertIn("/images", self.js_multi_content)
        self.assertIn("/evidence", self.js_multi_content)


class TestMultiImageCss(unittest.TestCase):
    """Verify that the CSS includes styles for multi-image elements."""

    @classmethod
    def setUpClass(cls) -> None:
        """Read the style.css file content."""
        css_path = Path(__file__).resolve().parent.parent / "static" / "style.css"
        cls.css_content = css_path.read_text(encoding="utf-8")

    def test_image_form_card_styled(self) -> None:
        """The .image-form-card class should be styled."""
        self.assertIn(".image-form-card", self.css_content)

    def test_image_form_header_styled(self) -> None:
        """The .image-form-header class should be styled."""
        self.assertIn(".image-form-header", self.css_content)

    def test_add_image_button_styled(self) -> None:
        """The #add-image-btn should be styled."""
        self.assertIn("#add-image-btn", self.css_content)

    def test_image_dropzone_styled(self) -> None:
        """The .image-dropzone class should be styled."""
        self.assertIn(".image-dropzone", self.css_content)

    def test_image_remove_button_styled(self) -> None:
        """The .image-remove-btn class should be styled."""
        self.assertIn(".image-remove-btn", self.css_content)

    def test_evidence_summaries_styled(self) -> None:
        """The #evidence-summaries-list should be styled."""
        self.assertIn("#evidence-summaries-list", self.css_content)


if __name__ == "__main__":
    unittest.main()
