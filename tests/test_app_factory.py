from __future__ import annotations

import unittest
from unittest.mock import patch

from flask import jsonify

from app import create_app


class AppFactoryTests(unittest.TestCase):
    def _create_app(self, config: dict[str, object]) -> object:
        with (
            patch("app.load_config", return_value=config),
            patch("app.register_routes", autospec=True),
        ):
            return create_app("config.yaml")

    def test_create_app_sets_max_content_length_from_evidence_threshold(self) -> None:
        app = self._create_app({"evidence": {"large_file_threshold_mb": 42}})
        self.assertEqual(app.config["MAX_CONTENT_LENGTH"], 42 * 1024 * 1024)

    def test_create_app_no_max_content_length_when_zero(self) -> None:
        app = self._create_app({"evidence": {"large_file_threshold_mb": 0}})
        self.assertIsNone(app.config.get("MAX_CONTENT_LENGTH"))

    def test_413_error_handler_returns_json(self) -> None:
        from werkzeug.exceptions import RequestEntityTooLarge

        app = self._create_app({"evidence": {"large_file_threshold_mb": 1}})

        @app.post("/test-upload")
        def test_upload() -> tuple[object, int]:
            raise RequestEntityTooLarge()

        client = app.test_client()
        resp = client.post(
            "/test-upload",
            headers={"X-CSRF-Token": app.config["CSRF_TOKEN"]},
        )
        self.assertEqual(resp.status_code, 413)
        self.assertIn("error", resp.get_json())

    def test_csrf_token_endpoint_returns_token(self) -> None:
        app = self._create_app({})
        client = app.test_client()

        resp = client.get("/api/csrf-token")

        self.assertEqual(resp.status_code, 200)
        payload = resp.get_json()
        self.assertEqual(payload["csrf_token"], app.config["CSRF_TOKEN"])

    def test_csrf_protection_rejects_post_without_token(self) -> None:
        app = self._create_app({})

        @app.post("/test-csrf")
        def test_csrf() -> tuple[object, int]:
            return jsonify({"ok": True}), 200

        client = app.test_client()
        resp = client.post("/test-csrf")

        self.assertEqual(resp.status_code, 403)
        self.assertIn("CSRF token missing or invalid", resp.get_json()["error"])

    def test_csrf_protection_allows_post_with_valid_token(self) -> None:
        app = self._create_app({})

        @app.post("/test-csrf")
        def test_csrf() -> tuple[object, int]:
            return jsonify({"ok": True}), 200

        client = app.test_client()
        resp = client.post(
            "/test-csrf",
            headers={"X-CSRF-Token": app.config["CSRF_TOKEN"]},
        )

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json(), {"ok": True})


if __name__ == "__main__":
    unittest.main()
