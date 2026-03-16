"""Flask application factory for AIFT.

Provides the :func:`create_app` factory function that initialises the Flask
application, loads configuration from ``config.yaml``, sets the upload size
limit, registers all HTTP route blueprints, and configures CSRF protection.

A Python version guard runs at import time so that downstream code can
assume a supported interpreter.

Attributes:
    CSRF_HEADER: Name of the HTTP header used to transmit the CSRF token.
    CSRF_SAFE_METHODS: HTTP methods exempt from CSRF validation (read-only
        methods that do not modify server state).
"""

from __future__ import annotations

import secrets
from pathlib import Path

from runtime_compat import assert_supported_python_version

assert_supported_python_version()

from flask import Flask, jsonify, request

from .config import PROJECT_ROOT, load_config
from .routes import register_routes

CSRF_HEADER = "X-CSRF-Token"
CSRF_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def create_app(config_path: str | None = None) -> Flask:
    """Create and configure the Flask application instance.

    Loads AIFT configuration (merging defaults, YAML, and environment
    variables), stores it in ``app.config["AIFT_CONFIG"]``, configures the
    maximum upload size, generates a per-process CSRF token, installs CSRF
    validation middleware, and registers all HTTP routes.

    Args:
        config_path: Optional path to a YAML configuration file.  When
            *None*, the default ``config.yaml`` in the project root is used.

    Returns:
        A fully configured :class:`~flask.Flask` application instance.
    """
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    aift_config = load_config(config_path)
    # Store the resolved absolute path so all downstream code uses it consistently.
    resolved_config_path = str(Path(config_path)) if config_path is not None else str(PROJECT_ROOT / "config.yaml")
    app.config["AIFT_CONFIG"] = aift_config
    app.config["AIFT_CONFIG_PATH"] = resolved_config_path

    # Generate a per-process CSRF token for protecting state-changing requests.
    app.config["CSRF_TOKEN"] = secrets.token_hex(32)

    max_upload_mb = aift_config.get("server", {}).get("max_upload_mb")
    if isinstance(max_upload_mb, (int, float)):
        app.config["MAX_CONTENT_LENGTH"] = int(max_upload_mb) * 1024 * 1024

    _register_csrf_protection(app)
    register_routes(app)

    return app


def _register_csrf_protection(app: Flask) -> None:
    """Install a ``before_request`` hook that validates the CSRF token.

    All requests whose method is not in :data:`CSRF_SAFE_METHODS` must
    include a valid ``X-CSRF-Token`` header matching the token stored in
    ``app.config["CSRF_TOKEN"]``.  Requests to the CSRF token endpoint
    itself (``/api/csrf-token``) are exempt so the frontend can obtain the
    token.

    Args:
        app: The Flask application to attach the hook to.
    """

    @app.before_request
    def _enforce_csrf() -> tuple | None:
        """Reject state-changing requests that lack a valid CSRF token.

        Returns:
            A 403 JSON error response tuple when validation fails, or
            ``None`` to allow the request to proceed.
        """
        if request.method in CSRF_SAFE_METHODS:
            return None
        if request.path == "/api/csrf-token":
            return None
        token = request.headers.get(CSRF_HEADER, "")
        if not secrets.compare_digest(token, app.config["CSRF_TOKEN"]):
            return jsonify({"error": "CSRF token missing or invalid."}), 403
        return None

    @app.get("/api/csrf-token")
    def _get_csrf_token() -> tuple:
        """Return the CSRF token so the frontend can include it in requests.

        Returns:
            A JSON response containing the CSRF token with a 200 status.
        """
        return jsonify({"csrf_token": app.config["CSRF_TOKEN"]}), 200
