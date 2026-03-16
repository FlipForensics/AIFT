"""Flask application factory for AIFT.

Provides the :func:`create_app` factory function that initialises the Flask
application, loads configuration from ``config.yaml``, sets the upload size
limit, and registers all HTTP route blueprints.

A Python version guard runs at import time so that downstream code can
assume a supported interpreter.
"""

from __future__ import annotations

from pathlib import Path

from runtime_compat import assert_supported_python_version

assert_supported_python_version()

from flask import Flask

from .config import PROJECT_ROOT, load_config
from .routes import register_routes


def create_app(config_path: str | None = None) -> Flask:
    """Create and configure the Flask application instance.

    Loads AIFT configuration (merging defaults, YAML, and environment
    variables), stores it in ``app.config["AIFT_CONFIG"]``, configures the
    maximum upload size, and registers all HTTP routes.

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

    max_upload_mb = aift_config.get("server", {}).get("max_upload_mb")
    if isinstance(max_upload_mb, (int, float)):
        app.config["MAX_CONTENT_LENGTH"] = int(max_upload_mb) * 1024 * 1024

    register_routes(app)

    return app
