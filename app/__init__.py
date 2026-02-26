"""Flask application factory for AIFT."""

from __future__ import annotations

from pathlib import Path

from runtime_compat import assert_supported_python_version

assert_supported_python_version()

from flask import Flask

from .config import PROJECT_ROOT, load_config
from .routes import register_routes


def create_app(config_path: str | None = None) -> Flask:
    """Create and configure the Flask app instance."""
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
