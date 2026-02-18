"""Flask application factory for AIFT."""

from __future__ import annotations

from flask import Flask

from .config import load_config
from .routes import register_routes


def create_app(config_path: str = "config.yaml") -> Flask:
    """Create and configure the Flask app instance."""
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    aift_config = load_config(config_path)
    app.config["AIFT_CONFIG"] = aift_config
    app.config["AIFT_CONFIG_PATH"] = config_path

    max_upload_mb = aift_config.get("server", {}).get("max_upload_mb")
    if isinstance(max_upload_mb, (int, float)):
        app.config["MAX_CONTENT_LENGTH"] = int(max_upload_mb) * 1024 * 1024

    register_routes(app)

    return app
