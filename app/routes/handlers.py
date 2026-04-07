"""HTTP route definitions for the AIFT (AI Forensic Triage) Flask application.

This module serves as the central registration point for all route blueprints.
It defines the core ``routes_bp`` blueprint (static/UI, case management, and
settings routes) and imports sub-blueprints from:

* :mod:`evidence` -- evidence helpers and route handlers.
* :mod:`artifacts` -- artifact/profile helpers and route handlers.
* :mod:`analysis` -- AI-powered analysis routes.
* :mod:`chat` -- interactive chat routes.

Supporting logic lives in:

* :mod:`state` -- shared state, constants, SSE streaming.
* :mod:`evidence` -- archive extraction, CSV/hash helpers.
* :mod:`artifacts` -- artifact option normalisation, profile helpers.
* :mod:`tasks` -- background parse/analysis/chat runners.

Attributes:
    routes_bp: Flask ``Blueprint`` for core routes (UI, cases, settings).
"""

from __future__ import annotations

import copy
from datetime import datetime
import logging
from pathlib import Path
import threading  # noqa: F401 -- re-exported for test patching
from urllib.request import urlopen, Request
from urllib.error import URLError
from uuid import uuid4

from flask import (
    Blueprint,
    Flask,
    Response,
    current_app,
    g,
    render_template,
    request,
    send_file,
)

from ..ai_providers import AIProviderError, create_provider  # noqa: F401 -- re-exported
from ..analyzer import ForensicAnalyzer  # noqa: F401 -- re-exported for test patching
from ..audit import AuditLogger
from ..case_manager import CaseManager
from ..case_logging import (
    case_log_context,  # noqa: F401 -- re-exported
    pop_case_log_context,
    push_case_log_context,
    register_case_log_handler,
)
from ..config import load_config, save_config, validate_config
from ..hasher import compute_hashes, verify_hash  # noqa: F401 -- re-exported
from ..parser import WINDOWS_ARTIFACT_REGISTRY, ForensicParser  # noqa: F401 -- re-exported
from ..reporter import ReportGenerator  # noqa: F401 -- re-exported
from ..version import TOOL_VERSION  # noqa: F401 -- re-exported

from .state import (
    CASES_ROOT,
    IMAGES_ROOT,
    CONNECTION_TEST_SYSTEM_PROMPT,
    CONNECTION_TEST_USER_PROMPT,
    SSE_INITIAL_IDLE_GRACE_SECONDS,  # noqa: F401 -- re-exported for test patching
    CASE_STATES,
    PARSE_PROGRESS,
    ANALYSIS_PROGRESS,
    CHAT_PROGRESS,
    STATE_LOCK,
    now_iso,
    error_response,
    success_response,
    resolve_logo_filename,
    new_progress,
    mask_sensitive,
    deep_merge,
    audit_config_change,
    cleanup_terminal_cases,
    safe_name,
)
from .artifacts import (
    RECOMMENDED_PROFILE_EXCLUDED_ARTIFACTS,  # noqa: F401 -- re-exported for test access
)

# Sub-blueprints
from .evidence import evidence_bp
from .artifacts import artifact_bp
from .analysis import analysis_bp
from .chat import chat_bp
from .images import images_bp

__all__ = ["register_routes"]

LOGGER = logging.getLogger(__name__)

routes_bp = Blueprint("routes", __name__)
_REQUEST_CASE_LOG_TOKEN = "_aift_case_log_token"


# ---------------------------------------------------------------------------
# Request lifecycle hooks
# ---------------------------------------------------------------------------

@routes_bp.before_app_request
def _bind_case_log_context_for_request() -> None:
    """Bind case-specific logging context before each request."""
    case_id: str | None = None
    case_id = str((request.view_args or {}).get("case_id", "")).strip() or None
    setattr(g, _REQUEST_CASE_LOG_TOKEN, push_case_log_context(case_id))


@routes_bp.teardown_app_request
def _clear_case_log_context_for_request(_error: BaseException | None) -> None:
    """Pop case-scoped logging context after each request.

    Args:
        _error: Optional exception (ignored).
    """
    token = getattr(g, _REQUEST_CASE_LOG_TOKEN, None)
    if token is not None:
        pop_case_log_context(token)
        setattr(g, _REQUEST_CASE_LOG_TOKEN, None)


# ---------------------------------------------------------------------------
# Static / UI routes
# ---------------------------------------------------------------------------

@routes_bp.get("/")
def index() -> str:
    """Serve the main single-page application HTML.

    Returns:
        Rendered ``index.html`` template.
    """
    return render_template(
        "index.html",
        logo_filename=resolve_logo_filename(),
        tool_version=TOOL_VERSION,
    )


@routes_bp.get("/api/version/check")
def version_check() -> tuple[Response, int] | Response:
    """Check whether a newer AIFT release is available on GitHub.

    Fetches the latest release tag from the GitHub API and compares it
    with the running ``TOOL_VERSION``.  The comparison is purely
    string-based (not semver) so any difference is reported.

    Returns:
        JSON with ``current``, ``latest``, and ``update_available`` fields,
        or an error payload when the network is unreachable.
    """
    import json as _json

    github_url = (
        "https://api.github.com/repos/FlipForensics/AIFT/releases/latest"
    )
    req = Request(github_url, headers={"Accept": "application/vnd.github+json"})
    try:
        with urlopen(req, timeout=5) as resp:
            data = _json.loads(resp.read().decode())
        tag: str = data.get("tag_name", "")
        latest = tag.lstrip("vV")
        return success_response({
            "current": TOOL_VERSION,
            "latest": latest,
            "update_available": latest != TOOL_VERSION,
        })
    except (URLError, OSError, ValueError) as exc:
        LOGGER.debug("Version check failed: %s", exc)
        return error_response("offline", 503)


@routes_bp.get("/favicon.ico")
def favicon() -> Response | tuple[Response, int]:
    """Serve the application favicon.

    Returns:
        The logo image file, or a 404 error.
    """
    logo_filename = resolve_logo_filename()
    if not logo_filename:
        return error_response("Icon not found.", 404)
    return image_asset(logo_filename)


@routes_bp.get("/images/<path:filename>")
def image_asset(filename: str) -> Response | tuple[Response, int]:
    """Serve a static image asset from the images directory.

    Args:
        filename: Image filename (no directory components).

    Returns:
        The image file, or a JSON error.
    """
    if not IMAGES_ROOT.is_dir():
        return error_response("Image directory not found.", 404)

    normalized = str(filename).strip()
    if not normalized or Path(normalized).name != normalized:
        return error_response("Invalid image filename.", 400)
    if "/" in normalized or "\\" in normalized:
        return error_response("Invalid image filename.", 400)

    image_path = IMAGES_ROOT / normalized
    if not image_path.is_file():
        return error_response("Image not found.", 404)

    return send_file(image_path)


# ---------------------------------------------------------------------------
# Case management routes
# ---------------------------------------------------------------------------

@routes_bp.post("/api/cases")
def create_case() -> tuple[Response, int]:
    """Create a new forensic analysis case.

    Uses :class:`~app.case_manager.CaseManager` to create the multi-image
    directory layout (``images/``, ``reports/``, ``audit.jsonl``).  For
    backward compatibility, the response is unchanged: ``case_id`` and
    ``case_name``.

    Returns:
        ``(Response, 201)`` with case_id and case_name, or error.
    """
    cleanup_terminal_cases()

    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return error_response("Request body must be a JSON object.", 400)
    case_name = str(payload.get("case_name", "")).strip()
    has_custom_name = bool(case_name)
    if not case_name:
        case_name = datetime.now().strftime("Case %Y-%m-%d %H:%M:%S")

    # Use sanitised case name + timestamp as folder name for readability;
    # fall back to UUID if no custom name was provided.
    if has_custom_name:
        folder_name = safe_name(case_name, "case") + "_" + datetime.now().strftime("%Y%m%d_%H%M%S")
    else:
        folder_name = str(uuid4())
    case_id = folder_name
    case_dir = CASES_ROOT / case_id

    # Create multi-image directory layout via CaseManager helpers.
    case_dir.mkdir(parents=True, exist_ok=True)
    (case_dir / "images").mkdir(exist_ok=True)
    (case_dir / "reports").mkdir(exist_ok=True)

    # Keep legacy directories for backward compatibility with code that
    # still references case_dir/evidence and case_dir/parsed directly.
    (case_dir / "evidence").mkdir(exist_ok=True)
    (case_dir / "parsed").mkdir(exist_ok=True)

    try:
        log_file_path = register_case_log_handler(case_id=case_id, case_dir=case_dir)
    except OSError:
        LOGGER.exception("Failed to initialize case log file for case %s", case_id)
        return error_response("Failed to initialize case logging due to a filesystem error.", 500)

    with case_log_context(case_id):
        LOGGER.info("Initialized case logging at %s", log_file_path)

    audit = AuditLogger(case_dir)
    audit.log(
        "case_created",
        {
            "case_id": case_id,
            "name": case_name,
            "creation_time": now_iso(),
        },
    )

    case_state = {
        "case_id": case_id,
        "case_name": case_name,
        "case_dir": case_dir,
        "audit": audit,
        "evidence_mode": "",
        "source_path": "",
        "stored_path": "",
        "uploaded_files": [],
        "evidence_path": "",
        "evidence_hashes": {},
        "image_metadata": {},
        "available_artifacts": [],
        "selected_artifacts": [],
        "analysis_artifacts": [],
        "artifact_options": [],
        "analysis_date_range": None,
        "csv_output_dir": "",
        "parse_results": [],
        "artifact_csv_paths": {},
        "investigation_context": "",
        "analysis_results": {},
        "status": "active",
        "log_file_path": str(log_file_path),
        "images": [],
        "image_states": {},
    }
    with STATE_LOCK:
        CASE_STATES[case_id] = case_state
        PARSE_PROGRESS[case_id] = new_progress()
        ANALYSIS_PROGRESS[case_id] = new_progress()
        CHAT_PROGRESS[case_id] = new_progress()

    return success_response({"case_id": case_id, "case_name": case_name}, 201)


# ---------------------------------------------------------------------------
# Settings routes
# ---------------------------------------------------------------------------

@routes_bp.get("/api/settings")
def get_settings() -> Response:
    """Retrieve current settings with sensitive values masked.

    Returns:
        JSON with masked configuration.
    """
    config = current_app.config.get("AIFT_CONFIG", {})
    if not isinstance(config, dict):
        config = {}
    return success_response(mask_sensitive(config))


@routes_bp.post("/api/settings")
def update_settings() -> Response | tuple[Response, int]:
    """Update application settings by deep-merging the request payload.

    Returns:
        JSON with updated masked configuration, or 400 error.
    """
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return error_response("Settings payload must be a JSON object.", 400)

    config_path = Path(str(current_app.config.get("AIFT_CONFIG_PATH", "config.yaml")))
    current_config = load_config(config_path, use_env_overrides=False)
    changed_keys = deep_merge(current_config, payload)

    validation_errors = validate_config(current_config)
    if validation_errors:
        return error_response(
            f"Invalid settings: {'; '.join(validation_errors)}", 400
        )

    save_config(current_config, config_path)

    refreshed = load_config(config_path)
    current_app.config["AIFT_CONFIG"] = refreshed
    if changed_keys:
        LOGGER.info("Updated settings: %s", ", ".join(changed_keys))
        audit_config_change(changed_keys)

    return success_response(mask_sensitive(refreshed))


@routes_bp.post("/api/settings/test-connection")
def test_settings_connection() -> Response | tuple[Response, int]:
    """Test the configured AI provider connection.

    Returns:
        JSON with model info and response preview, or error.
    """
    config = current_app.config.get("AIFT_CONFIG", {})
    if not isinstance(config, dict):
        return error_response("Invalid in-memory configuration state.", 500)
    analysis_config = config.get("analysis", {})
    if not isinstance(analysis_config, dict):
        analysis_config = {}
    raw_connection_tokens = analysis_config.get("connection_test_max_tokens", 256)
    try:
        connection_max_tokens = max(1, int(raw_connection_tokens))
    except (TypeError, ValueError):
        connection_max_tokens = 256

    try:
        provider = create_provider(copy.deepcopy(config))
        model_info = provider.get_model_info()
        reply = provider.analyze(
            system_prompt=CONNECTION_TEST_SYSTEM_PROMPT,
            user_prompt=CONNECTION_TEST_USER_PROMPT,
            max_tokens=connection_max_tokens,
        )
        preview = str(reply).strip()
        if not preview:
            return error_response("Provider returned an empty response.", 502)
        return success_response(
            {
                "status": "ok",
                "model_info": model_info,
                "response_preview": preview[:240],
            }
        )
    except ValueError as error:
        LOGGER.warning("Settings connection test rejected due to configuration: %s", error)
        return error_response(str(error), 400)
    except AIProviderError as error:
        LOGGER.warning("Settings connection test failed: %s", error)
        return error_response(str(error), 502)
    except Exception:
        LOGGER.exception("Unexpected failure during settings connection test.")
        return error_response("Unexpected error while testing provider connection.", 500)


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

def register_routes(app: Flask) -> None:
    """Register all HTTP route handlers with the Flask application.

    Registers the core ``routes_bp`` blueprint plus sub-blueprints for
    evidence, artifact, analysis, chat, and multi-image routes.

    Args:
        app: The Flask application instance.
    """
    app.register_blueprint(routes_bp)
    app.register_blueprint(evidence_bp)
    app.register_blueprint(artifact_bp)
    app.register_blueprint(analysis_bp)
    app.register_blueprint(chat_bp)
    app.register_blueprint(images_bp)
