"""HTTP route definitions for the AIFT (AI Forensic Triage) Flask application.

This module implements all HTTP endpoints for the 5-step forensic analysis
wizard and supporting features (settings, profiles, chat, static assets).

Route handlers delegate to helpers and background tasks defined in:

* :mod:`routes_state` -- shared state, constants, SSE streaming.
* :mod:`routes_evidence` -- evidence intake, archive extraction, CSV/hash.
* :mod:`routes_artifacts` -- artifact options, profile management.
* :mod:`routes_tasks` -- background parse/analysis/chat runners.

Attributes:
    routes_bp: Flask ``Blueprint`` instance containing all route registrations.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import threading
from typing import Any
from zipfile import ZIP_DEFLATED, ZipFile
from uuid import uuid4

from flask import (
    Blueprint,
    Flask,
    Response,
    current_app,
    g,
    jsonify,
    render_template,
    request,
    send_file,
)

from ..ai_providers import AIProviderError, create_provider
from ..analyzer import ForensicAnalyzer  # noqa: F401 -- re-exported for test patching
from ..audit import AuditLogger
from ..case_logging import (
    case_log_context,
    pop_case_log_context,
    push_case_log_context,
    register_case_log_handler,
)
from ..chat import ChatManager
from ..config import load_config, save_config
from ..hasher import compute_hashes, verify_hash
from ..parser import ARTIFACT_REGISTRY, ForensicParser  # noqa: F401 -- ARTIFACT_REGISTRY re-exported for test access
from ..reporter import ReportGenerator
from ..version import TOOL_VERSION

# --- Imports from route submodules ---
from .state import (
    LOGGER as _STATE_LOGGER,
    PROJECT_ROOT,
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
    safe_name,
    resolve_logo_filename,
    new_progress,
    set_progress_status,
    emit_progress,
    stream_sse,
    get_case,
    mark_case_status,
    cleanup_case_entries,
    cleanup_terminal_cases,
    mask_sensitive,
    deep_merge,
    audit_config_change,
)
from .evidence import (
    resolve_evidence_payload,
    resolve_hash_verification_path,
    collect_case_csv_paths,
    read_audit_entries,
)
from .artifacts import (
    RECOMMENDED_PROFILE_EXCLUDED_ARTIFACTS,  # noqa: F401 -- re-exported for test access
    extract_parse_selection_payload,
    validate_analysis_date_range,
    sanitize_prompt,
    resolve_profiles_root,
    compose_profile_response,
    load_profiles_from_directory,
    normalize_profile_name,
    normalize_artifact_options,
    profile_path_for_new_name,
    write_profile_file,
)
from .tasks import (
    run_task_with_case_log_context,
    run_parse,
    run_analysis,
    run_chat,
    load_case_analysis_results,
    resolve_case_investigation_context,
)

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
    if request.blueprint == routes_bp.name:
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

    Returns:
        ``(Response, 201)`` with case_id and case_name, or error.
    """
    cleanup_terminal_cases()

    payload = request.get_json(silent=True) or {}
    case_name = str(payload.get("case_name", "")).strip()
    if not case_name:
        case_name = datetime.now().strftime("Case %Y-%m-%d %H:%M:%S")

    case_id = str(uuid4())
    case_dir = CASES_ROOT / case_id
    (case_dir / "evidence").mkdir(parents=True, exist_ok=True)
    (case_dir / "parsed").mkdir(parents=True, exist_ok=True)
    (case_dir / "reports").mkdir(parents=True, exist_ok=True)
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
    }
    with STATE_LOCK:
        CASE_STATES[case_id] = case_state
        PARSE_PROGRESS[case_id] = new_progress()
        ANALYSIS_PROGRESS[case_id] = new_progress()
        CHAT_PROGRESS[case_id] = new_progress()

    return success_response({"case_id": case_id, "case_name": case_name}, 201)


@routes_bp.post("/api/cases/<case_id>/evidence")
def intake_evidence(case_id: str) -> Response | tuple[Response, int]:
    """Ingest evidence for an existing case.

    Args:
        case_id: UUID of the case.

    Returns:
        JSON with evidence metadata, hashes, and available artifacts.
    """
    case = get_case(case_id)
    if case is None:
        return error_response(f"Case not found: {case_id}", 404)

    with STATE_LOCK:
        case_dir = case["case_dir"]
        audit_logger = case["audit"]

    try:
        evidence_payload = resolve_evidence_payload(case_dir)
        source_path = Path(evidence_payload["source_path"])
        dissect_path = Path(evidence_payload["dissect_path"])

        if source_path.is_file():
            hashes = dict(compute_hashes(source_path))
        else:
            hashes = {"sha256": "N/A (directory)", "md5": "N/A (directory)", "size_bytes": 0}
        hashes["filename"] = source_path.name

        with ForensicParser(
            evidence_path=dissect_path,
            case_dir=case_dir,
            audit_logger=audit_logger,
        ) as parser:
            metadata = parser.get_image_metadata()
            available_artifacts = parser.get_available_artifacts()

        audit_logger.log(
            "evidence_intake",
            {
                "filename": source_path.name,
                "source_mode": evidence_payload["mode"],
                "source_path": evidence_payload["source_path"],
                "stored_path": evidence_payload["stored_path"],
                "uploaded_files": list(evidence_payload.get("uploaded_files", [])),
                "dissect_path": str(dissect_path),
                "sha256": hashes["sha256"],
                "md5": hashes["md5"],
                "file_size_bytes": hashes["size_bytes"],
            },
        )
        audit_logger.log(
            "image_opened",
            {
                "hostname": metadata.get("hostname", "Unknown"),
                "os_version": metadata.get("os_version", "Unknown"),
                "domain": metadata.get("domain", "Unknown"),
                "available_artifacts": [
                    str(item.get("key"))
                    for item in available_artifacts
                    if item.get("available")
                ],
            },
        )

        with STATE_LOCK:
            case["evidence_mode"] = evidence_payload["mode"]
            case["source_path"] = evidence_payload["source_path"]
            case["stored_path"] = evidence_payload["stored_path"]
            case["uploaded_files"] = list(evidence_payload.get("uploaded_files", []))
            case["evidence_path"] = str(dissect_path)
            case["evidence_hashes"] = hashes
            case["image_metadata"] = metadata
            case["available_artifacts"] = available_artifacts

        return success_response(
            {
                "case_id": case_id,
                "source_mode": evidence_payload["mode"],
                "source_path": evidence_payload["source_path"],
                "evidence_path": str(dissect_path),
                "uploaded_files": list(evidence_payload.get("uploaded_files", [])),
                "hashes": hashes,
                "metadata": metadata,
                "available_artifacts": available_artifacts,
            }
        )
    except (ValueError, FileNotFoundError) as error:
        return error_response(str(error), 400)
    except Exception:
        LOGGER.exception("Evidence intake failed for case %s", case_id)
        return error_response(
            "Evidence intake failed due to an unexpected error. "
            "Confirm the evidence file is supported and try again.",
            500,
        )


# ---------------------------------------------------------------------------
# Parse routes
# ---------------------------------------------------------------------------

@routes_bp.post("/api/cases/<case_id>/parse")
def start_parse(case_id: str) -> tuple[Response, int]:
    """Start background parsing of selected forensic artifacts.

    Args:
        case_id: UUID of the case.

    Returns:
        ``(Response, 202)`` confirming start, or error.
    """
    case = get_case(case_id)
    if case is None:
        return error_response(f"Case not found: {case_id}", 404)
    with STATE_LOCK:
        has_evidence = bool(str(case.get("evidence_path", "")).strip())
    if not has_evidence:
        return error_response("No evidence loaded for this case.", 400)

    payload = request.get_json(silent=True) or {}
    try:
        artifact_options, parse_artifacts, analysis_artifacts = extract_parse_selection_payload(payload)
    except ValueError as error:
        return error_response(str(error), 400)

    if not parse_artifacts:
        return error_response("Provide at least one artifact key to parse.", 400)
    try:
        analysis_date_range = validate_analysis_date_range(payload.get("analysis_date_range"))
    except ValueError as error:
        return error_response(str(error), 400)

    with STATE_LOCK:
        parse_state = PARSE_PROGRESS.setdefault(case_id, new_progress())
        if parse_state.get("status") == "running":
            return error_response("Parsing is already running for this case.", 409)
        PARSE_PROGRESS[case_id] = new_progress(status="running")
        case["status"] = "running"
        case["selected_artifacts"] = list(parse_artifacts)
        case["analysis_artifacts"] = list(analysis_artifacts)
        case["artifact_options"] = list(artifact_options)
        case["analysis_date_range"] = analysis_date_range

    parse_started_event: dict[str, Any] = {
        "type": "parse_started",
        "artifacts": parse_artifacts,
        "analysis_artifacts": analysis_artifacts,
        "artifact_options": artifact_options,
        "total_artifacts": len(parse_artifacts),
    }
    if analysis_date_range is not None:
        parse_started_event["analysis_date_range"] = analysis_date_range
    emit_progress(PARSE_PROGRESS, case_id, parse_started_event)
    config_snapshot = copy.deepcopy(current_app.config.get("AIFT_CONFIG", {}))
    threading.Thread(
        target=run_task_with_case_log_context,
        args=(case_id, run_parse, case_id, parse_artifacts, analysis_artifacts, artifact_options, config_snapshot),
        daemon=True,
    ).start()

    response_payload: dict[str, Any] = {
        "status": "started",
        "case_id": case_id,
        "artifacts": parse_artifacts,
        "ai_artifacts": analysis_artifacts,
        "artifact_options": artifact_options,
    }
    if analysis_date_range is not None:
        response_payload["analysis_date_range"] = analysis_date_range
    response_payload["success"] = True
    return jsonify(response_payload), 202


@routes_bp.get("/api/cases/<case_id>/parse/progress")
def stream_parse_progress(case_id: str) -> Response | tuple[Response, int]:
    """Stream parsing progress events via SSE.

    Args:
        case_id: UUID of the case.

    Returns:
        SSE Response, or 404 error.
    """
    if get_case(case_id) is None:
        return error_response(f"Case not found: {case_id}", 404)
    return stream_sse(PARSE_PROGRESS, case_id)


# ---------------------------------------------------------------------------
# Analysis routes
# ---------------------------------------------------------------------------

@routes_bp.post("/api/cases/<case_id>/analyze")
def start_analysis(case_id: str) -> tuple[Response, int]:
    """Start background AI-powered analysis.

    Args:
        case_id: UUID of the case.

    Returns:
        ``(Response, 202)`` confirming start, or error.
    """
    case = get_case(case_id)
    if case is None:
        return error_response(f"Case not found: {case_id}", 404)

    with STATE_LOCK:
        has_results = bool(case.get("parse_results") or case.get("artifact_csv_paths"))
        analysis_artifacts_state = case.get("analysis_artifacts")
        case_dir = case["case_dir"]
        analysis_date_range = case.get("analysis_date_range")
        audit_logger = case["audit"]

    if not has_results:
        return error_response("No parsed artifacts found. Run parsing first.", 400)
    if isinstance(analysis_artifacts_state, list):
        configured_analysis_artifacts = [
            artifact
            for artifact in (str(item).strip() for item in analysis_artifacts_state)
            if artifact
        ]
        if not configured_analysis_artifacts:
            return error_response(
                "No artifacts are marked `Parse and use in AI`. Select at least one AI-enabled artifact and parse again.",
                400,
            )

    payload = request.get_json(silent=True) or {}
    prompt = str(payload.get("prompt", "")).strip()

    prompt_path = Path(case_dir) / "prompt.txt"
    prompt_details: dict[str, Any] = {"prompt": sanitize_prompt(prompt)}
    if isinstance(analysis_date_range, dict):
        start_date = str(analysis_date_range.get("start_date", "")).strip()
        end_date = str(analysis_date_range.get("end_date", "")).strip()
        if start_date and end_date:
            prompt_details["analysis_date_range"] = {
                "start_date": start_date,
                "end_date": end_date,
            }
    with STATE_LOCK:
        analysis_state = ANALYSIS_PROGRESS.setdefault(case_id, new_progress())
        if analysis_state.get("status") == "running":
            return error_response("Analysis is already running for this case.", 409)
        prompt_path.write_text(prompt, encoding="utf-8")
        ANALYSIS_PROGRESS[case_id] = new_progress(status="running")
        case["status"] = "running"
        case["investigation_context"] = prompt
        analysis_artifacts_snapshot = list(case.get("analysis_artifacts", []))

    audit_logger.log("prompt_submitted", prompt_details)

    emit_progress(
        ANALYSIS_PROGRESS, case_id,
        {
            "type": "analysis_started",
            "prompt_provided": bool(prompt),
            "analysis_artifact_count": len(analysis_artifacts_snapshot),
        },
    )
    config_snapshot = copy.deepcopy(current_app.config.get("AIFT_CONFIG", {}))
    threading.Thread(
        target=run_task_with_case_log_context,
        args=(case_id, run_analysis, case_id, prompt, config_snapshot),
        daemon=True,
    ).start()

    return success_response(
        {
            "status": "started",
            "case_id": case_id,
            "analysis_artifacts": analysis_artifacts_snapshot,
        },
        202,
    )


@routes_bp.get("/api/cases/<case_id>/analyze/progress")
def stream_analysis_progress(case_id: str) -> Response | tuple[Response, int]:
    """Stream analysis progress events via SSE.

    Args:
        case_id: UUID of the case.

    Returns:
        SSE Response, or 404 error.
    """
    if get_case(case_id) is None:
        return error_response(f"Case not found: {case_id}", 404)
    return stream_sse(ANALYSIS_PROGRESS, case_id)


# ---------------------------------------------------------------------------
# Chat routes
# ---------------------------------------------------------------------------

@routes_bp.post("/api/cases/<case_id>/chat")
def chat_with_case(case_id: str) -> Response | tuple[Response, int]:
    """Initiate a chat interaction about completed analysis results.

    Args:
        case_id: UUID of the case.

    Returns:
        ``(Response, 202)`` confirming start, or error.
    """
    case = get_case(case_id)
    if case is None:
        return error_response(f"Case not found: {case_id}", 404)

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return error_response("Chat payload must be a JSON object.", 400)

    message = str(payload.get("message", "")).strip()
    if not message:
        return error_response("`message` is required.", 400)

    with STATE_LOCK:
        case_snapshot_for_check = dict(case)
    if not load_case_analysis_results(case_snapshot_for_check):
        return error_response("No analysis results available for this case. Run analysis first.", 400)

    config = current_app.config.get("AIFT_CONFIG", {})
    if not isinstance(config, dict):
        return error_response("Invalid in-memory configuration state.", 500)

    with STATE_LOCK:
        chat_state = CHAT_PROGRESS.setdefault(case_id, new_progress())
        if chat_state.get("status") == "running":
            return error_response("Chat is already running for this case.", 409)
        CHAT_PROGRESS[case_id] = new_progress(status="running")

    config_snapshot = copy.deepcopy(config)
    threading.Thread(
        target=run_task_with_case_log_context,
        args=(case_id, run_chat, case_id, message, config_snapshot),
        daemon=True,
    ).start()
    return success_response({"status": "processing"}, 202)


@routes_bp.get("/api/cases/<case_id>/chat/stream")
def stream_chat_progress(case_id: str) -> Response | tuple[Response, int]:
    """Stream chat response tokens via SSE.

    Args:
        case_id: UUID of the case.

    Returns:
        SSE Response, or 404 error.
    """
    if get_case(case_id) is None:
        return error_response(f"Case not found: {case_id}", 404)
    return stream_sse(CHAT_PROGRESS, case_id)


@routes_bp.get("/api/cases/<case_id>/chat/history")
def get_case_chat_history(case_id: str) -> Response | tuple[Response, int]:
    """Retrieve the full chat message history for a case.

    Args:
        case_id: UUID of the case.

    Returns:
        JSON response with chat messages, or 404 error.
    """
    case = get_case(case_id)
    if case is None:
        return error_response(f"Case not found: {case_id}", 404)
    with STATE_LOCK:
        case_dir = case["case_dir"]
    manager = ChatManager(case_dir)
    return success_response({"messages": manager.get_history()})


@routes_bp.delete("/api/cases/<case_id>/chat/history")
def clear_case_chat_history(case_id: str) -> Response | tuple[Response, int]:
    """Clear the chat history for a case.

    Args:
        case_id: UUID of the case.

    Returns:
        JSON confirmation, or 404 error.
    """
    case = get_case(case_id)
    if case is None:
        return error_response(f"Case not found: {case_id}", 404)
    with STATE_LOCK:
        case_dir = case["case_dir"]
        audit_logger = case["audit"]
    manager = ChatManager(case_dir)
    manager.clear()
    audit_logger.log("chat_history_cleared", {"case_id": case_id})
    return success_response({"status": "cleared", "case_id": case_id})


# ---------------------------------------------------------------------------
# Report / CSV download routes
# ---------------------------------------------------------------------------

@routes_bp.get("/api/cases/<case_id>/report")
def download_report(case_id: str) -> Response | tuple[Response, int]:
    """Generate and download the HTML forensic analysis report.

    Args:
        case_id: UUID of the case.

    Returns:
        The HTML report as an attachment, or error.
    """
    case = get_case(case_id)
    if case is None:
        return error_response(f"Case not found: {case_id}", 404)

    with STATE_LOCK:
        case_snapshot = dict(case)
        audit_logger = case["audit"]

    hashes = dict(case_snapshot.get("evidence_hashes", {}))
    intake_sha256 = str(hashes.get("sha256", "")).strip()
    verification_path = resolve_hash_verification_path(case_snapshot)

    if intake_sha256.startswith("N/A"):
        hash_ok = True
        computed_sha256 = intake_sha256
    elif verification_path is None or not intake_sha256:
        return error_response("Evidence hash context is missing for this case.", 400)
    elif not verification_path.exists():
        return error_response("Evidence file is no longer available for hash verification.", 404)
    else:
        hash_ok, computed_sha256 = verify_hash(
            verification_path, intake_sha256, return_computed=True,
        )
    audit_logger.log(
        "hash_verification",
        {
            "expected_sha256": intake_sha256,
            "computed_sha256": computed_sha256,
            "match": hash_ok,
            "verification_path": str(verification_path),
        },
    )

    hashes["case_id"] = case_id
    hashes["expected_sha256"] = intake_sha256
    hashes["hash_verified"] = hash_ok

    analysis_results = dict(case_snapshot.get("analysis_results", {}))
    analysis_results.setdefault("case_id", case_id)
    analysis_results.setdefault("case_name", str(case_snapshot.get("case_name", "")))
    analysis_results.setdefault("per_artifact", [])
    analysis_results.setdefault("summary", "")

    case_dir = case_snapshot["case_dir"]
    investigation_context = str(case_snapshot.get("investigation_context", ""))
    if not investigation_context:
        prompt_path = Path(case_dir) / "prompt.txt"
        if prompt_path.exists():
            investigation_context = prompt_path.read_text(encoding="utf-8")

    report_generator = ReportGenerator(cases_root=CASES_ROOT)
    report_path = report_generator.generate(
        analysis_results=analysis_results,
        image_metadata=dict(case_snapshot.get("image_metadata", {})),
        evidence_hashes=hashes,
        investigation_context=investigation_context,
        audit_log_entries=read_audit_entries(Path(case_dir)),
    )
    audit_logger.log(
        "report_generated",
        {"report_filename": report_path.name, "hash_verified": hash_ok},
    )
    mark_case_status(case_id, "completed")
    cleanup_case_entries(case_id)

    return send_file(
        report_path,
        as_attachment=True,
        download_name=report_path.name,
        mimetype="text/html",
    )


@routes_bp.get("/api/cases/<case_id>/csvs")
def download_csv_bundle(case_id: str) -> Response | tuple[Response, int]:
    """Download all parsed CSV files as a ZIP archive.

    Args:
        case_id: UUID of the case.

    Returns:
        ZIP archive as attachment, or 404 error.
    """
    case = get_case(case_id)
    if case is None:
        return error_response(f"Case not found: {case_id}", 404)

    with STATE_LOCK:
        case_snapshot = dict(case)

    csv_paths = collect_case_csv_paths(case_snapshot)
    if not csv_paths:
        return error_response("No parsed CSV files available for this case.", 404)

    reports_dir = Path(case_snapshot["case_dir"]) / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    zip_path = reports_dir / f"parsed_csvs_{timestamp}.zip"
    used_names: set[str] = set()
    with ZipFile(zip_path, "w", compression=ZIP_DEFLATED) as archive:
        for csv_path in csv_paths:
            base_name = csv_path.name
            arcname = base_name
            counter = 1
            while arcname in used_names:
                stem = Path(base_name).stem
                suffix = Path(base_name).suffix
                arcname = f"{stem}_{counter}{suffix}"
                counter += 1
            used_names.add(arcname)
            archive.write(csv_path, arcname=arcname)

    return send_file(
        zip_path,
        as_attachment=True,
        download_name=f"{case_id}_parsed_csvs.zip",
        mimetype="application/zip",
    )


# ---------------------------------------------------------------------------
# Profile routes
# ---------------------------------------------------------------------------

@routes_bp.get("/api/artifact-profiles")
def list_artifact_profiles() -> Response:
    """List all available artifact profiles.

    Returns:
        JSON response with the ``profiles`` list.
    """
    config_path = Path(str(current_app.config.get("AIFT_CONFIG_PATH", "config.yaml")))
    profiles_root = resolve_profiles_root(config_path)
    return success_response({"profiles": compose_profile_response(profiles_root)})


@routes_bp.post("/api/artifact-profiles")
def save_artifact_profile() -> Response | tuple[Response, int]:
    """Create or update a user-defined artifact profile.

    Returns:
        JSON with saved profile and updated profiles list, or error.
    """
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return error_response("Profile payload must be a JSON object.", 400)

    try:
        profile_name = normalize_profile_name(payload.get("name"))
    except ValueError as error:
        return error_response(str(error), 400)

    try:
        artifact_options = normalize_artifact_options(payload.get("artifact_options"))
    except ValueError as error:
        return error_response(str(error), 400)
    if not artifact_options:
        return error_response("Profile must include at least one artifact option.", 400)

    config_path = Path(str(current_app.config.get("AIFT_CONFIG_PATH", "config.yaml")))
    profiles_root = resolve_profiles_root(config_path)

    try:
        profiles = load_profiles_from_directory(profiles_root)
        profile_key = profile_name.lower()
        existing = next(
            (
                profile
                for profile in profiles
                if str(profile.get("name", "")).strip().lower() == profile_key
            ),
            None,
        )
        if existing is not None and bool(existing.get("builtin", False)):
            return error_response("`recommended` is a built-in profile and cannot be overwritten.", 400)

        if existing is not None:
            target_path = Path(existing.get("path"))
        else:
            target_path = profile_path_for_new_name(profiles_root, profile_name)

        response_profile = {
            "name": profile_name,
            "builtin": False,
            "artifact_options": artifact_options,
        }
        write_profile_file(target_path, response_profile)
    except OSError:
        LOGGER.exception("Failed to save artifact profile '%s'", profile_name)
        return error_response(
            "Failed to save the profile due to a filesystem error. "
            "Check directory permissions and retry.",
            500,
        )

    return success_response(
        {
            "status": "saved",
            "profile": response_profile,
            "profiles": compose_profile_response(profiles_root),
        }
    )


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

    Args:
        app: The Flask application instance.
    """
    app.register_blueprint(routes_bp)
