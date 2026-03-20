"""AI analysis route handlers for the AIFT Flask application.

Handles starting and streaming progress of AI-powered forensic analysis.

Attributes:
    analysis_bp: Flask Blueprint for analysis routes.
    LOGGER: Module-level logger.
"""

from __future__ import annotations

import copy
import logging
import threading
from pathlib import Path
from typing import Any

from flask import Blueprint, Response, current_app, request

from .state import (
    STATE_LOCK,
    ANALYSIS_PROGRESS,
    error_response,
    success_response,
    get_case,
    new_progress,
    emit_progress,
    stream_sse,
)
from .artifacts import sanitize_prompt
from .tasks import run_task_with_case_log_context, run_analysis

__all__ = ["analysis_bp"]

LOGGER = logging.getLogger(__name__)

analysis_bp = Blueprint("analysis", __name__)


@analysis_bp.post("/api/cases/<case_id>/analyze")
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
    if not isinstance(payload, dict):
        return error_response("Request body must be a JSON object.", 400)
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


@analysis_bp.get("/api/cases/<case_id>/analyze/progress")
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
