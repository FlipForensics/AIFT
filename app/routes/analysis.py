"""AI analysis route handlers for the AIFT Flask application.

Handles starting and streaming progress of AI-powered forensic analysis.

Attributes:
    analysis_bp: Flask Blueprint for analysis routes.
"""

from __future__ import annotations

import copy
import threading
from pathlib import Path
from typing import Any

from flask import Blueprint, Response, current_app, request

from .state import (
    STATE_LOCK,
    ANALYSIS_PROGRESS,
    cancel_progress,
    error_response,
    success_response,
    get_case,
    new_progress,
    emit_progress,
    stream_sse,
)
from .artifacts import sanitize_prompt
from .tasks import run_task_with_case_log_context, run_analysis, run_multi_image_analysis_task

__all__ = ["analysis_bp"]

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

    # Read case state, validate, and transition to "running" in a single lock
    # acquisition to prevent a TOCTOU window where the status could go stale
    # between the read and the mutation.
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

    # Multi-image: payload may contain an ``images`` list with per-image
    # artifact selections.  When present, the multi-image analysis flow
    # is used instead of the legacy single-image path.
    images_payload: list[dict[str, Any]] | None = None
    raw_images = payload.get("images")
    if isinstance(raw_images, list) and raw_images:
        images_payload = [
            {
                "image_id": str(img.get("image_id", "")),
                "artifacts": [str(a) for a in img.get("artifacts", []) if a],
            }
            for img in raw_images
            if isinstance(img, dict) and img.get("image_id")
        ]
        if not images_payload:
            images_payload = None

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
    if images_payload:
        prompt_details["multi_image"] = True
        prompt_details["image_count"] = len(images_payload)

    with STATE_LOCK:
        analysis_state = ANALYSIS_PROGRESS.setdefault(case_id, new_progress())
        if analysis_state.get("status") == "running":
            return error_response("Analysis is already running for this case.", 409)
        ANALYSIS_PROGRESS[case_id] = new_progress(status="running")
        case["status"] = "running"
        case["investigation_context"] = prompt
        # Invalidate prior analysis outputs so a subsequent failure cannot
        # leave stale results accessible via chat/report/download routes.
        case["analysis_results"] = {}
        analysis_artifacts_snapshot = list(case.get("analysis_artifacts", []))

    # Write the prompt file outside the lock — it doesn't depend on shared
    # state and avoids blocking other threads during file I/O.
    prompt_path.write_text(prompt, encoding="utf-8")

    # Remove the on-disk results file outside the lock to avoid holding
    # the lock during I/O.
    stale_results_path = Path(case_dir) / "analysis_results.json"
    if stale_results_path.exists():
        stale_results_path.unlink(missing_ok=True)

    audit_logger.log("prompt_submitted", prompt_details)

    # Determine total artifact count for the SSE started event.
    if images_payload:
        total_artifact_count = sum(len(img.get("artifacts", [])) for img in images_payload)
    else:
        total_artifact_count = len(analysis_artifacts_snapshot)

    emit_progress(
        ANALYSIS_PROGRESS, case_id,
        {
            "type": "analysis_started",
            "prompt_provided": bool(prompt),
            "analysis_artifact_count": total_artifact_count,
            "multi_image": images_payload is not None,
        },
    )
    config_snapshot = copy.deepcopy(current_app.config.get("AIFT_CONFIG", {}))

    if images_payload:
        threading.Thread(
            target=run_task_with_case_log_context,
            args=(case_id, run_multi_image_analysis_task, case_id, prompt,
                  images_payload, config_snapshot),
            daemon=True,
        ).start()
    else:
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
            "multi_image": images_payload is not None,
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


@analysis_bp.post("/api/cases/<case_id>/analyze/cancel")
def cancel_analysis_route(case_id: str) -> tuple[Response, int]:
    """Cancel a running analysis operation for a case.

    Args:
        case_id: UUID of the case.

    Returns:
        ``(Response, 200)`` confirming cancellation, or error.
    """
    if get_case(case_id) is None:
        return error_response(f"Case not found: {case_id}", 404)
    cancelled = cancel_progress(ANALYSIS_PROGRESS, case_id)
    if not cancelled:
        return error_response("No running analysis to cancel.", 409)
    return success_response({"status": "cancelling", "case_id": case_id})
