"""REST API endpoints for headless automation of AIFT forensic triage runs.

Exposes a Flask Blueprint that allows external tools to trigger, monitor,
cancel, and retrieve results of automated analysis runs via JSON HTTP.

Run state is held in a module-level dictionary protected by a reentrant
lock.  Only one automation run may execute at a time; additional requests
receive a 409 Conflict response.  Completed/failed runs are evicted from
memory after :data:`RUN_TTL_SECONDS` (1 hour).

Attributes:
    AUTOMATION_RUNS: In-memory dict mapping run IDs to state dicts.
    RUNS_LOCK: Reentrant lock protecting :data:`AUTOMATION_RUNS`.
    RUN_TTL_SECONDS: Seconds to keep finished runs in memory before eviction.
    automation_bp: Flask Blueprint registered under ``/api/automation``.
"""

from __future__ import annotations

import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from flask import Blueprint, Response, jsonify, request, send_file

from app.automation.engine import AutomationRequest, AutomationResult, run_automation
from app.routes.artifacts import validate_analysis_date_range
from app.routes.state import CASES_ROOT, error_response, success_response

__all__ = ["automation_bp"]

LOGGER = logging.getLogger(__name__)

automation_bp = Blueprint("automation", __name__)

AUTOMATION_RUNS: dict[str, dict[str, Any]] = {}
RUNS_LOCK = threading.RLock()
RUN_TTL_SECONDS = 3600  # 1 hour


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    """Return the current UTC time as an ISO 8601 string with ``Z`` suffix.

    Returns:
        A string like ``"2026-04-15T10:30:00Z"``.
    """
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z")
    )


def _cleanup_expired_runs() -> None:
    """Evict finished runs whose age exceeds :data:`RUN_TTL_SECONDS`.

    Must be called while *not* holding :data:`RUNS_LOCK` — the function
    acquires it internally.
    """
    now = time.monotonic()
    with RUNS_LOCK:
        expired = [
            rid
            for rid, run in AUTOMATION_RUNS.items()
            if run.get("status") in ("completed", "failed", "cancelled")
            and (now - run.get("_finished_mono", now)) > RUN_TTL_SECONDS
        ]
        for rid in expired:
            AUTOMATION_RUNS.pop(rid, None)


def _has_running_run() -> bool:
    """Check whether an automation run is currently in progress.

    Thread-safe: acquires :data:`RUNS_LOCK`.

    Returns:
        ``True`` if any run has status ``"running"`` or ``"started"``.
    """
    with RUNS_LOCK:
        return any(
            run.get("status") in ("running", "started")
            for run in AUTOMATION_RUNS.values()
        )


def _get_run(run_id: str) -> dict[str, Any] | None:
    """Retrieve a run state dict by ID.

    Thread-safe: acquires :data:`RUNS_LOCK`.

    Args:
        run_id: UUID of the run.

    Returns:
        The run state dict, or ``None``.
    """
    with RUNS_LOCK:
        return AUTOMATION_RUNS.get(run_id)


def _elapsed(run: dict[str, Any]) -> float:
    """Compute elapsed seconds since the run started.

    Args:
        run: Run state dict (must contain ``_started_mono``).

    Returns:
        Elapsed seconds, rounded to one decimal place.
    """
    start = run.get("_started_mono", time.monotonic())
    return round(time.monotonic() - start, 1)


def _build_status_response(run: dict[str, Any]) -> dict[str, Any]:
    """Build the JSON-serialisable status payload for a run.

    Args:
        run: Run state dict.

    Returns:
        Dict ready for ``jsonify()``.
    """
    status = run["status"]
    payload: dict[str, Any] = {
        "success": True,
        "run_id": run["run_id"],
        "case_id": run.get("case_id", ""),
        "status": status,
        "phase": run.get("phase", ""),
        "message": run.get("message", ""),
        "percentage": run.get("percentage", 0.0),
        "started_at": run.get("started_at", ""),
        "elapsed_seconds": (
            run.get("elapsed_seconds", 0.0)
            if status in ("completed", "failed", "cancelled")
            else _elapsed(run)
        ),
    }
    if status == "completed":
        payload["completed_at"] = run.get("completed_at", "")
        payload["result"] = run.get("result")
    if status == "failed":
        payload["errors"] = run.get("errors", [])
    return payload


# ---------------------------------------------------------------------------
# Background thread target
# ---------------------------------------------------------------------------

def _run_automation_thread(
    run_id: str,
    automation_request: AutomationRequest,
    cancel_event: threading.Event,
) -> None:
    """Execute :func:`run_automation` and update the run state dict.

    Intended to be the target of a daemon ``threading.Thread``.

    Args:
        run_id: UUID identifying this run.
        automation_request: Populated request dataclass.
        cancel_event: Event signalled when the user cancels the run.
    """

    def _progress(phase: str, message: str, percentage: float) -> None:
        """Update run state from the engine's progress callback.

        Args:
            phase: Pipeline phase name.
            message: Human-readable progress message.
            percentage: Completion within the phase, 0.0--100.0.
        """
        with RUNS_LOCK:
            run = AUTOMATION_RUNS.get(run_id)
            if run is None or run["status"] in ("cancelled",):
                return
            run["status"] = "running"
            run["phase"] = phase
            run["message"] = message
            run["percentage"] = round(percentage, 1)

    try:
        result: AutomationResult = run_automation(
            automation_request, progress_callback=_progress,
        )
    except Exception as exc:
        LOGGER.exception("Automation run %s raised an unexpected exception", run_id)
        with RUNS_LOCK:
            run = AUTOMATION_RUNS.get(run_id)
            if run is not None and run["status"] != "cancelled":
                run["status"] = "failed"
                run["phase"] = "error"
                run["message"] = f"Unexpected error: {exc}"
                run["errors"] = [str(exc)]
                run["elapsed_seconds"] = _elapsed(run)
                run["_finished_mono"] = time.monotonic()
        return

    with RUNS_LOCK:
        run = AUTOMATION_RUNS.get(run_id)
        if run is None:
            return
        if run["status"] == "cancelled":
            return  # User cancelled; don't overwrite status.

        run["case_id"] = result.case_id
        run["elapsed_seconds"] = _elapsed(run)
        run["_finished_mono"] = time.monotonic()

        if result.success:
            run["status"] = "completed"
            run["phase"] = "done"
            run["message"] = "Automation run completed successfully"
            run["percentage"] = 100.0
            run["completed_at"] = _now_iso()
            run["result"] = {
                "html_report_path": str(result.html_report_path) if result.html_report_path else None,
                "json_report_path": str(result.json_report_path) if result.json_report_path else None,
                "evidence_files_processed": len(result.evidence_files),
                "warnings": list(result.warnings),
            }
        else:
            run["status"] = "failed"
            run["phase"] = run.get("phase", "unknown")
            run["message"] = result.errors[0] if result.errors else "Unknown error"
            run["errors"] = list(result.errors)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _validate_run_request(payload: dict[str, Any]) -> tuple[dict[str, Any] | None, str]:
    """Validate the POST body for starting an automation run.

    Args:
        payload: Parsed JSON request body.

    Returns:
        Tuple of ``(validated_params, error_message)``.  On success the
        error message is empty; on failure validated_params is ``None``.
    """
    evidence_path = str(payload.get("evidence_path", "")).strip()
    if not evidence_path:
        return None, "Field 'evidence_path' is required and must not be empty."

    prompt = str(payload.get("prompt", "")).strip()
    if not prompt:
        return None, "Field 'prompt' is required and must not be empty."

    # Date range validation (strict — return 400 on bad format).
    date_range_raw = payload.get("date_range")
    date_range_tuple: tuple[str, str] | None = None
    if date_range_raw is not None:
        try:
            validated = validate_analysis_date_range(date_range_raw)
            if validated is not None:
                date_range_tuple = (validated["start_date"], validated["end_date"])
        except ValueError as exc:
            return None, f"Invalid date_range: {exc}"

    params: dict[str, Any] = {
        "evidence_path": evidence_path,
        "prompt": prompt,
        "output_dir": str(payload.get("output_dir", "")).strip() or None,
        "profile_name": str(payload.get("profile_name", "")).strip() or None,
        "config_path": str(payload.get("config_path", "")).strip() or None,
        "case_name": str(payload.get("case_name", "")).strip() or None,
        "skip_hashing": bool(payload.get("skip_hashing", False)),
        "date_range": date_range_tuple,
    }
    return params, ""


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@automation_bp.post("/api/automation/run")
def start_run() -> tuple[Response, int]:
    """Start a new automated forensic triage run.

    Validates the JSON request body, ensures no other run is active,
    spawns a background daemon thread, and returns 202 Accepted with the
    new run ID and a status URL.

    Returns:
        ``(Response, 202)`` on success, or an error tuple (400/409).
    """
    _cleanup_expired_runs()

    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return error_response("Request body must be a JSON object.", 400)

    params, error_msg = _validate_run_request(payload)
    if params is None:
        return error_response(error_msg, 400)

    if _has_running_run():
        return error_response(
            "An automation run is already in progress. "
            "Only one concurrent run is allowed.",
            409,
        )

    run_id = str(uuid4())
    case_id = ""  # Populated by the background thread once the case is created.
    cancel_event = threading.Event()

    # Resolve output_dir — default to case reports dir once case_id is known.
    # If not provided, use a temporary placeholder; the engine creates the
    # case and sets up directories internally.  We pass the CASES_ROOT so
    # the engine can resolve it.
    output_dir = params["output_dir"]
    if not output_dir:
        output_dir = str(CASES_ROOT / run_id / "reports")

    automation_request = AutomationRequest(
        evidence_path=params["evidence_path"],
        prompt=params["prompt"],
        output_dir=output_dir,
        profile_name=params["profile_name"],
        config_path=params["config_path"],
        case_name=params["case_name"],
        skip_hashing=params["skip_hashing"],
        date_range=params["date_range"],
    )

    run_state: dict[str, Any] = {
        "run_id": run_id,
        "case_id": case_id,
        "status": "started",
        "phase": "initializing",
        "message": "Automation run started",
        "percentage": 0.0,
        "started_at": _now_iso(),
        "completed_at": None,
        "elapsed_seconds": 0.0,
        "evidence_path": params["evidence_path"],
        "result": None,
        "errors": [],
        "cancel_event": cancel_event,
        "_started_mono": time.monotonic(),
    }

    with RUNS_LOCK:
        AUTOMATION_RUNS[run_id] = run_state

    thread = threading.Thread(
        target=_run_automation_thread,
        args=(run_id, automation_request, cancel_event),
        daemon=True,
    )
    thread.start()

    return success_response(
        {
            "run_id": run_id,
            "case_id": case_id,
            "status": "started",
            "status_url": f"/api/automation/run/{run_id}/status",
            "message": "Automation run started",
        },
        202,
    )


@automation_bp.get("/api/automation/run/<run_id>/status")
def get_run_status(run_id: str) -> tuple[Response, int]:
    """Return the current status of an automation run.

    Args:
        run_id: UUID of the run.

    Returns:
        JSON status payload, or 404 if not found.
    """
    run = _get_run(run_id)
    if run is None:
        return error_response(f"Run not found: {run_id}", 404)
    return jsonify(_build_status_response(run)), 200


@automation_bp.get("/api/automation/runs")
def list_runs() -> tuple[Response, int]:
    """List all automation runs (active and recently completed/failed).

    Returns:
        JSON with a ``runs`` list containing summary dicts.
    """
    _cleanup_expired_runs()
    with RUNS_LOCK:
        runs_list = [
            {
                "run_id": run["run_id"],
                "case_id": run.get("case_id", ""),
                "status": run["status"],
                "started_at": run.get("started_at", ""),
                "evidence_path": run.get("evidence_path", ""),
            }
            for run in AUTOMATION_RUNS.values()
        ]
    return success_response({"runs": runs_list})


@automation_bp.post("/api/automation/run/<run_id>/cancel")
def cancel_run(run_id: str) -> tuple[Response, int]:
    """Cancel a running automation run.

    Sets the cancel event and marks the run as cancelled.  The background
    thread will stop updating the run state once it observes the flag.

    Args:
        run_id: UUID of the run.

    Returns:
        JSON success message, 404 if not found, or 409 if not running.
    """
    with RUNS_LOCK:
        run = AUTOMATION_RUNS.get(run_id)
        if run is None:
            return error_response(f"Run not found: {run_id}", 404)
        if run["status"] not in ("started", "running"):
            return error_response(
                f"Run is not active (status: {run['status']}). Cannot cancel.",
                409,
            )
        run["status"] = "cancelled"
        run["message"] = "Run cancelled by user"
        run["elapsed_seconds"] = _elapsed(run)
        run["_finished_mono"] = time.monotonic()
        cancel_event = run.get("cancel_event")
        if isinstance(cancel_event, threading.Event):
            cancel_event.set()

    return success_response({"message": "Run cancelled"})


@automation_bp.get("/api/automation/run/<run_id>/report/html")
def download_html_report(run_id: str) -> Response | tuple[Response, int]:
    """Download the HTML report for a completed automation run.

    Args:
        run_id: UUID of the run.

    Returns:
        The HTML file as an attachment, or an error response.
    """
    run = _get_run(run_id)
    if run is None:
        return error_response(f"Run not found: {run_id}", 404)
    if run.get("status") != "completed":
        return error_response("Report not available — run has not completed.", 404)

    result = run.get("result") or {}
    html_path_str = result.get("html_report_path")
    if not html_path_str:
        return error_response("HTML report was not generated for this run.", 404)

    html_path = Path(html_path_str)
    if not html_path.is_file():
        return error_response("HTML report file not found on disk.", 404)

    return send_file(html_path, as_attachment=True, download_name=html_path.name)


@automation_bp.get("/api/automation/run/<run_id>/report/json")
def download_json_report(run_id: str) -> Response | tuple[Response, int]:
    """Download the JSON report for a completed automation run.

    Args:
        run_id: UUID of the run.

    Returns:
        The JSON file as an attachment, or an error response.
    """
    run = _get_run(run_id)
    if run is None:
        return error_response(f"Run not found: {run_id}", 404)
    if run.get("status") != "completed":
        return error_response("Report not available — run has not completed.", 404)

    result = run.get("result") or {}
    json_path_str = result.get("json_report_path")
    if not json_path_str:
        return error_response("JSON report was not generated for this run.", 404)

    json_path = Path(json_path_str)
    if not json_path.is_file():
        return error_response("JSON report file not found on disk.", 404)

    return send_file(json_path, as_attachment=True, download_name=json_path.name)
