"""Multi-image management route handlers for the AIFT Flask application.

Provides endpoints for adding images to a case, listing images, and
image-specific evidence intake and parsing.  These routes delegate to the
existing evidence and parsing logic but operate on per-image directories
managed by :class:`~app.case_manager.CaseManager`.

Attributes:
    images_bp: Flask Blueprint for multi-image routes.
"""

from __future__ import annotations

import copy
import json
import logging
import shutil
import threading
from pathlib import Path
from typing import Any

from flask import Blueprint, Response, current_app, request

from ..case_manager import CaseManager
from .evidence_utils import (
    compute_evidence_hashes as _compute_evidence_hashes,
    open_dissect_target as _open_dissect_target,
    should_skip_hashing as _should_skip_hashing,
)

from .state import (
    ANALYSIS_PROGRESS,
    CASES_ROOT,
    CHAT_PROGRESS,
    PARSE_PROGRESS,
    STATE_LOCK,
    emit_progress,
    error_response,
    get_case,
    new_progress,
    stream_sse,
    success_response,
)

__all__ = ["images_bp", "get_case_manager"]

LOGGER = logging.getLogger(__name__)

images_bp = Blueprint("images", __name__)


def get_case_manager() -> CaseManager:
    """Return a CaseManager instance bound to the global cases directory.

    Returns:
        A :class:`~app.case_manager.CaseManager` instance.
    """
    return CaseManager(CASES_ROOT)


def _get_or_create_default_image(case_id: str) -> str | None:
    """Return the first image ID for a case, creating one if none exist.

    If the case has no images yet, a default image is created with the
    label ``"default"``.  If the case uses the legacy flat layout, it is
    migrated first.

    Args:
        case_id: UUID of the case.

    Returns:
        The image ID string, or ``None`` if the case does not exist on
        disk.
    """
    cm = get_case_manager()
    case_dir = CASES_ROOT / case_id
    if not case_dir.is_dir():
        return None

    # Migrate legacy flat layout if needed.
    if cm.is_legacy_case(case_id):
        return cm.migrate_legacy_case(case_id)

    # Check for existing images.
    try:
        info = cm.get_case_info(case_id)
    except FileNotFoundError:
        return None

    if info["images"]:
        return info["images"][0]["image_id"]

    # No images yet -- create a default one and ensure the in-memory
    # case state tracks it so downstream code that reads case["images"]
    # does not find an uninitialised list.
    image_id = cm.add_image(case_id, label="default")
    case = get_case(case_id)
    if case is not None:
        with STATE_LOCK:
            images_list = case.setdefault("images", [])
            if not any(img.get("image_id") == image_id for img in images_list):
                images_list.append({"image_id": image_id, "label": "default"})
    return image_id


def _progress_key(case_id: str, image_id: str) -> str:
    """Build a composite progress-store key for an image parse operation.

    Args:
        case_id: UUID of the case.
        image_id: UUID of the image.

    Returns:
        A string key like ``"<case_id>::<image_id>"``.
    """
    return f"{case_id}::{image_id}"


# ---------------------------------------------------------------------------
# Image management routes
# ---------------------------------------------------------------------------


@images_bp.post("/api/cases/<case_id>/images")
def add_image(case_id: str) -> tuple[Response, int]:
    """Add a new image slot to an existing case.

    Expects a JSON body with an optional ``label`` field.

    Args:
        case_id: UUID of the case.

    Returns:
        ``(Response, 201)`` with ``image_id`` and ``label``, or error.
    """
    case = get_case(case_id)
    if case is None:
        return error_response(f"Case not found: {case_id}", 404)

    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return error_response("Request body must be a JSON object.", 400)

    label = str(payload.get("label", "")).strip()

    cm = get_case_manager()
    try:
        image_id = cm.add_image(case_id, label=label)
    except FileNotFoundError:
        return error_response(f"Case directory not found for: {case_id}", 404)

    # Track images in the in-memory case state.
    with STATE_LOCK:
        images_list = case.setdefault("images", [])
        images_list.append({"image_id": image_id, "label": label})

    return success_response({"image_id": image_id, "label": label}, 201)


@images_bp.get("/api/cases/<case_id>/images")
def list_images(case_id: str) -> tuple[Response, int] | Response:
    """List all images in a case with their metadata.

    Args:
        case_id: UUID of the case.

    Returns:
        JSON with an ``images`` list, or 404 error.
    """
    case = get_case(case_id)
    if case is None:
        return error_response(f"Case not found: {case_id}", 404)

    cm = get_case_manager()
    try:
        info = cm.get_case_info(case_id)
    except FileNotFoundError:
        return error_response(f"Case directory not found for: {case_id}", 404)

    return success_response({"images": info["images"]})


@images_bp.delete("/api/cases/<case_id>/images/<image_id>")
def delete_image(case_id: str, image_id: str) -> tuple[Response, int]:
    """Remove an ingested image and its data from a case.

    Validates that the case and image exist, prevents deletion while
    analysis or parsing is running, removes the image directory from
    disk, clears in-memory state for the image, and logs the action.

    Args:
        case_id: UUID of the case.
        image_id: UUID of the image.

    Returns:
        ``(Response, 200)`` with the removed ``image_id``, or error.
    """
    case = get_case(case_id)
    if case is None:
        return error_response(f"Case not found: {case_id}", 404)

    cm = get_case_manager()
    try:
        cm.get_image_dir(case_id, image_id)
    except FileNotFoundError:
        return error_response(f"Image not found: {image_id}", 404)
    except ValueError:
        return error_response("Invalid image identifier.", 400)

    # Prevent deletion while parsing or analysis is running.
    with STATE_LOCK:
        case_status = str(case.get("status", "")).strip().lower()
    if case_status == "running":
        return error_response(
            "Cannot remove an image while parsing or analysis is running.", 409,
        )

    # Remove the image directory from disk.
    try:
        cm.delete_image(case_id, image_id)
    except FileNotFoundError:
        return error_response(f"Image not found: {image_id}", 404)
    except ValueError:
        return error_response("Invalid image identifier.", 400)
    except OSError:
        LOGGER.exception(
            "Failed to delete image directory for case %s image %s",
            case_id, image_id,
        )
        return error_response(
            "Failed to remove the image directory from disk.", 500,
        )

    # Clear in-memory state for the image.
    with STATE_LOCK:
        # Remove from the images list.
        images_list = case.get("images", [])
        case["images"] = [
            img for img in images_list
            if img.get("image_id") != image_id
        ]

        # Remove from image_states.
        image_states = case.get("image_states", {})
        image_states.pop(image_id, None)

        # Clear per-image progress keys.
        img_progress_key = _progress_key(case_id, image_id)
        PARSE_PROGRESS.pop(img_progress_key, None)
        ANALYSIS_PROGRESS.pop(img_progress_key, None)
        CHAT_PROGRESS.pop(img_progress_key, None)

    # Note: CaseManager.delete_image() already writes an "image_deleted"
    # audit entry, so we do not duplicate it here.

    return success_response({"image_id": image_id})


# ---------------------------------------------------------------------------
# Image-specific evidence intake
# ---------------------------------------------------------------------------


@images_bp.post("/api/cases/<case_id>/images/<image_id>/evidence")
def intake_image_evidence(case_id: str, image_id: str) -> Response | tuple[Response, int]:
    """Ingest evidence for a specific image within a case.

    Behaves identically to the legacy ``POST /api/cases/<case_id>/evidence``
    endpoint, but stores files under the image-specific directory and writes
    image metadata to ``metadata.json``.

    Args:
        case_id: UUID of the case.
        image_id: UUID of the image.

    Returns:
        JSON with evidence metadata, hashes, and available artifacts.
    """
    case = get_case(case_id)
    if case is None:
        return error_response(f"Case not found: {case_id}", 404)

    cm = get_case_manager()
    try:
        image_dir = cm.get_image_dir(case_id, image_id)
    except FileNotFoundError:
        return error_response(f"Image not found: {image_id}", 404)
    except ValueError:
        return error_response("Invalid image identifier.", 400)

    with STATE_LOCK:
        case_dir = case["case_dir"]
        audit_logger = case["audit"]

    # Use the image-specific evidence directory.
    evidence_dir = image_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    from .evidence import resolve_evidence_payload

    try:
        # Temporarily point the case_dir to the image_dir so
        # resolve_evidence_payload writes to the correct location.
        evidence_payload = _resolve_evidence_for_image(image_dir)
        source_path = Path(evidence_payload["source_path"])
        dissect_path = Path(evidence_payload["dissect_path"])

        # Determine whether the user opted to skip hashing.
        skip_hashing = _should_skip_hashing()

        files_to_hash = evidence_payload.get("evidence_files_to_hash", [])
        hashes, file_hashes = _compute_evidence_hashes(
            files_to_hash, source_path, skip_hashing,
        )

        metadata, available_artifacts, detected_os_type = _open_dissect_target(
            dissect_path, case_dir, audit_logger, case_id,
        )

        audit_logger.log(
            "evidence_intake",
            {
                "filename": source_path.name,
                "image_id": image_id,
                "source_mode": evidence_payload["mode"],
                "source_path": evidence_payload["source_path"],
                "stored_path": evidence_payload["stored_path"],
                "uploaded_files": list(evidence_payload.get("uploaded_files", [])),
                "dissect_path": str(dissect_path),
                "sha256": hashes["sha256"],
                "md5": hashes["md5"],
                "file_size_bytes": hashes["size_bytes"],
                "evidence_file_hashes": [
                    {"path": h["path"], "sha256": h["sha256"], "md5": h["md5"], "size_bytes": h["size_bytes"]}
                    for h in file_hashes
                ],
            },
        )
        audit_logger.log(
            "image_opened",
            {
                "image_id": image_id,
                "hostname": metadata.get("hostname", "Unknown"),
                "os_version": metadata.get("os_version", "Unknown"),
                "os_type": detected_os_type,
                "domain": metadata.get("domain", "Unknown"),
                "available_artifacts": [
                    str(item.get("key"))
                    for item in available_artifacts
                    if item.get("available")
                ],
            },
        )

        # Update image metadata.json on disk.
        _update_image_metadata(image_dir, metadata, hashes, detected_os_type)

        # Store in case state under the image.
        with STATE_LOCK:
            image_states = case.setdefault("image_states", {})

            # Capture previous per-image state before updating so we can
            # preserve parse results and clean up external parsed output.
            prev_img_state = image_states.get(image_id, {})
            prev_csv_output_dir = str(prev_img_state.get("csv_output_dir", "")).strip()

            # Update the image state, preserving any existing parse
            # results and CSV paths from a previous parse run so that
            # re-uploading evidence does not silently discard them.
            new_img_state: dict[str, Any] = {
                "evidence_path": str(dissect_path),
                "evidence_hashes": hashes,
                "evidence_file_hashes": [
                    {"path": h["path"], "sha256": h["sha256"], "md5": h["md5"], "size_bytes": h["size_bytes"]}
                    for h in file_hashes
                ],
                "image_metadata": metadata,
                "os_type": detected_os_type,
                "available_artifacts": available_artifacts,
                "source_path": evidence_payload["source_path"],
                "stored_path": evidence_payload["stored_path"],
                "uploaded_files": list(evidence_payload.get("uploaded_files", [])),
            }
            for _keep_key in ("parse_results", "artifact_csv_paths", "csv_output_dir"):
                if _keep_key in prev_img_state:
                    new_img_state.setdefault(_keep_key, prev_img_state[_keep_key])
            image_states[image_id] = new_img_state

            # Check whether any OTHER image already has parse results.
            # If so, we must not wipe case-level downstream state because
            # that would destroy results from those images.
            other_images_have_results = any(
                img_id != image_id and bool(st.get("parse_results"))
                for img_id, st in image_states.items()
            )

            # Always set top-level evidence fields for backward
            # compatibility with V1 code paths.
            case["evidence_mode"] = evidence_payload["mode"]
            case["source_path"] = evidence_payload["source_path"]
            case["stored_path"] = evidence_payload["stored_path"]
            case["uploaded_files"] = list(evidence_payload.get("uploaded_files", []))
            case["evidence_path"] = str(dissect_path)
            case["evidence_hashes"] = hashes
            case["evidence_file_hashes"] = [
                {"path": h["path"], "sha256": h["sha256"], "md5": h["md5"], "size_bytes": h["size_bytes"]}
                for h in file_hashes
            ]
            case["image_metadata"] = metadata
            case["os_type"] = detected_os_type
            case["available_artifacts"] = available_artifacts

            # Invalidate case-level downstream state only when no other
            # image has parse results.  This prevents adding Image 2 from
            # destroying parse/analysis results that belong to Image 1.
            if not other_images_have_results:
                case["parse_results"] = []
                case["artifact_csv_paths"] = {}
                case["analysis_results"] = {}
                case["csv_output_dir"] = ""
                case["selected_artifacts"] = []
                case["analysis_artifacts"] = []
                case["artifact_options"] = []
                case["analysis_date_range"] = None
                case["investigation_context"] = ""

            # Only reset to evidence_loaded when no other image has
            # parse results; otherwise keep the current status so the
            # UI does not lose track of prior parsing progress.
            if not other_images_have_results:
                case["status"] = "evidence_loaded"

            # Clear per-image progress keys so stale SSE streams are not
            # reused.  Only clear the case-level keys when this is the
            # sole image (no other images have results).
            img_progress_key = _progress_key(case_id, image_id)
            PARSE_PROGRESS.pop(img_progress_key, None)
            ANALYSIS_PROGRESS.pop(img_progress_key, None)
            CHAT_PROGRESS.pop(img_progress_key, None)
            if not other_images_have_results:
                PARSE_PROGRESS.pop(case_id, None)
                ANALYSIS_PROGRESS.pop(case_id, None)
                CHAT_PROGRESS.pop(case_id, None)

        # Remove stale on-disk artifacts so disk fallbacks cannot
        # resurrect results from prior evidence.
        case_dir_path = Path(str(case_dir))

        # Clean up external CSV output directory for this specific
        # image (mirrors the logic in evidence.py::intake_evidence).
        from .evidence import _cleanup_parsed_output
        _cleanup_parsed_output(case_dir_path, prev_csv_output_dir)

        # Clean up the image-specific parsed directory.
        image_parsed_dir = image_dir / "parsed"
        if image_parsed_dir.is_dir():
            shutil.rmtree(image_parsed_dir, ignore_errors=True)

        # Only clean case-level legacy parsed dir and stale analysis
        # files when no other image retains parse results.  Otherwise
        # adding a new image would destroy on-disk state for prior images.
        if not other_images_have_results:
            parsed_dir_legacy = case_dir_path / "parsed"
            if parsed_dir_legacy.is_dir():
                shutil.rmtree(parsed_dir_legacy, ignore_errors=True)
            for stale_file in ("analysis_results.json", "prompt.txt", "chat_history.jsonl"):
                stale_path = case_dir_path / stale_file
                if stale_path.exists():
                    stale_path.unlink(missing_ok=True)

        os_warning = ""
        if detected_os_type == "unknown":
            os_warning = (
                "Could not detect the operating system of this image. "
                "Artifact availability may be incomplete — verify that the "
                "image format is supported by Dissect."
            )

        response_data: dict[str, Any] = {
            "case_id": case_id,
            "image_id": image_id,
            "source_mode": evidence_payload["mode"],
            "source_path": evidence_payload["source_path"],
            "evidence_path": str(dissect_path),
            "uploaded_files": list(evidence_payload.get("uploaded_files", [])),
            "hashes": hashes,
            "metadata": metadata,
            "os_type": detected_os_type,
            "available_artifacts": available_artifacts,
        }
        if os_warning:
            response_data["os_warning"] = os_warning

        return success_response(response_data)
    except (ValueError, FileNotFoundError) as error:
        return error_response(str(error), 400)
    except Exception:
        LOGGER.exception("Evidence intake failed for case %s image %s", case_id, image_id)
        return error_response(
            "Evidence intake failed due to an unexpected error. "
            "Confirm the evidence file is supported and try again.",
            500,
        )


# ---------------------------------------------------------------------------
# Image-specific parsing
# ---------------------------------------------------------------------------


@images_bp.post("/api/cases/<case_id>/images/<image_id>/parse")
def start_image_parse(case_id: str, image_id: str) -> tuple[Response, int]:
    """Start background parsing of selected artifacts for a specific image.

    Args:
        case_id: UUID of the case.
        image_id: UUID of the image.

    Returns:
        ``(Response, 202)`` confirming start, or error.
    """
    case = get_case(case_id)
    if case is None:
        return error_response(f"Case not found: {case_id}", 404)

    cm = get_case_manager()
    try:
        image_dir = cm.get_image_dir(case_id, image_id)
    except FileNotFoundError:
        return error_response(f"Image not found: {image_id}", 404)
    except ValueError:
        return error_response("Invalid image identifier.", 400)

    # Verify evidence is loaded for this image.
    with STATE_LOCK:
        image_states = case.get("image_states", {})
        img_state = image_states.get(image_id, {})
        evidence_path = str(img_state.get("evidence_path", "")).strip()

    if not evidence_path:
        return error_response("No evidence loaded for this image.", 400)

    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return error_response("Request body must be a JSON object.", 400)

    from .artifacts import extract_parse_selection_payload, validate_analysis_date_range

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

    progress_key = _progress_key(case_id, image_id)
    parsed_dir = image_dir / "parsed"
    parsed_dir.mkdir(parents=True, exist_ok=True)

    with STATE_LOCK:
        parse_state = PARSE_PROGRESS.setdefault(progress_key, new_progress())
        if parse_state.get("status") == "running":
            return error_response("Parsing is already running for this image.", 409)
        PARSE_PROGRESS[progress_key] = new_progress(status="running")

        # Also set the case-level progress for backward compat.
        # Use copy.copy() to avoid a shared reference -- otherwise
        # mutations to the per-image progress dict would silently
        # affect the case-level progress (and vice-versa).
        PARSE_PROGRESS[case_id] = copy.copy(PARSE_PROGRESS[progress_key])

        case["status"] = "running"
        case["selected_artifacts"] = list(parse_artifacts)
        case["analysis_artifacts"] = list(analysis_artifacts)
        case["artifact_options"] = list(artifact_options)
        case["analysis_date_range"] = analysis_date_range

    emit_progress(PARSE_PROGRESS, progress_key, {
        "type": "parse_started",
        "image_id": image_id,
        "artifacts": parse_artifacts,
        "analysis_artifacts": analysis_artifacts,
        "artifact_options": artifact_options,
        "total_artifacts": len(parse_artifacts),
    })

    config_snapshot = copy.deepcopy(current_app.config.get("AIFT_CONFIG", {}))

    from .tasks import run_task_with_case_log_context

    threading.Thread(
        target=run_task_with_case_log_context,
        args=(
            case_id, _run_image_parse,
            case_id, image_id, parse_artifacts, analysis_artifacts,
            artifact_options, config_snapshot, str(evidence_path), str(parsed_dir),
        ),
        daemon=True,
    ).start()

    response_payload: dict[str, Any] = {
        "status": "started",
        "case_id": case_id,
        "image_id": image_id,
        "artifacts": parse_artifacts,
        "ai_artifacts": analysis_artifacts,
        "artifact_options": artifact_options,
    }
    if analysis_date_range is not None:
        response_payload["analysis_date_range"] = analysis_date_range
    response_payload["success"] = True
    from flask import jsonify
    return jsonify(response_payload), 202


@images_bp.get("/api/cases/<case_id>/images/<image_id>/parse/progress")
def stream_image_parse_progress(case_id: str, image_id: str) -> Response | tuple[Response, int]:
    """Stream parsing progress events for a specific image via SSE.

    Args:
        case_id: UUID of the case.
        image_id: UUID of the image.

    Returns:
        SSE Response, or 404 error.
    """
    if get_case(case_id) is None:
        return error_response(f"Case not found: {case_id}", 404)

    progress_key = _progress_key(case_id, image_id)
    # Fall back to case-level if image-specific key doesn't exist.
    with STATE_LOCK:
        if progress_key not in PARSE_PROGRESS:
            progress_key = case_id

    return stream_sse(PARSE_PROGRESS, progress_key)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _resolve_evidence_for_image(image_dir: Path) -> dict[str, Any]:
    """Resolve evidence payload using the image directory for storage.

    Delegates to :func:`~app.routes.evidence.resolve_evidence_payload` with
    the image directory as the case_dir, so files land in
    ``images/<image_id>/evidence/``.

    Args:
        image_dir: Path to the image directory.

    Returns:
        Evidence payload dict.
    """
    from .evidence import resolve_evidence_payload
    return resolve_evidence_payload(image_dir)


def _update_image_metadata(
    image_dir: Path,
    metadata: dict[str, str],
    hashes: dict[str, Any],
    os_type: str,
) -> None:
    """Update the image's metadata.json with evidence details.

    Args:
        image_dir: Path to the image directory.
        metadata: Dissect image metadata (hostname, os_version, etc.).
        hashes: Evidence hash information.
        os_type: Detected operating system type.
    """
    meta_path = image_dir / "metadata.json"
    existing: dict[str, Any] = {}
    if meta_path.is_file():
        try:
            existing = json.loads(meta_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            pass

    existing.update({
        "hostname": metadata.get("hostname", "Unknown"),
        "os_version": metadata.get("os_version", "Unknown"),
        "os_type": os_type,
        "domain": metadata.get("domain", "Unknown"),
        "hashes": {
            "sha256": hashes.get("sha256", ""),
            "md5": hashes.get("md5", ""),
        },
    })

    meta_path.write_text(
        json.dumps(existing, indent=2), encoding="utf-8",
    )


def _run_image_parse(
    case_id: str,
    image_id: str,
    parse_artifacts: list[str],
    analysis_artifacts: list[str],
    artifact_options: list[dict[str, str]],
    config_snapshot: dict[str, Any],
    evidence_path: str,
    parsed_dir: str,
) -> None:
    """Execute background parsing for a specific image.

    Delegates the core parse loop to :func:`tasks.run_parse_loop` and
    handles image-specific state storage and progress emission.

    Args:
        case_id: UUID of the case.
        image_id: UUID of the image.
        parse_artifacts: Artifact keys to parse.
        analysis_artifacts: Subset for AI analysis.
        artifact_options: Canonical artifact option dicts.
        config_snapshot: Deep copy of application config.
        evidence_path: Path to the Dissect evidence.
        parsed_dir: Path to the image-specific parsed directory.
    """
    from .state import (
        mark_case_status,
        set_progress_status,
    )
    from .tasks import run_parse_loop

    progress_key = _progress_key(case_id, image_id)

    case = get_case(case_id)
    if case is None:
        set_progress_status(PARSE_PROGRESS, progress_key, "failed", "Case not found.")
        emit_progress(PARSE_PROGRESS, progress_key, {"type": "parse_failed", "error": "Case not found."})
        return

    with STATE_LOCK:
        case_dir = case["case_dir"]
        audit_logger = case["audit"]

    try:
        outcome = run_parse_loop(
            case_id=case_id,
            evidence_path=evidence_path,
            case_dir=case_dir,
            audit_logger=audit_logger,
            parsed_dir=parsed_dir,
            parse_artifacts=parse_artifacts,
            progress_key=progress_key,
        )
        if outcome is None:
            # Parsing was cancelled.
            return

        results, csv_map = outcome
        with STATE_LOCK:
            # Store per-image parse results.
            image_states = case.setdefault("image_states", {})
            img_state = image_states.setdefault(image_id, {})
            img_state["parse_results"] = results
            img_state["artifact_csv_paths"] = csv_map
            img_state["csv_output_dir"] = parsed_dir

            # Also update case-level for backward compat.
            case["selected_artifacts"] = list(parse_artifacts)
            case["analysis_artifacts"] = list(analysis_artifacts)
            case["artifact_options"] = list(artifact_options)
            case["parse_results"] = results
            case["artifact_csv_paths"] = csv_map
            case["csv_output_dir"] = parsed_dir

        completed = sum(1 for item in results if item.get("success"))
        failed = len(results) - completed
        set_progress_status(PARSE_PROGRESS, progress_key, "completed")
        emit_progress(
            PARSE_PROGRESS, progress_key,
            {
                "type": "parse_completed",
                "image_id": image_id,
                "total_artifacts": len(results),
                "successful_artifacts": completed,
                "failed_artifacts": failed,
            },
        )
        mark_case_status(case_id, "parsed")
    except Exception:
        LOGGER.exception("Background parse failed for case %s image %s", case_id, image_id)
        user_message = (
            "Parsing failed due to an internal error. "
            "Check logs and retry after confirming the evidence file is readable."
        )
        mark_case_status(case_id, "error")
        set_progress_status(PARSE_PROGRESS, progress_key, "failed", user_message)
        emit_progress(PARSE_PROGRESS, progress_key, {"type": "parse_failed", "error": user_message})
