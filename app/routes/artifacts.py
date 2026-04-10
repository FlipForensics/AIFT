"""Artifact option normalisation, profile management, validation, and route handlers.

This module handles:

* Normalising artifact selection payloads (new ``artifact_options`` format
  and legacy ``artifacts``/``ai_artifacts`` format).
* Artifact profile CRUD (load, save, list) including the built-in
  ``recommended`` profile.
* Analysis date-range validation.
* Parse-progress extraction and prompt sanitisation utilities.
* Flask route handlers for starting/streaming parse operations and profile CRUD.

Attributes:
    PROFILE_NAME_RE: Regex for validating artifact profile names.
    BUILTIN_RECOMMENDED_PROFILE: Name of the built-in recommended profile.
    PROFILE_DIRNAME: Subdirectory for profile JSON files.
    PROFILE_FILE_SUFFIX: File extension for profile files.
    RECOMMENDED_PROFILE_EXCLUDED_ARTIFACTS: Artifacts excluded from the
        recommended profile.
    artifact_bp: Flask Blueprint for artifact and parse routes.
"""

from __future__ import annotations

import copy
import json
import logging
import threading
from datetime import datetime
from pathlib import Path
import re
from typing import Any

from flask import Blueprint, Response, current_app, request

from ..parser import LINUX_ARTIFACT_REGISTRY, WINDOWS_ARTIFACT_REGISTRY
from .state import (
    MODE_PARSE_AND_AI,
    MODE_PARSE_ONLY,
    PARSE_PROGRESS,
    STATE_LOCK,
    cancel_progress,
    emit_progress,
    error_response,
    get_case,
    new_progress,
    safe_int,
    safe_name,
    stream_sse,
    success_response,
)

# NOTE: .tasks imports are deferred to avoid circular import
# (tasks.py imports from artifacts.py). See _get_task_runners().

__all__ = [
    "PROFILE_NAME_RE",
    "BUILTIN_RECOMMENDED_PROFILE",
    "PROFILE_DIRNAME",
    "PROFILE_FILE_SUFFIX",
    "RECOMMENDED_PROFILE_EXCLUDED_ARTIFACTS",
    "artifact_bp",
    "normalize_artifact_mode",
    "normalize_artifact_options",
    "artifact_options_to_lists",
    "extract_parse_selection_payload",
    "validate_analysis_date_range",
    "extract_parse_progress",
    "sanitize_prompt",
    "resolve_profiles_root",
    "compose_profile_response",
    "load_profiles_from_directory",
    "normalize_profile_name",
    "profile_path_for_new_name",
    "write_profile_file",
]

LOGGER = logging.getLogger(__name__)

PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$")
BUILTIN_RECOMMENDED_PROFILE = "recommended"
PROFILE_DIRNAME = "profile"
PROFILE_FILE_SUFFIX = ".json"
RECOMMENDED_PROFILE_EXCLUDED_ARTIFACTS = {"mft", "usnjrnl", "evtx", "defender.evtx"}


# ---------------------------------------------------------------------------
# Artifact option helpers
# ---------------------------------------------------------------------------

def normalize_artifact_mode(value: Any, default_mode: str = MODE_PARSE_AND_AI) -> str:
    """Normalise an artifact processing mode to a valid constant.

    Args:
        value: Raw mode value.
        default_mode: Fallback mode.

    Returns:
        ``MODE_PARSE_AND_AI`` or ``MODE_PARSE_ONLY``.
    """
    mode = str(value or "").strip().lower()
    if mode == MODE_PARSE_ONLY:
        return MODE_PARSE_ONLY
    if mode == MODE_PARSE_AND_AI:
        return MODE_PARSE_AND_AI
    return default_mode


def _normalize_string_list(values: Any) -> list[str]:
    """Deduplicate and normalise a list of values to non-empty strings.

    Args:
        values: Input list (or non-list, returns empty).

    Returns:
        Deduplicated list of non-empty stripped strings.
    """
    if not isinstance(values, list):
        return []
    normalized: list[str] = []
    seen: set[str] = set()
    for value in values:
        text = str(value).strip()
        if not text or text in seen:
            continue
        seen.add(text)
        normalized.append(text)
    return normalized


def normalize_artifact_options(payload: Any) -> list[dict[str, str]]:
    """Normalise a raw artifact options payload into canonical form.

    Accepts lists of strings or dicts with various key names.

    Args:
        payload: Raw ``artifact_options`` value.

    Returns:
        List of dicts with ``artifact_key`` and ``mode`` keys.

    Raises:
        ValueError: If *payload* is not a list.
    """
    if not isinstance(payload, list):
        raise ValueError("`artifact_options` must be a JSON array.")

    normalized: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in payload:
        artifact_key = ""
        mode = MODE_PARSE_AND_AI

        if isinstance(item, str):
            artifact_key = item.strip()
        elif isinstance(item, dict):
            artifact_key = str(item.get("artifact_key") or item.get("key") or "").strip()
            if "mode" in item:
                mode = normalize_artifact_mode(item.get("mode"))
            elif "ai_enabled" in item:
                mode = MODE_PARSE_AND_AI if bool(item.get("ai_enabled")) else MODE_PARSE_ONLY
            else:
                mode = normalize_artifact_mode(item.get("parse_mode"), default_mode=MODE_PARSE_AND_AI)
        else:
            continue

        if not artifact_key or artifact_key in seen:
            continue
        seen.add(artifact_key)
        normalized.append({"artifact_key": artifact_key, "mode": mode})

    return normalized


def artifact_options_to_lists(artifact_options: list[dict[str, str]]) -> tuple[list[str], list[str]]:
    """Split normalised artifact options into parse and analysis lists.

    Args:
        artifact_options: Canonical artifact option dicts.

    Returns:
        ``(parse_artifacts, analysis_artifacts)`` tuple.
    """
    parse_artifacts: list[str] = []
    analysis_artifacts: list[str] = []
    for option in artifact_options:
        artifact_key = str(option.get("artifact_key", "")).strip()
        if not artifact_key:
            continue
        parse_artifacts.append(artifact_key)
        if normalize_artifact_mode(option.get("mode")) == MODE_PARSE_AND_AI:
            analysis_artifacts.append(artifact_key)
    return parse_artifacts, analysis_artifacts


def _build_artifact_options_from_lists(
    parse_artifacts: list[str],
    analysis_artifacts: list[str],
) -> list[dict[str, str]]:
    """Construct canonical artifact options from separate lists.

    Args:
        parse_artifacts: All artifact keys to parse.
        analysis_artifacts: Subset for AI analysis.

    Returns:
        List of dicts with ``artifact_key`` and ``mode``.
    """
    analysis_set = set(analysis_artifacts)
    return [
        {
            "artifact_key": artifact_key,
            "mode": MODE_PARSE_AND_AI if artifact_key in analysis_set else MODE_PARSE_ONLY,
        }
        for artifact_key in parse_artifacts
    ]


def extract_parse_selection_payload(
    payload: dict[str, Any],
) -> tuple[list[dict[str, str]], list[str], list[str]]:
    """Extract and normalise artifact selection from a parse request payload.

    Supports both ``artifact_options`` (new) and ``artifacts``/``ai_artifacts``
    (legacy) formats.

    Args:
        payload: Parsed JSON body from the parse-start request.

    Returns:
        ``(artifact_options, parse_artifacts, analysis_artifacts)`` tuple.

    Raises:
        ValueError: If the payload contains invalid fields.
    """
    if "artifact_options" in payload:
        artifact_options = normalize_artifact_options(payload.get("artifact_options"))
        parse_artifacts, analysis_artifacts = artifact_options_to_lists(artifact_options)
        return artifact_options, parse_artifacts, analysis_artifacts

    artifacts_raw = payload.get("artifacts", [])
    if not isinstance(artifacts_raw, list):
        raise ValueError("`artifacts` must be a JSON array.")
    parse_artifacts = _normalize_string_list(artifacts_raw)

    if "ai_artifacts" in payload:
        ai_raw = payload.get("ai_artifacts")
        if not isinstance(ai_raw, list):
            raise ValueError("`ai_artifacts` must be a JSON array.")
        selected_set = set(parse_artifacts)
        analysis_artifacts = [key for key in _normalize_string_list(ai_raw) if key in selected_set]
    else:
        analysis_artifacts = list(parse_artifacts)

    artifact_options = _build_artifact_options_from_lists(
        parse_artifacts=parse_artifacts,
        analysis_artifacts=analysis_artifacts,
    )
    return artifact_options, parse_artifacts, analysis_artifacts


def validate_analysis_date_range(payload: Any) -> dict[str, str] | None:
    """Validate and normalise an optional analysis date range.

    Args:
        payload: Raw ``analysis_date_range`` value from request JSON.

    Returns:
        Dict with ``start_date`` and ``end_date``, or ``None``.

    Raises:
        ValueError: On invalid format or range.
    """
    if payload is None:
        return None

    if not isinstance(payload, dict):
        raise ValueError("`analysis_date_range` must be an object.")

    start_raw = payload.get("start_date")
    end_raw = payload.get("end_date")
    start_text = str(start_raw).strip() if start_raw is not None else ""
    end_text = str(end_raw).strip() if end_raw is not None else ""
    if not start_text and not end_text:
        return None
    if not start_text or not end_text:
        raise ValueError(
            "Provide both `analysis_date_range.start_date` and `analysis_date_range.end_date`."
        )

    try:
        start_date = datetime.strptime(start_text, "%Y-%m-%d").date()
        end_date = datetime.strptime(end_text, "%Y-%m-%d").date()
    except ValueError as error:
        raise ValueError("Date range values must use YYYY-MM-DD format.") from error

    if start_date > end_date:
        raise ValueError(
            "`analysis_date_range.start_date` must be earlier than or equal to `end_date`."
        )

    return {
        "start_date": start_date.isoformat(),
        "end_date": end_date.isoformat(),
    }


def extract_parse_progress(fallback_artifact: str, args: tuple[Any, ...]) -> tuple[str, int]:
    """Extract artifact key and record count from a parser progress callback.

    Args:
        fallback_artifact: Default artifact key.
        args: Positional arguments from the callback.

    Returns:
        ``(artifact_key, record_count)`` tuple.
    """
    if not args:
        return fallback_artifact, 0
    first = args[0]
    if isinstance(first, dict):
        return str(first.get("artifact_key", fallback_artifact)), safe_int(first.get("record_count", 0))
    if len(args) >= 2:
        return str(args[0] or fallback_artifact), safe_int(args[1], 0)
    return fallback_artifact, safe_int(first, 0)


def sanitize_prompt(prompt: str, max_chars: int = 2000) -> str:
    """Normalise and truncate a user prompt for audit logging.

    Args:
        prompt: Raw user prompt text.
        max_chars: Maximum character length. Defaults to 2000.

    Returns:
        Normalised (and possibly truncated) prompt string.
    """
    normalized = " ".join(prompt.split())
    if len(normalized) <= max_chars:
        return normalized
    return f"{normalized[:max_chars]}... [truncated]"


# ---------------------------------------------------------------------------
# Profile management
# ---------------------------------------------------------------------------

def _recommended_artifact_options() -> list[dict[str, str]]:
    """Build artifact options for the built-in 'recommended' profile.

    Includes artifacts from both the Windows and Linux registries so that
    a single profile works regardless of the evidence OS.  Duplicate keys
    (e.g. ``services``) are emitted only once.

    Returns:
        List of artifact option dicts for the recommended profile.
    """
    profile: list[dict[str, str]] = []
    seen: set[str] = set()
    for registry in (WINDOWS_ARTIFACT_REGISTRY, LINUX_ARTIFACT_REGISTRY):
        for artifact_key in registry:
            normalized_key = str(artifact_key).strip().lower()
            if normalized_key in RECOMMENDED_PROFILE_EXCLUDED_ARTIFACTS:
                continue
            if normalized_key in seen:
                continue
            seen.add(normalized_key)
            profile.append({"artifact_key": str(artifact_key), "mode": MODE_PARSE_AND_AI})
    return profile


def resolve_profiles_root(config_path: str | Path) -> Path:
    """Resolve the directory where artifact profiles are stored.

    Args:
        config_path: Path to the AIFT configuration file.

    Returns:
        Absolute ``Path`` to the profiles directory.
    """
    return Path(config_path).parent / PROFILE_DIRNAME


def _recommended_profile_payload() -> dict[str, Any]:
    """Build the full payload for the built-in recommended profile.

    Returns:
        Dict with ``name``, ``builtin``, and ``artifact_options``.
    """
    return {
        "name": BUILTIN_RECOMMENDED_PROFILE,
        "builtin": True,
        "artifact_options": _recommended_artifact_options(),
    }


def write_profile_file(path: Path, payload: dict[str, Any]) -> None:
    """Write an artifact profile to a JSON file.

    Args:
        path: Destination file path.
        payload: Profile data to serialise.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(payload, indent=2, ensure_ascii=True)
    path.write_text(f"{content}\n", encoding="utf-8")


def _load_profile_file(path: Path) -> dict[str, Any] | None:
    """Load and validate a single artifact profile from a JSON file.

    Args:
        path: Path to the profile JSON file.

    Returns:
        Validated profile dict, or ``None`` if invalid.
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        LOGGER.warning("Skipping unreadable profile file: %s", path)
        return None

    if not isinstance(raw, dict):
        LOGGER.warning("Skipping invalid profile payload in %s", path)
        return None

    name = str(raw.get("name", "")).strip() or path.stem
    if not name:
        return None
    if name.lower() != BUILTIN_RECOMMENDED_PROFILE and not PROFILE_NAME_RE.fullmatch(name):
        LOGGER.warning("Skipping profile with invalid name in %s", path)
        return None

    options_payload = raw.get("artifact_options")
    if options_payload is None:
        options_payload = raw.get("selections", [])
    try:
        artifact_options = normalize_artifact_options(options_payload if options_payload is not None else [])
    except ValueError:
        LOGGER.warning("Skipping profile with invalid artifact options in %s", path)
        return None

    builtin = bool(raw.get("builtin", False))
    if name.lower() == BUILTIN_RECOMMENDED_PROFILE:
        builtin = True
        artifact_options = _recommended_artifact_options()
    elif not artifact_options:
        LOGGER.warning("Skipping profile with no artifact options in %s", path)
        return None

    return {
        "name": name,
        "builtin": builtin,
        "artifact_options": artifact_options,
        "path": path,
    }


def _ensure_recommended_profile(profiles_root: Path) -> None:
    """Ensure the built-in recommended profile exists on disk.

    Args:
        profiles_root: Directory for profile files.
    """
    recommended_path = profiles_root / f"{BUILTIN_RECOMMENDED_PROFILE}{PROFILE_FILE_SUFFIX}"
    if recommended_path.exists():
        return
    write_profile_file(recommended_path, _recommended_profile_payload())


def load_profiles_from_directory(profiles_root: Path) -> list[dict[str, Any]]:
    """Load all valid artifact profiles from the profiles directory.

    Args:
        profiles_root: Directory containing profile JSON files.

    Returns:
        Sorted list of validated profile dicts.
    """
    profiles_root.mkdir(parents=True, exist_ok=True)
    _ensure_recommended_profile(profiles_root)

    profiles: list[dict[str, Any]] = []
    seen_names: set[str] = set()
    for path in sorted(profiles_root.glob(f"*{PROFILE_FILE_SUFFIX}"), key=lambda item: item.name.lower()):
        profile = _load_profile_file(path)
        if profile is None:
            continue
        profile_key = str(profile.get("name", "")).strip().lower()
        if not profile_key or profile_key in seen_names:
            continue
        seen_names.add(profile_key)
        profiles.append(profile)

    profiles.sort(
        key=lambda item: (
            0 if str(item.get("name", "")).strip().lower() == BUILTIN_RECOMMENDED_PROFILE else 1,
            str(item.get("name", "")).strip().lower(),
        )
    )
    return profiles


def profile_path_for_new_name(profiles_root: Path, profile_name: str) -> Path:
    """Compute a unique file path for a new artifact profile.

    Args:
        profiles_root: Directory for profile files.
        profile_name: Human-readable profile name.

    Returns:
        A non-existent ``Path`` suitable for writing.
    """
    stem = safe_name(profile_name.lower(), fallback="profile")
    candidate = profiles_root / f"{stem}{PROFILE_FILE_SUFFIX}"
    if not candidate.exists():
        return candidate

    index = 1
    while True:
        candidate = profiles_root / f"{stem}_{index}{PROFILE_FILE_SUFFIX}"
        if not candidate.exists():
            return candidate
        index += 1


def normalize_profile_name(value: Any) -> str:
    """Validate and normalise a profile name from user input.

    Args:
        value: Raw profile name.

    Returns:
        Stripped, validated profile name.

    Raises:
        ValueError: If the name is empty, reserved, or invalid.
    """
    name = str(value or "").strip()
    if not name:
        raise ValueError("Profile name is required.")
    if name.lower() == BUILTIN_RECOMMENDED_PROFILE:
        raise ValueError("`recommended` is a built-in profile and cannot be overwritten.")
    if not PROFILE_NAME_RE.fullmatch(name):
        raise ValueError(
            "Profile name must be 1-64 chars and use letters, numbers, spaces, period, underscore, or hyphen."
        )
    return name


def compose_profile_response(profiles_root: Path) -> list[dict[str, Any]]:
    """Build the API response payload for all artifact profiles.

    Args:
        profiles_root: Directory containing profile files.

    Returns:
        List of dicts with ``name``, ``builtin``, and ``artifact_options``.
    """
    return [
        {
            "name": str(profile.get("name", "")).strip(),
            "builtin": bool(profile.get("builtin", False)),
            "artifact_options": list(profile.get("artifact_options", [])),
        }
        for profile in load_profiles_from_directory(profiles_root)
    ]


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------

artifact_bp = Blueprint("artifacts", __name__)


def _purge_stale_parsed_data(case_dir: Path, prev_csv_output_dir: str) -> None:
    """Remove parsed CSV data from disk before a new parse run.

    Cleans both the default ``case_dir/parsed`` directory and any external
    CSV output directory that was used by the previous parse run.

    Args:
        case_dir: Path to the case directory.
        prev_csv_output_dir: The ``csv_output_dir`` stored from the previous
            parse run.  May be empty if no prior run exists.
    """
    from .evidence_utils import safe_rmtree

    cases_root = case_dir.resolve().parent

    # Clean the default parsed directory inside the case folder.
    default_parsed = case_dir / "parsed"
    safe_rmtree(default_parsed, cases_root)

    # Clean external CSV output directory if configured and different
    # from the default location.
    if not prev_csv_output_dir:
        return
    prev_path = Path(prev_csv_output_dir)
    if not prev_path.is_dir():
        return
    resolved_prev = prev_path.resolve()
    resolved_default = default_parsed.resolve()
    if resolved_prev == resolved_default:
        return  # Already handled above.
    safe_rmtree(prev_path, cases_root)


def _purge_stale_downstream_case_files(case_dir: Path) -> None:
    """Remove stale analysis/chat artifacts before a new parse run.

    Args:
        case_dir: Path to the case directory.
    """
    for stale_name in ("analysis_results.json", "prompt.txt", "chat_history.jsonl"):
        stale_path = case_dir / stale_name
        try:
            stale_path.unlink(missing_ok=True)
        except OSError:
            LOGGER.warning("Failed to remove stale case artifact: %s", stale_path, exc_info=True)


@artifact_bp.post("/api/cases/<case_id>/parse")
def start_parse(case_id: str) -> tuple[Response, int]:
    """Start background parsing of selected forensic artifacts.

    For backward compatibility, if multi-image state exists for this case,
    delegates to the first image's parse endpoint.  Otherwise falls through
    to the original case-level parsing logic.

    Args:
        case_id: UUID of the case.

    Returns:
        ``(Response, 202)`` confirming start, or error.
    """
    case = get_case(case_id)
    if case is None:
        return error_response(f"Case not found: {case_id}", 404)

    # Delegate to image-specific parse if images exist.
    from .images import start_image_parse
    with STATE_LOCK:
        image_states = case.get("image_states", {})
    if image_states:
        first_image_id = next(iter(image_states))
        return start_image_parse(case_id, first_image_id)

    with STATE_LOCK:
        has_evidence = bool(str(case.get("evidence_path", "")).strip())
    if not has_evidence:
        return error_response("No evidence loaded for this case.", 400)

    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return error_response("Request body must be a JSON object.", 400)
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
        case_dir = Path(case["case_dir"])
        PARSE_PROGRESS[case_id] = new_progress(status="running")
        case["status"] = "running"
        case["selected_artifacts"] = list(parse_artifacts)
        case["analysis_artifacts"] = list(analysis_artifacts)
        case["artifact_options"] = list(artifact_options)
        case["analysis_date_range"] = analysis_date_range

        # Capture previous CSV output dir before clearing so we can
        # remove stale on-disk data outside the case directory.
        prev_csv_output_dir = str(case.get("csv_output_dir", "")).strip()

        # Invalidate prior parse-derived outputs so a failed rerun
        # cannot leave stale data usable by downstream analysis.
        case["parse_results"] = []
        case["artifact_csv_paths"] = {}
        case["analysis_results"] = {}
        case["csv_output_dir"] = ""
        case["investigation_context"] = ""

    _purge_stale_parsed_data(case_dir, prev_csv_output_dir)
    _purge_stale_downstream_case_files(case_dir)

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
    from .tasks import run_task_with_case_log_context, run_parse  # deferred to avoid circular import
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
    return success_response(response_payload, 202)


@artifact_bp.get("/api/cases/<case_id>/parse/progress")
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


@artifact_bp.post("/api/cases/<case_id>/parse/cancel")
def cancel_parse(case_id: str) -> tuple[Response, int]:
    """Cancel a running parse operation for a case.

    Cancels both the case-level progress entry and any per-image
    progress entries (keyed as ``<case_id>::<image_id>``), so that
    multi-image parse threads also receive the cancel signal.

    Args:
        case_id: UUID of the case.

    Returns:
        ``(Response, 200)`` confirming cancellation, or error.
    """
    if get_case(case_id) is None:
        return error_response(f"Case not found: {case_id}", 404)
    cancelled = cancel_progress(PARSE_PROGRESS, case_id)

    # Also cancel all per-image progress entries for this case.
    # Per-image keys use the format "<case_id>::<image_id>".
    prefix = f"{case_id}::"
    with STATE_LOCK:
        image_keys = [
            key for key in PARSE_PROGRESS
            if key.startswith(prefix)
        ]
    for img_key in image_keys:
        cancel_progress(PARSE_PROGRESS, img_key)
        cancelled = True

    if not cancelled:
        return error_response("No running parse to cancel.", 409)
    return success_response({"status": "cancelling", "case_id": case_id})


@artifact_bp.get("/api/artifact-profiles")
def list_artifact_profiles() -> Response:
    """List all available artifact profiles.

    Returns:
        JSON response with the ``profiles`` list.
    """
    config_path = Path(str(current_app.config.get("AIFT_CONFIG_PATH", "config.yaml")))
    profiles_root = resolve_profiles_root(config_path)
    return success_response({"profiles": compose_profile_response(profiles_root)})


@artifact_bp.post("/api/artifact-profiles")
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
