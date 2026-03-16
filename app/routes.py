"""HTTP route definitions for the AIFT (AI Forensic Triage) Flask application.

This module implements all HTTP endpoints for the 5-step forensic analysis wizard:

1. **Evidence** -- Upload or reference a disk image (E01, ZIP, 7z, tar, raw, VMDK, etc.).
2. **Artifacts** -- Select which forensic artifacts to parse and whether each should
   be included in AI analysis.
3. **Parsing** -- Background parsing via Dissect with real-time SSE progress streaming.
4. **Analysis** -- AI-powered forensic analysis of parsed CSV artifacts with SSE
   progress streaming.
5. **Results** -- Download the HTML report, CSV bundle, or engage in follow-up chat
   with the AI about analysis findings.

The module also provides endpoints for:

* Application settings management (read, update, test AI provider connection).
* Artifact profile management (list, create/update user-defined profiles).
* Chat with the AI about completed analysis results, with SSE streaming for tokens.
* Static asset serving (logo images, favicon).

All long-running operations (parsing, analysis, chat) execute on background
``threading.Thread`` instances. Progress is communicated to the frontend via
Server-Sent Events (SSE) using in-memory event stores guarded by a reentrant lock.

Attributes:
    LOGGER: Module-level logger instance for application logging.
    PROJECT_ROOT: Absolute ``Path`` to the AIFT project root directory (one level
        above the ``app/`` package).
    CASES_ROOT: Absolute ``Path`` to the ``cases/`` directory where per-case data
        is stored.
    IMAGES_ROOT: Absolute ``Path`` to the ``images/`` directory for logo and static
        image assets.
    SENSITIVE_KEYS: Set of lowercase key names whose values must be masked in API
        responses (e.g., ``api_key``, ``token``, ``secret``, ``password``).
    MASKED: Placeholder string used when masking sensitive configuration values.
    SAFE_NAME_RE: Compiled regex that matches non-alphanumeric characters (excluding
        dots, hyphens, underscores) for sanitizing file and profile names.
    EWF_SEGMENT_RE: Compiled regex for matching EWF (EnCase) split segment filenames
        (e.g., ``image.E01``, ``image.E02``).
    SPLIT_RAW_SEGMENT_RE: Compiled regex for matching split raw disk image segments
        (e.g., ``image.000``, ``image.001``).
    DISSECT_EVIDENCE_EXTENSIONS: Frozen set of all file extensions that Dissect's
        ``Target.open()`` can handle, including containers, loaders, and archives.
    PROFILE_NAME_RE: Compiled regex for validating artifact profile names
        (1-64 alphanumeric characters, spaces, dots, underscores, or hyphens).
    MODE_PARSE_AND_AI: Constant string indicating an artifact should be both parsed
        and included in AI analysis.
    MODE_PARSE_ONLY: Constant string indicating an artifact should be parsed but
        excluded from AI analysis.
    BUILTIN_RECOMMENDED_PROFILE: Name of the built-in recommended artifact profile.
    PROFILE_DIRNAME: Subdirectory name where artifact profile JSON files are stored.
    PROFILE_FILE_SUFFIX: File extension for artifact profile files.
    RECOMMENDED_PROFILE_EXCLUDED_ARTIFACTS: Set of artifact keys excluded from the
        built-in recommended profile due to their large output size.
    CONNECTION_TEST_SYSTEM_PROMPT: System prompt used when testing AI provider
        connectivity.
    CONNECTION_TEST_USER_PROMPT: User prompt used when testing AI provider
        connectivity.
    CHAT_HISTORY_MAX_PAIRS: Maximum number of user/assistant message pairs retained
        in chat context.
    TERMINAL_CASE_STATUSES: Frozen set of case status values that indicate a case
        has reached a terminal state and can be cleaned up.
    SSE_POLL_INTERVAL_SECONDS: Sleep interval between SSE polling iterations.
    SSE_INITIAL_IDLE_GRACE_SECONDS: Grace period before an idle SSE stream is
        terminated.
    CASE_STATES: In-memory dictionary mapping case IDs to their full state
        dictionaries. Protected by ``STATE_LOCK``.
    PARSE_PROGRESS: In-memory dictionary mapping case IDs to parsing progress
        state (events list, status, error). Protected by ``STATE_LOCK``.
    ANALYSIS_PROGRESS: In-memory dictionary mapping case IDs to analysis progress
        state. Protected by ``STATE_LOCK``.
    CHAT_PROGRESS: In-memory dictionary mapping case IDs to chat progress state.
        Protected by ``STATE_LOCK``.
    STATE_LOCK: Reentrant threading lock protecting all in-memory state dictionaries.
    routes_bp: Flask ``Blueprint`` instance containing all route registrations.
"""

from __future__ import annotations

import copy
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import re
import shutil
import threading
import time
from collections.abc import Mapping
from typing import Any, Callable
from uuid import uuid4
import tarfile
from zipfile import BadZipFile, ZIP_DEFLATED, ZipFile

import py7zr

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
    stream_with_context,
)
from werkzeug.utils import secure_filename

from .analyzer import ForensicAnalyzer
from .ai_providers import AIProviderError, create_provider
from .audit import AuditLogger
from .case_logging import (
    case_log_context,
    pop_case_log_context,
    push_case_log_context,
    register_case_log_handler,
    unregister_case_log_handler,
)
from .config import LOGO_FILE_CANDIDATES, load_config, save_config
from .chat import ChatManager
from .hasher import compute_hashes, verify_hash
from .parser import ARTIFACT_REGISTRY, ForensicParser
from .reporter import ReportGenerator
from .version import TOOL_VERSION

LOGGER = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CASES_ROOT = PROJECT_ROOT / "cases"
IMAGES_ROOT = PROJECT_ROOT / "images"
SENSITIVE_KEYS = {"api_key", "token", "secret", "password"}
MASKED = "********"
SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]+")
EWF_SEGMENT_RE = re.compile(r"^(?P<base>.+)\.(?:e|ex|s|l)(?P<segment>\d{2})$", re.IGNORECASE)
SPLIT_RAW_SEGMENT_RE = re.compile(r"^(?P<base>.+)\.(?P<segment>\d{3})$")

# All file extensions Dissect's Target.open() can handle directly (containers + loaders).
DISSECT_EVIDENCE_EXTENSIONS = frozenset({
    # EWF / EnCase
    ".e01", ".ex01", ".s01", ".l01",
    # Raw / DD disk images
    ".dd", ".img", ".raw", ".bin", ".iso",
    # Split raw segments
    ".000", ".001",
    # Virtual disk formats
    ".vmdk", ".vhd", ".vhdx", ".vdi", ".qcow2", ".hdd", ".hds",
    # VM configuration (auto-loads associated disks)
    ".vmx", ".vmwarevm", ".vbox", ".vmcx", ".ovf", ".ova", ".pvm", ".pvs", ".utm", ".xva", ".vma",
    # Backup formats
    ".vbk",
    # Dissect-native containers
    ".asdf", ".asif",
    # Forensic logical images
    ".ad1",
    # Archives that Dissect loaders handle
    ".tar", ".gz", ".tgz",
    # Archives (handled by our own extraction + Dissect)
    ".zip", ".7z",
})

# Extensions for evidence files we look for inside extracted archives.
_EVIDENCE_FILE_EXTENSIONS = frozenset({
    ".e01", ".ex01", ".s01", ".l01",
    ".dd", ".img", ".raw", ".bin", ".iso",
    ".vmdk", ".vhd", ".vhdx", ".vdi", ".qcow2", ".hdd", ".hds",
    ".vmx", ".vbox", ".vmcx", ".ovf", ".ova",
    ".asdf", ".asif", ".ad1",
    ".000", ".001",
})
PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.-]{0,63}$")

MODE_PARSE_AND_AI = "parse_and_ai"
MODE_PARSE_ONLY = "parse_only"
BUILTIN_RECOMMENDED_PROFILE = "recommended"
PROFILE_DIRNAME = "profile"
PROFILE_FILE_SUFFIX = ".json"
RECOMMENDED_PROFILE_EXCLUDED_ARTIFACTS = {"mft", "usnjrnl", "evtx", "defender.evtx"}
CONNECTION_TEST_SYSTEM_PROMPT = "You are a connectivity test assistant. Reply briefly."
CONNECTION_TEST_USER_PROMPT = "Reply with: Connection OK."
DEFAULT_FORENSIC_SYSTEM_PROMPT = (
    "You are a digital forensic analyst. "
    "Analyze ONLY the data provided to you. "
    "Do not fabricate evidence. "
    "Prioritize incident-relevant findings and response actions; use baseline only as supporting context."
)
CHAT_HISTORY_MAX_PAIRS = 20
TERMINAL_CASE_STATUSES = frozenset({"completed", "failed", "error"})
SSE_POLL_INTERVAL_SECONDS = 0.2
SSE_INITIAL_IDLE_GRACE_SECONDS = 1.0

CASE_STATES: dict[str, dict[str, Any]] = {}
PARSE_PROGRESS: dict[str, dict[str, Any]] = {}
ANALYSIS_PROGRESS: dict[str, dict[str, Any]] = {}
CHAT_PROGRESS: dict[str, dict[str, Any]] = {}
STATE_LOCK = threading.RLock()

routes_bp = Blueprint("routes", __name__)
_REQUEST_CASE_LOG_TOKEN = "_aift_case_log_token"


@routes_bp.before_app_request
def _bind_case_log_context_for_request() -> None:
    """Bind case-specific logging context before each incoming request.

    Extracts the ``case_id`` from the request's URL path parameters (if
    present) and pushes a case-scoped logging context so that all log
    messages emitted during the request are tagged with the case ID.

    The resulting context token is stored on Flask's ``g`` object for
    cleanup in the corresponding teardown handler.
    """
    case_id: str | None = None
    if request.blueprint == routes_bp.name:
        case_id = str((request.view_args or {}).get("case_id", "")).strip() or None
    setattr(g, _REQUEST_CASE_LOG_TOKEN, push_case_log_context(case_id))


@routes_bp.teardown_app_request
def _clear_case_log_context_for_request(_error: BaseException | None) -> None:
    """Pop the case-scoped logging context after each request completes.

    This teardown handler restores the logging context to its pre-request
    state, ensuring that case-specific log tagging does not leak across
    requests.

    Args:
        _error: Optional exception that occurred during request handling.
            Ignored; context cleanup happens unconditionally.
    """
    token = getattr(g, _REQUEST_CASE_LOG_TOKEN, None)
    if token is not None:
        pop_case_log_context(token)
        setattr(g, _REQUEST_CASE_LOG_TOKEN, None)


def _now_iso() -> str:
    """Return the current UTC timestamp as an ISO 8601 string with a ``Z`` suffix.

    Returns:
        A string like ``"2025-01-15T08:30:00Z"`` representing the current
        UTC time, truncated to whole seconds.
    """
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _error(message: str, status: int) -> tuple[Response, int]:
    """Create a JSON error response tuple for Flask route handlers.

    Args:
        message: Human-readable error description to include in the response body.
        status: HTTP status code for the response (e.g., 400, 404, 500).

    Returns:
        A tuple of ``(Response, int)`` containing a JSON body with an ``"error"``
        key and the corresponding HTTP status code.
    """
    return jsonify({"error": message}), status


def _safe_name(value: str, fallback: str = "item") -> str:
    """Sanitize a string for use as a safe filesystem or identifier name.

    Replaces any characters that are not alphanumeric, dots, hyphens, or
    underscores with underscores, then strips leading/trailing underscores.

    Args:
        value: The raw string to sanitize.
        fallback: Value to return if sanitization produces an empty string.
            Defaults to ``"item"``.

    Returns:
        A sanitized string safe for use in file paths and identifiers, or
        the fallback if the result would be empty.
    """
    cleaned = SAFE_NAME_RE.sub("_", value).strip("_")
    return cleaned or fallback


def _resolve_logo_filename() -> str:
    """Resolve the filename of the application logo image from the images directory.

    Searches ``IMAGES_ROOT`` for a logo file matching the configured candidate
    filenames (from ``LOGO_FILE_CANDIDATES``). If no candidate matches, falls
    back to the first image file found in the directory by alphabetical order.

    Returns:
        The filename (not full path) of the resolved logo image, or an empty
        string if no suitable image file is found or the images directory does
        not exist.
    """
    if IMAGES_ROOT.is_dir():
        for filename in LOGO_FILE_CANDIDATES:
            if (IMAGES_ROOT / filename).is_file():
                return filename

        image_files = sorted(
            path.name
            for path in IMAGES_ROOT.iterdir()
            if path.is_file() and path.suffix.lower() in {".png", ".jpg", ".jpeg", ".webp", ".svg"}
        )
        if image_files:
            return image_files[0]

    return ""


def _new_progress(status: str = "idle") -> dict[str, Any]:
    """Create a fresh progress-tracking dictionary for SSE event stores.

    Args:
        status: Initial status string. Defaults to ``"idle"``. Typical values
            are ``"idle"``, ``"running"``, ``"completed"``, and ``"failed"``.

    Returns:
        A dictionary with keys ``"status"`` (str), ``"events"`` (empty list),
        and ``"error"`` (None).
    """
    return {"status": status, "events": [], "error": None}


def _set_progress_status(
    store: dict[str, dict[str, Any]],
    case_id: str,
    status: str,
    error: str | None = None,
) -> None:
    """Update the status (and optionally the error message) in a progress store.

    Thread-safe: acquires ``STATE_LOCK`` before modifying the store.

    Args:
        store: One of ``PARSE_PROGRESS``, ``ANALYSIS_PROGRESS``, or
            ``CHAT_PROGRESS``.
        case_id: UUID of the case whose progress is being updated.
        status: New status string (e.g., ``"running"``, ``"completed"``,
            ``"failed"``).
        error: Optional human-readable error message. Defaults to ``None``.
    """
    with STATE_LOCK:
        state = store.setdefault(case_id, _new_progress())
        state["status"] = status
        state["error"] = error


def _emit_progress(
    store: dict[str, dict[str, Any]],
    case_id: str,
    payload: dict[str, Any],
) -> None:
    """Append a progress event to a case's SSE event store.

    Each event is automatically assigned a monotonically increasing
    ``sequence`` number and a ``timestamp`` (if not already present in
    the payload). Thread-safe: acquires ``STATE_LOCK`` before modifying
    the store.

    Args:
        store: One of ``PARSE_PROGRESS``, ``ANALYSIS_PROGRESS``, or
            ``CHAT_PROGRESS``.
        case_id: UUID of the case to emit the event for.
        payload: Dictionary describing the event. Must include a ``"type"``
            key (e.g., ``"artifact_started"``, ``"token"``, ``"error"``).
    """
    event = dict(payload)
    event.setdefault("timestamp", _now_iso())
    with STATE_LOCK:
        state = store.setdefault(case_id, _new_progress())
        event["sequence"] = len(state["events"])
        state["events"].append(event)


def _normalize_case_status(value: Any) -> str:
    """Normalize a case status value to a lowercase, stripped string.

    Args:
        value: Raw status value, which may be ``None``, a string, or any
            other type coercible to string.

    Returns:
        A lowercase, whitespace-stripped string representation of the status.
    """
    return str(value or "").strip().lower()


def _mark_case_status(case_id: str, status: str) -> None:
    """Update the in-memory status of a case in ``CASE_STATES``.

    Thread-safe: acquires ``STATE_LOCK`` before modifying state. If the
    case does not exist in the store, this is a no-op.

    Args:
        case_id: UUID of the case to update.
        status: New status string (e.g., ``"active"``, ``"parsed"``,
            ``"completed"``, ``"failed"``, ``"error"``).
    """
    normalized_status = _normalize_case_status(status)
    with STATE_LOCK:
        case = CASE_STATES.get(case_id)
        if case is not None:
            case["status"] = normalized_status


def _cleanup_case_entries(case_id: str) -> None:
    """Remove all in-memory state entries for a specific case.

    Clears the case from ``CASE_STATES``, ``PARSE_PROGRESS``,
    ``ANALYSIS_PROGRESS``, and ``CHAT_PROGRESS``, and unregisters the
    case-specific log handler.

    Args:
        case_id: UUID of the case whose entries should be removed.
    """
    with STATE_LOCK:
        CASE_STATES.pop(case_id, None)
        PARSE_PROGRESS.pop(case_id, None)
        ANALYSIS_PROGRESS.pop(case_id, None)
        CHAT_PROGRESS.pop(case_id, None)
    unregister_case_log_handler(case_id)


def _cleanup_terminal_cases(exclude_case_id: str | None = None) -> None:
    """Remove in-memory state for all cases that have reached a terminal status.

    Terminal statuses are defined in ``TERMINAL_CASE_STATUSES`` (completed,
    failed, error). This prevents unbounded memory growth from accumulated
    finished cases.

    Args:
        exclude_case_id: Optional case ID to exempt from cleanup, even if it
            is in a terminal status. Useful when a new case is being created
            immediately after another completes.
    """
    with STATE_LOCK:
        terminal_case_ids = [
            case_id
            for case_id, case in CASE_STATES.items()
            if case_id != exclude_case_id
            and _normalize_case_status(case.get("status")) in TERMINAL_CASE_STATUSES
        ]
        for case_id in terminal_case_ids:
            CASE_STATES.pop(case_id, None)
            PARSE_PROGRESS.pop(case_id, None)
            ANALYSIS_PROGRESS.pop(case_id, None)
            CHAT_PROGRESS.pop(case_id, None)
    for case_id in terminal_case_ids:
        unregister_case_log_handler(case_id)


def _mask_sensitive(data: Any) -> Any:
    """Recursively mask sensitive values in a data structure before API output.

    Any dictionary key whose lowercase name is in ``SENSITIVE_KEYS`` will
    have its value replaced with the ``MASKED`` placeholder string. Nested
    dicts and lists are traversed recursively.

    Args:
        data: Input data structure (dict, list, or scalar) to mask.

    Returns:
        A new data structure with identical shape, but sensitive values
        replaced by ``MASKED``. Non-dict, non-list values are returned
        unchanged.
    """
    if isinstance(data, dict):
        masked: dict[str, Any] = {}
        for key, value in data.items():
            if key.lower() in SENSITIVE_KEYS:
                masked[key] = MASKED if str(value).strip() else ""
            else:
                masked[key] = _mask_sensitive(value)
        return masked
    if isinstance(data, list):
        return [_mask_sensitive(item) for item in data]
    return data


def _deep_merge(current: dict[str, Any], updates: dict[str, Any], prefix: str = "") -> list[str]:
    """Recursively merge ``updates`` into ``current``, tracking changed keys.

    Nested dictionaries are merged recursively. Sensitive keys whose value
    equals ``MASKED`` are skipped to prevent overwriting real secrets with
    the placeholder. Values are deep-copied before assignment.

    Args:
        current: The target dictionary to be mutated in place.
        updates: The source dictionary containing new or updated values.
        prefix: Dot-separated key prefix used for recursive tracking of
            nested key paths. Callers should not set this.

    Returns:
        A list of dot-separated key paths that were actually changed
        (e.g., ``["analysis.ai_max_tokens", "provider.api_key"]``).
    """
    changed: list[str] = []
    for key, value in updates.items():
        if not isinstance(key, str):
            continue
        full_key = f"{prefix}{key}"
        if key in current and isinstance(current[key], dict) and isinstance(value, dict):
            changed.extend(_deep_merge(current[key], value, f"{full_key}."))
            continue
        if key.lower() in SENSITIVE_KEYS and isinstance(value, str) and value == MASKED:
            continue
        if current.get(key) != value:
            current[key] = copy.deepcopy(value)
            changed.append(full_key)
    return changed


def _is_sensitive_path(path: str) -> bool:
    """Check whether a dot-separated configuration key path contains a sensitive segment.

    Args:
        path: Dot-separated key path (e.g., ``"provider.api_key"``).

    Returns:
        ``True`` if any segment of the path matches a key in ``SENSITIVE_KEYS``.
    """
    return any(segment.strip().lower() in SENSITIVE_KEYS for segment in path.split("."))


def _sanitize_changed_keys(changed_keys: list[str]) -> list[str]:
    """Sanitize a list of changed configuration key paths for audit logging.

    Deduplicates keys, strips whitespace, and appends ``"(redacted)"`` to
    any key path that contains a sensitive segment.

    Args:
        changed_keys: Raw list of dot-separated key paths from ``_deep_merge``.

    Returns:
        A deduplicated, sanitized list of key path strings safe for inclusion
        in audit log entries.
    """
    sanitized: list[str] = []
    for key in changed_keys:
        if not isinstance(key, str):
            continue
        normalized = key.strip()
        if not normalized:
            continue
        if _is_sensitive_path(normalized):
            normalized = f"{normalized} (redacted)"
        if normalized not in sanitized:
            sanitized.append(normalized)
    return sanitized


def _audit_config_change(changed_keys: list[str]) -> None:
    """Write a ``config_changed`` audit log entry to all active cases.

    This ensures that configuration changes (e.g., switching AI provider)
    are recorded in the forensic audit trail of every currently-active case.

    Args:
        changed_keys: List of dot-separated configuration key paths that
            were modified. Sensitive keys are redacted before logging.
    """
    sanitized_keys = _sanitize_changed_keys(changed_keys)
    if not sanitized_keys:
        return

    with STATE_LOCK:
        audit_loggers = [
            case.get("audit")
            for case in CASE_STATES.values()
            if isinstance(case, dict) and case.get("audit") is not None
        ]

    details = {
        "changed_keys": sanitized_keys,
        "changed_count": len(sanitized_keys),
    }
    for audit_logger in audit_loggers:
        try:
            audit_logger.log("config_changed", details)
        except Exception:
            LOGGER.exception("Failed to write config_changed audit entry.")


def _safe_int(value: Any, default: int = 0) -> int:
    """Safely convert a value to an integer, returning a default on failure.

    Args:
        value: Value to convert. May be ``None``, a string, a number, or
            any other type.
        default: Fallback integer to return when conversion fails.
            Defaults to ``0``.

    Returns:
        The integer representation of ``value``, or ``default`` if conversion
        raises ``TypeError`` or ``ValueError``.
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _close_forensic_parser(parser: Any) -> None:
    """Safely close a ``ForensicParser`` instance, suppressing any errors.

    Checks for a callable ``close`` method on the parser and invokes it.
    Any exceptions raised during closing are logged but not propagated,
    ensuring cleanup always completes.

    Args:
        parser: A ``ForensicParser`` instance (or any object with an
            optional ``close()`` method).
    """
    close_method = getattr(parser, "close", None)
    if not callable(close_method):
        return

    try:
        close_method()
    except Exception:
        LOGGER.exception("Failed to close forensic parser.")


def _validate_analysis_date_range(
    payload: Any,
) -> dict[str, str] | None:
    """Validate and normalize an optional analysis date range from request payload.

    Ensures both ``start_date`` and ``end_date`` are present and in
    ``YYYY-MM-DD`` format, and that the start date does not exceed the end
    date.

    Args:
        payload: Raw value from the request JSON under the
            ``"analysis_date_range"`` key. Expected to be ``None`` or a dict
            with ``"start_date"`` and ``"end_date"`` string values.

    Returns:
        A dictionary with ISO-formatted ``"start_date"`` and ``"end_date"``
        strings, or ``None`` if no date range was provided.

    Raises:
        ValueError: If the payload is not a dict, dates are not in the correct
            format, only one boundary is provided, or start exceeds end.
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


def _extract_parse_progress(fallback_artifact: str, args: tuple[Any, ...]) -> tuple[str, int]:
    """Extract artifact key and record count from a parser progress callback's arguments.

    The parser progress callback may be invoked with varying signatures:
    a single dict, two positional arguments, or a single integer count.
    This function normalizes all variants.

    Args:
        fallback_artifact: Artifact key to use if one cannot be extracted
            from the callback arguments.
        args: Positional arguments received by the progress callback.

    Returns:
        A tuple of ``(artifact_key, record_count)``.
    """
    if not args:
        return fallback_artifact, 0
    first = args[0]
    if isinstance(first, dict):
        return str(first.get("artifact_key", fallback_artifact)), _safe_int(first.get("record_count", 0))
    if len(args) >= 2:
        return str(args[0] or fallback_artifact), _safe_int(args[1], 0)
    return fallback_artifact, _safe_int(first, 0)


def _sanitize_prompt(prompt: str, max_chars: int = 2000) -> str:
    """Normalize and truncate a user-provided prompt for safe audit logging.

    Collapses all whitespace runs to single spaces and truncates the result
    to ``max_chars``, appending a ``"... [truncated]"`` indicator if needed.

    Args:
        prompt: Raw user prompt text.
        max_chars: Maximum character length before truncation. Defaults to 2000.

    Returns:
        The normalized (and possibly truncated) prompt string.
    """
    normalized = " ".join(prompt.split())
    if len(normalized) <= max_chars:
        return normalized
    return f"{normalized[:max_chars]}... [truncated]"


def _normalize_artifact_mode(value: Any, default_mode: str = MODE_PARSE_AND_AI) -> str:
    """Normalize an artifact processing mode string to one of the two valid constants.

    Args:
        value: Raw mode value from the request payload. May be ``None``, a
            string, or any other type coercible to string.
        default_mode: Mode to return when ``value`` does not match either
            valid mode. Defaults to ``MODE_PARSE_AND_AI``.

    Returns:
        Either ``MODE_PARSE_AND_AI`` or ``MODE_PARSE_ONLY``.
    """
    mode = str(value or "").strip().lower()
    if mode == MODE_PARSE_ONLY:
        return MODE_PARSE_ONLY
    if mode == MODE_PARSE_AND_AI:
        return MODE_PARSE_AND_AI
    return default_mode


def _normalize_string_list(values: Any) -> list[str]:
    """Deduplicate and normalize a list of values into a list of non-empty strings.

    Each element is converted to a stripped string. Empty strings and
    duplicates are removed while preserving insertion order.

    Args:
        values: Input list (or non-list value, which returns an empty list).

    Returns:
        A deduplicated list of non-empty, stripped strings.
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


def _normalize_artifact_options(payload: Any) -> list[dict[str, str]]:
    """Normalize a raw artifact options payload into a canonical list of option dicts.

    Accepts multiple input formats for backwards compatibility:

    * A list of strings (artifact keys, all default to ``MODE_PARSE_AND_AI``).
    * A list of dicts with ``"artifact_key"``/``"key"``, and optionally ``"mode"``,
      ``"ai_enabled"``, or ``"parse_mode"`` fields.

    Deduplicates by artifact key, preserving first occurrence.

    Args:
        payload: Raw ``"artifact_options"`` value from the request JSON.

    Returns:
        A list of dicts, each with ``"artifact_key"`` (str) and ``"mode"``
        (str, one of ``MODE_PARSE_AND_AI`` or ``MODE_PARSE_ONLY``).

    Raises:
        ValueError: If ``payload`` is not a list.
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
                mode = _normalize_artifact_mode(item.get("mode"))
            elif "ai_enabled" in item:
                mode = MODE_PARSE_AND_AI if bool(item.get("ai_enabled")) else MODE_PARSE_ONLY
            else:
                mode = _normalize_artifact_mode(item.get("parse_mode"), default_mode=MODE_PARSE_AND_AI)
        else:
            continue

        if not artifact_key or artifact_key in seen:
            continue
        seen.add(artifact_key)
        normalized.append({"artifact_key": artifact_key, "mode": mode})

    return normalized


def _artifact_options_to_lists(artifact_options: list[dict[str, str]]) -> tuple[list[str], list[str]]:
    """Split normalized artifact options into separate parse and analysis lists.

    Args:
        artifact_options: Canonical list of artifact option dicts as produced
            by ``_normalize_artifact_options``.

    Returns:
        A tuple of ``(parse_artifacts, analysis_artifacts)`` where
        ``parse_artifacts`` contains all artifact keys and
        ``analysis_artifacts`` contains only those with mode
        ``MODE_PARSE_AND_AI``.
    """
    parse_artifacts: list[str] = []
    analysis_artifacts: list[str] = []
    for option in artifact_options:
        artifact_key = str(option.get("artifact_key", "")).strip()
        if not artifact_key:
            continue
        parse_artifacts.append(artifact_key)
        if _normalize_artifact_mode(option.get("mode")) == MODE_PARSE_AND_AI:
            analysis_artifacts.append(artifact_key)
    return parse_artifacts, analysis_artifacts


def _build_artifact_options_from_lists(
    parse_artifacts: list[str],
    analysis_artifacts: list[str],
) -> list[dict[str, str]]:
    """Construct canonical artifact options from separate parse and analysis lists.

    This is the inverse of ``_artifact_options_to_lists``, used when the
    request payload provides the legacy ``"artifacts"`` / ``"ai_artifacts"``
    format instead of the unified ``"artifact_options"`` format.

    Args:
        parse_artifacts: List of all artifact keys to be parsed.
        analysis_artifacts: Subset of artifact keys that should also be
            included in AI analysis.

    Returns:
        A list of dicts with ``"artifact_key"`` and ``"mode"`` fields.
    """
    analysis_set = set(analysis_artifacts)
    return [
        {
            "artifact_key": artifact_key,
            "mode": MODE_PARSE_AND_AI if artifact_key in analysis_set else MODE_PARSE_ONLY,
        }
        for artifact_key in parse_artifacts
    ]


def _extract_parse_selection_payload(payload: dict[str, Any]) -> tuple[list[dict[str, str]], list[str], list[str]]:
    """Extract and normalize artifact selection from a parse request payload.

    Supports two payload formats:

    * **New format**: ``"artifact_options"`` -- a list of dicts with per-artifact
      mode settings.
    * **Legacy format**: ``"artifacts"`` (list of keys) and optional
      ``"ai_artifacts"`` (subset for AI analysis).

    Args:
        payload: Parsed JSON body from the parse start request.

    Returns:
        A tuple of ``(artifact_options, parse_artifacts, analysis_artifacts)``
        where ``artifact_options`` is the canonical form used internally.

    Raises:
        ValueError: If the payload contains invalid or non-list artifact
            fields.
    """
    if "artifact_options" in payload:
        artifact_options = _normalize_artifact_options(payload.get("artifact_options"))
        parse_artifacts, analysis_artifacts = _artifact_options_to_lists(artifact_options)
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


def _recommended_artifact_options() -> list[dict[str, str]]:
    """Build the artifact options list for the built-in 'recommended' profile.

    Includes all artifacts from ``ARTIFACT_REGISTRY`` except those listed in
    ``RECOMMENDED_PROFILE_EXCLUDED_ARTIFACTS`` (large-output artifacts like
    MFT, USN Journal, and full EVTX). All included artifacts are set to
    ``MODE_PARSE_AND_AI``.

    Returns:
        A list of artifact option dicts for the recommended profile.
    """
    profile: list[dict[str, str]] = []
    for artifact_key in ARTIFACT_REGISTRY:
        normalized_key = str(artifact_key).strip().lower()
        if normalized_key in RECOMMENDED_PROFILE_EXCLUDED_ARTIFACTS:
            continue
        profile.append({"artifact_key": str(artifact_key), "mode": MODE_PARSE_AND_AI})
    return profile


def _resolve_profiles_root(config_path: str | Path) -> Path:
    """Resolve the filesystem directory where artifact profiles are stored.

    Profiles are stored in a subdirectory named ``PROFILE_DIRNAME`` alongside
    the application configuration file.

    Args:
        config_path: Path to the AIFT configuration file (e.g., ``config.yaml``).

    Returns:
        Absolute ``Path`` to the profiles directory.
    """
    path = Path(config_path)
    return path.parent / PROFILE_DIRNAME


def _recommended_profile_payload() -> dict[str, Any]:
    """Build the full JSON-serializable payload for the built-in recommended profile.

    Returns:
        A dictionary with ``"name"``, ``"builtin"`` (True), and
        ``"artifact_options"`` keys, ready for writing to disk.
    """
    return {
        "name": BUILTIN_RECOMMENDED_PROFILE,
        "builtin": True,
        "artifact_options": _recommended_artifact_options(),
    }


def _write_profile_file(path: Path, payload: dict[str, Any]) -> None:
    """Write an artifact profile payload to a JSON file on disk.

    Creates parent directories as needed. The file is written with a trailing
    newline for POSIX compatibility.

    Args:
        path: Destination file path for the profile JSON.
        payload: Profile data to serialize (must be JSON-serializable).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(payload, indent=2, ensure_ascii=True)
    path.write_text(f"{content}\n", encoding="utf-8")


def _load_profile_file(path: Path) -> dict[str, Any] | None:
    """Load and validate a single artifact profile from a JSON file.

    Performs validation of the profile name (against ``PROFILE_NAME_RE``),
    normalizes artifact options, and handles the special ``recommended``
    built-in profile. Invalid or unreadable profiles are logged and skipped.

    Args:
        path: Path to the profile JSON file.

    Returns:
        A validated profile dict with ``"name"``, ``"builtin"``,
        ``"artifact_options"``, and ``"path"`` keys, or ``None`` if the
        file is invalid or unreadable.
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
        artifact_options = _normalize_artifact_options(options_payload if options_payload is not None else [])
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
    """Ensure the built-in recommended profile file exists on disk.

    Overwrites any existing file at the recommended profile path to keep
    it synchronized with the current ``ARTIFACT_REGISTRY``.

    Args:
        profiles_root: Directory where profile JSON files are stored.
    """
    recommended_path = profiles_root / f"{BUILTIN_RECOMMENDED_PROFILE}{PROFILE_FILE_SUFFIX}"
    _write_profile_file(recommended_path, _recommended_profile_payload())


def _load_profiles_from_directory(profiles_root: Path) -> list[dict[str, Any]]:
    """Load all valid artifact profiles from the profiles directory.

    Creates the directory if it does not exist, ensures the recommended
    built-in profile is present, then loads and validates all ``*.json``
    files. Profiles are deduplicated by name (case-insensitive) and sorted
    with the recommended profile first, followed by alphabetical order.

    Args:
        profiles_root: Directory containing profile JSON files.

    Returns:
        A sorted list of validated profile dictionaries.
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


def _profile_path_for_new_name(profiles_root: Path, profile_name: str) -> Path:
    """Compute a unique file path for a new artifact profile.

    Derives a filesystem-safe stem from the profile name and appends a
    numeric suffix if the candidate path already exists.

    Args:
        profiles_root: Directory where profile JSON files are stored.
        profile_name: Human-readable name of the new profile.

    Returns:
        A ``Path`` to a non-existent file suitable for writing the profile.
    """
    stem = _safe_name(profile_name.lower(), fallback="profile")
    candidate = profiles_root / f"{stem}{PROFILE_FILE_SUFFIX}"
    if not candidate.exists():
        return candidate

    index = 1
    while True:
        candidate = profiles_root / f"{stem}_{index}{PROFILE_FILE_SUFFIX}"
        if not candidate.exists():
            return candidate
        index += 1


def _normalize_profile_name(value: Any) -> str:
    """Validate and normalize a profile name from user input.

    Strips whitespace, rejects the reserved ``recommended`` name, and
    validates against ``PROFILE_NAME_RE``.

    Args:
        value: Raw profile name from the request payload.

    Returns:
        The stripped, validated profile name string.

    Raises:
        ValueError: If the name is empty, matches the reserved built-in
            profile name, or fails regex validation.
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


def _compose_profile_response(profiles_root: Path) -> list[dict[str, Any]]:
    """Build the API response payload for all artifact profiles.

    Loads profiles from disk, strips internal fields (like ``path``), and
    returns a list of JSON-serializable profile dictionaries.

    Args:
        profiles_root: Directory containing profile JSON files.

    Returns:
        A list of dicts, each with ``"name"``, ``"builtin"``, and
        ``"artifact_options"`` keys.
    """
    return [
        {
            "name": str(profile.get("name", "")).strip(),
            "builtin": bool(profile.get("builtin", False)),
            "artifact_options": list(profile.get("artifact_options", [])),
        }
        for profile in _load_profiles_from_directory(profiles_root)
    ]


def _build_csv_map(parse_results: list[dict[str, Any]]) -> dict[str, str]:
    """Build a mapping of artifact keys to their parsed CSV file paths.

    Iterates over parse results and extracts the first available CSV path
    for each successfully parsed artifact.

    Args:
        parse_results: List of per-artifact parse result dicts, each
            containing ``"artifact_key"``, ``"success"``, and either
            ``"csv_path"`` or ``"csv_paths"``.

    Returns:
        A dictionary mapping artifact key strings to CSV file path strings.
    """
    mapping: dict[str, str] = {}
    for result in parse_results:
        artifact = str(result.get("artifact_key", "")).strip()
        if not artifact or not result.get("success"):
            continue
        csv_path = str(result.get("csv_path", "")).strip()
        if csv_path:
            mapping[artifact] = csv_path
            continue
        csv_paths = result.get("csv_paths")
        if isinstance(csv_paths, list) and csv_paths:
            mapping[artifact] = str(csv_paths[0])
    return mapping


def _stream_sse(store: dict[str, dict[str, Any]], case_id: str) -> Response:
    """Create an SSE streaming ``Response`` that polls a progress event store.

    Yields ``data:`` frames containing JSON-serialized events from the
    specified store. The stream terminates when the store's status reaches
    a terminal state (completed, failed, error) or an idle timeout expires.

    Args:
        store: One of ``PARSE_PROGRESS``, ``ANALYSIS_PROGRESS``, or
            ``CHAT_PROGRESS``.
        case_id: UUID of the case whose events to stream.

    Returns:
        A Flask ``Response`` with ``text/event-stream`` MIME type.
    """
    @stream_with_context
    def stream() -> Any:
        """Generate SSE data frames by polling the progress event store."""
        last = 0
        initial_idle_deadline = time.monotonic() + SSE_INITIAL_IDLE_GRACE_SECONDS
        while True:
            with STATE_LOCK:
                state = store.get(case_id)
                if state is None:
                    missing = {"type": "error", "message": "Case not found."}
                    status = "failed"
                    pending: list[dict[str, Any]] = [missing]
                else:
                    status = str(state.get("status", "idle"))
                    events = list(state.get("events", []))
                    pending = events[last:]
                    last = len(events)

            if not pending and status == "idle":
                if time.monotonic() < initial_idle_deadline:
                    yield ": keep-alive\n\n"
                    time.sleep(SSE_POLL_INTERVAL_SECONDS)
                    continue
                idle = {"type": "idle", "status": "idle"}
                yield f"data: {json.dumps(idle, separators=(',', ':'))}\n\n"
                break

            for event in pending:
                yield f"data: {json.dumps(event, separators=(',', ':'))}\n\n"

            if status in {"completed", "failed", "error"} and not pending:
                break

            if not pending:
                yield ": keep-alive\n\n"
            time.sleep(SSE_POLL_INTERVAL_SECONDS)

    return Response(
        stream(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


def _get_case(case_id: str) -> dict[str, Any] | None:
    """Retrieve the in-memory state dictionary for a case.

    Thread-safe: acquires ``STATE_LOCK`` before reading.

    Args:
        case_id: UUID of the case to look up.

    Returns:
        The case state dictionary, or ``None`` if the case does not exist.
    """
    with STATE_LOCK:
        return CASE_STATES.get(case_id)


def _extract_archive_members(
    destination: Path,
    members: list[tuple[str, Any]],
    *,
    empty_message: str,
    unsafe_paths_message: str,
    no_files_message: str,
    extract_member: Callable[[Any, Path], None] | None = None,
    extract_all_members: Callable[[list[tuple[Any, Path]]], None] | None = None,
) -> Path:
    """Extract archive members safely and return the best Dissect target path.

    Validates that no extracted member escapes the destination directory
    (path traversal protection), extracts all members using the provided
    callback, then locates the best evidence file or directory for Dissect.

    Exactly one of ``extract_member`` or ``extract_all_members`` must be
    provided.

    Args:
        destination: Root directory to extract archive contents into.
        members: List of ``(member_name, member_object)`` tuples for each
            file in the archive.
        empty_message: Error message when the archive has no members.
        unsafe_paths_message: Error message when a member path escapes the
            destination directory.
        no_files_message: Error message when extraction produces no files.
        extract_member: Callback to extract a single member. Receives
            ``(member_object, target_path)``.
        extract_all_members: Callback to extract all members at once.
            Receives a list of ``(member_object, target_path)`` tuples.

    Returns:
        Path to the best evidence file (preferring E01) or the extraction
        directory if no recognized evidence file is found.

    Raises:
        ValueError: If the archive is empty, contains unsafe paths, produces
            no files, or both/neither extraction callbacks are provided.
    """
    if (extract_member is None) == (extract_all_members is None):
        raise ValueError("Exactly one extraction callback must be provided.")

    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()

    if not members:
        raise ValueError(empty_message)

    validated_members: list[tuple[Any, Path]] = []
    for member_name, member in members:
        member_path = Path(member_name)
        target = (root / member_path).resolve()
        if not target.is_relative_to(root):
            raise ValueError(unsafe_paths_message)
        target.parent.mkdir(parents=True, exist_ok=True)
        validated_members.append((member, target))

    if extract_all_members is not None:
        extract_all_members(validated_members)
    else:
        for member, target in validated_members:
            extract_member(member, target)

    files = sorted(path for path in destination.rglob("*") if path.is_file())
    if not files:
        raise ValueError(no_files_message)
    evidence_files = [
        path for path in files if path.suffix.lower() in _EVIDENCE_FILE_EXTENSIONS
    ]
    if evidence_files:
        # Prefer E01 if present, otherwise return first match.
        for ef in evidence_files:
            if ef.suffix.lower() == ".e01":
                return ef
        return evidence_files[0]

    top_level_entries: set[str] = set()
    has_top_level_file = False
    for file_path in files:
        relative_parts = file_path.relative_to(destination).parts
        if not relative_parts:
            continue
        top_level_entries.add(relative_parts[0])
        if len(relative_parts) == 1:
            has_top_level_file = True

    if not has_top_level_file and len(top_level_entries) == 1:
        wrapper_dir = destination / sorted(top_level_entries)[0]
        if wrapper_dir.is_dir():
            return wrapper_dir

    return destination


def _extract_zip(zip_path: Path, destination: Path) -> Path:
    """Extract a ZIP archive and return the best Dissect target path.

    Args:
        zip_path: Path to the ZIP evidence file.
        destination: Directory to extract archive contents into.

    Returns:
        Path to the best evidence file or extraction directory for Dissect.

    Raises:
        ValueError: If the ZIP is invalid, empty, or contains unsafe paths.
    """
    try:
        with ZipFile(zip_path, "r") as archive:
            members = [(member.filename, member) for member in archive.infolist() if not member.is_dir()]

            def _extract_member(member: Any, target: Path) -> None:
                """Extract a single ZIP member to the target path."""
                with archive.open(member, "r") as src, target.open("wb") as dst:
                    shutil.copyfileobj(src, dst)
            return _extract_archive_members(
                destination,
                members,
                empty_message="Evidence ZIP is empty.",
                unsafe_paths_message="Evidence ZIP contains unsafe paths.",
                no_files_message="Evidence ZIP extraction produced no files.",
                extract_member=_extract_member,
            )
    except BadZipFile as error:
        raise ValueError(f"Invalid ZIP evidence file: {zip_path.name}") from error


def _extract_tar(tar_path: Path, destination: Path) -> Path:
    """Extract a tar (or tar.gz/tgz) archive and return the best Dissect target path.

    Args:
        tar_path: Path to the tar evidence file.
        destination: Directory to extract archive contents into.

    Returns:
        Path to the best evidence file or extraction directory for Dissect.

    Raises:
        ValueError: If the tar is invalid, empty, or contains unsafe paths.
    """
    try:
        with tarfile.open(tar_path, "r:*") as archive:
            members = [(member.name, member) for member in archive.getmembers() if member.isfile()]

            def _extract_member(member: Any, target: Path) -> None:
                """Extract a single tar member to the target path."""
                src = archive.extractfile(member)
                if src is None:
                    return
                with src, target.open("wb") as dst:
                    shutil.copyfileobj(src, dst)
            return _extract_archive_members(
                destination,
                members,
                empty_message="Evidence tar archive is empty.",
                unsafe_paths_message="Evidence tar archive contains unsafe paths.",
                no_files_message="Evidence tar extraction produced no files.",
                extract_member=_extract_member,
            )
    except tarfile.TarError as error:
        raise ValueError(f"Invalid tar evidence file: {tar_path.name}") from error


def _extract_7z(archive_path: Path, destination: Path) -> Path:
    """Extract a 7z archive and return the best Dissect target path.

    Args:
        archive_path: Path to the 7z evidence file.
        destination: Directory to extract archive contents into.

    Returns:
        Path to the best evidence file or extraction directory for Dissect.

    Raises:
        ValueError: If the 7z archive is invalid, empty, or contains unsafe paths.
    """
    try:
        with py7zr.SevenZipFile(archive_path, mode="r") as archive:
            members = [(name, name) for name in archive.getnames() if not name.endswith("/")]

            def _extract_members(_members: list[tuple[Any, Path]]) -> None:
                """Extract all 7z members to the destination directory."""
                archive.extractall(path=destination)

            return _extract_archive_members(
                destination,
                members,
                empty_message="Evidence 7z archive is empty.",
                unsafe_paths_message="Evidence 7z archive contains unsafe paths.",
                no_files_message="Evidence 7z extraction produced no files.",
                extract_all_members=_extract_members,
            )
    except py7zr.Bad7zFile as error:
        raise ValueError(f"Invalid 7z evidence file: {archive_path.name}") from error


def _collect_uploaded_files() -> list[Any]:
    """Collect all uploaded file storage objects from the current Flask request.

    Iterates over all keys in ``request.files`` and gathers every
    ``FileStorage`` object that has a non-empty filename.

    Returns:
        A list of ``werkzeug.datastructures.FileStorage`` objects.
    """
    uploaded: list[Any] = []
    for key in request.files:
        for file_storage in request.files.getlist(key):
            if file_storage and file_storage.filename:
                uploaded.append(file_storage)
    return uploaded


def _unique_destination(path: Path) -> Path:
    """Generate a unique file path by appending a numeric suffix if needed.

    If ``path`` does not already exist, it is returned as-is. Otherwise,
    a ``_1``, ``_2``, etc. suffix is appended to the stem until a
    non-existing candidate is found.

    Args:
        path: Desired file path that may already exist.

    Returns:
        A ``Path`` guaranteed not to exist on disk.
    """
    if not path.exists():
        return path

    counter = 1
    while True:
        candidate = path.with_name(f"{path.stem}_{counter}{path.suffix}")
        if not candidate.exists():
            return candidate
        counter += 1


def _resolve_uploaded_dissect_path(uploaded_paths: list[Path]) -> Path:
    """Determine the primary Dissect target path from a list of uploaded files.

    Handles single files, split EWF/raw segment sets, and rejects mixed
    archive-plus-segment uploads. For segment sets, returns the lowest-
    numbered segment (E01 for EWF, .000 for split raw).

    Args:
        uploaded_paths: List of paths to uploaded evidence files.

    Returns:
        The ``Path`` to pass to Dissect's ``Target.open()``.

    Raises:
        ValueError: If no files were uploaded or the upload contains both
            archive and segment files.
    """
    if not uploaded_paths:
        raise ValueError("No uploaded evidence files were provided.")

    if len(uploaded_paths) == 1:
        return uploaded_paths[0]

    archive_exts = {".zip", ".tar", ".gz", ".tgz", ".7z"}
    archive_paths = [path for path in uploaded_paths if path.suffix.lower() in archive_exts]
    if archive_paths and len(uploaded_paths) > 1:
        raise ValueError("Upload either one archive file or raw evidence segments, not both.")

    segment_groups: dict[str, list[tuple[int, Path]]] = {}
    for path in uploaded_paths:
        match = EWF_SEGMENT_RE.match(path.name) or SPLIT_RAW_SEGMENT_RE.match(path.name)
        if not match:
            continue
        base_name = match.group("base").lower()
        segment_number = int(match.group("segment"))
        segment_groups.setdefault(base_name, []).append((segment_number, path))

    if segment_groups:
        ordered_groups = sorted(
            segment_groups.values(),
            key=lambda group: (
                0 if any(segment <= 1 for segment, _ in group) else 1,
                -len(group),
                min(segment for segment, _ in group),
                min(path.name.lower() for _, path in group),
            ),
        )
        chosen_group = ordered_groups[0]
        # Return the lowest-numbered segment (E01=1, split raw=0).
        return min(chosen_group, key=lambda item: item[0])[1]

    return uploaded_paths[0]


def _normalize_user_path(value: str) -> str:
    """Strip surrounding quotes and whitespace from a user-supplied file path.

    Removes straight double quotes and Unicode left/right double quotes
    that users may inadvertently include when pasting paths.

    Args:
        value: Raw path string from user input.

    Returns:
        The cleaned path string.
    """
    return (
        str(value)
        .replace('"', "")
        .replace("\u201c", "")
        .replace("\u201d", "")
        .strip()
    )


def _resolve_evidence_payload(case_dir: Path) -> dict[str, Any]:
    """Resolve the evidence source from the current request and prepare it for Dissect.

    Handles two intake modes: multipart file upload and JSON path reference.
    For archive formats (ZIP, tar, 7z), the archive is extracted into the
    case's evidence directory and the best Dissect target path is located.

    Args:
        case_dir: Path to the case's root directory (contains ``evidence/``).

    Returns:
        A dictionary with keys ``"mode"`` (``"upload"`` or ``"path"``),
        ``"filename"``, ``"source_path"``, ``"stored_path"``,
        ``"dissect_path"``, and ``"uploaded_files"``.

    Raises:
        ValueError: If no evidence is provided, the path is invalid, or
            archive extraction fails.
        FileNotFoundError: If the referenced evidence path does not exist.
    """
    evidence_dir = case_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)

    uploaded_files = _collect_uploaded_files()
    uploaded_paths: list[Path] = []
    if uploaded_files:
        timestamp = int(time.time())
        for index, uploaded_file in enumerate(uploaded_files, start=1):
            filename = secure_filename(uploaded_file.filename) or f"evidence_{timestamp}_{index}.bin"
            stored_path = _unique_destination(evidence_dir / filename)
            uploaded_file.save(stored_path)
            uploaded_paths.append(stored_path)

        source_path = _resolve_uploaded_dissect_path(uploaded_paths)
        mode = "upload"
    else:
        payload = request.get_json(silent=True) or {}
        path_value = payload.get("path")
        if not isinstance(path_value, str):
            raise ValueError(
                "Provide evidence via multipart upload or JSON body with {'path': 'C:\\Evidence\\disk-image.E01'}."
            )
        normalized_path = _normalize_user_path(path_value)
        if not normalized_path:
            raise ValueError(
                "Provide evidence via multipart upload or JSON body with {'path': 'C:\\Evidence\\disk-image.E01'}."
            )
        source_path = Path(normalized_path).expanduser()
        if not source_path.exists():
            raise FileNotFoundError(f"Evidence path does not exist: {source_path}")
        if not source_path.is_file() and not source_path.is_dir():
            raise ValueError(f"Evidence path is not a file or directory: {source_path}")
        uploaded_paths = []
        mode = "path"

    dissect_path = source_path
    suffix = source_path.suffix.lower()
    if source_path.is_file() and suffix == ".zip":
        extract_dir = evidence_dir / f"extracted_{_safe_name(source_path.stem, 'evidence')}_{int(time.time())}"
        dissect_path = _extract_zip(source_path, extract_dir)
    elif source_path.is_file() and suffix in {".tar", ".gz", ".tgz"}:
        extract_dir = evidence_dir / f"extracted_{_safe_name(source_path.stem, 'evidence')}_{int(time.time())}"
        dissect_path = _extract_tar(source_path, extract_dir)
    elif source_path.is_file() and suffix == ".7z":
        extract_dir = evidence_dir / f"extracted_{_safe_name(source_path.stem, 'evidence')}_{int(time.time())}"
        dissect_path = _extract_7z(source_path, extract_dir)

    return {
        "mode": mode,
        "filename": source_path.name,
        "source_path": str(source_path),
        "stored_path": str(source_path) if mode == "upload" else "",
        "dissect_path": str(dissect_path),
        "uploaded_files": [str(path) for path in uploaded_paths],
    }


def _read_audit_entries(case_dir: Path) -> list[dict[str, Any]]:
    """Read all audit log entries from a case's ``audit.jsonl`` file.

    Parses each line as JSON, skipping blank lines and malformed entries.

    Args:
        case_dir: Path to the case's root directory.

    Returns:
        A list of parsed audit entry dictionaries in file order, or an
        empty list if the audit file does not exist.
    """
    audit_path = case_dir / "audit.jsonl"
    if not audit_path.exists():
        return []
    entries: list[dict[str, Any]] = []
    with audit_path.open("r", encoding="utf-8", errors="replace") as stream:
        for line in stream:
            text = line.strip()
            if not text:
                continue
            try:
                parsed = json.loads(text)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                entries.append(parsed)
    return entries


def _load_forensic_system_prompt() -> str:
    """Load the forensic AI system prompt from the ``prompts/`` directory.

    Falls back to ``DEFAULT_FORENSIC_SYSTEM_PROMPT`` if the file is
    missing, unreadable, or empty.

    Returns:
        The system prompt string for forensic analysis AI calls.
    """
    prompt_path = PROJECT_ROOT / "prompts" / "system_prompt.md"
    try:
        prompt_text = prompt_path.read_text(encoding="utf-8").strip()
    except OSError:
        LOGGER.warning("Failed to read system prompt from %s; using fallback prompt.", prompt_path)
        return DEFAULT_FORENSIC_SYSTEM_PROMPT
    return prompt_text or DEFAULT_FORENSIC_SYSTEM_PROMPT


def _load_case_analysis_results(case: dict[str, Any]) -> dict[str, Any] | None:
    """Load analysis results for a case from memory or disk.

    First checks the in-memory ``analysis_results`` field. If empty or
    absent, attempts to read from ``analysis_results.json`` on disk.

    Args:
        case: The in-memory case state dictionary.

    Returns:
        A dictionary of analysis results, or ``None`` if no results are
        available from either source.
    """
    in_memory = case.get("analysis_results")
    if isinstance(in_memory, dict) and in_memory:
        return dict(in_memory)

    results_path = Path(case["case_dir"]) / "analysis_results.json"
    if not results_path.exists():
        return dict(in_memory) if isinstance(in_memory, dict) else None

    try:
        parsed = json.loads(results_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        LOGGER.warning("Failed to load analysis results from %s", results_path, exc_info=True)
        return dict(in_memory) if isinstance(in_memory, dict) else None

    if isinstance(parsed, dict):
        return parsed
    return dict(in_memory) if isinstance(in_memory, dict) else None


def _resolve_case_investigation_context(case: dict[str, Any]) -> str:
    """Resolve the investigation context prompt for a case.

    Checks the in-memory ``investigation_context`` field first. If empty,
    falls back to reading ``prompt.txt`` from the case directory.

    Args:
        case: The in-memory case state dictionary.

    Returns:
        The investigation context string, or an empty string if none is
        available.
    """
    context = str(case.get("investigation_context", "")).strip()
    if context:
        return context

    prompt_path = Path(case["case_dir"]) / "prompt.txt"
    if not prompt_path.exists():
        return ""

    try:
        return prompt_path.read_text(encoding="utf-8")
    except OSError:
        LOGGER.warning("Failed to read investigation context prompt at %s", prompt_path, exc_info=True)
        return ""


def _resolve_case_parsed_dir(case: dict[str, Any]) -> Path:
    """Resolve the directory containing parsed CSV files for a case.

    Checks the in-memory ``csv_output_dir`` field, then infers from
    existing CSV paths, and finally falls back to ``<case_dir>/parsed``.

    Args:
        case: The in-memory case state dictionary.

    Returns:
        Path to the directory containing the case's parsed CSV files.
    """
    csv_output_dir = str(case.get("csv_output_dir", "")).strip()
    if csv_output_dir:
        return Path(csv_output_dir)

    csv_paths = _collect_case_csv_paths(case)
    if csv_paths:
        return csv_paths[0].parent

    return Path(case["case_dir"]) / "parsed"


def _render_chat_messages_for_provider(messages: list[dict[str, str]]) -> str:
    """Render a list of chat messages into a single prompt string for the AI provider.

    Formats the first user message as a ``Context Block``, the last user
    message as ``New User Question``, and intermediate messages with their
    role labels. System messages are skipped.

    Args:
        messages: Ordered list of message dicts, each with ``"role"`` and
            ``"content"`` keys.

    Returns:
        A formatted multi-section string suitable for sending to the AI
        provider as a single prompt.
    """
    rendered_sections: list[str] = []
    first_user_rendered = False
    last_user_index = -1
    for index, message in enumerate(messages):
        role = str(message.get("role", "")).strip().lower()
        content = str(message.get("content", "")).strip()
        if role == "user" and content:
            last_user_index = index

    for index, message in enumerate(messages):
        role = str(message.get("role", "")).strip().lower()
        content = str(message.get("content", "")).strip()
        if not content or role == "system":
            continue

        if role == "user" and not first_user_rendered:
            rendered_sections.append(f"Context Block:\n{content}")
            first_user_rendered = True
            continue

        if role == "user" and index == last_user_index:
            rendered_sections.append(f"New User Question:\n{content}")
            continue

        label = "User" if role == "user" else "Assistant" if role == "assistant" else role.title()
        rendered_sections.append(f"{label}:\n{content}")

    return "\n\n".join(rendered_sections).strip()


_COMPRESS_FINDINGS_FALLBACK_PROMPT = (
    "You are a forensic analysis assistant. Compress per-artifact findings "
    "while preserving all critical forensic details. Return only the "
    "compressed text in bullet-point format, no preamble."
)


def _load_compress_findings_prompt() -> str:
    """Load the prompt used to compress per-artifact findings with AI.

    Falls back to ``_COMPRESS_FINDINGS_FALLBACK_PROMPT`` if the prompt
    file is missing, unreadable, or empty.

    Returns:
        The system prompt string for the findings compression AI call.
    """
    prompt_path = PROJECT_ROOT / "prompts" / "compress_findings.md"
    try:
        prompt_text = prompt_path.read_text(encoding="utf-8").strip()
    except OSError:
        LOGGER.warning("Failed to read compress findings prompt from %s; using fallback.", prompt_path)
        return _COMPRESS_FINDINGS_FALLBACK_PROMPT
    return prompt_text or _COMPRESS_FINDINGS_FALLBACK_PROMPT


def _compress_findings_with_ai(
    provider: Any,
    findings_text: str,
    max_tokens: int,
) -> str | None:
    """Use the AI provider to compress per-artifact findings.

    Sends the full findings text to the AI with a compression prompt,
    targeting roughly 25% of the configured max tokens. Falls back
    gracefully on failure so the caller can use the uncompressed context.

    Args:
        provider: An initialized AI provider instance with an ``analyze``
            method.
        findings_text: The full per-artifact findings text to compress.
        max_tokens: The configured maximum token budget, used to calculate
            the compression target.

    Returns:
        The compressed findings text, or ``None`` if compression fails or
        the input is empty.
    """
    if not findings_text or not findings_text.strip():
        return None

    target_tokens = max(200, int(max_tokens * 0.25))
    try:
        compressed = provider.analyze(
            system_prompt=_load_compress_findings_prompt(),
            user_prompt=(
                f"Compress the following per-artifact forensic findings to "
                f"roughly {target_tokens} tokens. Keep the bullet-point "
                f"format (\"- artifact: summary\"). Preserve every "
                f"suspicious indicator, timestamp, path, and conclusion.\n\n"
                f"{findings_text}"
            ),
            max_tokens=target_tokens,
        )
        result = str(compressed).strip()
        return result if result else None
    except (AIProviderError, Exception):
        LOGGER.warning(
            "AI-powered findings compression failed; falling back to full context.",
            exc_info=True,
        )
        return None


def _resolve_chat_max_tokens(config: dict[str, Any]) -> int:
    """Resolve the maximum token count for chat from the application config.

    Reads ``analysis.ai_max_tokens`` from the config and validates it is
    a positive integer.

    Args:
        config: The full application configuration dictionary.

    Returns:
        The resolved positive integer token limit.

    Raises:
        ValueError: If the token setting is missing, non-numeric, or not
            a positive integer.
    """
    analysis_config = config.get("analysis", {})
    if not isinstance(analysis_config, dict):
        raise ValueError(
            "Chat max tokens are not configured. Set `analysis.ai_max_tokens` in Settings."
        )

    if "ai_max_tokens" not in analysis_config:
        raise ValueError(
            "Chat max tokens are not configured. Set `analysis.ai_max_tokens` in Settings."
        )

    try:
        resolved = int(analysis_config.get("ai_max_tokens"))
    except (TypeError, ValueError):
        raise ValueError(
            "Invalid `analysis.ai_max_tokens` value in Settings. Provide a positive integer."
        ) from None

    if resolved <= 0:
        raise ValueError(
            "Invalid `analysis.ai_max_tokens` value in Settings. Provide a positive integer."
        )
    return resolved


def _resolve_hash_verification_path(case: dict[str, Any]) -> Path | None:
    """Resolve the file path to use for evidence hash verification.

    Checks ``source_path`` first, then falls back to ``evidence_path``.

    Args:
        case: The in-memory case state dictionary.

    Returns:
        A ``Path`` to the evidence file for hash verification, or ``None``
        if neither source is available.
    """
    source_path = str(case.get("source_path", "")).strip()
    if source_path:
        return Path(source_path)

    evidence_path = str(case.get("evidence_path", "")).strip()
    if evidence_path:
        return Path(evidence_path)

    return None


def _resolve_case_csv_output_dir(case: dict[str, Any], config_snapshot: dict[str, Any]) -> Path:
    """Resolve the output directory for parsed CSV files.

    Uses the ``evidence.csv_output_dir`` config setting if present,
    appending the case ID as a subdirectory. Falls back to
    ``<case_dir>/parsed``.

    Args:
        case: The in-memory case state dictionary.
        config_snapshot: A snapshot of the application configuration.

    Returns:
        Absolute ``Path`` to the CSV output directory for this case.
    """
    config = config_snapshot if isinstance(config_snapshot, dict) else {}
    evidence_config = config.get("evidence", {}) if isinstance(config, dict) else {}
    configured = str(evidence_config.get("csv_output_dir", "")).strip() if isinstance(evidence_config, dict) else ""
    case_dir = Path(case["case_dir"])
    case_id = str(case.get("case_id", "")).strip()

    if not configured:
        return case_dir / "parsed"

    output_root = Path(configured).expanduser()
    if not output_root.is_absolute():
        output_root = (PROJECT_ROOT / output_root).resolve()
    if case_id:
        return output_root / case_id / "parsed"
    return output_root / "parsed"


def _collect_case_csv_paths(case: dict[str, Any]) -> list[Path]:
    """Collect all parsed CSV file paths for a case.

    Gathers paths from ``artifact_csv_paths``, ``parse_results``, and
    falls back to globbing ``<case_dir>/parsed/*.csv``. Results are
    deduplicated and sorted by filename.

    Args:
        case: The in-memory case state dictionary.

    Returns:
        A sorted list of existing CSV file ``Path`` objects.
    """
    collected: list[Path] = []
    seen: set[str] = set()

    def _add_path(candidate: Any) -> None:
        """Add a CSV path to the collection if it exists and is not a duplicate."""
        path_text = str(candidate or "").strip()
        if not path_text:
            return
        path = Path(path_text)
        if not path.exists() or not path.is_file():
            return
        key = str(path.resolve())
        if key in seen:
            return
        seen.add(key)
        collected.append(path)

    csv_map = case.get("artifact_csv_paths")
    if isinstance(csv_map, dict):
        for csv_path in csv_map.values():
            _add_path(csv_path)

    parse_results = case.get("parse_results")
    if isinstance(parse_results, list):
        for result in parse_results:
            if not isinstance(result, dict) or not result.get("success"):
                continue
            _add_path(result.get("csv_path"))
            csv_paths = result.get("csv_paths")
            if isinstance(csv_paths, list):
                for path in csv_paths:
                    _add_path(path)

    if collected:
        return sorted(collected, key=lambda path: path.name.lower())

    parsed_dir = Path(case["case_dir"]) / "parsed"
    fallback = sorted(path for path in parsed_dir.glob("*.csv") if path.is_file())
    return fallback


def _run_parse(
    case_id: str,
    parse_artifacts: list[str],
    analysis_artifacts: list[str],
    artifact_options: list[dict[str, str]],
    config_snapshot: dict[str, Any],
) -> None:
    """Execute background parsing of selected forensic artifacts.

    Opens a ``ForensicParser`` for the case's evidence, iterates over
    each artifact, emits SSE progress events, and stores results in the
    case's in-memory state. On failure, marks the case as errored and
    emits a failure event.

    Args:
        case_id: UUID of the case to parse.
        parse_artifacts: List of artifact keys to parse.
        analysis_artifacts: Subset of artifact keys to include in AI
            analysis.
        artifact_options: Canonical artifact option dicts with per-artifact
            mode settings.
        config_snapshot: Deep copy of the application config at the time
            parsing was initiated.
    """
    case = _get_case(case_id)
    if case is None:
        _set_progress_status(PARSE_PROGRESS, case_id, "failed", "Case not found.")
        _emit_progress(PARSE_PROGRESS, case_id, {"type": "parse_failed", "error": "Case not found."})
        return

    with STATE_LOCK:
        evidence_path = str(case.get("evidence_path", "")).strip()
        case_dir = case["case_dir"]
        audit_logger = case["audit"]
        case_snapshot = dict(case)

    if not evidence_path:
        _mark_case_status(case_id, "failed")
        _set_progress_status(PARSE_PROGRESS, case_id, "failed", "No evidence available for parsing.")
        _emit_progress(
            PARSE_PROGRESS,
            case_id,
            {"type": "parse_failed", "error": "No evidence available for parsing."},
        )
        return

    parser: Any | None = None
    try:
        csv_output_dir = _resolve_case_csv_output_dir(case_snapshot, config_snapshot=config_snapshot)
        parser = ForensicParser(
            evidence_path=evidence_path,
            case_dir=case_dir,
            audit_logger=audit_logger,
            parsed_dir=csv_output_dir,
        )
        results: list[dict[str, Any]] = []
        total = len(parse_artifacts)

        for index, artifact in enumerate(parse_artifacts, start=1):
            _emit_progress(
                PARSE_PROGRESS,
                case_id,
                {"type": "artifact_started", "artifact_key": artifact, "index": index, "total": total},
            )

            def _progress_callback(*args: Any, **_kwargs: Any) -> None:
                """Emit per-artifact parse progress events to the SSE store."""
                artifact_key, record_count = _extract_parse_progress(artifact, args)
                _emit_progress(
                    PARSE_PROGRESS,
                    case_id,
                    {"type": "artifact_progress", "artifact_key": artifact_key, "record_count": record_count},
                )

            result = parser.parse_artifact(artifact, progress_callback=_progress_callback)
            result_entry = {"artifact_key": artifact, **result}
            results.append(result_entry)

            _emit_progress(
                PARSE_PROGRESS,
                case_id,
                {
                    "type": "artifact_completed" if result.get("success") else "artifact_failed",
                    "artifact_key": artifact,
                    "record_count": _safe_int(result.get("record_count", 0)),
                    "duration_seconds": float(result.get("duration_seconds", 0.0)),
                    "csv_path": str(result.get("csv_path", "")),
                    "error": result.get("error"),
                },
            )

        csv_map = _build_csv_map(results)
        with STATE_LOCK:
            case["selected_artifacts"] = list(parse_artifacts)
            case["analysis_artifacts"] = list(analysis_artifacts)
            case["artifact_options"] = list(artifact_options)
            case["parse_results"] = results
            case["artifact_csv_paths"] = csv_map
            case["csv_output_dir"] = str(csv_output_dir)

        completed = sum(1 for item in results if item.get("success"))
        failed = len(results) - completed
        _set_progress_status(PARSE_PROGRESS, case_id, "completed")
        _emit_progress(
            PARSE_PROGRESS,
            case_id,
            {
                "type": "parse_completed",
                "total_artifacts": len(results),
                "successful_artifacts": completed,
                "failed_artifacts": failed,
            },
        )
        _mark_case_status(case_id, "parsed")
    except Exception:
        LOGGER.exception("Background parse failed for case %s", case_id)
        user_message = (
            "Parsing failed due to an internal error. "
            "Check logs and retry after confirming the evidence file is readable."
        )
        _mark_case_status(case_id, "error")
        _set_progress_status(PARSE_PROGRESS, case_id, "failed", user_message)
        _emit_progress(PARSE_PROGRESS, case_id, {"type": "parse_failed", "error": user_message})
    finally:
        if parser is not None:
            _close_forensic_parser(parser)


def _run_analysis(case_id: str, prompt: str, config_snapshot: dict[str, Any]) -> None:
    """Execute background AI-powered forensic analysis of parsed artifacts.

    Creates a ``ForensicAnalyzer``, runs the full analysis pipeline,
    persists results to disk and in-memory state, and emits SSE progress
    events. On failure, marks the case as errored.

    Args:
        case_id: UUID of the case to analyze.
        prompt: Investigation context / user prompt describing what to
            look for in the evidence.
        config_snapshot: Deep copy of the application config at the time
            analysis was initiated.
    """
    case = _get_case(case_id)
    if case is None:
        _set_progress_status(ANALYSIS_PROGRESS, case_id, "failed", "Case not found.")
        _emit_progress(ANALYSIS_PROGRESS, case_id, {"type": "analysis_failed", "error": "Case not found."})
        return

    with STATE_LOCK:
        csv_map = dict(case.get("artifact_csv_paths", {}))
        parse_results_snapshot = list(case.get("parse_results", []))
        analysis_artifacts_state = case.get("analysis_artifacts")
        selected_artifacts_snapshot = list(case.get("selected_artifacts", []))
        case_dir = case["case_dir"]
        audit_logger = case["audit"]
        image_metadata_snapshot = dict(case.get("image_metadata", {}))
        artifact_options_snapshot = list(case.get("artifact_options", []))
        analysis_date_range = case.get("analysis_date_range")

    if not csv_map:
        csv_map = _build_csv_map(parse_results_snapshot)
    if isinstance(analysis_artifacts_state, list):
        artifacts = [str(item) for item in analysis_artifacts_state if str(item) in csv_map]
    else:
        artifacts = [item for item in selected_artifacts_snapshot if item in csv_map]
    if not artifacts and not isinstance(analysis_artifacts_state, list):
        artifacts = sorted(csv_map.keys())
    if not artifacts:
        message = (
            "No parsed CSV artifacts are marked `Parse and use in AI`."
            if isinstance(analysis_artifacts_state, list)
            else "No parsed CSV artifacts available."
        )
        _mark_case_status(case_id, "failed")
        _set_progress_status(ANALYSIS_PROGRESS, case_id, "failed", message)
        _emit_progress(
            ANALYSIS_PROGRESS,
            case_id,
            {"type": "analysis_failed", "error": message},
        )
        return

    try:
        analyzer = ForensicAnalyzer(
            case_dir=case_dir,
            config=config_snapshot,
            audit_logger=audit_logger,
            artifact_csv_paths=csv_map,
        )
        metadata = dict(image_metadata_snapshot)
        metadata["artifact_csv_paths"] = csv_map
        metadata["parse_results"] = parse_results_snapshot
        metadata["analysis_artifacts"] = list(artifacts)
        metadata["artifact_options"] = artifact_options_snapshot
        if isinstance(analysis_date_range, dict):
            metadata["analysis_date_range"] = {
                "start_date": str(analysis_date_range.get("start_date", "")).strip(),
                "end_date": str(analysis_date_range.get("end_date", "")).strip(),
            }

        def _analysis_progress(*args: Any) -> None:
            """Emit per-artifact analysis progress events to the SSE store."""
            artifact_key = ""
            status = ""
            result: dict[str, Any] = {}

            if len(args) >= 3:
                artifact_key = str(args[0])
                status = str(args[1])
                result_payload = args[2]
                if isinstance(result_payload, dict):
                    result = dict(result_payload)
            elif len(args) == 1 and isinstance(args[0], dict):
                payload = args[0]
                artifact_key = str(payload.get("artifact_key", ""))
                status = str(payload.get("status", ""))
                result_payload = payload.get("result")
                if isinstance(result_payload, dict):
                    result = dict(result_payload)
            else:
                return

            if status == "started":
                _emit_progress(
                    ANALYSIS_PROGRESS,
                    case_id,
                    {
                        "type": "artifact_analysis_started",
                        "artifact_key": artifact_key,
                        "result": result,
                    },
                )
                return

            if status == "thinking":
                _emit_progress(
                    ANALYSIS_PROGRESS,
                    case_id,
                    {
                        "type": "artifact_analysis_thinking",
                        "artifact_key": artifact_key,
                        "result": result,
                    },
                )
                return

            _emit_progress(
                ANALYSIS_PROGRESS,
                case_id,
                {
                    "type": "artifact_analysis_completed",
                    "artifact_key": artifact_key,
                    "status": status or "complete",
                    "result": result,
                },
            )

        output = analyzer.run_full_analysis(
            artifact_keys=artifacts,
            investigation_context=prompt,
            metadata=metadata,
            progress_callback=_analysis_progress,
        )
        analysis_results_path = Path(case_dir) / "analysis_results.json"
        with analysis_results_path.open("w", encoding="utf-8") as analysis_results_file:
            json.dump(output, analysis_results_file, indent=2, ensure_ascii=True)
            analysis_results_file.write("\n")
        with STATE_LOCK:
            case["investigation_context"] = prompt
            case["analysis_results"] = output

        _emit_progress(
            ANALYSIS_PROGRESS,
            case_id,
            {
                "type": "analysis_summary",
                "summary": str(output.get("summary", "")),
                "model_info": output.get("model_info", {}),
            },
        )
        _set_progress_status(ANALYSIS_PROGRESS, case_id, "completed")
        _emit_progress(
            ANALYSIS_PROGRESS,
            case_id,
            {
                "type": "analysis_completed",
                "artifact_count": len(output.get("per_artifact", [])),
                "per_artifact": list(output.get("per_artifact", [])),
            },
        )
        _mark_case_status(case_id, "completed")
    except Exception:
        LOGGER.exception("Background analysis failed for case %s", case_id)
        user_message = (
            "Analysis failed due to an internal error. "
            "Verify provider settings and retry."
        )
        _mark_case_status(case_id, "error")
        _set_progress_status(ANALYSIS_PROGRESS, case_id, "failed", user_message)
        _emit_progress(ANALYSIS_PROGRESS, case_id, {"type": "analysis_failed", "error": user_message})


def _run_chat(case_id: str, message: str, config_snapshot: dict[str, Any]) -> None:
    """Execute a background chat interaction with the AI about analysis results.

    Builds the conversation context from analysis results and chat history,
    optionally compresses findings if they exceed the token budget, streams
    AI response tokens as SSE events, and persists the exchange to chat
    history.

    Args:
        case_id: UUID of the case for the chat session.
        message: The user's chat message / question.
        config_snapshot: Deep copy of the application config at the time
            the chat was initiated.
    """
    case = _get_case(case_id)
    if case is None:
        _set_progress_status(CHAT_PROGRESS, case_id, "failed", "Case not found.")
        _emit_progress(CHAT_PROGRESS, case_id, {"type": "error", "message": "Case not found."})
        return

    with STATE_LOCK:
        case_snapshot = dict(case)
        audit_logger = case["audit"]

    analysis_results = _load_case_analysis_results(case_snapshot)
    if not analysis_results:
        message_text = "No analysis results available for this case. Run analysis first."
        _set_progress_status(CHAT_PROGRESS, case_id, "failed", message_text)
        _emit_progress(CHAT_PROGRESS, case_id, {"type": "error", "message": message_text})
        return

    if not isinstance(config_snapshot, dict):
        _set_progress_status(CHAT_PROGRESS, case_id, "failed", "Invalid in-memory configuration state.")
        _emit_progress(
            CHAT_PROGRESS,
            case_id,
            {"type": "error", "message": "Invalid in-memory configuration state."},
        )
        return

    try:
        chat_max_tokens = _resolve_chat_max_tokens(config_snapshot)
    except ValueError as error:
        message_text = str(error)
        LOGGER.warning("Chat configuration rejected for case %s: %s", case_id, message_text)
        _set_progress_status(CHAT_PROGRESS, case_id, "failed", message_text)
        _emit_progress(CHAT_PROGRESS, case_id, {"type": "error", "message": message_text})
        return

    case_dir = case_snapshot["case_dir"]
    chat_manager = ChatManager(case_dir, max_context_tokens=chat_max_tokens)
    history_snapshot = chat_manager.get_history()
    message_index = (
        sum(1 for entry in history_snapshot if str(entry.get("role", "")).strip().lower() == "user") + 1
    )
    audit_logger.log(
        "chat_message_sent",
        {
            "message_index": message_index,
            "message": _sanitize_prompt(message, max_chars=8000),
        },
    )

    try:
        # Reserve 20% of the token budget for the AI response.
        prompt_budget = int(chat_max_tokens * 0.8)

        provider = create_provider(copy.deepcopy(config_snapshot))

        investigation_context = _resolve_case_investigation_context(case_snapshot)
        image_metadata = dict(case_snapshot.get("image_metadata", {}))

        context_block = chat_manager.build_chat_context(
            analysis_results=analysis_results,
            investigation_context=investigation_context,
            metadata=image_metadata,
        )

        # Compress per-artifact findings with AI when context exceeds budget.
        if chat_manager.context_needs_compression(context_block, prompt_budget):
            per_artifact_text = chat_manager._format_per_artifact_findings(
                analysis_results if isinstance(analysis_results, Mapping) else {},
            )
            compressed = _compress_findings_with_ai(provider, per_artifact_text, chat_max_tokens)
            if compressed:
                context_block = chat_manager.rebuild_context_with_compressed_findings(
                    analysis_results=analysis_results,
                    investigation_context=investigation_context,
                    metadata=image_metadata,
                    compressed_findings=compressed,
                )

        retrieved_payload = chat_manager.retrieve_csv_data(
            question=message,
            parsed_dir=_resolve_case_parsed_dir(case_snapshot),
        )
        retrieved_artifacts: list[str] = []
        if isinstance(retrieved_payload.get("artifacts"), list):
            retrieved_artifacts = [
                str(item).strip()
                for item in retrieved_payload.get("artifacts", [])
                if str(item).strip()
            ]

        message_for_ai = message
        retrieved_data = str(retrieved_payload.get("data", "")).strip()
        if bool(retrieved_payload.get("retrieved")) and retrieved_data:
            message_for_ai = (
                "Retrieved CSV data for this question:\n"
                f"{retrieved_data}\n\n"
                "User question:\n"
                f"{message}"
            )
            audit_logger.log(
                "chat_data_retrieval",
                {
                    "message_index": message_index,
                    "artifacts": list(retrieved_artifacts),
                    "rows_returned": retrieved_data.count("\n"),
                },
            )

        system_prompt = _load_forensic_system_prompt()

        # Calculate remaining token budget for conversation history.
        fixed_tokens = (
            chat_manager.estimate_token_count(system_prompt)
            + chat_manager.estimate_token_count(context_block)
            + chat_manager.estimate_token_count(message_for_ai)
        )
        history_budget = max(0, prompt_budget - fixed_tokens)

        recent_history = chat_manager.get_recent_history(max_pairs=CHAT_HISTORY_MAX_PAIRS)
        fitted_history = chat_manager.fit_history(recent_history, history_budget)

        ai_messages: list[dict[str, str]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": context_block},
        ]
        for history_message in fitted_history:
            role = str(history_message.get("role", "")).strip().lower()
            content = str(history_message.get("content", "")).strip()
            if role in {"user", "assistant"} and content:
                ai_messages.append({"role": role, "content": content})
        ai_messages.append({"role": "user", "content": message_for_ai})
        chat_user_prompt = _render_chat_messages_for_provider(ai_messages)
        if not chat_user_prompt:
            chat_user_prompt = (
                f"Context Block:\n{context_block}\n\n"
                f"New User Question:\n{message_for_ai}"
            )
        started_at = time.perf_counter()
        chunks: list[str] = []
        # 80% of context window for prompt, 20% for AI response.
        chat_response_max_tokens = max(1, int(chat_max_tokens * 0.2))
        for chunk in provider.analyze_stream(
            system_prompt=system_prompt,
            user_prompt=chat_user_prompt,
            max_tokens=chat_response_max_tokens,
        ):
            chunk_text = str(chunk)
            if not chunk_text:
                continue
            chunks.append(chunk_text)
            _emit_progress(
                CHAT_PROGRESS,
                case_id,
                {"type": "token", "content": chunk_text},
            )

        response_text = "".join(chunks).strip()
        duration_ms = int((time.perf_counter() - started_at) * 1000)
        if not response_text:
            raise AIProviderError("Provider returned an empty response.")

        chat_manager.add_message("user", message, metadata={"message_index": message_index})
        assistant_metadata: dict[str, Any] = {"message_index": message_index}
        if retrieved_artifacts:
            assistant_metadata["data_retrieved"] = list(retrieved_artifacts)
        chat_manager.add_message("assistant", response_text, metadata=assistant_metadata)

        audit_logger.log(
            "chat_response_received",
            {
                "message_index": message_index,
                "duration_ms": duration_ms,
                "response_tokens_estimate": chat_manager.estimate_token_count(response_text),
                "data_retrieved": bool(retrieved_artifacts),
                "retrieved_artifacts": list(retrieved_artifacts),
            },
        )

        _set_progress_status(CHAT_PROGRESS, case_id, "completed")
        _emit_progress(
            CHAT_PROGRESS,
            case_id,
            {
                "type": "done",
                "data_retrieved": list(retrieved_artifacts),
            },
        )
    except ValueError as error:
        LOGGER.warning("Chat request rejected for case %s: %s", case_id, error)
        _set_progress_status(CHAT_PROGRESS, case_id, "failed", str(error))
        _emit_progress(CHAT_PROGRESS, case_id, {"type": "error", "message": str(error)})
    except AIProviderError as error:
        LOGGER.warning("Chat provider request failed for case %s: %s", case_id, error)
        _set_progress_status(CHAT_PROGRESS, case_id, "failed", str(error))
        _emit_progress(CHAT_PROGRESS, case_id, {"type": "error", "message": str(error)})
    except Exception:
        LOGGER.exception("Unexpected failure during chat for case %s", case_id)
        error_message = "Unexpected error while generating chat response."
        _set_progress_status(CHAT_PROGRESS, case_id, "failed", error_message)
        _emit_progress(CHAT_PROGRESS, case_id, {"type": "error", "message": error_message})


def _run_parse_with_case_log_context(
    case_id: str,
    parse_artifacts: list[str],
    analysis_artifacts: list[str],
    artifact_options: list[dict[str, str]],
    config_snapshot: dict[str, Any],
) -> None:
    """Wrapper that runs ``_run_parse`` within case-scoped logging context.

    Ensures all log messages emitted during background parsing are tagged
    with the case ID.

    Args:
        case_id: UUID of the case to parse.
        parse_artifacts: List of artifact keys to parse.
        analysis_artifacts: Subset of artifact keys for AI analysis.
        artifact_options: Canonical artifact option dicts.
        config_snapshot: Deep copy of the application config.
    """
    with case_log_context(case_id):
        _run_parse(
            case_id=case_id,
            parse_artifacts=parse_artifacts,
            analysis_artifacts=analysis_artifacts,
            artifact_options=artifact_options,
            config_snapshot=config_snapshot,
        )


def _run_analysis_with_case_log_context(case_id: str, prompt: str, config_snapshot: dict[str, Any]) -> None:
    """Wrapper that runs ``_run_analysis`` within case-scoped logging context.

    Args:
        case_id: UUID of the case to analyze.
        prompt: Investigation context / user prompt.
        config_snapshot: Deep copy of the application config.
    """
    with case_log_context(case_id):
        _run_analysis(case_id=case_id, prompt=prompt, config_snapshot=config_snapshot)


def _run_chat_with_case_log_context(case_id: str, message: str, config_snapshot: dict[str, Any]) -> None:
    """Wrapper that runs ``_run_chat`` within case-scoped logging context.

    Args:
        case_id: UUID of the case for the chat session.
        message: The user's chat message.
        config_snapshot: Deep copy of the application config.
    """
    with case_log_context(case_id):
        _run_chat(case_id=case_id, message=message, config_snapshot=config_snapshot)


@routes_bp.get("/")
def index() -> str:
    """Serve the main single-page application HTML.

    Returns:
        Rendered ``index.html`` template with logo filename and tool version
        injected as template variables.
    """
    return render_template(
        "index.html",
        logo_filename=_resolve_logo_filename(),
        tool_version=TOOL_VERSION,
    )


@routes_bp.get("/favicon.ico")
def favicon() -> Response | tuple[Response, int]:
    """Serve the application favicon using the resolved logo image.

    Returns:
        The logo image file as a response, or a 404 JSON error if no
        logo image is found.
    """
    logo_filename = _resolve_logo_filename()
    if not logo_filename:
        return _error("Icon not found.", 404)
    return image_asset(logo_filename)


@routes_bp.get("/images/<path:filename>")
def image_asset(filename: str) -> Response | tuple[Response, int]:
    """Serve a static image asset from the images directory.

    Validates the filename to prevent path traversal and serves the
    file if it exists.

    Args:
        filename: Name of the image file to serve (no directory components
            allowed).

    Returns:
        The image file as a response, or a JSON error with appropriate
        status code (400 for invalid filename, 404 for missing file).
    """
    if not IMAGES_ROOT.is_dir():
        return _error("Image directory not found.", 404)

    normalized = str(filename).strip()
    if not normalized or Path(normalized).name != normalized:
        return _error("Invalid image filename.", 400)
    if "/" in normalized or "\\" in normalized:
        return _error("Invalid image filename.", 400)

    image_path = IMAGES_ROOT / normalized
    if not image_path.is_file():
        return _error("Image not found.", 404)

    return send_file(image_path)


@routes_bp.post("/api/cases")
def create_case() -> tuple[Response, int]:
    """Create a new forensic analysis case.

    Initializes case directories (evidence, parsed, reports), sets up
    audit logging, and registers the case in the in-memory state store.
    Cleans up terminal cases to prevent unbounded memory growth.

    Returns:
        A tuple of ``(Response, 201)`` with the new ``case_id`` and
        ``case_name``, or ``(Response, 500)`` on filesystem errors.
    """
    _cleanup_terminal_cases()

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
        return _error("Failed to initialize case logging due to a filesystem error.", 500)

    with case_log_context(case_id):
        LOGGER.info("Initialized case logging at %s", log_file_path)

    audit = AuditLogger(case_dir)
    audit.log(
        "case_created",
        {
            "case_id": case_id,
            "name": case_name,
            "creation_time": _now_iso(),
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
        PARSE_PROGRESS[case_id] = _new_progress()
        ANALYSIS_PROGRESS[case_id] = _new_progress()
        CHAT_PROGRESS[case_id] = _new_progress()

    return jsonify({"case_id": case_id, "case_name": case_name}), 201


@routes_bp.post("/api/cases/<case_id>/evidence")
def intake_evidence(case_id: str) -> Response | tuple[Response, int]:
    """Ingest evidence for an existing case.

    Accepts evidence via multipart file upload or JSON path reference.
    Computes integrity hashes, opens the evidence with Dissect to extract
    metadata and available artifacts, and records the intake in the audit
    log.

    Args:
        case_id: UUID of the case to attach evidence to.

    Returns:
        JSON response with evidence metadata, hashes, and available
        artifacts, or a JSON error with appropriate status code.
    """
    case = _get_case(case_id)
    if case is None:
        return _error(f"Case not found: {case_id}", 404)

    with STATE_LOCK:
        case_dir = case["case_dir"]
        audit_logger = case["audit"]

    try:
        evidence_payload = _resolve_evidence_payload(case_dir)
        source_path = Path(evidence_payload["source_path"])
        dissect_path = Path(evidence_payload["dissect_path"])

        if source_path.is_file():
            hashes = dict(compute_hashes(source_path))
        else:
            hashes = {"sha256": "N/A (directory)", "md5": "N/A (directory)", "size_bytes": 0}
        hashes["filename"] = source_path.name

        parser = ForensicParser(
            evidence_path=dissect_path,
            case_dir=case_dir,
            audit_logger=audit_logger,
        )
        try:
            metadata = parser.get_image_metadata()
            available_artifacts = parser.get_available_artifacts()
        finally:
            _close_forensic_parser(parser)

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

        return jsonify(
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
        return _error(str(error), 400)
    except Exception:
        LOGGER.exception("Evidence intake failed for case %s", case_id)
        return _error(
            "Evidence intake failed due to an unexpected error. "
            "Confirm the evidence file is supported and try again.",
            500,
        )


@routes_bp.post("/api/cases/<case_id>/parse")
def start_parse(case_id: str) -> tuple[Response, int]:
    """Start background parsing of selected forensic artifacts.

    Validates the artifact selection, initializes parsing progress, and
    launches a background thread to run the parser. Progress is streamed
    via the ``/parse/progress`` SSE endpoint.

    Args:
        case_id: UUID of the case to parse.

    Returns:
        A tuple of ``(Response, 202)`` confirming parsing has started,
        or a JSON error with status 400/404/409.
    """
    case = _get_case(case_id)
    if case is None:
        return _error(f"Case not found: {case_id}", 404)
    with STATE_LOCK:
        has_evidence = bool(str(case.get("evidence_path", "")).strip())
    if not has_evidence:
        return _error("No evidence loaded for this case.", 400)

    payload = request.get_json(silent=True) or {}
    try:
        artifact_options, parse_artifacts, analysis_artifacts = _extract_parse_selection_payload(payload)
    except ValueError as error:
        return _error(str(error), 400)

    if not parse_artifacts:
        return _error("Provide at least one artifact key to parse.", 400)
    try:
        analysis_date_range = _validate_analysis_date_range(
            payload.get("analysis_date_range"),
        )
    except ValueError as error:
        return _error(str(error), 400)

    with STATE_LOCK:
        parse_state = PARSE_PROGRESS.setdefault(case_id, _new_progress())
        if parse_state.get("status") == "running":
            return _error("Parsing is already running for this case.", 409)
        PARSE_PROGRESS[case_id] = _new_progress(status="running")
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
    _emit_progress(
        PARSE_PROGRESS,
        case_id,
        parse_started_event,
    )
    config_snapshot = copy.deepcopy(current_app.config.get("AIFT_CONFIG", {}))
    threading.Thread(
        target=_run_parse_with_case_log_context,
        args=(case_id, parse_artifacts, analysis_artifacts, artifact_options, config_snapshot),
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
    return jsonify(response_payload), 202


@routes_bp.get("/api/cases/<case_id>/parse/progress")
def stream_parse_progress(case_id: str) -> Response | tuple[Response, int]:
    """Stream parsing progress events via Server-Sent Events.

    Args:
        case_id: UUID of the case whose parse progress to stream.

    Returns:
        An SSE ``Response`` stream, or a 404 JSON error if the case is
        not found.
    """
    if _get_case(case_id) is None:
        return _error(f"Case not found: {case_id}", 404)
    return _stream_sse(PARSE_PROGRESS, case_id)


@routes_bp.post("/api/cases/<case_id>/analyze")
def start_analysis(case_id: str) -> tuple[Response, int]:
    """Start background AI-powered analysis of parsed artifacts.

    Validates that parsed artifacts exist, saves the investigation prompt,
    and launches a background thread to run the analyzer. Progress is
    streamed via the ``/analyze/progress`` SSE endpoint.

    Args:
        case_id: UUID of the case to analyze.

    Returns:
        A tuple of ``(Response, 202)`` confirming analysis has started,
        or a JSON error with status 400/404/409.
    """
    case = _get_case(case_id)
    if case is None:
        return _error(f"Case not found: {case_id}", 404)

    with STATE_LOCK:
        has_results = bool(case.get("parse_results") or case.get("artifact_csv_paths"))
        analysis_artifacts_state = case.get("analysis_artifacts")
        case_dir = case["case_dir"]
        analysis_date_range = case.get("analysis_date_range")
        audit_logger = case["audit"]

    if not has_results:
        return _error("No parsed artifacts found. Run parsing first.", 400)
    if isinstance(analysis_artifacts_state, list):
        configured_analysis_artifacts = [
            artifact
            for artifact in (str(item).strip() for item in analysis_artifacts_state)
            if artifact
        ]
        if not configured_analysis_artifacts:
            return _error(
                "No artifacts are marked `Parse and use in AI`. Select at least one AI-enabled artifact and parse again.",
                400,
            )

    payload = request.get_json(silent=True) or {}
    prompt = str(payload.get("prompt", "")).strip()

    prompt_path = Path(case_dir) / "prompt.txt"
    prompt_details: dict[str, Any] = {"prompt": _sanitize_prompt(prompt)}
    if isinstance(analysis_date_range, dict):
        start_date = str(analysis_date_range.get("start_date", "")).strip()
        end_date = str(analysis_date_range.get("end_date", "")).strip()
        if start_date and end_date:
            prompt_details["analysis_date_range"] = {
                "start_date": start_date,
                "end_date": end_date,
            }
    with STATE_LOCK:
        analysis_state = ANALYSIS_PROGRESS.setdefault(case_id, _new_progress())
        if analysis_state.get("status") == "running":
            return _error("Analysis is already running for this case.", 409)
        prompt_path.write_text(prompt, encoding="utf-8")
        ANALYSIS_PROGRESS[case_id] = _new_progress(status="running")
        case["status"] = "running"
        case["investigation_context"] = prompt
        analysis_artifacts_snapshot = list(case.get("analysis_artifacts", []))

    audit_logger.log("prompt_submitted", prompt_details)

    _emit_progress(
        ANALYSIS_PROGRESS,
        case_id,
        {
            "type": "analysis_started",
            "prompt_provided": bool(prompt),
            "analysis_artifact_count": len(analysis_artifacts_snapshot),
        },
    )
    config_snapshot = copy.deepcopy(current_app.config.get("AIFT_CONFIG", {}))
    threading.Thread(
        target=_run_analysis_with_case_log_context,
        args=(case_id, prompt, config_snapshot),
        daemon=True,
    ).start()

    return jsonify(
        {
            "status": "started",
            "case_id": case_id,
            "analysis_artifacts": analysis_artifacts_snapshot,
        }
    ), 202


@routes_bp.get("/api/cases/<case_id>/analyze/progress")
def stream_analysis_progress(case_id: str) -> Response | tuple[Response, int]:
    """Stream analysis progress events via Server-Sent Events.

    Args:
        case_id: UUID of the case whose analysis progress to stream.

    Returns:
        An SSE ``Response`` stream, or a 404 JSON error if the case is
        not found.
    """
    if _get_case(case_id) is None:
        return _error(f"Case not found: {case_id}", 404)
    return _stream_sse(ANALYSIS_PROGRESS, case_id)


@routes_bp.post("/api/cases/<case_id>/chat")
def chat_with_case(case_id: str) -> Response | tuple[Response, int]:
    """Initiate a chat interaction with the AI about completed analysis results.

    Validates the request payload, checks that analysis results exist,
    and launches a background thread for the AI chat exchange. Response
    tokens are streamed via the ``/chat/stream`` SSE endpoint.

    Args:
        case_id: UUID of the case to chat about.

    Returns:
        A tuple of ``(Response, 202)`` confirming chat processing has
        started, or a JSON error with status 400/404/409/500.
    """
    case = _get_case(case_id)
    if case is None:
        return _error(f"Case not found: {case_id}", 404)

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return _error("Chat payload must be a JSON object.", 400)

    message = str(payload.get("message", "")).strip()
    if not message:
        return _error("`message` is required.", 400)

    with STATE_LOCK:
        case_snapshot_for_check = dict(case)
    if not _load_case_analysis_results(case_snapshot_for_check):
        return _error("No analysis results available for this case. Run analysis first.", 400)

    config = current_app.config.get("AIFT_CONFIG", {})
    if not isinstance(config, dict):
        return _error("Invalid in-memory configuration state.", 500)

    with STATE_LOCK:
        chat_state = CHAT_PROGRESS.setdefault(case_id, _new_progress())
        if chat_state.get("status") == "running":
            return _error("Chat is already running for this case.", 409)
        CHAT_PROGRESS[case_id] = _new_progress(status="running")

    config_snapshot = copy.deepcopy(config)
    threading.Thread(
        target=_run_chat_with_case_log_context,
        args=(case_id, message, config_snapshot),
        daemon=True,
    ).start()
    return jsonify({"status": "processing"}), 202


@routes_bp.get("/api/cases/<case_id>/chat/stream")
def stream_chat_progress(case_id: str) -> Response | tuple[Response, int]:
    """Stream chat response tokens via Server-Sent Events.

    Args:
        case_id: UUID of the case whose chat progress to stream.

    Returns:
        An SSE ``Response`` stream, or a 404 JSON error if the case is
        not found.
    """
    if _get_case(case_id) is None:
        return _error(f"Case not found: {case_id}", 404)
    return _stream_sse(CHAT_PROGRESS, case_id)


@routes_bp.get("/api/cases/<case_id>/chat/history")
def get_case_chat_history(case_id: str) -> Response | tuple[Response, int]:
    """Retrieve the full chat message history for a case.

    Args:
        case_id: UUID of the case whose chat history to retrieve.

    Returns:
        JSON response containing the list of chat messages, or a 404
        JSON error if the case is not found.
    """
    case = _get_case(case_id)
    if case is None:
        return _error(f"Case not found: {case_id}", 404)
    with STATE_LOCK:
        case_dir = case["case_dir"]
    manager = ChatManager(case_dir)
    return jsonify(manager.get_history())


@routes_bp.delete("/api/cases/<case_id>/chat/history")
def clear_case_chat_history(case_id: str) -> Response | tuple[Response, int]:
    """Clear the chat message history for a case.

    Deletes all stored chat messages and logs the action to the audit trail.

    Args:
        case_id: UUID of the case whose chat history to clear.

    Returns:
        JSON response confirming the history was cleared, or a 404 JSON
        error if the case is not found.
    """
    case = _get_case(case_id)
    if case is None:
        return _error(f"Case not found: {case_id}", 404)
    with STATE_LOCK:
        case_dir = case["case_dir"]
        audit_logger = case["audit"]
    manager = ChatManager(case_dir)
    manager.clear()
    audit_logger.log("chat_history_cleared", {"case_id": case_id})
    return jsonify({"status": "cleared", "case_id": case_id})


@routes_bp.get("/api/cases/<case_id>/report")
def download_report(case_id: str) -> Response | tuple[Response, int]:
    """Generate and download the HTML forensic analysis report.

    Verifies evidence integrity by re-computing hashes, generates the
    report using ``ReportGenerator``, logs the generation to the audit
    trail, and marks the case as completed.

    Args:
        case_id: UUID of the case to generate the report for.

    Returns:
        The HTML report file as an attachment download, or a JSON error
        with status 400/404.
    """
    case = _get_case(case_id)
    if case is None:
        return _error(f"Case not found: {case_id}", 404)

    with STATE_LOCK:
        case_snapshot = dict(case)
        audit_logger = case["audit"]

    hashes = dict(case_snapshot.get("evidence_hashes", {}))
    intake_sha256 = str(hashes.get("sha256", "")).strip()
    verification_path = _resolve_hash_verification_path(case_snapshot)

    # Directory evidence cannot be hashed; skip verification.
    if intake_sha256.startswith("N/A"):
        hash_ok = True
        computed_sha256 = intake_sha256
    elif verification_path is None or not intake_sha256:
        return _error("Evidence hash context is missing for this case.", 400)
    elif not verification_path.exists():
        return _error("Evidence file is no longer available for hash verification.", 404)
    else:
        hash_ok, computed_sha256 = verify_hash(
            verification_path,
            intake_sha256,
            return_computed=True,
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
        audit_log_entries=_read_audit_entries(Path(case_dir)),
    )
    audit_logger.log(
        "report_generated",
        {"report_filename": report_path.name, "hash_verified": hash_ok},
    )
    _mark_case_status(case_id, "completed")
    _cleanup_case_entries(case_id)

    return send_file(
        report_path,
        as_attachment=True,
        download_name=report_path.name,
        mimetype="text/html",
    )


@routes_bp.get("/api/cases/<case_id>/csvs")
def download_csv_bundle(case_id: str) -> Response | tuple[Response, int]:
    """Download all parsed CSV files as a ZIP archive.

    Collects all CSV files for the case, bundles them into a ZIP archive
    with deduplication of filenames, and returns it as a download.

    Args:
        case_id: UUID of the case whose CSV files to download.

    Returns:
        The ZIP archive as an attachment download, or a JSON error with
        status 404 if the case or CSV files are not found.
    """
    case = _get_case(case_id)
    if case is None:
        return _error(f"Case not found: {case_id}", 404)

    with STATE_LOCK:
        case_snapshot = dict(case)

    csv_paths = _collect_case_csv_paths(case_snapshot)
    if not csv_paths:
        return _error("No parsed CSV files available for this case.", 404)

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


@routes_bp.get("/api/artifact-profiles")
def list_artifact_profiles() -> Response:
    """List all available artifact profiles.

    Returns:
        JSON response containing a ``"profiles"`` list with each profile's
        name, builtin flag, and artifact options.
    """
    config_path = Path(str(current_app.config.get("AIFT_CONFIG_PATH", "config.yaml")))
    profiles_root = _resolve_profiles_root(config_path)
    return jsonify({"profiles": _compose_profile_response(profiles_root)})


@routes_bp.post("/api/artifact-profiles")
def save_artifact_profile() -> Response | tuple[Response, int]:
    """Create or update a user-defined artifact profile.

    Validates the profile name and artifact options, prevents overwriting
    the built-in recommended profile, and persists the profile to disk.

    Returns:
        JSON response with the saved profile and updated profiles list,
        or a JSON error with status 400/500.
    """
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return _error("Profile payload must be a JSON object.", 400)

    try:
        profile_name = _normalize_profile_name(payload.get("name"))
    except ValueError as error:
        return _error(str(error), 400)

    try:
        artifact_options = _normalize_artifact_options(payload.get("artifact_options"))
    except ValueError as error:
        return _error(str(error), 400)
    if not artifact_options:
        return _error("Profile must include at least one artifact option.", 400)

    config_path = Path(str(current_app.config.get("AIFT_CONFIG_PATH", "config.yaml")))
    profiles_root = _resolve_profiles_root(config_path)

    try:
        profiles = _load_profiles_from_directory(profiles_root)
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
            return _error("`recommended` is a built-in profile and cannot be overwritten.", 400)

        if existing is not None:
            target_path = Path(existing.get("path"))
        else:
            target_path = _profile_path_for_new_name(profiles_root, profile_name)

        response_profile = {
            "name": profile_name,
            "builtin": False,
            "artifact_options": artifact_options,
        }
        _write_profile_file(target_path, response_profile)
    except OSError:
        LOGGER.exception("Failed to save artifact profile '%s'", profile_name)
        return _error(
            "Failed to save the profile due to a filesystem error. "
            "Check directory permissions and retry.",
            500,
        )

    return jsonify(
        {
            "status": "saved",
            "profile": response_profile,
            "profiles": _compose_profile_response(profiles_root),
        }
    )


@routes_bp.get("/api/settings")
def get_settings() -> Response:
    """Retrieve the current application settings with sensitive values masked.

    Returns:
        JSON response containing the full configuration dictionary with
        API keys, tokens, and passwords replaced by ``MASKED``.
    """
    config = current_app.config.get("AIFT_CONFIG", {})
    if not isinstance(config, dict):
        config = {}
    return jsonify(_mask_sensitive(config))


@routes_bp.post("/api/settings")
def update_settings() -> Response | tuple[Response, int]:
    """Update application settings by deep-merging the request payload.

    Merges the submitted configuration into the current settings, saves
    to disk, refreshes the in-memory config, and audits any changes to
    active cases.

    Returns:
        JSON response with the updated (masked) configuration, or a 400
        JSON error if the payload is invalid.
    """
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return _error("Settings payload must be a JSON object.", 400)

    config_path = Path(str(current_app.config.get("AIFT_CONFIG_PATH", "config.yaml")))
    current_config = load_config(config_path, use_env_overrides=False)
    changed_keys = _deep_merge(current_config, payload)
    save_config(current_config, config_path)

    refreshed = load_config(config_path)
    current_app.config["AIFT_CONFIG"] = refreshed
    if changed_keys:
        LOGGER.info("Updated settings: %s", ", ".join(changed_keys))
        _audit_config_change(changed_keys)

    return jsonify(_mask_sensitive(refreshed))


@routes_bp.post("/api/settings/test-connection")
def test_settings_connection() -> Response | tuple[Response, int]:
    """Test the configured AI provider connection.

    Creates a provider instance from the current settings and sends a
    short connectivity test prompt. Reports the model info and a preview
    of the response.

    Returns:
        JSON response with ``"status": "ok"``, model info, and response
        preview on success, or a JSON error with status 400/500/502 on
        failure.
    """
    config = current_app.config.get("AIFT_CONFIG", {})
    if not isinstance(config, dict):
        return _error("Invalid in-memory configuration state.", 500)
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
            return _error("Provider returned an empty response.", 502)
        return jsonify(
            {
                "status": "ok",
                "model_info": model_info,
                "response_preview": preview[:240],
            }
        )
    except ValueError as error:
        LOGGER.warning("Settings connection test rejected due to configuration: %s", error)
        return _error(str(error), 400)
    except AIProviderError as error:
        LOGGER.warning("Settings connection test failed: %s", error)
        return _error(str(error), 502)
    except Exception:
        LOGGER.exception("Unexpected failure during settings connection test.")
        return _error("Unexpected error while testing provider connection.", 500)


def register_routes(app: Flask) -> None:
    """Register all HTTP route handlers with the Flask application.

    Attaches the ``routes_bp`` blueprint containing all AIFT endpoint
    definitions to the given Flask app instance.

    Args:
        app: The Flask application instance to register routes on.
    """
    app.register_blueprint(routes_bp)


__all__ = [
    "ANALYSIS_PROGRESS",
    "CASE_STATES",
    "CHAT_PROGRESS",
    "PARSE_PROGRESS",
    "register_routes",
]
