"""HTTP route definitions for AIFT."""

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
TERMINAL_CASE_STATUSES = frozenset({"completed", "failed", "error"})
SSE_POLL_INTERVAL_SECONDS = 0.2
SSE_INITIAL_IDLE_GRACE_SECONDS = 1.0

CASE_STATES: dict[str, dict[str, Any]] = {}
PARSE_PROGRESS: dict[str, dict[str, Any]] = {}
ANALYSIS_PROGRESS: dict[str, dict[str, Any]] = {}
STATE_LOCK = threading.RLock()

routes_bp = Blueprint("routes", __name__)
_REQUEST_CASE_LOG_TOKEN = "_aift_case_log_token"


@routes_bp.before_app_request
def _bind_case_log_context_for_request() -> None:
    case_id: str | None = None
    if request.blueprint == routes_bp.name:
        case_id = str((request.view_args or {}).get("case_id", "")).strip() or None
    setattr(g, _REQUEST_CASE_LOG_TOKEN, push_case_log_context(case_id))


@routes_bp.teardown_app_request
def _clear_case_log_context_for_request(_error: BaseException | None) -> None:
    token = getattr(g, _REQUEST_CASE_LOG_TOKEN, None)
    if token is not None:
        pop_case_log_context(token)
        setattr(g, _REQUEST_CASE_LOG_TOKEN, None)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _error(message: str, status: int) -> tuple[Response, int]:
    return jsonify({"error": message}), status


def _safe_name(value: str, fallback: str = "item") -> str:
    cleaned = SAFE_NAME_RE.sub("_", value).strip("_")
    return cleaned or fallback


def _resolve_logo_filename() -> str:
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
    return {"status": status, "events": [], "error": None}


def _set_progress_status(
    store: dict[str, dict[str, Any]],
    case_id: str,
    status: str,
    error: str | None = None,
) -> None:
    with STATE_LOCK:
        state = store.setdefault(case_id, _new_progress())
        state["status"] = status
        state["error"] = error


def _emit_progress(
    store: dict[str, dict[str, Any]],
    case_id: str,
    payload: dict[str, Any],
) -> None:
    event = dict(payload)
    event.setdefault("timestamp", _now_iso())
    with STATE_LOCK:
        state = store.setdefault(case_id, _new_progress())
        event["sequence"] = len(state["events"])
        state["events"].append(event)


def _normalize_case_status(value: Any) -> str:
    return str(value or "").strip().lower()


def _mark_case_status(case_id: str, status: str) -> None:
    normalized_status = _normalize_case_status(status)
    with STATE_LOCK:
        case = CASE_STATES.get(case_id)
        if case is not None:
            case["status"] = normalized_status


def _cleanup_case_entries(case_id: str) -> None:
    with STATE_LOCK:
        CASE_STATES.pop(case_id, None)
        PARSE_PROGRESS.pop(case_id, None)
        ANALYSIS_PROGRESS.pop(case_id, None)
    unregister_case_log_handler(case_id)


def _cleanup_terminal_cases(exclude_case_id: str | None = None) -> None:
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
    for case_id in terminal_case_ids:
        unregister_case_log_handler(case_id)


def _mask_sensitive(data: Any) -> Any:
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
    return any(segment.strip().lower() in SENSITIVE_KEYS for segment in path.split("."))


def _sanitize_changed_keys(changed_keys: list[str]) -> list[str]:
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
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _close_forensic_parser(parser: Any) -> None:
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
    if not args:
        return fallback_artifact, 0
    first = args[0]
    if isinstance(first, dict):
        return str(first.get("artifact_key", fallback_artifact)), _safe_int(first.get("record_count", 0))
    if len(args) >= 2:
        return str(args[0] or fallback_artifact), _safe_int(args[1], 0)
    return fallback_artifact, _safe_int(first, 0)


def _sanitize_prompt(prompt: str, max_chars: int = 2000) -> str:
    normalized = " ".join(prompt.split())
    if len(normalized) <= max_chars:
        return normalized
    return f"{normalized[:max_chars]}... [truncated]"


def _normalize_artifact_mode(value: Any, default_mode: str = MODE_PARSE_AND_AI) -> str:
    mode = str(value or "").strip().lower()
    if mode == MODE_PARSE_ONLY:
        return MODE_PARSE_ONLY
    if mode == MODE_PARSE_AND_AI:
        return MODE_PARSE_AND_AI
    return default_mode


def _normalize_string_list(values: Any) -> list[str]:
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
    analysis_set = set(analysis_artifacts)
    return [
        {
            "artifact_key": artifact_key,
            "mode": MODE_PARSE_AND_AI if artifact_key in analysis_set else MODE_PARSE_ONLY,
        }
        for artifact_key in parse_artifacts
    ]


def _extract_parse_selection_payload(payload: dict[str, Any]) -> tuple[list[dict[str, str]], list[str], list[str]]:
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
    profile: list[dict[str, str]] = []
    for artifact_key in ARTIFACT_REGISTRY:
        normalized_key = str(artifact_key).strip().lower()
        if normalized_key in RECOMMENDED_PROFILE_EXCLUDED_ARTIFACTS:
            continue
        profile.append({"artifact_key": str(artifact_key), "mode": MODE_PARSE_AND_AI})
    return profile


def _resolve_profiles_root(config_path: str | Path) -> Path:
    path = Path(config_path)
    return path.parent / PROFILE_DIRNAME


def _recommended_profile_payload() -> dict[str, Any]:
    return {
        "name": BUILTIN_RECOMMENDED_PROFILE,
        "builtin": True,
        "artifact_options": _recommended_artifact_options(),
    }


def _write_profile_file(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(payload, indent=2, ensure_ascii=True)
    path.write_text(f"{content}\n", encoding="utf-8")


def _load_profile_file(path: Path) -> dict[str, Any] | None:
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
    recommended_path = profiles_root / f"{BUILTIN_RECOMMENDED_PROFILE}{PROFILE_FILE_SUFFIX}"
    _write_profile_file(recommended_path, _recommended_profile_payload())


def _load_profiles_from_directory(profiles_root: Path) -> list[dict[str, Any]]:
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
    return [
        {
            "name": str(profile.get("name", "")).strip(),
            "builtin": bool(profile.get("builtin", False)),
            "artifact_options": list(profile.get("artifact_options", [])),
        }
        for profile in _load_profiles_from_directory(profiles_root)
    ]


def _build_csv_map(parse_results: list[dict[str, Any]]) -> dict[str, str]:
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
    @stream_with_context
    def stream() -> Any:
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
    try:
        with ZipFile(zip_path, "r") as archive:
            members = [(member.filename, member) for member in archive.infolist() if not member.is_dir()]

            def _extract_member(member: Any, target: Path) -> None:
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
    """Extract a tar (or tar.gz/tgz) archive and return the best Dissect target path."""
    try:
        with tarfile.open(tar_path, "r:*") as archive:
            members = [(member.name, member) for member in archive.getmembers() if member.isfile()]

            def _extract_member(member: Any, target: Path) -> None:
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
    """Extract a 7z archive and return the best Dissect target path."""
    try:
        with py7zr.SevenZipFile(archive_path, mode="r") as archive:
            members = [(name, name) for name in archive.getnames() if not name.endswith("/")]

            def _extract_members(_members: list[tuple[Any, Path]]) -> None:
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
    uploaded: list[Any] = []
    for key in request.files:
        for file_storage in request.files.getlist(key):
            if file_storage and file_storage.filename:
                uploaded.append(file_storage)
    return uploaded


def _unique_destination(path: Path) -> Path:
    if not path.exists():
        return path

    counter = 1
    while True:
        candidate = path.with_name(f"{path.stem}_{counter}{path.suffix}")
        if not candidate.exists():
            return candidate
        counter += 1


def _resolve_uploaded_dissect_path(uploaded_paths: list[Path]) -> Path:
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
    return (
        str(value)
        .replace('"', "")
        .replace("\u201c", "")
        .replace("\u201d", "")
        .strip()
    )


def _resolve_evidence_payload(case_dir: Path) -> dict[str, Any]:
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


def _resolve_hash_verification_path(case: dict[str, Any]) -> Path | None:
    source_path = str(case.get("source_path", "")).strip()
    if source_path:
        return Path(source_path)

    evidence_path = str(case.get("evidence_path", "")).strip()
    if evidence_path:
        return Path(evidence_path)

    return None


def _resolve_case_csv_output_dir(case: dict[str, Any], config_snapshot: dict[str, Any]) -> Path:
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
    collected: list[Path] = []
    seen: set[str] = set()

    def _add_path(candidate: Any) -> None:
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
    case = _get_case(case_id)
    if case is None:
        _set_progress_status(PARSE_PROGRESS, case_id, "failed", "Case not found.")
        _emit_progress(PARSE_PROGRESS, case_id, {"type": "parse_failed", "error": "Case not found."})
        return

    evidence_path = str(case.get("evidence_path", "")).strip()
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
        csv_output_dir = _resolve_case_csv_output_dir(case, config_snapshot=config_snapshot)
        parser = ForensicParser(
            evidence_path=evidence_path,
            case_dir=case["case_dir"],
            audit_logger=case["audit"],
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
    case = _get_case(case_id)
    if case is None:
        _set_progress_status(ANALYSIS_PROGRESS, case_id, "failed", "Case not found.")
        _emit_progress(ANALYSIS_PROGRESS, case_id, {"type": "analysis_failed", "error": "Case not found."})
        return

    csv_map = dict(case.get("artifact_csv_paths", {}))
    if not csv_map:
        csv_map = _build_csv_map(list(case.get("parse_results", [])))
    analysis_artifacts_state = case.get("analysis_artifacts")
    if isinstance(analysis_artifacts_state, list):
        artifacts = [str(item) for item in analysis_artifacts_state if str(item) in csv_map]
    else:
        artifacts = [item for item in case.get("selected_artifacts", []) if item in csv_map]
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
            case_dir=case["case_dir"],
            config=config_snapshot,
            audit_logger=case["audit"],
            artifact_csv_paths=csv_map,
        )
        metadata = dict(case.get("image_metadata", {}))
        metadata["artifact_csv_paths"] = csv_map
        metadata["parse_results"] = list(case.get("parse_results", []))
        metadata["analysis_artifacts"] = list(artifacts)
        metadata["artifact_options"] = list(case.get("artifact_options", []))
        analysis_date_range = case.get("analysis_date_range")
        if isinstance(analysis_date_range, dict):
            metadata["analysis_date_range"] = {
                "start_date": str(analysis_date_range.get("start_date", "")).strip(),
                "end_date": str(analysis_date_range.get("end_date", "")).strip(),
            }

        def _analysis_progress(*args: Any) -> None:
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


def _run_parse_with_case_log_context(
    case_id: str,
    parse_artifacts: list[str],
    analysis_artifacts: list[str],
    artifact_options: list[dict[str, str]],
    config_snapshot: dict[str, Any],
) -> None:
    with case_log_context(case_id):
        _run_parse(
            case_id=case_id,
            parse_artifacts=parse_artifacts,
            analysis_artifacts=analysis_artifacts,
            artifact_options=artifact_options,
            config_snapshot=config_snapshot,
        )


def _run_analysis_with_case_log_context(case_id: str, prompt: str, config_snapshot: dict[str, Any]) -> None:
    with case_log_context(case_id):
        _run_analysis(case_id=case_id, prompt=prompt, config_snapshot=config_snapshot)


@routes_bp.get("/")
def index() -> str:
    return render_template(
        "index.html",
        logo_filename=_resolve_logo_filename(),
        tool_version=TOOL_VERSION,
    )


@routes_bp.get("/favicon.ico")
def favicon() -> Response | tuple[Response, int]:
    logo_filename = _resolve_logo_filename()
    if not logo_filename:
        return _error("Icon not found.", 404)
    return image_asset(logo_filename)


@routes_bp.get("/images/<path:filename>")
def image_asset(filename: str) -> Response | tuple[Response, int]:
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

    return jsonify({"case_id": case_id, "case_name": case_name}), 201


@routes_bp.post("/api/cases/<case_id>/evidence")
def intake_evidence(case_id: str) -> Response | tuple[Response, int]:
    case = _get_case(case_id)
    if case is None:
        return _error(f"Case not found: {case_id}", 404)

    try:
        evidence_payload = _resolve_evidence_payload(case["case_dir"])
        source_path = Path(evidence_payload["source_path"])
        dissect_path = Path(evidence_payload["dissect_path"])

        if source_path.is_file():
            hashes = dict(compute_hashes(source_path))
        else:
            hashes = {"sha256": "N/A (directory)", "md5": "N/A (directory)", "size_bytes": 0}
        hashes["filename"] = source_path.name

        parser = ForensicParser(
            evidence_path=dissect_path,
            case_dir=case["case_dir"],
            audit_logger=case["audit"],
        )
        try:
            metadata = parser.get_image_metadata()
            available_artifacts = parser.get_available_artifacts()
        finally:
            _close_forensic_parser(parser)

        case["audit"].log(
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
        case["audit"].log(
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
    case = _get_case(case_id)
    if case is None:
        return _error(f"Case not found: {case_id}", 404)
    if not str(case.get("evidence_path", "")).strip():
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
    if _get_case(case_id) is None:
        return _error(f"Case not found: {case_id}", 404)
    return _stream_sse(PARSE_PROGRESS, case_id)


@routes_bp.post("/api/cases/<case_id>/analyze")
def start_analysis(case_id: str) -> tuple[Response, int]:
    case = _get_case(case_id)
    if case is None:
        return _error(f"Case not found: {case_id}", 404)
    if not case.get("parse_results") and not case.get("artifact_csv_paths"):
        return _error("No parsed artifacts found. Run parsing first.", 400)
    analysis_artifacts_state = case.get("analysis_artifacts")
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

    prompt_path = Path(case["case_dir"]) / "prompt.txt"
    prompt_details: dict[str, Any] = {"prompt": _sanitize_prompt(prompt)}
    analysis_date_range = case.get("analysis_date_range")
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

    case["audit"].log("prompt_submitted", prompt_details)

    _emit_progress(
        ANALYSIS_PROGRESS,
        case_id,
        {
            "type": "analysis_started",
            "prompt_provided": bool(prompt),
            "analysis_artifact_count": len(case.get("analysis_artifacts", [])),
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
            "analysis_artifacts": list(case.get("analysis_artifacts", [])),
        }
    ), 202


@routes_bp.get("/api/cases/<case_id>/analyze/progress")
def stream_analysis_progress(case_id: str) -> Response | tuple[Response, int]:
    if _get_case(case_id) is None:
        return _error(f"Case not found: {case_id}", 404)
    return _stream_sse(ANALYSIS_PROGRESS, case_id)


@routes_bp.get("/api/cases/<case_id>/report")
def download_report(case_id: str) -> Response | tuple[Response, int]:
    case = _get_case(case_id)
    if case is None:
        return _error(f"Case not found: {case_id}", 404)

    hashes = dict(case.get("evidence_hashes", {}))
    intake_sha256 = str(hashes.get("sha256", "")).strip()
    verification_path = _resolve_hash_verification_path(case)

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
    case["audit"].log(
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

    analysis_results = dict(case.get("analysis_results", {}))
    analysis_results.setdefault("case_id", case_id)
    analysis_results.setdefault("case_name", str(case.get("case_name", "")))
    analysis_results.setdefault("per_artifact", [])
    analysis_results.setdefault("summary", "")

    investigation_context = str(case.get("investigation_context", ""))
    if not investigation_context:
        prompt_path = Path(case["case_dir"]) / "prompt.txt"
        if prompt_path.exists():
            investigation_context = prompt_path.read_text(encoding="utf-8")

    report_generator = ReportGenerator(cases_root=CASES_ROOT)
    report_path = report_generator.generate(
        analysis_results=analysis_results,
        image_metadata=dict(case.get("image_metadata", {})),
        evidence_hashes=hashes,
        investigation_context=investigation_context,
        audit_log_entries=_read_audit_entries(Path(case["case_dir"])),
    )
    case["audit"].log(
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
    case = _get_case(case_id)
    if case is None:
        return _error(f"Case not found: {case_id}", 404)

    csv_paths = _collect_case_csv_paths(case)
    if not csv_paths:
        return _error("No parsed CSV files available for this case.", 404)

    reports_dir = Path(case["case_dir"]) / "reports"
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
    config_path = Path(str(current_app.config.get("AIFT_CONFIG_PATH", "config.yaml")))
    profiles_root = _resolve_profiles_root(config_path)
    return jsonify({"profiles": _compose_profile_response(profiles_root)})


@routes_bp.post("/api/artifact-profiles")
def save_artifact_profile() -> Response | tuple[Response, int]:
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
    config = current_app.config.get("AIFT_CONFIG", {})
    if not isinstance(config, dict):
        config = {}
    return jsonify(_mask_sensitive(config))


@routes_bp.post("/api/settings")
def update_settings() -> Response | tuple[Response, int]:
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
    """Register all routes for AIFT."""
    app.register_blueprint(routes_bp)


__all__ = [
    "ANALYSIS_PROGRESS",
    "CASE_STATES",
    "PARSE_PROGRESS",
    "register_routes",
]
