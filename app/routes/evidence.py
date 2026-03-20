"""Evidence intake, archive extraction, CSV/hash helpers, and route handlers.

This module handles all evidence-related logic: uploading files, resolving
paths, extracting ZIP/tar/7z archives, computing and verifying hashes,
collecting parsed CSV paths, reading audit log entries, and the Flask route
handlers for evidence intake, report generation, and CSV bundle downloads.

Attributes:
    EWF_SEGMENT_RE: Compiled regex for EWF split segment filenames.
    SPLIT_RAW_SEGMENT_RE: Compiled regex for split raw disk image segments.
    evidence_bp: Flask Blueprint for evidence-related routes.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import tarfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from zipfile import BadZipFile, ZipFile, ZIP_DEFLATED

import py7zr

from flask import Blueprint, Response, request, send_file
from werkzeug.utils import secure_filename

from ..hasher import compute_hashes, verify_hash
from ..parser import ForensicParser
from ..reporter import ReportGenerator

from .state import (
    ANALYSIS_PROGRESS,
    CASES_ROOT,
    CHAT_PROGRESS,
    PARSE_PROGRESS,
    PROJECT_ROOT,
    STATE_LOCK,
    error_response,
    get_case,
    mark_case_status,
    safe_name,
    success_response,
)

__all__ = [
    "EWF_SEGMENT_RE",
    "SPLIT_RAW_SEGMENT_RE",
    "evidence_bp",
    "resolve_evidence_payload",
    "resolve_hash_verification_path",
    "resolve_case_csv_output_dir",
    "collect_case_csv_paths",
    "build_csv_map",
    "read_audit_entries",
]

LOGGER = logging.getLogger(__name__)

EWF_SEGMENT_RE = re.compile(r"^(?P<base>.+)\.(?:e|ex|s|l)(?P<segment>\d{2})$", re.IGNORECASE)
SPLIT_RAW_SEGMENT_RE = re.compile(r"^(?P<base>.+)\.(?P<segment>\d{3})$")

# Extensions for evidence files we look for inside extracted archives.
_EVIDENCE_FILE_EXTENSIONS = frozenset({
    ".e01", ".ex01", ".s01", ".l01",
    ".dd", ".img", ".raw", ".bin", ".iso",
    ".vmdk", ".vhd", ".vhdx", ".vdi", ".qcow2", ".hdd", ".hds",
    ".vmx", ".vbox", ".vmcx", ".ovf", ".ova",
    ".asdf", ".asif", ".ad1",
    ".000", ".001",
})


# ---------------------------------------------------------------------------
# Archive extraction
# ---------------------------------------------------------------------------

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

    Validates path traversal, extracts, then locates the best evidence file.
    Exactly one of *extract_member* or *extract_all_members* must be provided.

    Args:
        destination: Root directory to extract into.
        members: List of ``(member_name, member_object)`` tuples.
        empty_message: Error for empty archives.
        unsafe_paths_message: Error for path traversal.
        no_files_message: Error when extraction produces no files.
        extract_member: Callback to extract a single member.
        extract_all_members: Callback to extract all members at once.

    Returns:
        Path to the best evidence file or extraction directory.

    Raises:
        ValueError: On empty, unsafe, or failed extraction.
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
        if member_path.is_absolute() or ".." in member_path.parts:
            raise ValueError(unsafe_paths_message)
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
        zip_path: Path to the ZIP file.
        destination: Directory to extract into.

    Returns:
        Path to the best evidence file or directory.

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
                unsafe_paths_message="Archive rejected: contains unsafe file paths",
                no_files_message="Evidence ZIP extraction produced no files.",
                extract_member=_extract_member,
            )
    except BadZipFile as error:
        raise ValueError(f"Invalid ZIP evidence file: {zip_path.name}") from error


def _extract_tar(tar_path: Path, destination: Path) -> Path:
    """Extract a tar archive and return the best Dissect target path.

    Args:
        tar_path: Path to the tar file.
        destination: Directory to extract into.

    Returns:
        Path to the best evidence file or directory.

    Raises:
        ValueError: If the tar is invalid, empty, or contains unsafe paths.
    """
    try:
        with tarfile.open(tar_path, "r:*") as archive:
            raw_members = archive.getmembers()
            for member in raw_members:
                if member.islnk() or member.issym():
                    raise ValueError("Archive rejected: contains unsafe file paths")
            members = [(member.name, member) for member in raw_members if member.isfile()]

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
                unsafe_paths_message="Archive rejected: contains unsafe file paths",
                no_files_message="Evidence tar extraction produced no files.",
                extract_member=_extract_member,
            )
    except tarfile.TarError as error:
        raise ValueError(f"Invalid tar evidence file: {tar_path.name}") from error


def _extract_7z(archive_path: Path, destination: Path) -> Path:
    """Extract a 7z archive and return the best Dissect target path.

    Args:
        archive_path: Path to the 7z file.
        destination: Directory to extract into.

    Returns:
        Path to the best evidence file or directory.

    Raises:
        ValueError: If the 7z is invalid, empty, or contains unsafe paths.
    """
    try:
        with py7zr.SevenZipFile(archive_path, mode="r") as archive:
            members = [(name, name) for name in archive.getnames() if not name.endswith("/")]

            def _extract_members(validated: list[tuple[Any, Path]]) -> None:
                """Extract 7z members via temp directory for path-traversal safety."""
                import tempfile
                with tempfile.TemporaryDirectory() as tmpdir:
                    tmp = Path(tmpdir)
                    archive.extractall(path=tmp)
                    for member_name, target in validated:
                        src = tmp / member_name
                        if src.is_file():
                            target.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copy2(src, target)

            return _extract_archive_members(
                destination,
                members,
                empty_message="Evidence 7z archive is empty.",
                unsafe_paths_message="Archive rejected: contains unsafe file paths",
                no_files_message="Evidence 7z extraction produced no files.",
                extract_all_members=_extract_members,
            )
    except py7zr.Bad7zFile as error:
        raise ValueError(f"Invalid 7z evidence file: {archive_path.name}") from error


# ---------------------------------------------------------------------------
# Upload / path resolution
# ---------------------------------------------------------------------------

def _collect_uploaded_files() -> list[Any]:
    """Collect all uploaded ``FileStorage`` objects from the current request.

    Returns:
        A list of ``FileStorage`` objects with non-empty filenames.
    """
    uploaded: list[Any] = []
    for key in request.files:
        for file_storage in request.files.getlist(key):
            if file_storage and file_storage.filename:
                uploaded.append(file_storage)
    return uploaded


def _unique_destination(path: Path) -> Path:
    """Generate a unique file path by appending a numeric suffix if needed.

    Args:
        path: Desired file path.

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
    """Determine the primary Dissect target path from uploaded files.

    Handles single files, split EWF/raw segment sets, and rejects mixed
    archive-plus-segment uploads.

    Args:
        uploaded_paths: List of uploaded evidence file paths.

    Returns:
        The ``Path`` to pass to Dissect's ``Target.open()``.

    Raises:
        ValueError: If no files uploaded or archive mixed with segments.
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
        if len(segment_groups) > 1:
            group_names = sorted(segment_groups.keys())
            raise ValueError(
                "Ambiguous upload: multiple segment groups detected "
                f"({', '.join(group_names)}). "
                "Upload only one split segment set at a time."
            )
        only_group = next(iter(segment_groups.values()))
        return min(only_group, key=lambda item: item[0])[1]

    return uploaded_paths[0]


def _normalize_user_path(value: str) -> str:
    """Strip surrounding quotes and whitespace from a user-supplied path.

    Args:
        value: Raw path string.

    Returns:
        Cleaned path string.
    """
    return (
        str(value)
        .replace('"', "")
        .replace("\u201c", "")
        .replace("\u201d", "")
        .strip()
    )


def _make_extract_dir(evidence_dir: Path, source_path: Path) -> Path:
    """Build a unique extraction directory path for an archive.

    Args:
        evidence_dir: Parent evidence directory.
        source_path: Path to the archive being extracted.

    Returns:
        A timestamped extraction directory path.
    """
    return evidence_dir / f"extracted_{safe_name(source_path.stem, 'evidence')}_{int(time.time())}"


def resolve_evidence_payload(case_dir: Path) -> dict[str, Any]:
    """Resolve the evidence source from the current request.

    Handles upload and JSON path reference modes. Archives are extracted.

    Args:
        case_dir: Path to the case's root directory.

    Returns:
        Dict with ``mode``, ``filename``, ``source_path``, ``stored_path``,
        ``dissect_path``, and ``uploaded_files``.

    Raises:
        ValueError: If no evidence provided or archive extraction fails.
        FileNotFoundError: If the referenced path does not exist.
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
        if not isinstance(payload, dict):
            raise ValueError("Request body must be a JSON object.")
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

    # Extract archives into the evidence directory.
    _ARCHIVE_EXTRACTORS = {
        ".zip": _extract_zip,
        ".tar": _extract_tar,
        ".gz": _extract_tar,
        ".tgz": _extract_tar,
        ".7z": _extract_7z,
    }
    dissect_path = source_path
    suffix = source_path.suffix.lower()
    extractor = _ARCHIVE_EXTRACTORS.get(suffix)
    if source_path.is_file() and extractor is not None:
        extract_dir = _make_extract_dir(evidence_dir, source_path)
        dissect_path = extractor(source_path, extract_dir)

    return {
        "mode": mode,
        "filename": source_path.name,
        "source_path": str(source_path),
        "stored_path": str(source_path) if mode == "upload" else "",
        "dissect_path": str(dissect_path),
        "uploaded_files": [str(path) for path in uploaded_paths],
    }


# ---------------------------------------------------------------------------
# Hash / CSV / audit helpers
# ---------------------------------------------------------------------------

def resolve_hash_verification_path(case: dict[str, Any]) -> Path | None:
    """Resolve the file path for evidence hash verification.

    Args:
        case: The in-memory case state dictionary.

    Returns:
        Path to the evidence file, or ``None``.
    """
    source_path = str(case.get("source_path", "")).strip()
    if source_path:
        return Path(source_path)
    evidence_path = str(case.get("evidence_path", "")).strip()
    if evidence_path:
        return Path(evidence_path)
    return None


def resolve_case_csv_output_dir(case: dict[str, Any], config_snapshot: dict[str, Any]) -> Path:
    """Resolve the output directory for parsed CSV files.

    Args:
        case: The in-memory case state dictionary.
        config_snapshot: Application configuration snapshot.

    Returns:
        Absolute ``Path`` to the CSV output directory.
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


def collect_case_csv_paths(case: dict[str, Any]) -> list[Path]:
    """Collect all parsed CSV file paths for a case.

    Args:
        case: The in-memory case state dictionary.

    Returns:
        A sorted list of existing CSV file paths.
    """
    collected: list[Path] = []
    seen: set[str] = set()

    def _add_path(candidate: Any) -> None:
        """Add a CSV path if it exists and is not a duplicate."""
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
            if isinstance(csv_path, list):
                for p in csv_path:
                    _add_path(p)
            else:
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
    return sorted(path for path in parsed_dir.glob("*.csv") if path.is_file())


def build_csv_map(parse_results: list[dict[str, Any]]) -> dict[str, str | list[str]]:
    """Build a mapping of artifact keys to their parsed CSV file paths.

    Split artifacts (e.g. EVTX) that produce multiple CSV files are
    represented as a ``list[str]`` value.  Single-file artifacts remain
    a plain ``str`` so existing callers are unaffected.

    Args:
        parse_results: List of per-artifact parse result dicts.

    Returns:
        Dict mapping artifact key strings to a single CSV path string
        or a list of CSV path strings for split artifacts.
    """
    mapping: dict[str, str | list[str]] = {}
    for result in parse_results:
        artifact = str(result.get("artifact_key", "")).strip()
        if not artifact or not result.get("success"):
            continue
        csv_paths = result.get("csv_paths")
        if isinstance(csv_paths, list) and csv_paths:
            non_empty = [str(p) for p in csv_paths if str(p).strip()]
            if len(non_empty) > 1:
                mapping[artifact] = non_empty
                continue
            if non_empty:
                mapping[artifact] = non_empty[0]
                continue
        csv_path = str(result.get("csv_path", "")).strip()
        if csv_path:
            mapping[artifact] = csv_path
    return mapping


def read_audit_entries(case_dir: Path) -> list[dict[str, Any]]:
    """Read all audit log entries from a case's ``audit.jsonl`` file.

    Args:
        case_dir: Path to the case's root directory.

    Returns:
        A list of parsed audit entry dicts, or empty list if missing.
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


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------

evidence_bp = Blueprint("evidence", __name__)


@evidence_bp.post("/api/cases/<case_id>/evidence")
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
            # Set new evidence metadata.
            case["evidence_mode"] = evidence_payload["mode"]
            case["source_path"] = evidence_payload["source_path"]
            case["stored_path"] = evidence_payload["stored_path"]
            case["uploaded_files"] = list(evidence_payload.get("uploaded_files", []))
            case["evidence_path"] = str(dissect_path)
            case["evidence_hashes"] = hashes
            case["image_metadata"] = metadata
            case["available_artifacts"] = available_artifacts

            # Invalidate all downstream state derived from prior evidence.
            case["parse_results"] = []
            case["artifact_csv_paths"] = {}
            case["analysis_results"] = {}
            case["csv_output_dir"] = ""
            case["selected_artifacts"] = []
            case["analysis_artifacts"] = []
            case["artifact_options"] = []
            case["analysis_date_range"] = None
            case["investigation_context"] = ""
            case["status"] = "evidence_loaded"

            # Clear progress stores so stale SSE streams are not reused.
            PARSE_PROGRESS.pop(case_id, None)
            ANALYSIS_PROGRESS.pop(case_id, None)
            CHAT_PROGRESS.pop(case_id, None)

        # Remove stale on-disk artifacts so disk fallbacks cannot
        # resurrect results from prior evidence.
        for stale_file in ("analysis_results.json", "prompt.txt", "chat_history.jsonl"):
            stale_path = case_dir / stale_file
            if stale_path.exists():
                stale_path.unlink(missing_ok=True)

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


@evidence_bp.get("/api/cases/<case_id>/report")
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

    return send_file(
        report_path,
        as_attachment=True,
        download_name=report_path.name,
        mimetype="text/html",
    )


@evidence_bp.get("/api/cases/<case_id>/csvs")
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
