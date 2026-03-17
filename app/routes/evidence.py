"""Evidence intake, archive extraction, and CSV/hash helpers for AIFT routes.

This module handles all evidence-related logic: uploading files, resolving
paths, extracting ZIP/tar/7z archives, computing and verifying hashes,
collecting parsed CSV paths, and reading audit log entries.

Attributes:
    EWF_SEGMENT_RE: Compiled regex for EWF split segment filenames.
    SPLIT_RAW_SEGMENT_RE: Compiled regex for split raw disk image segments.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import tarfile
import time
from pathlib import Path
from typing import Any, Callable
from zipfile import BadZipFile, ZipFile

import py7zr

from flask import request
from werkzeug.utils import secure_filename

from .state import (
    PROJECT_ROOT,
    safe_name,
)

__all__ = [
    "EWF_SEGMENT_RE",
    "SPLIT_RAW_SEGMENT_RE",
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
        return min(chosen_group, key=lambda item: item[0])[1]

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


def build_csv_map(parse_results: list[dict[str, Any]]) -> dict[str, str]:
    """Build a mapping of artifact keys to their parsed CSV file paths.

    Args:
        parse_results: List of per-artifact parse result dicts.

    Returns:
        Dict mapping artifact key strings to CSV path strings.
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
