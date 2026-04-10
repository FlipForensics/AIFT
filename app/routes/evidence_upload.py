"""Upload handling and evidence path resolution for evidence intake.

Handles collecting uploaded files from Flask requests, stream-saving with
size limits, resolving split-image segment groups, determining Dissect
target paths, normalising user-supplied paths, and archive extraction
dispatch.

Attributes:
    EWF_SEGMENT_RE: Compiled regex for EWF split segment filenames.
    SPLIT_RAW_SEGMENT_RE: Compiled regex for split raw disk image segments.
    SAVE_CHUNK_SIZE: Byte size of chunks used when stream-saving uploads.
"""

from __future__ import annotations

import logging
import re
import time
import uuid
from pathlib import Path
from typing import Any

from flask import current_app, request
from werkzeug.utils import secure_filename

from .evidence_archive import extract_zip, extract_tar, extract_7z
from .state import safe_name

LOGGER = logging.getLogger(__name__)

__all__ = [
    "EWF_SEGMENT_RE",
    "SPLIT_RAW_SEGMENT_RE",
    "SAVE_CHUNK_SIZE",
    "collect_uploaded_files",
    "save_with_limit",
    "unique_destination",
    "segment_identity",
    "collect_segment_group_paths",
    "resolve_uploaded_dissect_path",
    "normalize_user_path",
    "make_extract_dir",
    "resolve_evidence_payload",
]

EWF_SEGMENT_RE = re.compile(r"^(?P<base>.+)\.(?:e|ex|s|l)(?P<segment>\d{2})$", re.IGNORECASE)
SPLIT_RAW_SEGMENT_RE = re.compile(r"^(?P<base>.+)\.(?P<segment>\d{3})$")

SAVE_CHUNK_SIZE = 4 * 1024 * 1024  # 4 MiB


def collect_uploaded_files() -> list[Any]:
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


def save_with_limit(
    file_storage: Any,
    dest: Path,
    max_bytes: int,
    cumulative: int,
) -> int:
    """Stream-save an uploaded file, enforcing an optional size limit.

    Args:
        file_storage: Werkzeug ``FileStorage`` to save.
        dest: Destination path on disk.
        max_bytes: Maximum allowed total bytes across all files (0 = unlimited).
        cumulative: Bytes already written by prior files in this upload batch.

    Returns:
        Updated cumulative byte count after this file.

    Raises:
        ValueError: If the cumulative size exceeds *max_bytes*.
    """
    if max_bytes <= 0:
        file_storage.save(dest)
        return cumulative + dest.stat().st_size

    written = 0
    stream = file_storage.stream
    with open(dest, "wb") as out:
        while True:
            chunk = stream.read(SAVE_CHUNK_SIZE)
            if not chunk:
                break
            written += len(chunk)
            if cumulative + written > max_bytes:
                out.close()
                dest.unlink(missing_ok=True)
                limit_gb = max_bytes / (1024 * 1024 * 1024)
                raise ValueError(
                    f"Upload exceeds the Evidence Size Threshold "
                    f"({limit_gb:.1f} GB). Use path mode instead, or "
                    f"increase the threshold in Settings \u2192 Advanced."
                )
            out.write(chunk)
    return cumulative + written


def unique_destination(path: Path) -> Path:
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


def segment_identity(path_or_name: Path | str) -> tuple[str, str, int] | None:
    """Parse split-image segment identity from a filename.

    Args:
        path_or_name: Path or filename to inspect.

    Returns:
        ``(kind, base_name, segment_number)`` for known split-image naming
        schemes, or ``None`` if the name is not a recognized segment.
    """
    name = Path(path_or_name).name if isinstance(path_or_name, Path) else str(path_or_name)
    for kind, pattern in (("ewf", EWF_SEGMENT_RE), ("raw", SPLIT_RAW_SEGMENT_RE)):
        match = pattern.match(name)
        if match is not None:
            return kind, match.group("base").lower(), int(match.group("segment"))
    return None


def collect_segment_group_paths(source_path: Path) -> list[Path]:
    """Collect all sibling segment paths for a split-image source file.

    Args:
        source_path: Candidate source evidence file.

    Returns:
        Sorted list of sibling segment paths for the same split-image set, or
        an empty list when the path is not a recognized split-image segment.
    """
    if not source_path.is_file():
        return []

    identity = segment_identity(source_path)
    if identity is None:
        return []

    kind, base_name, _segment_number = identity
    segment_paths: list[tuple[int, Path]] = []
    try:
        siblings = source_path.parent.iterdir()
    except OSError:
        return [source_path]

    for sibling in siblings:
        if not sibling.is_file():
            continue
        sibling_identity = segment_identity(sibling)
        if sibling_identity is None:
            continue
        sibling_kind, sibling_base_name, sibling_segment_number = sibling_identity
        if sibling_kind == kind and sibling_base_name == base_name:
            segment_paths.append((sibling_segment_number, sibling))

    if not segment_paths:
        return [source_path]
    return [path for _segment_number, path in sorted(segment_paths, key=lambda item: item[0])]


def resolve_uploaded_dissect_path(uploaded_paths: list[Path]) -> Path:
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

    segment_groups: dict[tuple[str, str], list[tuple[int, Path]]] = {}
    for path in uploaded_paths:
        identity = segment_identity(path)
        if identity is None:
            continue
        kind, base_name, segment_number = identity
        segment_groups.setdefault((kind, base_name), []).append((segment_number, path))

    if segment_groups:
        if len(segment_groups) > 1:
            group_names = sorted({base_name for _kind, base_name in segment_groups})
            raise ValueError(
                "Ambiguous upload: multiple segment groups detected "
                f"({', '.join(group_names)}). "
                "Upload only one split segment set at a time."
            )
        only_group = next(iter(segment_groups.values()))
        return min(only_group, key=lambda item: item[0])[1]

    # Multiple files that are neither a single archive nor a recognized
    # segment set -- reject rather than silently analyzing only the first.
    raise ValueError(
        "Ambiguous upload: multiple files were provided but they do not "
        "form a recognized segment set. Upload a single evidence file, "
        "one archive, or a complete split-image segment set."
    )


def normalize_user_path(value: str) -> str:
    """Strip surrounding quotes and whitespace from a user-supplied path.

    Also rejects paths containing ``..`` components to prevent path traversal
    attacks.

    Args:
        value: Raw path string.

    Returns:
        Cleaned path string.

    Raises:
        ValueError: If the cleaned path contains ``..`` traversal components.
    """
    cleaned = (
        str(value)
        .replace('"', "")
        .replace("\u201c", "")
        .replace("\u201d", "")
        .strip()
    )

    if ".." in Path(cleaned).parts:
        LOGGER.warning(
            "Rejected path containing '..' traversal component: %s", cleaned
        )
        raise ValueError(
            "Path must not contain '..' directory traversal components."
        )

    return cleaned


def make_extract_dir(evidence_dir: Path, source_path: Path) -> Path:
    """Build a unique extraction directory path for an archive.

    Args:
        evidence_dir: Parent evidence directory.
        source_path: Path to the archive being extracted.

    Returns:
        A timestamped extraction directory path.
    """
    return evidence_dir / f"extracted_{safe_name(source_path.stem, 'evidence')}_{uuid.uuid4().hex[:12]}"


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

    uploaded_files = collect_uploaded_files()
    uploaded_paths: list[Path] = []
    if uploaded_files:
        aift_config = current_app.config.get("AIFT_CONFIG", {})
        threshold_mb = aift_config.get("evidence", {}).get("large_file_threshold_mb", 0)
        max_bytes = int(threshold_mb) * 1024 * 1024 if threshold_mb and threshold_mb > 0 else 0
        cumulative_bytes = 0
        timestamp = int(time.time())
        for index, uploaded_file in enumerate(uploaded_files, start=1):
            filename = secure_filename(uploaded_file.filename) or f"evidence_{timestamp}_{index}.bin"
            stored_path = unique_destination(evidence_dir / filename)
            cumulative_bytes = save_with_limit(uploaded_file, stored_path, max_bytes, cumulative_bytes)
            uploaded_paths.append(stored_path)

        source_path = resolve_uploaded_dissect_path(uploaded_paths)
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
        normalized_path = normalize_user_path(path_value)
        if not normalized_path:
            raise ValueError(
                "Provide evidence via multipart upload or JSON body with {'path': 'C:\\Evidence\\disk-image.E01'}."
            )
        source_path = Path(normalized_path).expanduser().resolve()
        if not source_path.exists():
            raise FileNotFoundError(f"Evidence path does not exist: {source_path}")
        if not source_path.is_file() and not source_path.is_dir():
            raise ValueError(f"Evidence path is not a file or directory: {source_path}")
        uploaded_paths = []
        mode = "path"

    # Extract archives into the evidence directory.
    _ARCHIVE_EXTRACTORS = {
        ".zip": extract_zip,
        ".tar": extract_tar,
        ".gz": extract_tar,
        ".tgz": extract_tar,
        ".7z": extract_7z,
    }
    dissect_path = source_path
    suffix = source_path.suffix.lower()
    extractor = _ARCHIVE_EXTRACTORS.get(suffix)
    if source_path.is_file() and extractor is not None:
        extract_dir = make_extract_dir(evidence_dir, source_path)
        dissect_path = extractor(source_path, extract_dir)

    # Determine the files to hash for integrity verification.
    # Archives are intentionally verified as the original container file.
    # Split-image uploads hash all uploaded segments, and path-based split
    # images hash all matching sibling segments on disk. Directories get N/A.
    if source_path.is_file() and len(uploaded_paths) > 1:
        evidence_files_to_hash = sorted(set(str(p) for p in uploaded_paths))
    elif source_path.is_file():
        segment_paths = collect_segment_group_paths(source_path)
        evidence_files_to_hash = [str(path) for path in segment_paths] if segment_paths else [str(source_path)]
    else:
        evidence_files_to_hash = []

    return {
        "mode": mode,
        "filename": source_path.name,
        "source_path": str(source_path),
        "stored_path": str(source_path) if mode == "upload" else "",
        "dissect_path": str(dissect_path),
        "uploaded_files": [str(path) for path in uploaded_paths],
        "evidence_files_to_hash": evidence_files_to_hash,
    }
