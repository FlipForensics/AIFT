"""Evidence folder scanner for automated forensic triage.

Recursively discovers forensic evidence files that Dissect can process,
handles split-image segment deduplication, and validates user-supplied
paths.

Attributes:
    ARCHIVE_EXTENSIONS: Extensions treated as archive containers.
    SKIP_NAMES: Filenames and directory names to ignore during scanning.
"""

from __future__ import annotations

import logging
from pathlib import Path

from app.routes.state import DISSECT_EVIDENCE_EXTENSIONS
from app.routes.evidence_upload import segment_identity

LOGGER = logging.getLogger(__name__)

ARCHIVE_EXTENSIONS: frozenset[str] = frozenset({
    ".zip", ".tar", ".gz", ".tgz", ".7z",
})

SKIP_NAMES: frozenset[str] = frozenset({
    "__MACOSX", "Thumbs.db", "desktop.ini", ".DS_Store",
})


def validate_evidence_path(path: str | Path) -> Path:
    """Resolve and validate an evidence path.

    Strips surrounding quotes, expands user home dir, resolves to absolute,
    rejects path traversal (``..`` components), and verifies existence.

    Args:
        path: Raw path string from user input.

    Returns:
        Resolved absolute Path.

    Raises:
        FileNotFoundError: If resolved path does not exist.
        ValueError: If path contains traversal components or is empty.
    """
    raw = str(path).strip().strip("'\"").strip()
    if not raw:
        raise ValueError("Evidence path must not be empty.")

    resolved = Path(raw).expanduser().resolve()

    # Reject traversal components in the original input.
    parts = Path(raw).parts
    if ".." in parts:
        raise ValueError(
            f"Path contains traversal component '..': {raw}"
        )

    if not resolved.exists():
        raise FileNotFoundError(f"Evidence path does not exist: {resolved}")

    return resolved


def _is_hidden_or_skipped(path: Path) -> bool:
    """Check whether a path should be skipped during scanning.

    Args:
        path: File or directory path to check.

    Returns:
        True if the path is hidden or in the skip list.
    """
    return path.name.startswith(".") or path.name in SKIP_NAMES


def _has_supported_extension(path: Path) -> bool:
    """Check whether a file has a supported evidence extension.

    Args:
        path: File path to check.

    Returns:
        True if the file's suffix is in DISSECT_EVIDENCE_EXTENSIONS.
    """
    return path.suffix.lower() in DISSECT_EVIDENCE_EXTENSIONS


def _deduplicate_segments(paths: list[Path]) -> list[Path]:
    """Remove duplicate split-image segments, keeping only the first.

    Groups sibling segments by their base identity string and retains
    only the lowest-numbered segment from each group.

    Args:
        paths: List of evidence file paths (may include segments).

    Returns:
        Filtered list with only the first segment per split-image group.
    """
    groups: dict[tuple[str, str], list[Path]] = {}
    non_segments: list[Path] = []

    for p in paths:
        seg = segment_identity(p)
        if seg is None:
            non_segments.append(p)
        else:
            kind, base, _num = seg
            key = (kind, base)
            groups.setdefault(key, []).append(p)

    # For each segment group, sort by filename and keep the first.
    first_segments: list[Path] = []
    for _key, group in groups.items():
        group.sort(key=lambda x: x.name.lower())
        first_segments.append(group[0])
        if len(group) > 1:
            LOGGER.debug(
                "Segment group with %d parts, keeping: %s",
                len(group),
                group[0].name,
            )

    return non_segments + first_segments


def discover_evidence(source_path: str | Path) -> list[Path]:
    """Discover all forensic evidence targets at the given path.

    If *source_path* is a file, validate it has a supported extension and
    return it in a single-element list.  If *source_path* is a directory,
    scan its **direct children only** (no recursive walk):

    - Child **files** with a supported extension are included as evidence.
    - Child **directories** are included as-is — Dissect can open certain
      directory structures (e.g. ``acquire`` tar extractions) as targets.
    - Hidden entries and common system files are skipped.

    Segment handling: when multiple segments of the same split image are
    found (e.g. ``image.E01``, ``image.E02``), only the first segment
    (lowest numbered) is included.

    Args:
        source_path: Path to a single evidence file or a directory to scan.

    Returns:
        Sorted list of unique Path objects, each pointing to a viable
        evidence file or a subdirectory that should be opened as a Dissect
        target.  Empty list if no evidence found.

    Raises:
        FileNotFoundError: If source_path does not exist.
        ValueError: If source_path is a file but has no supported extension.
    """
    resolved = Path(source_path).resolve()

    if not resolved.exists():
        raise FileNotFoundError(f"Evidence path does not exist: {resolved}")

    if resolved.is_file():
        if not _has_supported_extension(resolved):
            raise ValueError(
                f"Unsupported evidence file extension '{resolved.suffix}': "
                f"{resolved.name}"
            )
        return [resolved]

    # Shallow directory scan — direct children only.
    file_candidates: list[Path] = []
    dir_candidates: list[Path] = []

    for child in resolved.iterdir():
        if _is_hidden_or_skipped(child):
            continue
        if child.is_dir():
            dir_candidates.append(child)
        elif child.is_file() and _has_supported_extension(child):
            file_candidates.append(child)

    deduplicated_files = _deduplicate_segments(file_candidates)

    result = deduplicated_files + dir_candidates
    result.sort(key=lambda p: str(p))

    LOGGER.info("Discovered %d evidence target(s) in %s", len(result), resolved)
    return result
