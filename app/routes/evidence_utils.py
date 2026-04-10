"""Shared evidence-handling utilities used by both evidence and images routes.

Provides common logic for computing evidence hashes, checking whether hashing
should be skipped, opening a Dissect forensic target, and safety-checked
directory removal.  These functions were extracted from duplicated code in
:mod:`~app.routes.evidence` and :mod:`~app.routes.images` to ensure
consistent behaviour.

Attributes:
    LOGGER: Module-level logger instance.
"""

from __future__ import annotations

import logging
import shutil
from pathlib import Path
from typing import Any

from flask import request

LOGGER = logging.getLogger(__name__)

__all__ = [
    "compute_evidence_hashes",
    "open_dissect_target",
    "safe_rmtree",
    "should_skip_hashing",
]


def safe_rmtree(target_dir: Path, cases_root: Path) -> bool:
    """Remove a directory only if it passes safety checks.

    Guards against accidentally deleting filesystem roots or directories
    outside the known *cases_root*.  This is the single implementation of
    the safety-checked removal logic shared by evidence cleanup and stale
    parsed-data purging.

    Args:
        target_dir: The directory to remove.  Must already exist on disk
            for any removal to occur.
        cases_root: The resolved root directory that contains all case
            directories.  *target_dir* must be a descendant of this path.

    Returns:
        ``True`` if the directory was removed (or an ``rmtree`` was
        attempted with ``ignore_errors=True``).  ``False`` if removal
        was skipped due to a safety check or because the directory does
        not exist.
    """
    if not target_dir.is_dir():
        return False

    resolved = target_dir.resolve()

    # Refuse to delete filesystem roots.
    if resolved == Path(resolved.root) or resolved == Path(resolved.anchor):
        LOGGER.warning(
            "Refusing to remove directory at filesystem root: %s",
            resolved,
        )
        return False

    # Refuse to delete paths outside the known cases root.
    resolved_cases_root = cases_root.resolve()
    try:
        if not resolved.is_relative_to(resolved_cases_root):
            LOGGER.warning(
                "Refusing to remove directory outside cases root: %s",
                resolved,
            )
            return False
    except (TypeError, ValueError):
        return False

    LOGGER.info("Removing directory: %s", resolved)
    shutil.rmtree(resolved, ignore_errors=True)
    return True


def should_skip_hashing() -> bool:
    """Check whether the current Flask request opts to skip evidence hashing.

    Inspects either multipart form data or JSON body for a ``skip_hashing``
    flag.

    Returns:
        ``True`` if the user requested hashing be skipped.
    """
    if request.content_type and "multipart" in request.content_type:
        return bool(request.form.get("skip_hashing"))
    payload = request.get_json(silent=True) or {}
    if isinstance(payload, dict):
        return bool(payload.get("skip_hashing"))
    return False


def compute_evidence_hashes(
    files_to_hash: list[str],
    source_path: Path,
    skip_hashing: bool,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Compute SHA-256/MD5 hashes for evidence files.

    When *skip_hashing* is ``True``, placeholder values are returned.
    When *files_to_hash* is empty (e.g. a bare directory), ``N/A (directory)``
    placeholders are used.

    Args:
        files_to_hash: List of filesystem paths to hash.
        source_path: The primary source evidence path (used for ``filename``).
        skip_hashing: Whether hashing was skipped by user request.

    Returns:
        A ``(hashes_summary, file_hashes_list)`` tuple.  *hashes_summary* is
        a dict with ``sha256``, ``md5``, ``size_bytes``, and ``filename``
        keys.  *file_hashes_list* contains per-file hash dicts.
    """
    if skip_hashing:
        hashes: dict[str, Any] = {
            "sha256": "N/A (skipped)",
            "md5": "N/A (skipped)",
            "size_bytes": 0,
        }
        hashes["filename"] = source_path.name
        return hashes, []

    if files_to_hash:
        from ..hasher import compute_hashes as _compute_hashes

        file_hashes: list[dict[str, Any]] = []
        for fpath in files_to_hash:
            h = dict(_compute_hashes(fpath))
            h["path"] = fpath
            file_hashes.append(h)

        if len(file_hashes) == 1:
            hashes = dict(file_hashes[0])
        else:
            # Summary entry for backward compat -- individual hashes
            # are persisted separately in evidence_file_hashes.
            hashes = {
                "sha256": file_hashes[0]["sha256"],
                "md5": file_hashes[0]["md5"],
                "size_bytes": sum(h["size_bytes"] for h in file_hashes),
            }
        hashes["filename"] = source_path.name
        return hashes, file_hashes

    hashes = {
        "sha256": "N/A (directory)",
        "md5": "N/A (directory)",
        "size_bytes": 0,
    }
    hashes["filename"] = source_path.name
    return hashes, []


def open_dissect_target(
    dissect_path: Path,
    case_dir: Any,
    audit_logger: Any,
    case_id: str,
) -> tuple[dict[str, str], list[dict[str, Any]], str]:
    """Open a Dissect target and extract metadata and available artifacts.

    On failure, returns degraded defaults so the caller can still present
    a meaningful response to the user.

    Args:
        dissect_path: Path to the evidence for Dissect.
        case_dir: Case directory path (passed to ``ForensicParser``).
        audit_logger: Audit logger instance (passed to ``ForensicParser``).
        case_id: UUID of the case (used only in log messages).

    Returns:
        A ``(metadata, available_artifacts, os_type)`` tuple.  *metadata*
        contains ``hostname``, ``os_version``, and ``domain``.
    """
    from ..parser import ForensicParser

    try:
        with ForensicParser(
            evidence_path=dissect_path,
            case_dir=case_dir,
            audit_logger=audit_logger,
        ) as parser:
            metadata = parser.get_image_metadata()
            available_artifacts = parser.get_available_artifacts()
            detected_os_type = parser.os_type
    except Exception:
        LOGGER.warning(
            "Failed to open evidence with Dissect for case %s -- "
            "returning degraded response.",
            case_id,
            exc_info=True,
        )
        metadata = {
            "hostname": "Unknown",
            "os_version": "Unknown",
            "domain": "Unknown",
        }
        available_artifacts = []
        detected_os_type = "unknown"

    return metadata, available_artifacts, detected_os_type
