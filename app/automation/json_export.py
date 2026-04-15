"""Structured JSON report exporter for AIFT forensic analysis results.

Generates a machine-readable JSON file that mirrors the content of the
HTML report, suitable for consumption by other tools, SIEMs, or case
management systems.

Attributes:
    DISCLAIMER_TEXT: Standard disclaimer included in every JSON report.
    CONFIDENCE_LABEL_PATTERN: Regex for extracting confidence from analysis text.
    CONFIDENCE_ALLCAPS_PATTERN: Fallback regex for ALL-CAPS confidence words.
"""

from __future__ import annotations

import json
import logging
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.version import TOOL_VERSION

LOGGER = logging.getLogger(__name__)

DISCLAIMER_TEXT = (
    "This report was generated with AI assistance. All findings should be "
    "independently verified by a qualified forensic examiner before being "
    "used in any legal or formal proceeding."
)

CONFIDENCE_LABEL_PATTERN = re.compile(
    r"\bconfidence\b[\s:]+(?:\w+[\s:]+){0,3}(CRITICAL|HIGH|MEDIUM|LOW)\b",
    re.IGNORECASE,
)

CONFIDENCE_ALLCAPS_PATTERN = re.compile(r"\b(CRITICAL|HIGH|MEDIUM|LOW)\b")


def _resolve_confidence(text: str) -> str | None:
    """Extract a confidence label from free-text analysis.

    Uses a context-aware pattern first, then falls back to ALL-CAPS matching.

    Args:
        text: Analysis text to search.

    Returns:
        Uppercase confidence label, or None if not found.
    """
    if not text:
        return None
    match = CONFIDENCE_LABEL_PATTERN.search(text)
    if match:
        return match.group(1).upper()
    match = CONFIDENCE_ALLCAPS_PATTERN.search(text)
    if match:
        return match.group(1).upper()
    return None


def _stringify(value: Any) -> str:
    """Coerce a value to string, returning empty string for None.

    Args:
        value: Any value.

    Returns:
        String representation.
    """
    if value is None:
        return ""
    return str(value)


def _convert_v1_to_multi_image(analysis: dict[str, Any]) -> dict[str, Any]:
    """Convert a V1 single-image analysis result to multi-image format.

    Wraps V1 per-artifact findings and summary into a single-image entry
    under the ``images`` key, matching the normalisation logic in
    :class:`~app.reporter.generator.ReportGenerator`.

    Args:
        analysis: V1-format analysis results dict.

    Returns:
        Dict in multi-image format with a single ``"default"`` image entry.
    """
    per_artifact = (
        analysis.get("per_artifact")
        or analysis.get("per_artifact_findings")
        or []
    )
    summary = _stringify(
        analysis.get("summary") or analysis.get("executive_summary")
    )

    return {
        **analysis,
        "images": {
            "default": {
                "label": analysis.get("case_name", "Evidence Image"),
                "per_artifact": per_artifact,
                "summary": summary,
            }
        },
        "cross_image_summary": None,
        "model_info": analysis.get("model_info", {}),
    }


def _normalize_metadata(
    image_metadata: dict[str, Any] | list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Normalise image metadata to a list of dicts.

    Args:
        image_metadata: Single dict or list of dicts.

    Returns:
        List of metadata dicts.
    """
    if isinstance(image_metadata, list):
        return image_metadata
    return [image_metadata] if image_metadata else []


def _normalize_hashes(
    evidence_hashes: dict[str, Any] | list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Normalise evidence hashes to a list of dicts.

    Args:
        evidence_hashes: Single dict or list of dicts.

    Returns:
        List of hash dicts.
    """
    if isinstance(evidence_hashes, list):
        return evidence_hashes
    return [evidence_hashes] if evidence_hashes else []


def _build_evidence_entry(
    idx: int,
    image_id: str,
    image_data: dict[str, Any],
    metadata_list: list[dict[str, Any]],
    hashes_list: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a single evidence entry for the JSON report.

    Args:
        idx: Index for looking up metadata/hashes.
        image_id: Image identifier string.
        image_data: Analysis data for this image.
        metadata_list: All image metadata dicts.
        hashes_list: All evidence hash dicts.

    Returns:
        Evidence entry dict.
    """
    meta = metadata_list[idx] if idx < len(metadata_list) else {}
    hashes = hashes_list[idx] if idx < len(hashes_list) else {}

    ips_raw = meta.get("ips", [])
    if isinstance(ips_raw, str):
        ips_raw = [ips_raw] if ips_raw else []

    return {
        "image_id": image_id,
        "label": image_data.get("label", ""),
        "filename": meta.get("filename", meta.get("evidence_file", "")),
        "hostname": meta.get("hostname", ""),
        "os_version": meta.get("os_version", ""),
        "domain": meta.get("domain", ""),
        "ips": ips_raw,
        "hashes": {
            "sha256": hashes.get("sha256", ""),
            "md5": hashes.get("md5", ""),
            "size_bytes": hashes.get("size_bytes", 0),
            "verification_status": hashes.get(
                "verification_status",
                hashes.get("status", "UNAVAILABLE"),
            ),
        },
    }


def _build_artifact_entry(finding: dict[str, Any]) -> dict[str, Any]:
    """Build a single artifact analysis entry.

    Args:
        finding: Per-artifact finding dict from AI analysis.

    Returns:
        Artifact entry dict for JSON report.
    """
    text = _stringify(
        finding.get("analysis") or finding.get("analysis_text", "")
    )
    return {
        "artifact_key": finding.get("artifact_key", finding.get("artifact", "")),
        "artifact_name": finding.get("artifact_name", finding.get("artifact", "")),
        "analysis_text": text,
        "confidence": finding.get("confidence") or _resolve_confidence(text),
        "model": finding.get("model", ""),
    }


def export_json_report(
    case_id: str,
    case_name: str,
    analysis_results: dict[str, Any],
    image_metadata: dict[str, Any] | list[dict[str, Any]],
    evidence_hashes: dict[str, Any] | list[dict[str, Any]],
    investigation_context: str,
    audit_log_entries: list[dict[str, Any]],
    output_path: Path,
    tool_version: str | None = None,
) -> Path:
    """Export a complete JSON report mirroring the HTML report content.

    Handles both V1 (single-image) and multi-image analysis formats,
    normalising V1 to multi-image structure internally.  Writes atomically
    via a temporary file and rename.

    Args:
        case_id: Unique case identifier.
        case_name: Human-readable case name.
        analysis_results: AI analysis output (V1 or multi-image format).
        image_metadata: Per-image metadata (dict or list).
        evidence_hashes: Per-image hash info (dict or list).
        investigation_context: User's investigation prompt.
        audit_log_entries: Parsed audit.jsonl entries.
        output_path: Where to write the JSON file.
        tool_version: Override version string (defaults to TOOL_VERSION).

    Returns:
        Path to the written JSON file.

    Raises:
        OSError: If output_path is not writable.
    """
    version = tool_version or TOOL_VERSION
    analysis = dict(analysis_results)

    # Normalise to multi-image format.
    if "images" not in analysis:
        analysis = _convert_v1_to_multi_image(analysis)

    images_data: dict[str, Any] = analysis.get("images", {})
    model_info = analysis.get("model_info", {})
    metadata_list = _normalize_metadata(image_metadata)
    hashes_list = _normalize_hashes(evidence_hashes)

    # Build evidence entries.
    evidence_entries: list[dict[str, Any]] = []
    for idx, (image_id, image_data) in enumerate(images_data.items()):
        evidence_entries.append(
            _build_evidence_entry(idx, image_id, image_data, metadata_list, hashes_list)
        )

    # Build analysis section.
    analysis_section: dict[str, Any] = {"images": {}, "cross_image_summary": None}
    for image_id, image_data in images_data.items():
        per_artifact = image_data.get("per_artifact", [])
        if isinstance(per_artifact, dict):
            per_artifact = list(per_artifact.values())

        analysis_section["images"][image_id] = {
            "label": image_data.get("label", ""),
            "summary": _stringify(image_data.get("summary", "")),
            "artifacts": [_build_artifact_entry(f) for f in per_artifact],
        }

    analysis_section["cross_image_summary"] = analysis.get("cross_image_summary")

    # Build audit trail.
    audit_trail = [
        {
            "timestamp": entry.get("timestamp", ""),
            "action": entry.get("action", ""),
            "details": entry.get("details", {}),
        }
        for entry in audit_log_entries
    ]

    report = {
        "report_metadata": {
            "tool": "AIFT",
            "tool_version": version,
            "report_generated_utc": datetime.now(timezone.utc).isoformat(),
            "case_id": case_id,
            "case_name": case_name,
            "ai_provider": model_info.get("provider", "unknown"),
            "ai_model": model_info.get("model", "unknown"),
        },
        "investigation_context": investigation_context,
        "evidence": evidence_entries,
        "analysis": analysis_section,
        "audit_trail": audit_trail,
        "disclaimer": DISCLAIMER_TEXT,
    }

    # Atomic write via temp file.
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    tmp_fd = None
    tmp_path = None
    try:
        tmp_fd, tmp_name = tempfile.mkstemp(
            dir=output_path.parent,
            suffix=".tmp",
        )
        tmp_path = Path(tmp_name)
        with open(tmp_fd, "w", encoding="utf-8") as f:
            tmp_fd = None  # open() took ownership
            json.dump(report, f, indent=2, ensure_ascii=False)
        tmp_path.replace(output_path)
        LOGGER.info("JSON report written to %s", output_path)
    except Exception:
        if tmp_fd is not None:
            import os
            os.close(tmp_fd)
        if tmp_path is not None and tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        raise

    return output_path
