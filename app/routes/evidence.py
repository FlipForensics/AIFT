"""Evidence CSV/hash helpers, route handlers, and backward-compatible re-exports.

This module contains hash verification, CSV path collection, audit log
reading, parsed-output cleanup, and the Flask route handlers for evidence
intake, report generation, and CSV bundle downloads.

Archive extraction functions live in :mod:`evidence_archive` and upload /
path resolution functions live in :mod:`evidence_upload`.  The original
public names (``EWF_SEGMENT_RE``, ``SPLIT_RAW_SEGMENT_RE``,
``resolve_evidence_payload``, and the private ``_extract_*`` / ``_collect_*``
helpers) are re-exported here for backward compatibility.

Attributes:
    evidence_bp: Flask Blueprint for evidence-related routes.
"""

from __future__ import annotations

import copy
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from zipfile import ZipFile, ZIP_DEFLATED

from flask import Blueprint, Response, make_response, send_file

from ..hasher import compute_hashes, verify_hash
from ..parser import ForensicParser
from ..reporter import ReportGenerator

from .state import (
    ANALYSIS_PROGRESS,
    CASES_ROOT,
    CHAT_PROGRESS,
    PARSE_PROGRESS,
    PROJECT_ROOT,
    SAFE_NAME_RE,
    STATE_LOCK,
    error_response,
    get_case,
    mark_case_status,
    success_response,
)

# Backward-compatible re-exports from the split-out modules.
from .evidence_archive import (  # noqa: F401
    EVIDENCE_FILE_EXTENSIONS as _EVIDENCE_FILE_EXTENSIONS,
    extract_archive_members as _extract_archive_members,
    extract_zip as _extract_zip,
    extract_tar as _extract_tar,
    extract_7z as _extract_7z,
)
from .evidence_upload import (  # noqa: F401
    EWF_SEGMENT_RE,
    SPLIT_RAW_SEGMENT_RE,
    SAVE_CHUNK_SIZE as _SAVE_CHUNK_SIZE,
    collect_uploaded_files as _collect_uploaded_files,
    save_with_limit as _save_with_limit,
    unique_destination as _unique_destination,
    segment_identity as _segment_identity,
    collect_segment_group_paths as _collect_segment_group_paths,
    resolve_uploaded_dissect_path as _resolve_uploaded_dissect_path,
    normalize_user_path as _normalize_user_path,
    make_extract_dir as _make_extract_dir,
    resolve_evidence_payload,
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
    "generate_case_report",
]

LOGGER = logging.getLogger(__name__)



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
# Cleanup helpers
# ---------------------------------------------------------------------------


def _cleanup_parsed_output(case_dir: Path, prev_csv_output_dir: str) -> None:
    """Remove stale parsed CSV output from a previous parse run.

    Delegates to :func:`~app.routes.evidence_utils.cleanup_parsed_data`.

    .. deprecated::
        Use :func:`~app.routes.evidence_utils.cleanup_parsed_data` directly.

    Args:
        case_dir: Path to the case's root directory.
        prev_csv_output_dir: The ``csv_output_dir`` value stored from the
            previous parse run (may be empty).
    """
    from .evidence_utils import cleanup_parsed_data

    cleanup_parsed_data(
        case_dir=case_dir,
        image_states={},
        prev_csv_output_dir=prev_csv_output_dir,
        clean_default_parsed=False,
    )


# ---------------------------------------------------------------------------
# Route handlers
# ---------------------------------------------------------------------------

evidence_bp = Blueprint("evidence", __name__)


@evidence_bp.post("/api/cases/<case_id>/evidence")
def intake_evidence(case_id: str) -> Response | tuple[Response, int]:
    """Ingest evidence for an existing case.

    For backward compatibility, this endpoint auto-creates a default image
    if the case has none, then delegates to the image-specific evidence
    intake logic.  The response format is unchanged.

    Args:
        case_id: UUID of the case.

    Returns:
        JSON with evidence metadata, hashes, and available artifacts.
    """
    case = get_case(case_id)
    if case is None:
        return error_response(f"Case not found: {case_id}", 404)

    # Auto-create a default image for backward compatibility.
    from .images import _get_or_create_default_image, intake_image_evidence
    image_id = _get_or_create_default_image(case_id)
    if image_id:
        # Delegate to the image-specific handler; it reads from the
        # same Flask request context so uploads/JSON body are available.
        return intake_image_evidence(case_id, image_id)

    # _get_or_create_default_image returns None only when the case
    # directory is missing on disk, which should not happen since
    # get_case() already verified the case exists above.
    return error_response(
        "Failed to initialise image directory for this case.", 500
    )


def _verify_image_hashes(
    hashes: dict[str, Any],
    file_hash_entries: list[dict[str, Any]],
) -> tuple[bool, str, list[dict[str, object]]]:
    """Verify evidence hashes for a single image.

    Args:
        hashes: Hash summary dict with ``sha256``, ``md5``, etc.
        file_hash_entries: Per-file hash entries from intake.

    Returns:
        ``(hash_ok, computed_sha256, verify_details)`` tuple.
    """
    intake_sha256 = str(hashes.get("sha256", "")).strip()
    hashing_skipped = intake_sha256 == "N/A (skipped)"

    if hashing_skipped:
        return True, intake_sha256, []

    if intake_sha256.startswith("N/A"):
        return True, intake_sha256, []

    if file_hash_entries:
        hash_ok = True
        verify_details: list[dict[str, object]] = []
        for entry in file_hash_entries:
            fpath = Path(str(entry["path"]))
            expected = str(entry["sha256"]).strip().lower()
            if not fpath.exists():
                verify_details.append({
                    "path": str(fpath), "match": False,
                    "expected": expected, "computed": "FILE_MISSING",
                })
                hash_ok = False
                continue
            ok, computed = verify_hash(fpath, expected, return_computed=True)
            verify_details.append({
                "path": str(fpath), "match": ok,
                "expected": expected, "computed": computed,
            })
            if not ok:
                hash_ok = False
        computed_sha256 = (
            str(verify_details[0]["computed"]) if len(verify_details) == 1
            else "; ".join(str(d["computed"]) for d in verify_details)
        )
        return hash_ok, computed_sha256, verify_details

    # No file hash entries — try the legacy single-file path.
    source_path = str(hashes.get("_source_path", "")).strip()
    if source_path and intake_sha256:
        vpath = Path(source_path)
        if vpath.exists():
            ok, computed = verify_hash(vpath, intake_sha256, return_computed=True)
            return ok, computed, [{
                "path": source_path, "match": ok,
                "expected": intake_sha256, "computed": computed,
            }]

    # Cannot verify — treat as pass with empty details.
    return True, intake_sha256, []


def generate_case_report(case_id: str) -> dict[str, Any]:
    """Generate the HTML forensic report for a case and save it to disk.

    Performs hash verification for every image, assembles analysis
    context, renders the report via :class:`ReportGenerator`, and logs
    the result to the audit trail.  This function can be called from
    both the download route and from background tasks (e.g.
    auto-generation after analysis).

    For multi-image cases, per-image metadata and hashes are collected
    from ``image_states`` so the report correctly represents all images.

    Args:
        case_id: UUID of the case.

    Returns:
        A result dict with keys ``success`` (bool), and on success:
        ``report_path`` (:class:`~pathlib.Path`), ``hash_ok`` (bool).
        On failure: ``error`` (str).
    """
    case = get_case(case_id)
    if case is None:
        return {"success": False, "error": f"Case not found: {case_id}"}

    with STATE_LOCK:
        case_snapshot = dict(case)
        # Deep-copy mutable nested dicts so mutations outside the lock
        # (e.g. annotating evidence_hashes for the reporter) do not
        # bleed back into the live case state or race with other threads.
        case_snapshot["image_states"] = copy.deepcopy(
            case.get("image_states", {})
        )
        case_snapshot["evidence_hashes"] = copy.deepcopy(
            case.get("evidence_hashes", {})
        )
        audit_logger = case["audit"]

    # ------------------------------------------------------------------
    # Determine whether this is a multi-image case.
    # ------------------------------------------------------------------
    image_states = case_snapshot.get("image_states", {})
    images_list = case_snapshot.get("images", [])
    is_multi = isinstance(image_states, dict) and len(image_states) > 1

    # ------------------------------------------------------------------
    # Hash verification — per-image when multi, legacy otherwise.
    # ------------------------------------------------------------------
    if is_multi:
        # Build an ordered list of image IDs from the images list so the
        # metadata/hashes lists align with the analysis "images" dict.
        ordered_image_ids: list[str] = []
        for img_entry in images_list:
            if isinstance(img_entry, dict):
                img_id = str(img_entry.get("image_id", ""))
                if img_id and img_id in image_states:
                    ordered_image_ids.append(img_id)
        # Include any image_states keys not in images_list.
        for img_id in image_states:
            if img_id not in ordered_image_ids:
                ordered_image_ids.append(img_id)

        hash_ok = True
        all_verify_details: list[dict[str, object]] = []
        metadata_list: list[dict[str, Any]] = []
        hashes_list: list[dict[str, Any]] = []

        for img_id in ordered_image_ids:
            img_st = image_states.get(img_id, {})
            img_hashes = dict(img_st.get("evidence_hashes", {}))
            img_file_hashes = list(img_st.get("evidence_file_hashes", []))
            img_metadata = dict(img_st.get("image_metadata", {}))

            img_ok, _img_sha, img_details = _verify_image_hashes(
                img_hashes, img_file_hashes,
            )
            if not img_ok:
                hash_ok = False
            all_verify_details.extend(img_details)

            # Annotate the hashes dict for the reporter.
            img_hashes["case_id"] = case_id
            img_hashes["expected_sha256"] = str(img_hashes.get("sha256", "")).strip()
            img_hashes["hash_verified"] = (
                "skipped"
                if str(img_hashes.get("sha256", "")).strip() == "N/A (skipped)"
                else img_ok
            )
            metadata_list.append(img_metadata)
            hashes_list.append(img_hashes)

        # Use the first image's sha256 for the audit log summary.
        intake_sha256 = str(hashes_list[0].get("sha256", "")) if hashes_list else ""
        computed_sha256 = (
            "; ".join(str(d.get("computed", "")) for d in all_verify_details)
            if all_verify_details else intake_sha256
        )

        audit_logger.log(
            "hash_verification",
            {
                "expected_sha256": intake_sha256,
                "computed_sha256": computed_sha256,
                "match": hash_ok,
                "skipped": False,
                "verified_files": all_verify_details,
                "multi_image": True,
                "image_count": len(ordered_image_ids),
            },
        )

        # For backward-compat: build a combined hashes dict.
        hashes = dict(hashes_list[0]) if hashes_list else {}
        hashes["case_id"] = case_id
        hashes["hash_verified"] = hash_ok

        image_metadata_arg: dict[str, Any] | list[dict[str, Any]] = metadata_list
        evidence_hashes_arg: dict[str, Any] | list[dict[str, Any]] = hashes_list
    else:
        # Single-image / legacy path.
        hashes = dict(case_snapshot.get("evidence_hashes", {}))
        intake_sha256 = str(hashes.get("sha256", "")).strip()
        file_hash_entries = list(case_snapshot.get("evidence_file_hashes", []))

        hashing_skipped = intake_sha256 == "N/A (skipped)"

        # Safety defaults in case neither branch assigns these variables.
        computed_sha256 = ""
        verify_details: list[dict[str, Any]] = []

        if file_hash_entries or hashing_skipped or intake_sha256.startswith("N/A"):
            hash_ok, computed_sha256, verify_details = _verify_image_hashes(
                hashes, file_hash_entries,
            )
        else:
            # Fallback for cases created before evidence_file_hashes existed.
            verification_path = resolve_hash_verification_path(case_snapshot)
            if verification_path is None or not intake_sha256:
                return {"success": False, "error": "Evidence integrity data is missing for this case. Please re-upload or re-reference the evidence file to generate verification hashes."}
            if not verification_path.exists():
                return {"success": False, "error": "Evidence file is no longer available for hash verification."}
            hash_ok, computed_sha256 = verify_hash(
                verification_path, intake_sha256, return_computed=True,
            )
            verify_details = [{
                "path": str(verification_path),
                "match": hash_ok,
                "expected": intake_sha256,
                "computed": computed_sha256,
            }]

        audit_logger.log(
            "hash_verification",
            {
                "expected_sha256": intake_sha256,
                "computed_sha256": computed_sha256,
                "match": hash_ok,
                "skipped": hashing_skipped,
                "verified_files": verify_details,
            },
        )

        hashes["case_id"] = case_id
        hashes["expected_sha256"] = intake_sha256
        hashes["hash_verified"] = "skipped" if hashing_skipped else hash_ok

        image_metadata_arg = dict(case_snapshot.get("image_metadata", {}))
        evidence_hashes_arg = hashes

    # ------------------------------------------------------------------
    # Validate that analysis has been completed.
    # ------------------------------------------------------------------
    analysis_results = dict(case_snapshot.get("analysis_results", {}))

    has_per_artifact = bool(analysis_results.get("per_artifact") or analysis_results.get("per_artifact_findings"))
    has_summary = bool(
        str(analysis_results.get("summary", "")).strip()
        or str(analysis_results.get("executive_summary", "")).strip()
    )
    # Multi-image results store findings under "images" (a dict of
    # image_id -> {per_artifact, summary, label}), not at the top level.
    has_multi_image = bool(
        isinstance(analysis_results.get("images"), dict)
        and analysis_results["images"]
    )
    if not has_per_artifact and not has_summary and not has_multi_image:
        return {
            "success": False,
            "error": "Analysis has not been completed for this case.",
        }

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
        image_metadata=image_metadata_arg,
        evidence_hashes=evidence_hashes_arg,
        investigation_context=investigation_context,
        audit_log_entries=read_audit_entries(Path(case_dir)),
    )
    audit_logger.log(
        "report_generated",
        {"report_filename": report_path.name, "hash_verified": hash_ok},
    )
    mark_case_status(case_id, "completed")

    return {"success": True, "report_path": report_path, "hash_ok": hash_ok}


@evidence_bp.get("/api/cases/<case_id>/report")
def download_report(case_id: str) -> Response | tuple[Response, int]:
    """Generate and download the HTML forensic analysis report.

    If a report was already auto-generated after analysis, serves the
    existing file.  Otherwise generates a new one.

    Args:
        case_id: UUID of the case.

    Returns:
        The HTML report as an attachment, or error.
    """
    case = get_case(case_id)
    if case is None:
        return error_response(f"Case not found: {case_id}", 404)

    # Check if a report was already auto-generated after analysis.
    with STATE_LOCK:
        case_dir = case["case_dir"]
    reports_dir = Path(case_dir) / "reports"
    if reports_dir.is_dir():
        existing = sorted(reports_dir.glob("report_*.html"))
        if existing:
            report_path = existing[-1]
            # Check whether this report is stale relative to analysis
            # results.  If analysis was re-run but report generation
            # failed, the old report will be older than the results
            # file.  We still serve it (stale is better than nothing)
            # but add a header so the frontend can show a notice.
            stale = False
            analysis_path = Path(case_dir) / "analysis_results.json"
            if analysis_path.is_file():
                report_mtime = report_path.stat().st_mtime
                analysis_mtime = analysis_path.stat().st_mtime
                if report_mtime < analysis_mtime:
                    stale = True
                    LOGGER.warning(
                        "Report %s is older than analysis_results.json "
                        "for case %s — serving stale report",
                        report_path.name,
                        case_id,
                    )
            response = make_response(
                send_file(
                    report_path,
                    as_attachment=True,
                    download_name=report_path.name,
                    mimetype="text/html",
                )
            )
            if stale:
                response.headers["X-Report-Stale"] = "true"
            return response

    result = generate_case_report(case_id)
    if not result["success"]:
        return error_response(str(result["error"]), 400)

    report_path = result["report_path"]
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
        # Deep-copy image_states so iteration outside the lock cannot
        # race with concurrent modifications to the live state.
        case_snapshot["image_states"] = copy.deepcopy(
            case.get("image_states", {})
        )

    csv_paths = collect_case_csv_paths(case_snapshot)

    # Check for multi-image layout: gather per-image CSV paths organized
    # into subdirectories named by image label.
    image_states = case_snapshot.get("image_states", {})
    images_list = case_snapshot.get("images", [])
    multi_image_csvs: list[tuple[str, Path]] = []

    if isinstance(image_states, dict) and len(image_states) > 1:
        # Build a label lookup from the images list.
        label_map: dict[str, str] = {}
        for img in images_list:
            if isinstance(img, dict):
                label_map[str(img.get("image_id", ""))] = str(img.get("label", ""))

        for image_id, img_state in image_states.items():
            if not isinstance(img_state, dict):
                continue
            label = label_map.get(image_id, "").strip() or image_id
            # Sanitize label for use as a directory name.
            safe_label = SAFE_NAME_RE.sub("_", label).strip("_") or image_id

            # Collect CSVs from the image's parsed directory.
            csv_dir_str = str(img_state.get("csv_output_dir", "")).strip()
            if csv_dir_str:
                csv_dir = Path(csv_dir_str)
                if csv_dir.is_dir():
                    for csv_file in sorted(csv_dir.glob("*.csv")):
                        if csv_file.is_file():
                            multi_image_csvs.append((safe_label, csv_file))

    if not csv_paths and not multi_image_csvs:
        return error_response("No parsed CSV files available for this case.", 404)

    reports_dir = Path(case_snapshot["case_dir"]) / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    # Clean up previous ZIP bundles to prevent resource leak.
    for old_zip in reports_dir.glob("parsed_csvs_*.zip"):
        try:
            old_zip.unlink()
        except OSError:
            pass

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    zip_path = reports_dir / f"parsed_csvs_{timestamp}.zip"
    used_names: set[str] = set()

    with ZipFile(zip_path, "w", compression=ZIP_DEFLATED) as archive:
        if multi_image_csvs:
            # Multi-image: organize into subdirectories by image label.
            for subdir_name, csv_file in multi_image_csvs:
                arcname = f"{subdir_name}/{csv_file.name}"
                counter = 1
                while arcname in used_names:
                    stem = csv_file.stem
                    suffix = csv_file.suffix
                    arcname = f"{subdir_name}/{stem}_{counter}{suffix}"
                    counter += 1
                used_names.add(arcname)
                archive.write(csv_file, arcname=arcname)
        else:
            # Single-image / legacy: flat structure.
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
