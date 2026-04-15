"""Headless orchestration engine for automated AIFT forensic triage.

Runs the complete AIFT pipeline — evidence discovery, parsing, AI analysis,
and report generation — without Flask or a browser.  This module is the
shared core used by both the REST API endpoint and the CLI tool.

Attributes:
    PROFILE_DIR_NAME: Subdirectory name for artifact profiles.
    DEFAULT_PROFILE_NAME: Fallback profile when none specified.
"""

from __future__ import annotations

import json
import logging
import shutil
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.analyzer.core import ForensicAnalyzer
from app.audit import AuditLogger
from app.automation.discovery import discover_evidence, validate_evidence_path
from app.automation.json_export import export_json_report
from app.case_manager import CaseManager
from app.config import load_config
from app.hasher import compute_hashes
from app.parser.core import ForensicParser
from app.reporter.generator import ReportGenerator
from app.routes.artifacts import (
    artifact_options_to_lists,
    load_profiles_from_directory,
)
from app.version import TOOL_VERSION

LOGGER = logging.getLogger(__name__)

PROFILE_DIR_NAME = "profile"
DEFAULT_PROFILE_NAME = "recommended"

# Project root: app/automation/engine.py -> app/automation -> app -> root
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent


@dataclass
class AutomationRequest:
    """Parameters for an automated forensic triage run.

    Attributes:
        evidence_path: Path to evidence file or folder to process.
        prompt: Investigation context / prompt for AI analysis.
        output_dir: Directory where reports (HTML + JSON) will be written.
        profile_name: Artifact profile name.  Falls back to ``"recommended"``
            if None, empty, or not found.
        config_path: Path to config.yaml.  Falls back to default if None
            or not found.
        case_name: Optional human-readable case name for the report header.
        skip_hashing: If True, skip SHA-256/MD5 evidence hash computation.
        date_range: Optional ``(start_date, end_date)`` tuple for filtering
            analysis to a specific time window.
    """

    evidence_path: str | Path
    prompt: str
    output_dir: str | Path
    profile_name: str | None = None
    config_path: str | Path | None = None
    case_name: str | None = None
    skip_hashing: bool = False
    date_range: tuple[str, str] | None = None


@dataclass
class AutomationResult:
    """Result of an automated forensic triage run.

    Attributes:
        success: Whether the run completed without fatal errors.
        case_id: UUID of the created case.
        html_report_path: Path to the generated HTML report, or None if
            report generation failed.
        json_report_path: Path to the generated JSON report, or None if
            report generation failed.
        evidence_files: List of evidence file Paths that were processed.
        errors: List of error message strings for any fatal failures.
        warnings: List of non-fatal warning message strings.
        duration_seconds: Total wall-clock time of the run in seconds.
    """

    success: bool
    case_id: str
    html_report_path: Path | None = None
    json_report_path: Path | None = None
    evidence_files: list[Path] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0


def _notify(
    callback: Callable[[str, str, float], None] | None,
    phase: str,
    message: str,
    percentage: float,
) -> None:
    """Invoke progress callback if provided.

    Args:
        callback: Optional progress callback function.
        phase: Phase name (discovery, hashing, parsing, analysis, reporting).
        message: Human-readable status message.
        percentage: Progress within the phase, 0.0--100.0.
    """
    if callback is not None:
        try:
            callback(phase, message, percentage)
        except Exception:
            LOGGER.debug("Progress callback raised; ignoring.", exc_info=True)


def _load_config_safe(config_path: str | Path | None) -> tuple[dict[str, Any], list[str]]:
    """Load configuration, falling back to defaults on failure.

    Args:
        config_path: Path to config.yaml, or None for default.

    Returns:
        Tuple of ``(config_dict, warning_strings)``.
    """
    warnings: list[str] = []

    if config_path is not None:
        resolved = Path(config_path).resolve()
        if resolved.is_file():
            try:
                return load_config(resolved), warnings
            except Exception as exc:
                warnings.append(
                    f"Failed to load config from {resolved}: {exc}. "
                    "Falling back to default config."
                )
        else:
            warnings.append(
                f"Config path not found: {resolved}. Falling back to default."
            )

    return load_config(None), warnings


def _load_profile(
    profile_name: str | None,
) -> tuple[list[str], list[str], list[str]]:
    """Load artifact profile and split into parse/analysis lists.

    Args:
        profile_name: Requested profile name, or None for default.

    Returns:
        Tuple of ``(parse_artifacts, analysis_artifacts, warnings)``.
    """
    warnings: list[str] = []
    profiles_root = _PROJECT_ROOT / PROFILE_DIR_NAME
    profiles = load_profiles_from_directory(profiles_root)

    target_name = (profile_name or "").strip().lower() or DEFAULT_PROFILE_NAME
    matched = None
    for p in profiles:
        if str(p.get("name", "")).strip().lower() == target_name:
            matched = p
            break

    if matched is None:
        warnings.append(
            f"Profile '{profile_name}' not found. Falling back to "
            f"'{DEFAULT_PROFILE_NAME}'."
        )
        for p in profiles:
            if str(p.get("name", "")).strip().lower() == DEFAULT_PROFILE_NAME:
                matched = p
                break

    if matched is None:
        # Last resort: use first available profile.
        if profiles:
            matched = profiles[0]
            warnings.append(
                f"'{DEFAULT_PROFILE_NAME}' profile not found either. "
                f"Using '{matched.get('name', 'unknown')}'."
            )
        else:
            return [], [], warnings + ["No artifact profiles found."]

    artifact_options = matched.get("artifact_options", [])
    parse_artifacts, analysis_artifacts = artifact_options_to_lists(artifact_options)
    return parse_artifacts, analysis_artifacts, warnings


def _read_audit_log(case_dir: Path) -> list[dict[str, Any]]:
    """Read and parse the case audit.jsonl file into a list of dicts.

    Args:
        case_dir: Path to the case directory containing ``audit.jsonl``.

    Returns:
        List of parsed audit log entry dicts. Empty list on read failure.
    """
    audit_file = case_dir / "audit.jsonl"
    entries: list[dict[str, Any]] = []
    if not audit_file.exists():
        return entries
    try:
        for line in audit_file.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                entries.append(json.loads(line))
    except Exception as exc:
        LOGGER.warning("Failed to read audit log: %s", exc)
    return entries


def _generate_report_basename(case_id: str) -> str:
    """Build a report filename stem from case ID and current timestamp.

    Args:
        case_id: UUID case identifier.

    Returns:
        Filename stem without extension, e.g. ``AIFT_report_<uuid>_<ts>``.
    """
    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"AIFT_report_{case_id}_{ts}"


def run_automation(
    request: AutomationRequest,
    progress_callback: Callable[[str, str, float], None] | None = None,
) -> AutomationResult:
    """Execute a complete automated forensic triage pipeline.

    This is the main entry point for both API and CLI automation.  It runs
    synchronously (blocking) and handles the full workflow:

    1. Validate inputs (evidence path, config, profile, output dir).
    2. Load configuration from *config_path* (fallback to default).
    3. Load artifact profile (fallback to ``"recommended"``).
    4. Discover evidence files (folder scanning if directory given).
    5. Create a case via :class:`~app.case_manager.CaseManager`.
    6. For each evidence file: open Dissect target, extract metadata,
       compute hashes, intersect artifacts with profile, parse to CSV.
    7. Run AI analysis across all images.
    8. Generate HTML report (copied to *output_dir*).
    9. Generate JSON report (written to *output_dir*).
    10. Return :class:`AutomationResult` with all paths and status.

    The *progress_callback* receives ``(phase, message, percentage)`` where
    phase is one of ``"discovery"``, ``"hashing"``, ``"parsing"``,
    ``"analysis"``, ``"reporting"`` and percentage is 0.0--100.0.

    Error handling:

    - If evidence discovery finds 0 files: return failure immediately.
    - If a single image fails to open/parse: log warning, continue.
    - If ALL images fail: return failure.
    - If analysis fails: return failure with partial results.
    - If report generation fails: return failure but include
      ``analysis_results.json`` in the case directory.

    Args:
        request: Automation parameters dataclass.
        progress_callback: Optional callback for progress updates.

    Returns:
        AutomationResult with success status and output paths.
    """
    start_time = time.monotonic()
    result = AutomationResult(success=False, case_id="")

    # --- 1. Validate inputs ---
    try:
        evidence_path = validate_evidence_path(request.evidence_path)
    except (FileNotFoundError, ValueError) as exc:
        result.errors.append(str(exc))
        result.duration_seconds = time.monotonic() - start_time
        return result

    output_dir = Path(request.output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    # --- 2. Load configuration ---
    config, config_warnings = _load_config_safe(request.config_path)
    result.warnings.extend(config_warnings)

    # --- 3. Load profile ---
    parse_artifacts, analysis_artifacts, profile_warnings = _load_profile(
        request.profile_name
    )
    result.warnings.extend(profile_warnings)

    if not parse_artifacts:
        result.errors.append("No artifacts to parse after profile resolution.")
        result.duration_seconds = time.monotonic() - start_time
        return result

    # --- 4. Discover evidence ---
    _notify(progress_callback, "discovery", "Scanning for evidence files...", 0.0)
    try:
        evidence_files = discover_evidence(evidence_path)
    except (FileNotFoundError, ValueError) as exc:
        result.errors.append(f"Evidence discovery failed: {exc}")
        result.duration_seconds = time.monotonic() - start_time
        return result

    if not evidence_files:
        result.errors.append("No evidence files found at the specified path.")
        result.duration_seconds = time.monotonic() - start_time
        return result

    result.evidence_files = evidence_files
    _notify(
        progress_callback,
        "discovery",
        f"Found {len(evidence_files)} evidence file(s).",
        100.0,
    )

    # --- 5. Create case ---
    cases_dir = _PROJECT_ROOT / "cases"
    case_manager = CaseManager(cases_dir=cases_dir)
    case_name = request.case_name or f"Automated Triage {datetime.now(timezone.utc):%Y-%m-%d}"
    case_id = case_manager.create_case(case_name=case_name)
    result.case_id = case_id
    case_dir = cases_dir / case_id

    audit_logger = AuditLogger(case_directory=case_dir, tool_version=TOOL_VERSION)

    # --- 6. Per-image processing ---
    image_descriptors: list[dict[str, Any]] = []
    all_metadata: list[dict[str, Any]] = []
    all_hashes: list[dict[str, Any]] = []
    successful_images = 0

    for img_idx, ev_file in enumerate(evidence_files):
        img_label = ev_file.name
        pct = (img_idx / len(evidence_files)) * 100.0

        try:
            image_id = case_manager.add_image(case_id, label=img_label)
        except Exception as exc:
            msg = f"Failed to add image for {img_label}: {exc}"
            LOGGER.warning(msg)
            result.warnings.append(msg)
            continue

        image_dir = case_manager.get_image_dir(case_id, image_id)
        parsed_dir = image_dir / "parsed"

        # Open Dissect target and get metadata.
        try:
            parser = ForensicParser(
                evidence_path=ev_file,
                case_dir=case_dir,
                audit_logger=audit_logger,
                parsed_dir=parsed_dir,
            )
            metadata = parser.get_image_metadata()
            metadata["evidence_file"] = str(ev_file.name)
            available = parser.get_available_artifacts()
            os_type = parser.os_type
        except Exception as exc:
            msg = f"Failed to open evidence {img_label}: {exc}"
            LOGGER.warning(msg)
            result.warnings.append(msg)
            continue

        all_metadata.append(metadata)

        # Hash evidence.
        hashes_entry: dict[str, Any] = {
            "sha256": "",
            "md5": "",
            "size_bytes": 0,
            "verification_status": "SKIPPED",
        }
        if not request.skip_hashing:
            _notify(progress_callback, "hashing", f"Hashing {img_label}...", pct)
            try:
                h = compute_hashes(ev_file)
                hashes_entry = {
                    "sha256": h["sha256"],
                    "md5": h["md5"],
                    "size_bytes": h["size_bytes"],
                    "verification_status": "PASS",
                }
                audit_logger.log("evidence_intake", {
                    "file": str(ev_file),
                    "sha256": h["sha256"],
                    "md5": h["md5"],
                    "size_bytes": h["size_bytes"],
                })
            except Exception as exc:
                msg = f"Hashing failed for {img_label}: {exc}"
                LOGGER.warning(msg)
                result.warnings.append(msg)
                hashes_entry["verification_status"] = "UNAVAILABLE"

        all_hashes.append(hashes_entry)

        # Intersect profile artifacts with available.
        available_names = {a.get("name", a.get("artifact_key", "")) for a in available}
        image_parse = [a for a in parse_artifacts if a in available_names]
        image_analysis = [a for a in analysis_artifacts if a in available_names]

        if not image_parse:
            msg = f"No matching artifacts available for {img_label}."
            LOGGER.warning(msg)
            result.warnings.append(msg)
            continue

        # Parse artifacts.
        csv_paths: dict[str, str | Path] = {}
        _notify(progress_callback, "parsing", f"Parsing {img_label}...", pct)

        for artifact_key in image_parse:
            try:
                parse_result = parser.parse_artifact(artifact_key)
                if parse_result.get("success") and parse_result.get("csv_path"):
                    csv_paths[artifact_key] = parse_result["csv_path"]
                    # Handle EVTX multi-part CSVs.
                    if parse_result.get("csv_paths"):
                        csv_paths[artifact_key] = parse_result["csv_paths"]
            except Exception as exc:
                msg = f"Parse failed for {artifact_key} on {img_label}: {exc}"
                LOGGER.warning(msg)
                result.warnings.append(msg)

        if not csv_paths:
            msg = f"All artifact parsing failed for {img_label}."
            LOGGER.warning(msg)
            result.warnings.append(msg)
            continue

        successful_images += 1
        image_descriptors.append({
            "image_id": image_id,
            "label": img_label,
            "metadata": metadata,
            "artifact_keys": image_analysis,
            "parsed_dir": str(parsed_dir),
            "os_type": os_type,
            "csv_paths": csv_paths,
        })

    if successful_images == 0:
        result.errors.append("All evidence images failed to process.")
        result.duration_seconds = time.monotonic() - start_time
        return result

    # --- 7. AI Analysis ---
    _notify(progress_callback, "analysis", "Running AI analysis...", 0.0)
    analysis_results: dict[str, Any] = {}

    try:
        if len(image_descriptors) == 1:
            desc = image_descriptors[0]
            analyzer = ForensicAnalyzer(
                case_dir=case_dir,
                config=config,
                audit_logger=audit_logger,
                artifact_csv_paths=desc["csv_paths"],
                os_type=desc["os_type"],
            )
            analysis_results = analyzer.run_full_analysis(
                artifact_keys=desc["artifact_keys"],
                investigation_context=request.prompt,
                metadata=desc["metadata"],
            )
        else:
            # Multi-image: use first image's csv_paths for constructor,
            # then call run_multi_image_analysis.
            first = image_descriptors[0]
            analyzer = ForensicAnalyzer(
                case_dir=case_dir,
                config=config,
                audit_logger=audit_logger,
                artifact_csv_paths=first["csv_paths"],
                os_type=first["os_type"],
            )
            analysis_results = analyzer.run_multi_image_analysis(
                images_analysis_list=image_descriptors,
                cross_image_context=request.prompt,
            )

        # Persist analysis_results.json in case dir.
        results_file = case_dir / "analysis_results.json"
        with open(results_file, "w", encoding="utf-8") as f:
            json.dump(analysis_results, f, indent=2, ensure_ascii=True)

    except Exception as exc:
        msg = f"AI analysis failed: {exc}"
        LOGGER.error(msg, exc_info=True)
        result.errors.append(msg)
        result.duration_seconds = time.monotonic() - start_time
        return result

    _notify(progress_callback, "analysis", "Analysis complete.", 100.0)

    # --- 8 & 9. Report generation ---
    _notify(progress_callback, "reporting", "Generating reports...", 0.0)
    audit_entries = _read_audit_log(case_dir)
    basename = _generate_report_basename(case_id)

    # HTML report.
    try:
        generator = ReportGenerator(cases_root=cases_dir)
        # Inject case_id and case_name into analysis_results for the template.
        analysis_results.setdefault("case_id", case_id)
        analysis_results.setdefault("case_name", case_name)
        html_path = generator.generate(
            analysis_results=analysis_results,
            image_metadata=all_metadata,
            evidence_hashes=all_hashes,
            investigation_context=request.prompt,
            audit_log_entries=audit_entries,
        )
        # Copy to output_dir.
        dest_html = output_dir / f"{basename}.html"
        shutil.copy2(str(html_path), str(dest_html))
        result.html_report_path = dest_html
    except Exception as exc:
        msg = f"HTML report generation failed: {exc}"
        LOGGER.error(msg, exc_info=True)
        result.errors.append(msg)

    # JSON report.
    try:
        dest_json = output_dir / f"{basename}.json"
        export_json_report(
            case_id=case_id,
            case_name=case_name,
            analysis_results=analysis_results,
            image_metadata=all_metadata,
            evidence_hashes=all_hashes,
            investigation_context=request.prompt,
            audit_log_entries=audit_entries,
            output_path=dest_json,
        )
        result.json_report_path = dest_json
    except Exception as exc:
        msg = f"JSON report generation failed: {exc}"
        LOGGER.error(msg, exc_info=True)
        result.errors.append(msg)

    _notify(progress_callback, "reporting", "Reports generated.", 100.0)

    # --- Final result ---
    result.success = len(result.errors) == 0
    result.duration_seconds = time.monotonic() - start_time
    return result
