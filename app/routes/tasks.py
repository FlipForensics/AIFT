"""Background task runners for parsing, analysis, and multi-image analysis.

This module contains the long-running functions that execute on background
``threading.Thread`` instances:

* ``run_parse_loop`` -- Shared core parse loop used by all parse runners.
* ``run_parse`` -- Parse forensic artifacts via Dissect.
* ``run_analysis`` -- AI-powered analysis of parsed CSV artifacts.
* ``run_multi_image_analysis_task`` -- Multi-image forensic analysis.

The chat runner (``run_chat``) lives in :mod:`tasks_chat` and is
re-exported here for backward compatibility.

Each runner emits SSE progress events through the shared progress stores
defined in :mod:`routes_state` and uses a case-log-context wrapper to
ensure log messages are tagged with the case ID.
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Any, Callable

from ..analyzer import ForensicAnalyzer
from ..analyzer.core import AnalysisCancelledError
from ..case_logging import case_log_context
from ..parser import ForensicParser
from .state import (
    ANALYSIS_PROGRESS,
    PARSE_PROGRESS,
    STATE_LOCK,
    emit_progress,
    get_cancel_event,
    get_case,
    mark_case_status,
    safe_int,
    set_progress_status,
)
from .artifacts import (
    extract_parse_progress,
)

# Backward-compatible re-export: run_chat now lives in tasks_chat.
from .tasks_chat import run_chat  # noqa: F401
from .evidence import (
    build_csv_map,
    collect_case_csv_paths,
    generate_case_report,
    resolve_case_csv_output_dir,
)

__all__ = [
    "run_task_with_case_log_context",
    "run_parse_loop",
    "run_parse",
    "run_analysis",
    "run_multi_image_analysis_task",
    "run_chat",
    "load_case_analysis_results",
    "resolve_case_investigation_context",
    "resolve_case_parsed_dir",
]

LOGGER = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Prompt / context helpers
# ---------------------------------------------------------------------------

def load_case_analysis_results(case: dict[str, Any]) -> dict[str, Any] | None:
    """Load analysis results for a case from memory or disk.

    Args:
        case: The in-memory case state dictionary.

    Returns:
        Analysis results dict, or ``None``.
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


def resolve_case_investigation_context(case: dict[str, Any]) -> str:
    """Resolve the investigation context prompt for a case.

    Args:
        case: The in-memory case state dictionary.

    Returns:
        The investigation context string, or empty string.
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


def resolve_case_parsed_dir(case: dict[str, Any]) -> Path:
    """Resolve the directory containing parsed CSV files for a case.

    Args:
        case: The in-memory case state dictionary.

    Returns:
        Path to the parsed CSV directory.
    """
    csv_output_dir = str(case.get("csv_output_dir", "")).strip()
    if csv_output_dir:
        return Path(csv_output_dir)

    csv_paths = collect_case_csv_paths(case)
    if csv_paths:
        return csv_paths[0].parent

    return Path(case["case_dir"]) / "parsed"



# ---------------------------------------------------------------------------
# Case-log-context wrapper (replaces three duplicate wrappers)
# ---------------------------------------------------------------------------

def run_task_with_case_log_context(
    case_id: str,
    task_fn: Any,
    *args: Any,
    **kwargs: Any,
) -> None:
    """Run a background task function within case-scoped logging context.

    This replaces the three near-identical ``_run_*_with_case_log_context``
    wrappers with a single generic version.

    Args:
        case_id: UUID of the case (used for log tagging).
        task_fn: The callable to invoke.
        *args: Positional arguments forwarded to *task_fn*.
        **kwargs: Keyword arguments forwarded to *task_fn*.
    """
    with case_log_context(case_id):
        task_fn(*args, **kwargs)


# ---------------------------------------------------------------------------
# Shared parse loop
# ---------------------------------------------------------------------------

def run_parse_loop(
    case_id: str,
    evidence_path: str,
    case_dir: str,
    audit_logger: Any,
    parsed_dir: str,
    parse_artifacts: list[str],
    progress_key: str,
) -> tuple[list[dict[str, Any]], dict[str, str]] | None:
    """Execute the core artifact-parsing loop used by all parse runners.

    Opens a :class:`ForensicParser`, iterates over the requested artifacts,
    emits SSE progress events via *progress_key*, and returns the collected
    results together with a CSV path mapping.

    This function is the single source of truth for the inner parse logic
    shared between :func:`run_parse` (single-image V1 workflow) and
    :func:`_run_image_parse` in ``images.py`` (per-image workflow).

    Args:
        case_id: UUID of the case (used only for log messages).
        evidence_path: Filesystem path to the Dissect evidence file.
        case_dir: Filesystem path to the case directory.
        audit_logger: The case's :class:`AuditLogger` instance.
        parsed_dir: Directory where parsed CSV files are written.
        parse_artifacts: List of artifact keys to parse.
        progress_key: Key used in :data:`PARSE_PROGRESS` for SSE events.
            For single-image cases this equals *case_id*; for per-image
            parsing it is a composite key such as ``case_id::image_id``.

    Returns:
        A ``(results, csv_map)`` tuple on success, where *results* is a
        list of per-artifact result dicts and *csv_map* maps artifact keys
        to their CSV file paths.  Returns ``None`` if parsing was
        cancelled before completion.
    """
    cancel_event = get_cancel_event(PARSE_PROGRESS, progress_key)

    with ForensicParser(
        evidence_path=evidence_path,
        case_dir=case_dir,
        audit_logger=audit_logger,
        parsed_dir=parsed_dir,
    ) as parser:
        results: list[dict[str, Any]] = []
        total = len(parse_artifacts)

        for index, artifact in enumerate(parse_artifacts, start=1):
            if cancel_event is not None and cancel_event.is_set():
                LOGGER.info(
                    "Parsing cancelled for case %s before artifact %s",
                    case_id, artifact,
                )
                return None

            emit_progress(
                PARSE_PROGRESS, progress_key,
                {"type": "artifact_started", "artifact_key": artifact,
                 "index": index, "total": total},
            )

            def _progress_callback(
                *args: Any, _art: str = artifact, **_kwargs: Any,
            ) -> None:
                """Emit per-artifact parse progress events."""
                artifact_key, record_count = extract_parse_progress(_art, args)
                emit_progress(
                    PARSE_PROGRESS, progress_key,
                    {"type": "artifact_progress",
                     "artifact_key": artifact_key,
                     "record_count": record_count},
                )

            result = parser.parse_artifact(
                artifact, progress_callback=_progress_callback,
            )
            result_entry = {"artifact_key": artifact, **result}
            results.append(result_entry)

            emit_progress(
                PARSE_PROGRESS, progress_key,
                {
                    "type": (
                        "artifact_completed"
                        if result.get("success")
                        else "artifact_failed"
                    ),
                    "artifact_key": artifact,
                    "record_count": safe_int(result.get("record_count", 0)),
                    "duration_seconds": float(
                        result.get("duration_seconds", 0.0),
                    ),
                    "csv_path": str(result.get("csv_path", "")),
                    "error": result.get("error"),
                },
            )

        csv_map = build_csv_map(results)
        return results, csv_map


# ---------------------------------------------------------------------------
# Background task: parse
# ---------------------------------------------------------------------------

def run_parse(
    case_id: str,
    parse_artifacts: list[str],
    analysis_artifacts: list[str],
    artifact_options: list[dict[str, str]],
    config_snapshot: dict[str, Any],
) -> None:
    """Execute background parsing of selected forensic artifacts.

    Args:
        case_id: UUID of the case.
        parse_artifacts: Artifact keys to parse.
        analysis_artifacts: Subset for AI analysis.
        artifact_options: Canonical artifact option dicts.
        config_snapshot: Deep copy of application config.
    """
    case = get_case(case_id)
    if case is None:
        set_progress_status(PARSE_PROGRESS, case_id, "failed", "Case not found.")
        emit_progress(PARSE_PROGRESS, case_id, {"type": "parse_failed", "error": "Case not found."})
        return

    with STATE_LOCK:
        evidence_path = str(case.get("evidence_path", "")).strip()
        case_dir = case["case_dir"]
        audit_logger = case["audit"]
        case_snapshot = dict(case)

    if not evidence_path:
        mark_case_status(case_id, "failed")
        set_progress_status(PARSE_PROGRESS, case_id, "failed", "No evidence available for parsing.")
        emit_progress(PARSE_PROGRESS, case_id, {"type": "parse_failed", "error": "No evidence available for parsing."})
        return

    try:
        csv_output_dir = resolve_case_csv_output_dir(
            case_snapshot, config_snapshot=config_snapshot,
        )
        outcome = run_parse_loop(
            case_id=case_id,
            evidence_path=evidence_path,
            case_dir=case_dir,
            audit_logger=audit_logger,
            parsed_dir=str(csv_output_dir),
            parse_artifacts=parse_artifacts,
            progress_key=case_id,
        )
        if outcome is None:
            # Parsing was cancelled.
            return

        results, csv_map = outcome
        with STATE_LOCK:
            case["selected_artifacts"] = list(parse_artifacts)
            case["analysis_artifacts"] = list(analysis_artifacts)
            case["artifact_options"] = list(artifact_options)
            case["parse_results"] = results
            case["artifact_csv_paths"] = csv_map
            case["csv_output_dir"] = str(csv_output_dir)

        completed = sum(1 for item in results if item.get("success"))
        failed = len(results) - completed
        set_progress_status(PARSE_PROGRESS, case_id, "completed")
        emit_progress(
            PARSE_PROGRESS, case_id,
            {
                "type": "parse_completed",
                "total_artifacts": len(results),
                "successful_artifacts": completed,
                "failed_artifacts": failed,
            },
        )
        mark_case_status(case_id, "parsed")
    except Exception:
        LOGGER.exception("Background parse failed for case %s", case_id)
        user_message = (
            "Parsing failed due to an internal error. "
            "Check logs and retry after confirming the evidence file is readable."
        )
        mark_case_status(case_id, "error")
        set_progress_status(PARSE_PROGRESS, case_id, "failed", user_message)
        emit_progress(PARSE_PROGRESS, case_id, {"type": "parse_failed", "error": user_message})


# ---------------------------------------------------------------------------
# Background task: analysis
# ---------------------------------------------------------------------------

def _purge_stale_analysis(case: dict[str, Any], case_dir: str) -> None:
    """Clear in-memory and on-disk analysis results after a failed run.

    This prevents stale findings from a prior successful analysis from
    being served via chat, report, or download routes after a re-analysis
    fails or is cancelled.

    Args:
        case: The in-memory case state dictionary.
        case_dir: Path string to the case directory.
    """
    with STATE_LOCK:
        case["analysis_results"] = {}
    results_path = Path(case_dir) / "analysis_results.json"
    if results_path.exists():
        results_path.unlink(missing_ok=True)


def _make_analysis_progress_callback(case_id: str) -> Callable[..., None]:
    """Create a progress callback that emits SSE events for analysis.

    The returned callback handles three calling conventions:

    * ``(artifact_key, status, result_dict)`` -- three positional args.
    * ``({"artifact_key": ..., "status": ..., "result": ...})`` -- single
      dict positional arg.
    * Any other signature is silently ignored.

    Args:
        case_id: UUID of the case whose SSE stream should receive events.

    Returns:
        A callable suitable for passing as ``progress_callback`` to the
        analyzer pipeline.
    """

    def _analysis_progress(*args: Any) -> None:
        """Emit per-artifact analysis progress events."""
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
            emit_progress(ANALYSIS_PROGRESS, case_id, {
                "type": "artifact_analysis_started", "artifact_key": artifact_key, "result": result,
            })
            return

        if status == "thinking":
            emit_progress(ANALYSIS_PROGRESS, case_id, {
                "type": "artifact_analysis_thinking", "artifact_key": artifact_key, "result": result,
            })
            return

        emit_progress(ANALYSIS_PROGRESS, case_id, {
            "type": "artifact_analysis_completed",
            "artifact_key": artifact_key,
            "status": status or "complete",
            "result": result,
        })

    return _analysis_progress


def _auto_generate_report(case_id: str) -> None:
    """Auto-generate the HTML report after analysis, logging any failures.

    This is a best-effort operation: failures are logged as warnings but
    never propagated, because the analysis itself already succeeded.

    Args:
        case_id: UUID of the case whose report should be generated.
    """
    try:
        report_result = generate_case_report(case_id)
        if report_result.get("success"):
            LOGGER.info(
                "Auto-generated report for case %s: %s",
                case_id, report_result["report_path"].name,
            )
        else:
            LOGGER.warning(
                "Auto-report generation failed for case %s: %s",
                case_id, report_result.get("error", "unknown error"),
            )
    except Exception:
        LOGGER.warning(
            "Auto-report generation raised an exception for case %s",
            case_id, exc_info=True,
        )


def run_analysis(case_id: str, prompt: str, config_snapshot: dict[str, Any]) -> None:
    """Execute background AI-powered forensic analysis.

    Args:
        case_id: UUID of the case.
        prompt: Investigation context / user prompt.
        config_snapshot: Deep copy of application config.
    """
    cancel_event = get_cancel_event(ANALYSIS_PROGRESS, case_id)
    case = get_case(case_id)
    if case is None:
        set_progress_status(ANALYSIS_PROGRESS, case_id, "failed", "Case not found.")
        emit_progress(ANALYSIS_PROGRESS, case_id, {"type": "analysis_failed", "error": "Case not found."})
        return

    with STATE_LOCK:
        csv_map = dict(case.get("artifact_csv_paths", {}))
        parse_results_snapshot = list(case.get("parse_results", []))
        analysis_artifacts_state = case.get("analysis_artifacts")
        selected_artifacts_snapshot = list(case.get("selected_artifacts", []))
        case_dir = case["case_dir"]
        audit_logger = case["audit"]
        image_metadata_snapshot = dict(case.get("image_metadata", {}))
        os_type_snapshot = str(case.get("os_type") or "unknown")
        artifact_options_snapshot = list(case.get("artifact_options", []))
        analysis_date_range = case.get("analysis_date_range")

    if not csv_map:
        csv_map = build_csv_map(parse_results_snapshot)
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
        mark_case_status(case_id, "failed")
        set_progress_status(ANALYSIS_PROGRESS, case_id, "failed", message)
        emit_progress(ANALYSIS_PROGRESS, case_id, {"type": "analysis_failed", "error": message})
        return

    try:
        analyzer = ForensicAnalyzer(
            case_dir=case_dir,
            config=config_snapshot,
            audit_logger=audit_logger,
            artifact_csv_paths=csv_map,
            os_type=os_type_snapshot,
        )
        metadata = dict(image_metadata_snapshot)
        metadata["os_type"] = os_type_snapshot
        metadata["artifact_csv_paths"] = csv_map
        metadata["parse_results"] = parse_results_snapshot
        metadata["analysis_artifacts"] = list(artifacts)
        metadata["artifact_options"] = artifact_options_snapshot
        if isinstance(analysis_date_range, dict):
            metadata["analysis_date_range"] = {
                "start_date": str(analysis_date_range.get("start_date", "")).strip(),
                "end_date": str(analysis_date_range.get("end_date", "")).strip(),
            }

        _analysis_progress = _make_analysis_progress_callback(case_id)

        output = analyzer.run_full_analysis(
            artifact_keys=artifacts,
            investigation_context=prompt,
            metadata=metadata,
            progress_callback=_analysis_progress,
            cancel_check=(lambda: cancel_event.is_set()) if cancel_event is not None else None,
        )
        analysis_results_path = Path(case_dir) / "analysis_results.json"
        with analysis_results_path.open("w", encoding="utf-8") as analysis_results_file:
            json.dump(output, analysis_results_file, indent=2, ensure_ascii=True)
            analysis_results_file.write("\n")
        with STATE_LOCK:
            case["investigation_context"] = prompt
            case["analysis_results"] = output

        emit_progress(ANALYSIS_PROGRESS, case_id, {
            "type": "analysis_summary",
            "summary": str(output.get("summary", "")),
            "model_info": output.get("model_info", {}),
        })
        set_progress_status(ANALYSIS_PROGRESS, case_id, "completed")
        emit_progress(ANALYSIS_PROGRESS, case_id, {
            "type": "analysis_completed",
            "artifact_count": len(output.get("per_artifact", [])),
            "per_artifact": list(output.get("per_artifact", [])),
        })
        mark_case_status(case_id, "completed")

        # Auto-generate the HTML report so it's ready for download.
        _auto_generate_report(case_id)
    except AnalysisCancelledError:
        LOGGER.info("Analysis cancelled for case %s", case_id)
    except Exception:
        LOGGER.exception("Background analysis failed for case %s", case_id)
        _purge_stale_analysis(case, case_dir)
        user_message = (
            "Analysis failed due to an internal error. "
            "Verify provider settings and retry."
        )
        mark_case_status(case_id, "error")
        set_progress_status(ANALYSIS_PROGRESS, case_id, "failed", user_message)
        emit_progress(ANALYSIS_PROGRESS, case_id, {"type": "analysis_failed", "error": user_message})


# ---------------------------------------------------------------------------
# Background task: multi-image analysis
# ---------------------------------------------------------------------------

def run_multi_image_analysis_task(
    case_id: str,
    prompt: str,
    images_payload: list[dict[str, Any]],
    config_snapshot: dict[str, Any],
) -> None:
    """Execute background AI-powered multi-image forensic analysis.

    Builds image descriptors from the case state (including per-image
    parsed directories and metadata), then delegates to
    :meth:`ForensicAnalyzer.run_multi_image_analysis`.

    Args:
        case_id: UUID of the case.
        prompt: Investigation context / user prompt.
        images_payload: List of dicts with ``image_id`` and ``artifacts``
            keys, as received from the frontend.
        config_snapshot: Deep copy of application config.
    """
    cancel_event = get_cancel_event(ANALYSIS_PROGRESS, case_id)
    case = get_case(case_id)
    if case is None:
        set_progress_status(ANALYSIS_PROGRESS, case_id, "failed", "Case not found.")
        emit_progress(ANALYSIS_PROGRESS, case_id, {"type": "analysis_failed", "error": "Case not found."})
        return

    with STATE_LOCK:
        case_dir = case["case_dir"]
        audit_logger = case["audit"]
        image_states = dict(case.get("image_states", {}))
        case_images_list = list(case.get("images", []))

    # Build a label lookup from the case images list.
    label_lookup: dict[str, str] = {}
    for img_entry in case_images_list:
        if isinstance(img_entry, dict):
            label_lookup[str(img_entry.get("image_id", ""))] = str(img_entry.get("label", ""))

    # Build image descriptors for the analyzer.
    images: list[dict[str, Any]] = []
    skipped_images: list[dict[str, str]] = []
    for img in images_payload:
        image_id = str(img.get("image_id", ""))
        if not image_id:
            continue
        artifacts = [str(a) for a in img.get("artifacts", []) if a]
        if not artifacts:
            continue

        img_state = image_states.get(image_id, {})
        metadata = dict(img_state.get("image_metadata", {}))
        os_type = str(img_state.get("os_type", metadata.get("os_type", "unknown")))
        metadata["os_type"] = os_type

        # Resolve parsed directory.
        parsed_dir = str(img_state.get("csv_output_dir", "")).strip()
        if not parsed_dir:
            from ..case_manager import CaseManager
            from .state import CASES_ROOT
            cm = CaseManager(CASES_ROOT)
            try:
                image_dir = cm.get_image_dir(case_id, image_id)
                parsed_dir = str(image_dir / "parsed")
            except FileNotFoundError:
                skip_label = label_lookup.get(image_id, image_id)
                LOGGER.warning("Image dir not found for %s/%s", case_id, image_id)
                skipped_images.append({
                    "image_id": image_id,
                    "label": skip_label,
                    "reason": "Parsed data directory not found.",
                })
                emit_progress(ANALYSIS_PROGRESS, case_id, {
                    "type": "image_skipped",
                    "image_id": image_id,
                    "label": skip_label,
                    "reason": "Parsed data directory not found.",
                })
                continue

        label = label_lookup.get(image_id, "")
        if not label:
            label = metadata.get("hostname", image_id)

        images.append({
            "image_id": image_id,
            "label": label,
            "metadata": metadata,
            "artifact_keys": artifacts,
            "parsed_dir": parsed_dir,
        })

    if not images:
        message = "No valid images with artifacts for multi-image analysis."
        mark_case_status(case_id, "failed")
        set_progress_status(ANALYSIS_PROGRESS, case_id, "failed", message)
        emit_progress(ANALYSIS_PROGRESS, case_id, {"type": "analysis_failed", "error": message})
        return

    try:
        analyzer = ForensicAnalyzer(
            case_dir=case_dir,
            config=config_snapshot,
            audit_logger=audit_logger,
            os_type=str(images[0].get("metadata", {}).get("os_type", "unknown")),
        )

        _analysis_progress = _make_analysis_progress_callback(case_id)

        output = analyzer.run_multi_image_analysis(
            images=images,
            investigation_context=prompt,
            progress_callback=_analysis_progress,
            cancel_check=(lambda: cancel_event.is_set()) if cancel_event is not None else None,
        )

        # Attach skipped image information so the report can mention them.
        if skipped_images:
            output["skipped_images"] = skipped_images

        # Save results to disk.
        analysis_results_path = Path(case_dir) / "analysis_results.json"
        with analysis_results_path.open("w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, ensure_ascii=True)
            f.write("\n")
        with STATE_LOCK:
            case["investigation_context"] = prompt
            case["analysis_results"] = output

        # Build a combined summary for the SSE stream.
        cross_summary = str(output.get("cross_image_summary", "") or "")
        images_output = output.get("images", {})

        # Build a flat per_artifact list for backward-compatible SSE events.
        flat_per_artifact: list[dict[str, Any]] = []
        for img_id, img_data in images_output.items():
            if isinstance(img_data, dict):
                for pa in img_data.get("per_artifact", []):
                    if isinstance(pa, dict):
                        enriched = dict(pa)
                        enriched["image_id"] = img_id
                        enriched["image_label"] = str(img_data.get("label", img_id))
                        flat_per_artifact.append(enriched)

        # For the summary event: if cross-image summary exists, combine it
        # with per-image summaries; otherwise use the single image summary.
        if cross_summary:
            combined_summary = cross_summary
        elif len(images_output) == 1:
            single_data = next(iter(images_output.values()), {})
            combined_summary = str(single_data.get("summary", ""))
        else:
            combined_summary = ""

        emit_progress(ANALYSIS_PROGRESS, case_id, {
            "type": "analysis_summary",
            "summary": combined_summary,
            "model_info": output.get("model_info", {}),
            "multi_image": True,
            "images": {
                img_id: {
                    "label": str(img_data.get("label", img_id)),
                    "summary": str(img_data.get("summary", "")),
                }
                for img_id, img_data in images_output.items()
                if isinstance(img_data, dict)
            },
            "cross_image_summary": cross_summary,
            "skipped_images": skipped_images,
        })
        set_progress_status(ANALYSIS_PROGRESS, case_id, "completed")
        emit_progress(ANALYSIS_PROGRESS, case_id, {
            "type": "analysis_completed",
            "artifact_count": len(flat_per_artifact),
            "per_artifact": flat_per_artifact,
            "multi_image": True,
            "images": {
                img_id: {
                    "label": str(img_data.get("label", img_id)),
                    "per_artifact": list(img_data.get("per_artifact", [])),
                    "summary": str(img_data.get("summary", "")),
                }
                for img_id, img_data in images_output.items()
                if isinstance(img_data, dict)
            },
            "cross_image_summary": cross_summary,
            "skipped_images": skipped_images,
        })
        mark_case_status(case_id, "completed")

        # Auto-generate the HTML report.
        _auto_generate_report(case_id)
    except AnalysisCancelledError:
        LOGGER.info("Multi-image analysis cancelled for case %s", case_id)
    except Exception:
        LOGGER.exception("Background multi-image analysis failed for case %s", case_id)
        _purge_stale_analysis(case, case_dir)
        user_message = (
            "Multi-image analysis failed due to an internal error. "
            "Verify provider settings and retry."
        )
        mark_case_status(case_id, "error")
        set_progress_status(ANALYSIS_PROGRESS, case_id, "failed", user_message)
        emit_progress(ANALYSIS_PROGRESS, case_id, {"type": "analysis_failed", "error": user_message})

