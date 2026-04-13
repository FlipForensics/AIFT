"""Multi-image analysis orchestration for forensic triage.

Provides the ``run_multi_image_analysis`` function that extends the
single-image analysis pipeline with per-image summaries and cross-image
correlation.  The three-phase workflow is:

1. **Per-artifact analysis** — runs the existing ``analyze_artifact()``
   method for each artifact on each image.
2. **Per-image summary** — generates a cross-artifact summary scoped
   to each individual image.
3. **Cross-image correlation** — (multi-image only) sends all per-image
   summaries to the AI for cross-system correlation.

Single-image cases skip Phase 3 and return ``cross_image_summary=None``.

Attributes:
    LOGGER: Module-level logger instance.
    _ANALYZER_LOCK: Threading lock that guards shared analyzer state
        (``os_type``, ``artifact_csv_paths``, ``analysis_date_range``)
        during multi-image analysis.  Held for each full per-image pass
        (state swap + all ``analyze_artifact()`` calls) so that a
        concurrent thread on the same ``ForensicAnalyzer`` instance
        cannot corrupt the state mid-analysis.
    DEFAULT_CROSS_IMAGE_PROMPT_TEMPLATE: Fallback template used when
        ``prompts/cross_image_prompt.md`` cannot be loaded.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from time import perf_counter
from typing import Any, Callable

from .prompts import load_prompt_template
from .utils import emit_analysis_progress, estimate_tokens, sanitize_filename

LOGGER = logging.getLogger(__name__)

# Guards shared analyzer state (os_type, artifact_csv_paths, analysis_date_range)
# during multi-image analysis.  Held for each full per-image pass (state swap +
# all analyze_artifact() calls) so concurrent threads cannot corrupt each other.
_ANALYZER_LOCK = threading.Lock()

__all__ = [
    "build_cross_image_prompt",
    "run_multi_image_analysis",
]

DEFAULT_CROSS_IMAGE_PROMPT_TEMPLATE = (
    "## Investigation Context\n{{investigation_context}}\n\n"
    "## Systems Under Analysis\n{{image_metadata_table}}\n\n"
    "## Per-Image Summaries\n{{per_image_summaries}}\n\n"
    "## Task\nCorrelate the per-image findings into a unified "
    "multi-system incident assessment.\n"
)


def _build_image_metadata_table(images: list[dict[str, Any]]) -> str:
    """Build a Markdown table of image metadata for the cross-image prompt.

    Args:
        images: List of image descriptor dicts, each with ``image_id``,
            ``label``, and optional ``metadata`` keys.

    Returns:
        A Markdown-formatted table string.
    """
    lines = [
        "| # | Image ID | Label | Hostname | OS | Domain | IP(s) |",
        "|---|----------|-------|----------|----|--------|-------|",
    ]
    for index, image in enumerate(images, start=1):
        image_id = str(image.get("image_id", "unknown"))
        label = str(image.get("label", image_id))
        meta = image.get("metadata") or {}
        hostname = str(meta.get("hostname", "Unknown"))
        os_version = str(meta.get("os_version", meta.get("os_type", "Unknown")))
        domain = str(meta.get("domain", "Unknown"))
        ips = str(meta.get("ips", "Unknown"))
        lines.append(
            f"| {index} | {image_id} | {label} | {hostname} | {os_version} | {domain} | {ips} |"
        )
    return "\n".join(lines)


def _build_per_image_summaries_text(
    image_summaries: dict[str, dict[str, Any]],
) -> str:
    """Format all per-image summaries into a single text block.

    Args:
        image_summaries: Mapping of image IDs to result dicts, each
            containing ``label`` and ``summary`` keys.

    Returns:
        A Markdown-formatted string with each image's summary.
    """
    blocks: list[str] = []
    for image_id, data in image_summaries.items():
        label = str(data.get("label", image_id))
        summary = str(data.get("summary", "No summary available.")).strip()
        blocks.append(f"### {label} (Image: {image_id})\n\n{summary}")
    return "\n\n---\n\n".join(blocks) if blocks else "No per-image summaries available."


def build_cross_image_prompt(
    template: str,
    investigation_context: str,
    images: list[dict[str, Any]],
    image_summaries: dict[str, dict[str, Any]],
) -> str:
    """Build the cross-image correlation prompt from a template.

    Fills ``{{investigation_context}}``, ``{{image_metadata_table}}``,
    and ``{{per_image_summaries}}`` placeholders in the template.

    Args:
        template: The cross-image prompt template string.
        investigation_context: The user's investigation context text.
        images: List of image descriptor dicts for metadata table.
        image_summaries: Mapping of image IDs to result dicts with
            ``label`` and ``summary`` keys.

    Returns:
        The fully rendered cross-image prompt string.
    """
    metadata_table = _build_image_metadata_table(images)
    summaries_text = _build_per_image_summaries_text(image_summaries)

    prompt = template
    replacements = {
        "investigation_context": investigation_context.strip() or "No investigation context provided.",
        "image_metadata_table": metadata_table,
        "per_image_summaries": summaries_text,
    }
    for placeholder, value in replacements.items():
        prompt = prompt.replace(f"{{{{{placeholder}}}}}", value)
    return prompt


def _wrap_image_progress_callback(
    callback: Any,
    image_id: str,
    image_label: str,
) -> Callable[..., None]:
    """Wrap a progress callback to inject image_id and image_label.

    When ``analyze_artifact()`` emits "started" or "thinking" progress
    events, it does not include image context.  This wrapper enriches the
    payload dict so that the frontend can correctly group events by image
    instead of falling back to ``__single__``.

    Args:
        callback: The original progress callback.
        image_id: Image identifier to inject.
        image_label: Human-readable image label to inject.

    Returns:
        A wrapped callback with the same calling convention.
    """

    def _enriched(*args: Any) -> None:
        """Forward to the real callback with image fields injected."""
        if len(args) >= 3:
            # Three-arg convention: (artifact_key, status, payload_dict)
            artifact_key, status, payload = args[0], args[1], args[2]
            if isinstance(payload, dict):
                payload = {
                    **payload,
                    "image_id": image_id,
                    "image_label": image_label,
                }
            callback(artifact_key, status, payload)
        elif len(args) == 1 and isinstance(args[0], dict):
            # Single-dict convention
            enriched = dict(args[0])
            result = enriched.get("result")
            if isinstance(result, dict):
                enriched["result"] = {
                    **result,
                    "image_id": image_id,
                    "image_label": image_label,
                }
            callback(enriched)
        else:
            callback(*args)

    return _enriched


def run_multi_image_analysis(
    analyzer: Any,
    images: list[dict[str, Any]],
    investigation_context: str,
    progress_callback: Any | None = None,
    cancel_check: Callable[[], bool] | None = None,
    analysis_date_range: tuple[str, str] | None = None,
) -> dict[str, Any]:
    """Run the full multi-image analysis pipeline.

    Executes three phases:

    1. **Per-artifact analysis** for each image's selected artifacts.
    2. **Per-image summary** correlating each image's artifact findings.
    3. **Cross-image correlation** (only if more than one image).

    For single-image cases, Phase 3 is skipped and
    ``cross_image_summary`` is ``None``.

    Args:
        analyzer: A ``ForensicAnalyzer`` instance with an initialized
            AI provider.  The analyzer's ``case_dir``,
            ``artifact_csv_paths``, and prompt templates are used.
        images: List of image descriptor dicts.  Each dict has:

            - ``image_id`` (str): Unique image identifier.
            - ``label`` (str): Human-readable label (e.g.
              ``"Workstation-PC01 (Windows 10)"``).
            - ``metadata`` (dict): Host metadata with optional
              ``hostname``, ``os_version``, ``os_type``, ``domain``.
            - ``artifact_keys`` (list[str]): Artifacts to analyze.
            - ``parsed_dir`` (str): Path to the image's parsed CSV
              directory.

        investigation_context: Free-text investigation context.
        progress_callback: Optional callable for SSE progress streaming.
            Called as ``(artifact_key, status, payload)`` per the
            existing convention.
        cancel_check: Optional callable returning ``True`` when the
            user has cancelled.
        analysis_date_range: Optional ``(start_date, end_date)`` tuple
            for date-range filtering.  Applied to each image's
            artifacts, matching the single-image path convention.

    Returns:
        A dict with the structure::

            {
                "images": {
                    "<image_id>": {
                        "label": str,
                        "per_artifact": [...],
                        "summary": str,
                    },
                    ...
                },
                "cross_image_summary": str | None,
                "model_info": dict,
            }

    Raises:
        AnalysisCancelledError: If *cancel_check* returns ``True``.
    """
    from .core import AnalysisCancelledError

    image_results: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # Phase 1: Per-artifact analysis for each image
    # Hold the lock for the entire Phase 1 loop.  Saving and restoring
    # analyzer state happens inside the same lock acquisition so that a
    # concurrent thread can never observe partially-swapped state
    # (e.g. wrong os_type or empty artifact_csv_paths) between the
    # moment an exception releases the lock and the finally-block
    # re-acquires it.
    with _ANALYZER_LOCK:
        saved_os_type = analyzer.os_type
        saved_csv_paths = dict(analyzer.artifact_csv_paths)
        saved_date_range = analyzer.analysis_date_range

        try:
            for image in images:
                image_id = str(image.get("image_id", "unknown"))
                label = str(image.get("label", image_id))
                metadata = image.get("metadata") or {}
                artifact_keys = image.get("artifact_keys", [])
                parsed_dir = image.get("parsed_dir", "")

                if cancel_check is not None and cancel_check():
                    raise AnalysisCancelledError("Analysis cancelled by user.")

                # Update the analyzer's os_type and host metadata for
                # the current image so that OS-specific analysis logic
                # and prompt host context use the correct values.
                analyzer.os_type = str(
                    metadata.get("os_type", "unknown")
                )
                analyzer._host_metadata = metadata

                # Apply the user-configured date range filter so that
                # per-artifact data preparation honours it, matching
                # the single-image path behaviour.
                analyzer.analysis_date_range = analysis_date_range

                # Clear stale CSV paths from prior image iterations so
                # that analyze_artifact() and citation validation always
                # reference the current image's data — not a leftover
                # path from an earlier image that shares the same
                # artifact key.
                analyzer.artifact_csv_paths.clear()

                # Register the image's parsed CSV paths into the analyzer
                _register_image_csv_paths(analyzer, artifact_keys, parsed_dir)

                # Build investigation context with image label prefix
                image_context = (
                    f"System: {label}\n\n{investigation_context}"
                )

                # Wrap the progress callback so that ALL events
                # (started, thinking, complete) include image_id and
                # image_label.  Without this, streaming "started" events
                # from analyze_artifact() lack image context and the
                # frontend groups them under "__single__".
                image_cb = _wrap_image_progress_callback(
                    progress_callback, image_id, label,
                ) if progress_callback is not None else None

                per_artifact_results: list[dict[str, Any]] = []
                for artifact_key in artifact_keys:
                    if cancel_check is not None and cancel_check():
                        raise AnalysisCancelledError("Analysis cancelled by user.")

                    result = analyzer.analyze_artifact(
                        artifact_key=str(artifact_key),
                        investigation_context=image_context,
                        progress_callback=image_cb,
                    )
                    per_artifact_results.append(result)

                    if progress_callback is not None:
                        emit_analysis_progress(
                            progress_callback,
                            str(artifact_key),
                            "complete",
                            {**result, "image_id": image_id, "image_label": label},
                        )

                image_results[image_id] = {
                    "label": label,
                    "per_artifact": per_artifact_results,
                    "summary": "",
                    "metadata": metadata,
                }
        finally:
            # Restore analyzer state before the lock is released so the
            # caller (and Phase 2 summaries) always see the original
            # os_type and artifact_csv_paths, regardless of whether the
            # loop succeeded or raised.
            analyzer.os_type = saved_os_type
            analyzer.artifact_csv_paths = saved_csv_paths
            analyzer.analysis_date_range = saved_date_range

    # ------------------------------------------------------------------
    # Phase 2: Per-image summary
    # ------------------------------------------------------------------
    for image_id, img_data in image_results.items():
        if cancel_check is not None and cancel_check():
            raise AnalysisCancelledError("Analysis cancelled by user.")

        metadata = img_data.get("metadata") or {}
        per_artifact = img_data["per_artifact"]
        label = img_data["label"]

        if progress_callback is not None:
            emit_analysis_progress(
                progress_callback,
                f"summary_{image_id}",
                "started",
                {"artifact_key": f"summary_{image_id}",
                 "artifact_name": f"Summary: {label}",
                 "image_id": image_id, "image_label": label,
                 "status": "Generating per-image summary"},
            )

        summary = analyzer.generate_summary(
            per_artifact_results=per_artifact,
            investigation_context=f"System: {label}\n\n{investigation_context}",
            metadata=metadata,
        )
        img_data["summary"] = summary

        if progress_callback is not None:
            emit_analysis_progress(
                progress_callback,
                f"summary_{image_id}",
                "complete",
                {"artifact_key": f"summary_{image_id}",
                 "artifact_name": f"Summary: {label}",
                 "image_id": image_id, "image_label": label,
                 "summary": summary},
            )

    # ------------------------------------------------------------------
    # Phase 3: Cross-image correlation (only if > 1 image)
    # ------------------------------------------------------------------
    cross_image_summary: str | None = None

    if len(images) > 1:
        if cancel_check is not None and cancel_check():
            raise AnalysisCancelledError("Analysis cancelled by user.")

        cross_image_summary = _run_cross_image_correlation(
            analyzer=analyzer,
            images=images,
            image_results=image_results,
            investigation_context=investigation_context,
            progress_callback=progress_callback,
        )

    # ------------------------------------------------------------------
    # Build return value
    # ------------------------------------------------------------------
    output_images: dict[str, dict[str, Any]] = {}
    for image_id, img_data in image_results.items():
        output_images[image_id] = {
            "label": img_data["label"],
            "per_artifact": img_data["per_artifact"],
            "summary": img_data["summary"],
            "metadata": img_data.get("metadata", {}),
        }

    return {
        "images": output_images,
        "cross_image_summary": cross_image_summary,
        "model_info": dict(analyzer.model_info),
    }


def _register_image_csv_paths(
    analyzer: Any,
    artifact_keys: list[str],
    parsed_dir: str,
) -> None:
    """Register artifact CSV paths from an image's parsed directory.

    Scans the parsed directory for CSV files matching each artifact key
    and registers them in the analyzer's ``artifact_csv_paths`` dict.

    Args:
        analyzer: The ``ForensicAnalyzer`` instance.
        artifact_keys: List of artifact key strings to look for.
        parsed_dir: Path to the image's parsed directory.
    """
    if not parsed_dir:
        return

    parsed_path = Path(parsed_dir)
    if not parsed_path.exists():
        LOGGER.warning("Parsed directory does not exist: %s", parsed_dir)
        return

    for artifact_key in artifact_keys:
        key = str(artifact_key)
        safe_key = sanitize_filename(key)

        # Look for exact match first, then prefixed variants
        candidates: list[Path] = []
        for variant in (key, safe_key):
            exact = parsed_path / f"{variant}.csv"
            if exact.exists():
                candidates.append(exact)
                break
            prefixed = sorted(parsed_path.glob(f"{variant}_*.csv"))
            if prefixed:
                candidates.extend(prefixed)
                break

        if len(candidates) == 1:
            analyzer.artifact_csv_paths[key] = candidates[0]
        elif len(candidates) > 1:
            analyzer.artifact_csv_paths[key] = candidates


def _run_cross_image_correlation(
    analyzer: Any,
    images: list[dict[str, Any]],
    image_results: dict[str, dict[str, Any]],
    investigation_context: str,
    progress_callback: Any | None = None,
) -> str:
    """Execute Phase 3: cross-image correlation analysis.

    Loads the cross-image prompt template, fills it with per-image
    summaries and metadata, and sends it to the AI provider.

    Args:
        analyzer: The ``ForensicAnalyzer`` instance.
        images: List of image descriptor dicts.
        image_results: Mapping of image IDs to their analysis results.
        investigation_context: The user's investigation context.
        progress_callback: Optional progress callback.

    Returns:
        The AI-generated cross-image correlation summary text.
    """
    cross_image_prompt_template = load_prompt_template(
        analyzer.prompts_dir,
        "cross_image_prompt.md",
        DEFAULT_CROSS_IMAGE_PROMPT_TEMPLATE,
    )

    # Build summaries dict for prompt construction
    image_summaries: dict[str, dict[str, Any]] = {}
    for image_id, data in image_results.items():
        image_summaries[image_id] = {
            "label": data["label"],
            "summary": data["summary"],
        }

    cross_prompt = build_cross_image_prompt(
        template=cross_image_prompt_template,
        investigation_context=investigation_context,
        images=images,
        image_summaries=image_summaries,
    )

    artifact_key = "cross_image_correlation"
    artifact_name = "Cross-Image Correlation"

    if progress_callback is not None:
        emit_analysis_progress(
            progress_callback,
            artifact_key,
            "started",
            {"artifact_key": artifact_key, "artifact_name": artifact_name,
             "status": "Generating cross-image correlation analysis"},
        )

    model = analyzer.model_info.get("model", "unknown")
    provider = analyzer.model_info.get("provider", "unknown")

    analyzer._audit_log("analysis_started", {
        "artifact_key": artifact_key,
        "artifact_name": artifact_name,
        "provider": provider,
        "model": model,
        "image_count": len(images),
    })

    safe_key = sanitize_filename(artifact_key)
    analyzer._save_case_prompt(
        f"{safe_key}.md",
        analyzer.system_prompt,
        cross_prompt,
    )

    start_time = perf_counter()
    try:
        summary = analyzer._call_ai_with_retry(
            lambda: analyzer.ai_provider.analyze(
                system_prompt=analyzer.system_prompt,
                user_prompt=cross_prompt,
                max_tokens=analyzer.ai_response_max_tokens,
            )
        )
        duration_seconds = perf_counter() - start_time
        analyzer._audit_log("analysis_completed", {
            "artifact_key": artifact_key,
            "artifact_name": artifact_name,
            "token_count": estimate_tokens(summary, model_info=analyzer.model_info),
            "duration_seconds": round(duration_seconds, 6),
            "status": "success",
        })
    except Exception as error:
        # Re-raise cancellation so the caller can propagate it correctly
        # instead of silently swallowing it into a summary string.
        from .core import AnalysisCancelledError
        if isinstance(error, AnalysisCancelledError):
            raise
        duration_seconds = perf_counter() - start_time
        summary = f"Cross-image correlation failed: {error}"
        analyzer._audit_log("analysis_completed", {
            "artifact_key": artifact_key,
            "artifact_name": artifact_name,
            "token_count": 0,
            "duration_seconds": round(duration_seconds, 6),
            "status": "failed",
            "error": str(error),
        })

    if progress_callback is not None:
        emit_analysis_progress(
            progress_callback,
            artifact_key,
            "complete",
            {"artifact_key": artifact_key, "artifact_name": artifact_name,
             "cross_image_summary": summary},
        )

    return summary
