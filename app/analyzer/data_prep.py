"""Data preparation pipeline for forensic artifact analysis.

Handles date extraction from investigation context, CSV reading,
column projection, deduplication, statistics computation, and
final prompt assembly for AI analysis.
"""

from __future__ import annotations

import csv
import io
import logging
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping

from .constants import (
    DEDUP_COMMENT_COLUMN,
    DEDUPLICATED_PARSED_DIRNAME,
    LOW_SIGNAL_VALUES,
    METADATA_COLUMNS,
)
from .ioc import (
    build_artifact_final_context_reminder,
    build_priority_directives,
    extract_ioc_targets,
    format_ioc_targets,
)
from .utils import (
    format_datetime,
    is_dedup_safe_identifier_column,
    looks_like_timestamp_column,
    normalize_artifact_key,
    normalize_csv_row,
    normalize_table_cell,
    sanitize_filename,
    stringify_value,
    time_range_for_rows,
)

LOGGER = logging.getLogger(__name__)

__all__ = [
    "prepare_artifact_data",
    "write_analysis_input_csv",
    "resolve_analysis_input_output_dir",
    "build_artifact_csv_attachment",
    "counter_normalize",
    "compute_statistics",
    "select_ai_columns",
    "project_rows_for_analysis",
    "deduplicate_rows_for_analysis",
    "build_full_data_csv",
]


# ---------------------------------------------------------------------------
# Statistics and normalisation
# ---------------------------------------------------------------------------

def counter_normalize(value: str) -> str:
    """Normalize a cell value for frequency counting in statistics.

    Args:
        value: Raw cell value string.

    Returns:
        The normalized value, or empty string if low-signal.
    """
    cleaned = normalize_table_cell(value=value, cell_limit=120)
    if cleaned.lower() in LOW_SIGNAL_VALUES:
        return ""
    return cleaned


def compute_statistics(
    rows: list[dict[str, str]],
    columns: list[str],
) -> tuple[str, datetime | None, datetime | None]:
    """Compute record count, time range, and top-20 frequent values per column.

    Args:
        rows: List of normalized CSV row dicts.
        columns: Column names for frequency statistics.

    Returns:
        A 3-tuple of ``(statistics_text, min_time, max_time)``.
    """
    total_records = len(rows)
    min_time, max_time = time_range_for_rows(rows)
    counters: dict[str, Counter[str]] = {column: Counter() for column in columns}

    for row in rows:
        for column in columns:
            value = counter_normalize(row.get(column, ""))
            if value:
                counters[column][value] += 1

    lines = [
        f"Record count: {total_records}",
        f"Time range start: {format_datetime(min_time)}",
        f"Time range end: {format_datetime(max_time)}",
    ]

    if columns:
        lines.append("Top values (up to 20 per key column):")
        for column in columns:
            lines.append(f"- {column}:")
            top_values = counters[column].most_common(20)
            if not top_values:
                lines.append("  (no non-empty values)")
                continue
            for value, count in top_values:
                lines.append(f"  {count}x {value}")
    else:
        lines.append("Top values: no key columns selected.")

    return "\n".join(lines), min_time, max_time


# ---------------------------------------------------------------------------
# Column selection and projection
# ---------------------------------------------------------------------------

def select_ai_columns(
    artifact_key: str,
    available_columns: list[str],
    column_projections: dict[str, tuple[str, ...]],
    audit_log_fn: Any = None,
) -> tuple[list[str], bool]:
    """Select the subset of CSV columns to include in the AI prompt.

    Args:
        artifact_key: Artifact identifier for projection lookup.
        available_columns: Column names present in the source CSV.
        column_projections: Mapping of artifact keys to column tuples.
        audit_log_fn: Optional callable for logging missing columns.

    Returns:
        A 2-tuple of ``(selected_columns, projection_applied)``.
    """
    normalized_key = normalize_artifact_key(artifact_key)
    configured_columns = column_projections.get(normalized_key)
    # Fallback: try the base artifact type (part before first underscore/dot)
    # so that "evtx_security" still picks up the generic "evtx" projection
    # when no channel-specific projection is configured.
    if not configured_columns:
        base_key = normalized_key.split("_", 1)[0].split(".", 1)[0]
        if base_key != normalized_key:
            configured_columns = column_projections.get(base_key)
    if not configured_columns:
        return list(available_columns), False

    lookup = {column.strip().lower(): column for column in available_columns}
    projected_columns: list[str] = []
    missing_columns: list[str] = []
    has_wildcard = False
    for column_name in configured_columns:
        if column_name.strip() == "*":
            has_wildcard = True
            continue
        matched = lookup.get(column_name.strip().lower())
        if matched is not None:
            projected_columns.append(matched)
        else:
            missing_columns.append(column_name)

    # A trailing ``*`` means "pass through any remaining columns not already
    # listed".  This is used for artifacts with dynamic/variable fields (e.g.
    # systemd service records whose fields vary per unit).
    if has_wildcard:
        already_selected = {c.strip().lower() for c in projected_columns}
        for col in available_columns:
            if col.strip().lower() not in already_selected:
                projected_columns.append(col)

    if missing_columns and audit_log_fn is not None:
        audit_log_fn(
            "artifact_ai_projection_warning",
            {"artifact_key": artifact_key, "missing_columns": missing_columns,
             "available_columns": available_columns},
        )

    if not projected_columns:
        return list(available_columns), False
    return projected_columns, True


def project_rows_for_analysis(
    rows: list[dict[str, str]],
    columns: list[str],
) -> list[dict[str, str]]:
    """Project rows to only the selected columns for analysis.

    Args:
        rows: List of normalized row dicts.
        columns: Column names to retain.

    Returns:
        A new list of row dicts with only the specified columns
        and ``_row_ref``.
    """
    projected_rows: list[dict[str, str]] = []
    for row in rows:
        projected: dict[str, str] = {
            column: stringify_value(row.get(column, ""))
            for column in columns
        }
        row_ref = stringify_value(row.get("_row_ref", ""))
        if row_ref:
            projected["_row_ref"] = row_ref
        projected_rows.append(projected)
    return projected_rows


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def deduplicate_rows_for_analysis(
    rows: list[dict[str, str]],
    columns: list[str],
) -> tuple[list[dict[str, str]], list[str], int, int, list[str]]:
    """Deduplicate rows that differ only in timestamp or record-ID columns.

    Args:
        rows: List of projected row dicts.
        columns: Column names present in the rows.

    Returns:
        A 5-tuple of ``(kept_rows, output_columns, removed_count,
        annotated_count, variant_columns)``.
    """
    if not rows or not columns:
        return list(rows), list(columns), 0, 0, []

    variant_columns = [
        column for column in columns
        if looks_like_timestamp_column(column) or is_dedup_safe_identifier_column(column)
    ]
    if not variant_columns:
        return [dict(row) for row in rows], list(columns), 0, 0, []

    variant_set = set(variant_columns)
    base_columns = [
        column for column in columns
        if column not in variant_set and column.lower() not in METADATA_COLUMNS and column != DEDUP_COMMENT_COLUMN
    ]
    if not base_columns:
        return [dict(row) for row in rows], list(columns), 0, 0, variant_columns

    kept_rows: list[dict[str, str]] = []
    representative_by_key: dict[tuple[tuple[str, str], ...], int] = {}
    dedup_counts: Counter[int] = Counter()

    for row in rows:
        normalized_row = {str(key): stringify_value(value) for key, value in row.items()}
        key = tuple((column, normalized_row.get(column, "")) for column in base_columns)
        representative_index = representative_by_key.get(key)
        if representative_index is None:
            representative_by_key[key] = len(kept_rows)
            kept_rows.append(normalized_row)
            continue
        dedup_counts[representative_index] += 1

    annotated_rows = 0
    output_columns = list(columns)
    if dedup_counts:
        if DEDUP_COMMENT_COLUMN not in output_columns:
            output_columns.append(DEDUP_COMMENT_COLUMN)
        for representative_index, dedup_count in dedup_counts.items():
            kept_rows[representative_index][DEDUP_COMMENT_COLUMN] = (
                f"Deduplicated {dedup_count} records with matching event data and different timestamp/ID."
            )
            annotated_rows += 1

    removed_rows = sum(dedup_counts.values())
    return kept_rows, output_columns, removed_rows, annotated_rows, variant_columns


# ---------------------------------------------------------------------------
# CSV serialisation
# ---------------------------------------------------------------------------

def build_full_data_csv(
    rows: list[dict[str, str]],
    columns: list[str],
) -> str:
    """Serialize rows to inline CSV text for prompt inclusion.

    Args:
        rows: List of row dicts to serialize.
        columns: Column names for the CSV header.

    Returns:
        A CSV-formatted string with a ``row_ref`` column prepended.
    """
    if not columns:
        return "No columns available."

    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer)
    writer.writerow(["row_ref", *columns])
    for row in rows:
        writer.writerow([row.get("_row_ref", ""), *[row.get(column, "") for column in columns]])

    full_csv = buffer.getvalue().strip()
    if not full_csv:
        return "No rows available for analysis."
    return full_csv


# ---------------------------------------------------------------------------
# Analysis-input CSV output
# ---------------------------------------------------------------------------

def resolve_analysis_input_output_dir(case_dir: Path | None, source_csv_path: Path) -> Path:
    """Determine the output directory for deduplicated/projected CSV files.

    Args:
        case_dir: Optional case directory path.
        source_csv_path: Path to the original parsed CSV file.

    Returns:
        A ``Path`` to the output directory.
    """
    if case_dir is not None:
        return case_dir / DEDUPLICATED_PARSED_DIRNAME
    parent = source_csv_path.parent
    if parent.name.strip().lower() == "parsed":
        return parent.parent / DEDUPLICATED_PARSED_DIRNAME
    return parent / DEDUPLICATED_PARSED_DIRNAME


def write_analysis_input_csv(
    source_csv_path: Path,
    rows: list[dict[str, str]],
    columns: list[str],
    case_dir: Path | None = None,
) -> Path:
    """Write deduplicated/projected rows to a new CSV file for audit.

    Args:
        source_csv_path: Path to the original parsed CSV.
        rows: Row dicts to write.
        columns: Column names for the CSV header.
        case_dir: Optional case directory.

    Returns:
        Path to the newly written analysis-input CSV file.

    Raises:
        OSError: If the write fails.
    """
    output_dir = resolve_analysis_input_output_dir(case_dir=case_dir, source_csv_path=source_csv_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / source_csv_path.name

    write_columns = list(columns)
    include_row_ref = "_row_ref" not in write_columns and any("_row_ref" in r for r in rows)
    if include_row_ref:
        write_columns = ["row_ref", *write_columns]

    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=write_columns, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            out: dict[str, str] = {column: row.get(column, "") for column in columns}
            if include_row_ref:
                out["row_ref"] = row.get("_row_ref", "")
            writer.writerow(out)

    return output_path


def build_artifact_csv_attachment(artifact_key: str, csv_path: Path) -> dict[str, str]:
    """Build an attachment descriptor dict for an artifact CSV file.

    Args:
        artifact_key: Artifact identifier.
        csv_path: Path to the CSV file on disk.

    Returns:
        A dict with ``path``, ``name``, and ``mime_type`` keys.
    """
    filename_stem = sanitize_filename(artifact_key)
    filename = f"{filename_stem}.csv" if not filename_stem.lower().endswith(".csv") else filename_stem
    return {"path": str(csv_path), "name": filename, "mime_type": "text/csv"}


# ---------------------------------------------------------------------------
# Full artifact data preparation
# ---------------------------------------------------------------------------

def prepare_artifact_data(
    artifact_key: str,
    investigation_context: str,
    csv_path: Path,
    *,
    artifact_metadata: dict[str, str],
    artifact_prompt_template: str,
    artifact_prompt_template_small_context: str,
    artifact_instruction_prompts: dict[str, str],
    artifact_ai_column_projections: dict[str, tuple[str, ...]],
    artifact_deduplication_enabled: bool,
    ai_max_tokens: int,
    shortened_prompt_cutoff_tokens: int,
    case_dir: Path | None,
    audit_log_fn: Any = None,
) -> tuple[str, Path, list[str]]:
    """Prepare one artifact CSV as an analysis-ready prompt.

    Reads the full artifact CSV, applies column projection,
    deduplication, and statistics computation.  Fills the appropriate
    prompt template with all gathered data.

    All rows are loaded to preserve forensic completeness — no data is
    silently discarded.

    Args:
        artifact_key: Unique identifier for the artifact.
        investigation_context: Free-text investigation context.
        csv_path: Path to the artifact CSV file.
        artifact_metadata: Metadata dict for the artifact.
        artifact_prompt_template: Full prompt template.
        artifact_prompt_template_small_context: Shortened prompt template.
        artifact_instruction_prompts: Per-artifact instruction overrides.
        artifact_ai_column_projections: Column projection config.
        artifact_deduplication_enabled: Whether to deduplicate rows.
        ai_max_tokens: Configured AI context window size.
        shortened_prompt_cutoff_tokens: Token threshold for small template.
        case_dir: Optional case directory path.
        audit_log_fn: Optional callable ``(action, details)`` for audit.

    Returns:
        A 3-tuple of ``(prompt_text, analysis_csv_path, analysis_columns)``.
    """
    include_statistics = ai_max_tokens >= shortened_prompt_cutoff_tokens
    template = artifact_prompt_template if include_statistics else artifact_prompt_template_small_context

    rows: list[dict[str, str]] = []
    columns: list[str] = []

    with csv_path.open("r", newline="", encoding="utf-8-sig", errors="replace") as handle:
        reader = csv.DictReader(handle)
        columns = [str(c) for c in (reader.fieldnames or []) if c not in (None, "")]

        for source_row_count, raw_row in enumerate(reader, start=1):
            row = normalize_csv_row(raw_row, columns=columns)
            row["_row_ref"] = str(source_row_count)
            rows.append(row)

    analysis_columns, projection_applied = select_ai_columns(
        artifact_key=artifact_key, available_columns=columns,
        column_projections=artifact_ai_column_projections, audit_log_fn=audit_log_fn,
    )
    analysis_rows = project_rows_for_analysis(rows=rows, columns=analysis_columns)
    deduplicated_records = 0
    dedup_annotated_rows = 0
    dedup_variant_columns: list[str] = []
    analysis_csv_path = csv_path
    dedup_write_error = ""

    if artifact_deduplication_enabled:
        analysis_rows, analysis_columns, deduplicated_records, dedup_annotated_rows, dedup_variant_columns = (
            deduplicate_rows_for_analysis(rows=analysis_rows, columns=analysis_columns)
        )

    if projection_applied or artifact_deduplication_enabled:
        try:
            analysis_csv_path = write_analysis_input_csv(
                source_csv_path=csv_path, rows=analysis_rows, columns=analysis_columns, case_dir=case_dir,
            )
        except OSError as error:
            analysis_csv_path = csv_path
            dedup_write_error = str(error)

    if projection_applied and audit_log_fn is not None:
        projection_details: dict[str, Any] = {
            "artifact_key": artifact_key, "source_csv": str(csv_path),
            "analysis_csv": str(analysis_csv_path), "projection_columns": list(analysis_columns),
        }
        if dedup_write_error and not artifact_deduplication_enabled:
            projection_details["write_error"] = dedup_write_error
        audit_log_fn("artifact_ai_projection", projection_details)

    if artifact_deduplication_enabled and audit_log_fn is not None:
        dedup_audit_details: dict[str, Any] = {
            "artifact_key": artifact_key, "source_csv": str(csv_path),
            "analysis_csv": str(analysis_csv_path), "removed_records": deduplicated_records,
            "annotated_rows": dedup_annotated_rows, "variant_columns": list(dedup_variant_columns),
        }
        if dedup_write_error:
            dedup_audit_details["write_error"] = dedup_write_error
        audit_log_fn("artifact_deduplicated", dedup_audit_details)

    statistics = ""
    if include_statistics:
        statistics, min_time, max_time = compute_statistics(rows=analysis_rows, columns=analysis_columns)
        stats_prefix: list[str] = []

        if artifact_deduplication_enabled:
            dedup_details = [
                "Artifact deduplication enabled.",
                f"Rows removed as timestamp/ID-only duplicates: {deduplicated_records}.",
                f"Rows annotated with deduplication comment: {dedup_annotated_rows}.",
            ]
            if dedup_variant_columns:
                dedup_details.append("Dedup variant columns: " + ", ".join(dedup_variant_columns) + ".")
            stats_prefix.append("\n".join(dedup_details))

        if projection_applied:
            stats_prefix.append("AI column projection applied: " + ", ".join(analysis_columns) + ".")

        if stats_prefix:
            statistics = "\n".join(stats_prefix) + "\n" + statistics
    else:
        min_time, max_time = time_range_for_rows(analysis_rows)

    full_data_csv = build_full_data_csv(rows=analysis_rows, columns=analysis_columns)
    extracted_iocs = extract_ioc_targets(investigation_context)
    priority_directives = build_priority_directives(investigation_context, ioc_targets=extracted_iocs)
    ioc_targets = format_ioc_targets(investigation_context, ioc_targets=extracted_iocs)
    artifact_guidance = _resolve_analysis_instructions(
        artifact_key=artifact_key, artifact_metadata=artifact_metadata,
        artifact_instruction_prompts=artifact_instruction_prompts,
    )

    replacements = {
        "priority_directives": priority_directives,
        "investigation_context": investigation_context.strip() or "No investigation context provided.",
        "ioc_targets": ioc_targets,
        "artifact_key": artifact_key,
        "artifact_name": artifact_metadata.get("name", artifact_key),
        "artifact_description": artifact_metadata.get("description", "No artifact description available."),
        "total_records": str(len(analysis_rows)),
        "time_range_start": format_datetime(min_time),
        "time_range_end": format_datetime(max_time),
        "statistics": statistics,
        "analysis_instructions": artifact_guidance,
        "artifact_guidance": artifact_guidance,
        "data_csv": full_data_csv,
    }

    filled = template
    for placeholder, value in replacements.items():
        filled = filled.replace(f"{{{{{placeholder}}}}}", value)

    final_context_reminder = build_artifact_final_context_reminder(
        artifact_key=artifact_key,
        artifact_name=artifact_metadata.get("name", artifact_key),
        investigation_context=investigation_context,
        ioc_targets=extracted_iocs,
    )
    if final_context_reminder:
        filled = f"{filled.rstrip()}\n\n{final_context_reminder}\n"

    return filled, analysis_csv_path, analysis_columns


def _resolve_analysis_instructions(
    artifact_key: str,
    artifact_metadata: Mapping[str, str],
    artifact_instruction_prompts: dict[str, str],
) -> str:
    """Resolve artifact-specific analysis instructions for the AI prompt.

    Args:
        artifact_key: Artifact identifier.
        artifact_metadata: Metadata dict for the artifact.
        artifact_instruction_prompts: Per-artifact instruction overrides.

    Returns:
        The analysis instruction text.
    """
    normalized_key = normalize_artifact_key(artifact_key)
    # Try the raw key, the normalised key, and dot/underscore variants
    # so that "ssh.authorized_keys" matches "ssh_authorized_keys.md".
    candidates: list[str] = [artifact_key, normalized_key]
    # Also try the base artifact type (e.g. "evtx" from "evtx_security")
    # so channel-specific keys fall back to the generic instruction prompt.
    base_key = normalized_key.split("_", 1)[0].split(".", 1)[0]
    if base_key != normalized_key and base_key not in candidates:
        candidates.append(base_key)
    for variant in (artifact_key.replace(".", "_"), artifact_key.replace("_", ".")):
        if variant not in candidates:
            candidates.append(variant)
    for key in candidates:
        prompt = artifact_instruction_prompts.get(key.strip().lower(), "").strip()
        if prompt:
            return prompt

    for field in ("artifact_guidance", "analysis_instructions", "analysis_hint"):
        value = stringify_value(artifact_metadata.get(field, ""))
        if value:
            return value

    return "No specific analysis instructions are available for this artifact."
