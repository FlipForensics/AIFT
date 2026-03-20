"""Citation validation for AI-generated forensic analysis.

Spot-checks timestamps, row references, and column names cited by the AI
against source CSV data to detect potential hallucinations.

Attributes:
    LOGGER: Module-level logger instance.
"""

from __future__ import annotations

import csv
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .constants import CITED_ISO_TIMESTAMP_RE, CITED_ROW_REF_RE, CITED_COLUMN_REF_RE
from .utils import looks_like_timestamp_column, stringify_value

LOGGER = logging.getLogger(__name__)

__all__ = [
    "validate_citations",
    "timestamp_lookup_keys",
    "timestamp_found_in_csv",
    "match_column_name",
]


def timestamp_lookup_keys(value: str) -> set[str]:
    """Build comparable lookup keys for a timestamp string.

    Generates multiple normalized representations of the input timestamp
    (with/without timezone, with/without fractional seconds, space vs ``T``
    separator) so that citation checks can match regardless of formatting.

    Args:
        value: Raw timestamp string from the CSV data.

    Returns:
        A set of non-empty string keys suitable for membership testing.
    """
    text = value.strip()
    if not text:
        return set()

    normalized = text.replace(" ", "T")
    keys: set[str] = {text, normalized}

    match = CITED_ISO_TIMESTAMP_RE.search(normalized)
    if match:
        token = match.group()
        keys.add(token)
        normalized_token = token.replace(" ", "T")
        keys.add(normalized_token)

        if normalized_token.endswith("Z"):
            keys.add(f"{normalized_token[:-1]}+00:00")

        token_without_tz = normalized_token
        suffix = ""
        if token_without_tz.endswith("Z"):
            suffix = "Z"
            token_without_tz = token_without_tz[:-1]
        elif len(token_without_tz) >= 6 and token_without_tz[-6] in {"+", "-"} and token_without_tz[-3] == ":":
            suffix = token_without_tz[-6:]
            token_without_tz = token_without_tz[:-6]

        if "." in token_without_tz:
            base_seconds = token_without_tz.split(".", 1)[0]
            keys.add(base_seconds)
            if suffix:
                keys.add(f"{base_seconds}{suffix}")
        else:
            keys.add(token_without_tz)

    try:
        parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    except ValueError:
        parsed = None

    if parsed is not None:
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        keys.add(parsed.isoformat(timespec="seconds"))
        keys.add(parsed.isoformat(timespec="microseconds"))

    return {key for key in keys if key}


def timestamp_found_in_csv(cited: str, csv_timestamp_lookup: set[str]) -> bool:
    """Check whether a cited timestamp matches preloaded CSV timestamp lookup keys.

    Args:
        cited: Timestamp string cited by the AI in its analysis text.
        csv_timestamp_lookup: Pre-built set of normalized timestamp keys
            from the source CSV.

    Returns:
        ``True`` if any normalized form of *cited* is present in the
        lookup set, ``False`` otherwise.
    """
    if not csv_timestamp_lookup:
        return False
    return any(key in csv_timestamp_lookup for key in timestamp_lookup_keys(cited))


def match_column_name(
    cited_column: str, csv_columns: list[str]
) -> tuple[str, str | None]:
    """Match an AI-cited column name against actual CSV headers.

    Performs a three-tier match: exact, then case-insensitive with
    whitespace/underscore normalization (fuzzy), then reports unverifiable.

    Args:
        cited_column: Column name string cited by the AI.
        csv_columns: Actual CSV header column names.

    Returns:
        A 2-tuple of ``(match_status, matched_header)`` where
        *match_status* is one of ``"exact"``, ``"fuzzy"``, or
        ``"unverifiable"``.
    """
    cited_stripped = cited_column.strip()

    for header in csv_columns:
        if header == cited_stripped:
            return "exact", header

    def _normalize_col(name: str) -> str:
        """Normalize a column name for fuzzy comparison."""
        return name.strip().lower().replace("_", "").replace(" ", "")

    cited_norm = _normalize_col(cited_stripped)
    for header in csv_columns:
        if _normalize_col(header) == cited_norm:
            return "fuzzy", header

    return "unverifiable", None


def validate_citations(
    artifact_key: str,
    analysis_text: str,
    csv_path: Path,
    citation_spot_check_limit: int,
    audit_log_fn: Any = None,
) -> list[str]:
    """Spot-check timestamps, row references, and column names cited by the AI.

    Extracts ISO timestamps, ``row <N>`` references, and column/field
    name references from the AI's analysis text, then verifies each
    against the source CSV data.

    Args:
        artifact_key: Artifact identifier used for logging.
        analysis_text: The AI's analysis text to scan for citations.
        csv_path: Path to the source CSV file.
        citation_spot_check_limit: Maximum citations to validate per
            category.
        audit_log_fn: Optional callable ``(action, details)`` for audit
            logging.

    Returns:
        A list of human-readable warning strings for values that could
        not be verified.
    """
    if analysis_text.startswith("Analysis failed:"):
        return []

    cited_timestamps: list[str] = CITED_ISO_TIMESTAMP_RE.findall(analysis_text)
    cited_row_refs: list[str] = CITED_ROW_REF_RE.findall(analysis_text)

    cited_columns: list[str] = []
    for match in CITED_COLUMN_REF_RE.finditer(analysis_text):
        cited_col = match.group(1) or match.group(2) or match.group(3)
        if cited_col and cited_col.strip():
            cited_columns.append(cited_col.strip())
    seen_cols: set[str] = set()
    unique_cited_columns: list[str] = []
    for col in cited_columns:
        if col not in seen_cols:
            seen_cols.add(col)
            unique_cited_columns.append(col)
    cited_columns = unique_cited_columns

    if not cited_timestamps and not cited_row_refs and not cited_columns:
        return []

    csv_timestamp_lookup: set[str] = set()
    csv_row_refs: set[str] = set()
    csv_columns: list[str] = []
    try:
        with csv_path.open("r", newline="", encoding="utf-8-sig", errors="replace") as fh:
            reader = csv.DictReader(fh)
            csv_columns = [str(c) for c in (reader.fieldnames or []) if c not in (None, "")]
            ts_columns = [c for c in csv_columns if looks_like_timestamp_column(c)]
            has_row_ref_col = "row_ref" in csv_columns
            for row_number, raw_row in enumerate(reader, start=1):
                if has_row_ref_col:
                    ref_val = stringify_value(raw_row.get("row_ref"))
                    if ref_val:
                        csv_row_refs.add(ref_val)
                else:
                    csv_row_refs.add(str(row_number))
                for col in ts_columns:
                    val = stringify_value(raw_row.get(col))
                    if val:
                        csv_timestamp_lookup.update(timestamp_lookup_keys(val))
    except OSError:
        return []

    warnings: list[str] = []
    column_match_results: list[dict[str, str]] = []

    for ts in cited_timestamps[:citation_spot_check_limit]:
        if not timestamp_found_in_csv(ts, csv_timestamp_lookup):
            warnings.append(
                f"Note: AI cited timestamp {ts} which could not be verified in the source data."
            )

    for ref in cited_row_refs[:citation_spot_check_limit]:
        if ref not in csv_row_refs:
            warnings.append(
                f"Note: AI cited row {ref} which could not be verified in the source data."
            )

    for cited_col in cited_columns[:citation_spot_check_limit]:
        match_status, matched_header = match_column_name(cited_col, csv_columns)
        column_match_results.append({
            "cited": cited_col,
            "match_status": match_status,
            "matched_header": matched_header or "",
        })
        if match_status == "fuzzy":
            LOGGER.warning(
                "AI cited column '%s' is a fuzzy match for CSV header '%s' "
                "(case/whitespace difference) in artifact %s.",
                cited_col,
                matched_header,
                artifact_key,
            )
            warnings.append(
                f"Note: AI cited column '{cited_col}' is a fuzzy match for CSV header "
                f"'{matched_header}' (case or whitespace difference)."
            )
        elif match_status == "unverifiable":
            warnings.append(
                f"Note: AI cited column '{cited_col}' which does not match any column "
                f"in the source data — citation is unverifiable."
            )

    if warnings and audit_log_fn is not None:
        audit_details: dict[str, object] = {
            "artifact_key": artifact_key,
            "citation_validation": "warnings_found",
            "warning_count": len(warnings),
            "warnings": warnings[:10],
        }
        if column_match_results:
            audit_details["column_match_results"] = column_match_results[:10]
        audit_log_fn("citation_validation", audit_details)

    return warnings
