"""CSV data retrieval for chat-based forensic Q&A.

Provides heuristic matching of user questions to parsed artifact CSV
files, reading and formatting relevant rows for injection into AI
prompts so the model can answer data-specific queries.

Key responsibilities:

* **Artifact matching** -- Matches user questions against CSV filenames
  using generated aliases (stem, space-separated, base without part
  suffixes).
* **Column matching** -- Falls back to matching against CSV column headers
  when artifact-name matching finds nothing.
* **Row sampling** -- Reads up to a configurable limit of rows, compacting
  values and truncating long strings to keep prompt size manageable.

Attributes:
    CSV_RETRIEVAL_KEYWORDS: Tuple of lowercase keyword phrases that
        indicate the user is requesting raw data.
    CSV_ROW_LIMIT: Maximum number of CSV rows to include in a single
        retrieval response.
"""

from __future__ import annotations

import csv
import logging
import re
from pathlib import Path
from typing import Any

__all__ = [
    "retrieve_csv_data",
    "build_csv_aliases",
    "contains_heuristic_term",
]

log = logging.getLogger(__name__)

CSV_RETRIEVAL_KEYWORDS = (
    "show me",
    "list",
    "csv",
    "rows",
    "records",
    "check the",
    "look in",
)

CSV_ROW_LIMIT = 500


def _stringify(value: Any, default: str = "") -> str:
    """Convert *value* to a stripped string, returning *default* when empty.

    Args:
        value: Arbitrary value to stringify.
        default: Fallback string when *value* is *None* or blank.

    Returns:
        The stripped string representation or *default*.
    """
    text = str(value).strip() if value is not None else ""
    return text or default


def retrieve_csv_data(
    question: str,
    parsed_dir: str | Path,
    row_limit: int = CSV_ROW_LIMIT,
) -> dict[str, Any]:
    """Best-effort retrieval of raw CSV rows for data-centric chat questions.

    Heuristically matches the user's *question* against parsed artifact
    CSV filenames and column headers.  When a match is found, up to
    *row_limit* rows are read and formatted as a structured text block
    for injection into the AI prompt.

    Args:
        question: The user's chat question text.
        parsed_dir: Path to the directory containing parsed artifact
            CSV files.
        row_limit: Maximum total rows to include across all matched
            CSVs.  Defaults to :data:`CSV_ROW_LIMIT`.

    Returns:
        A dictionary with a ``retrieved`` boolean.  When *True*, also
        includes ``artifacts`` (list of matched CSV filenames) and
        ``data`` (formatted row text).
    """
    question_text = _stringify(question)
    if not question_text:
        return {"retrieved": False}

    parsed_path = Path(parsed_dir)
    if not parsed_path.exists() or not parsed_path.is_dir():
        return {"retrieved": False}

    csv_paths = sorted(path for path in parsed_path.glob("*.csv") if path.is_file())
    if not csv_paths:
        return {"retrieved": False}

    question_lower = question_text.lower()
    keyword_detected = any(kw in question_lower for kw in CSV_RETRIEVAL_KEYWORDS)

    target_paths = _match_target_paths(csv_paths, question_lower, keyword_detected)
    if target_paths is None:
        return {"retrieved": False}

    target_paths = list(dict.fromkeys(target_paths))
    artifacts = [path.name for path in target_paths]
    formatted_blocks: list[str] = []
    rows_remaining = row_limit

    for csv_path in target_paths:
        if rows_remaining <= 0:
            break
        headers, rows, total_row_count = _read_csv_rows(csv_path, limit=rows_remaining)
        if not headers and not rows:
            continue

        rows_remaining -= len(rows)
        formatted_blocks.append(
            _format_csv_block(csv_path.name, headers, rows, total_row_count)
        )

    if not formatted_blocks:
        return {
            "retrieved": True,
            "artifacts": artifacts,
            "data": "No readable rows found in selected CSV files.",
        }

    return {
        "retrieved": True,
        "artifacts": artifacts,
        "data": "\n\n".join(formatted_blocks),
    }


def _match_target_paths(
    csv_paths: list[Path],
    question_lower: str,
    keyword_detected: bool,
) -> list[Path] | None:
    """Determine which CSV files match the user's question.

    Tries artifact-name matching first, then column-header matching,
    then falls back to returning all CSVs if keywords were detected
    and the collection is small.

    Args:
        csv_paths: Sorted list of available CSV file paths.
        question_lower: Lowercased question text.
        keyword_detected: Whether retrieval keywords were found in
            the question.

    Returns:
        A list of matched paths, or *None* when no match is found.
    """
    aliases_by_path = {path: build_csv_aliases(path) for path in csv_paths}
    artifact_matches = [
        path
        for path, aliases in aliases_by_path.items()
        if any(contains_heuristic_term(question_lower, alias) for alias in aliases)
    ]

    if artifact_matches:
        return artifact_matches

    # Only scan CSV headers when artifact-name matching didn't find anything,
    # to avoid reading every CSV file on every chat message.
    headers_by_path = {path: _read_csv_headers(path) for path in csv_paths}
    matched_columns = {
        header.lower()
        for headers in headers_by_path.values()
        for header in headers
        if contains_heuristic_term(question_lower, header.lower())
    }
    if matched_columns:
        return [
            path
            for path, headers in headers_by_path.items()
            if any(header.lower() in matched_columns for header in headers)
        ]

    if keyword_detected and len(csv_paths) <= 3:
        return csv_paths

    return None


def build_csv_aliases(csv_path: Path) -> set[str]:
    """Build a set of lowercase name aliases for a CSV file.

    Aliases include the full filename, stem, space-separated stem,
    base name (without ``_partN`` suffixes), and leading segments
    before the first underscore.

    Args:
        csv_path: Path to the CSV file.

    Returns:
        A set of non-empty lowercase alias strings.
    """
    stem = csv_path.stem.lower()
    base = re.sub(r"_part\d+$", "", stem)
    aliases = {
        csv_path.name.lower(),
        stem,
        stem.replace("_", " "),
        base,
        base.replace("_", " "),
    }
    if "_" in stem:
        aliases.add(stem.split("_", 1)[0])
    if "_" in base:
        aliases.add(base.split("_", 1)[0])
    return {alias.strip() for alias in aliases if alias.strip()}


def contains_heuristic_term(question_lower: str, term: str) -> bool:
    """Check whether *term* appears as a distinct token in *question_lower*.

    Uses a word-boundary regex so that short substrings do not
    produce false positives.  Terms shorter than 3 characters are
    always rejected.

    Args:
        question_lower: Lowercased question text to search.
        term: Candidate term to look for.

    Returns:
        *True* when *term* (>= 3 chars) appears on a word boundary
        in *question_lower*.
    """
    normalized = term.strip().lower()
    if len(normalized) < 3:
        return False
    pattern = rf"(?<![a-z0-9]){re.escape(normalized)}(?![a-z0-9])"
    return re.search(pattern, question_lower) is not None


def _read_csv_headers(csv_path: Path) -> list[str]:
    """Read and return the header row from a CSV file.

    Args:
        csv_path: Path to the CSV file.

    Returns:
        A list of non-empty, stripped header strings.  Returns an
        empty list on read failure.
    """
    try:
        with csv_path.open("r", encoding="utf-8-sig", newline="", errors="replace") as csv_stream:
            header_row = next(csv.reader(csv_stream), [])
    except Exception:
        log.warning("Failed to read CSV headers from %s", csv_path, exc_info=True)
        return []

    return [_stringify(h) for h in header_row if _stringify(h)]


def _read_csv_rows(
    csv_path: Path,
    limit: int,
) -> tuple[list[str], list[dict[str, str]], int]:
    """Read up to *limit* data rows from a CSV file.

    Values are whitespace-collapsed and truncated to 240 characters
    to keep the resulting text compact for AI prompt injection.

    After reading the sampled rows, the remainder of the file is
    consumed (without storing data) to obtain an accurate total row
    count.

    Args:
        csv_path: Path to the CSV file.
        limit: Maximum number of data rows to read.

    Returns:
        A tuple of ``(headers, rows, total_row_count)`` where
        *headers* is a list of column name strings, *rows* is a
        list of ordered dictionaries mapping column names to string
        values, and *total_row_count* is the total number of data
        rows in the file (including those beyond *limit*).  Returns
        ``([], [], 0)`` on read failure or when *limit* is
        non-positive.
    """
    if limit <= 0:
        return [], [], 0

    try:
        with csv_path.open("r", encoding="utf-8-sig", newline="", errors="replace") as csv_stream:
            reader = csv.DictReader(csv_stream)
            headers = [_stringify(field) for field in (reader.fieldnames or []) if _stringify(field)]

            rows: list[dict[str, str]] = []
            total_row_count = 0
            for row in reader:
                total_row_count += 1
                if len(rows) < limit:
                    compact_row: dict[str, str] = {}
                    for column in headers:
                        value = _stringify(row.get(column, ""))
                        value = re.sub(r"\s+", " ", value)
                        if len(value) > 240:
                            value = f"{value[:237]}..."
                        compact_row[column] = value
                    rows.append(compact_row)
    except Exception:
        log.warning("Failed to read CSV rows from %s", csv_path, exc_info=True)
        return [], [], 0

    return headers, rows, total_row_count


def _format_csv_block(
    filename: str,
    headers: list[str],
    rows: list[dict[str, str]],
    total_row_count: int,
) -> str:
    """Format CSV data as a readable text block for AI prompt injection.

    Args:
        filename: The CSV filename for the block header.
        headers: Column name strings.
        rows: List of row dictionaries.
        total_row_count: Total rows in the source file.

    Returns:
        A formatted multi-line text block.
    """
    block_lines = [f"Artifact: {filename}"]
    block_lines.append(
        f"Total rows: {total_row_count}"
        + (f" (showing first {len(rows)})" if len(rows) < total_row_count else "")
    )
    if headers:
        block_lines.append(f"Columns: {', '.join(headers)}")
    if rows:
        block_lines.append("Rows:")
        for row_index, row in enumerate(rows, start=1):
            parts = [f"{column}={value}" for column, value in row.items()]
            block_lines.append(f"{row_index}. " + " | ".join(parts))
    else:
        block_lines.append("Rows: none")
    return "\n".join(block_lines)
