"""Pure utility functions for the forensic analyzer pipeline.

Provides string manipulation, datetime parsing, CSV normalisation, filename
sanitisation, token estimation, and other stateless helpers used across the
analyzer sub-modules.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .constants import (
    INTEGER_RE,
    TIMESTAMP_COLUMN_HINTS,
    TOKEN_CHAR_RATIO,
)

try:
    import tiktoken
    _TIKTOKEN_AVAILABLE = True
except ImportError:
    _TIKTOKEN_AVAILABLE = False

__all__ = [
    "stringify_value",
    "format_datetime",
    "normalize_table_cell",
    "sanitize_filename",
    "build_datetime",
    "parse_int",
    "normalize_datetime",
    "parse_datetime_value",
    "looks_like_timestamp_column",
    "extract_row_datetime",
    "time_range_for_rows",
    "normalize_artifact_key",
    "unique_preserve_order",
    "truncate_for_prompt",
    "extract_url_host",
    "normalize_csv_row",
    "coerce_projection_columns",
    "emit_analysis_progress",
    "estimate_tokens",
    "is_dedup_safe_identifier_column",
    "read_int_setting",
    "read_bool_setting",
    "read_path_setting",
]


# ---------------------------------------------------------------------------
# String helpers
# ---------------------------------------------------------------------------

def stringify_value(value: Any) -> str:
    """Convert an arbitrary value to a stripped string.

    Args:
        value: Any value (string, ``None``, number, etc.).

    Returns:
        The stripped string representation, or an empty string for ``None``.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    return str(value).strip()


def format_datetime(value: datetime | None) -> str:
    """Format a datetime as an ISO string, or ``"N/A"`` for ``None``.

    Args:
        value: Datetime to format, or ``None``.

    Returns:
        ISO-formatted datetime string or ``"N/A"``.
    """
    if value is None:
        return "N/A"
    return value.isoformat()


def normalize_table_cell(value: str, cell_limit: int) -> str:
    """Normalize and truncate a cell value for table/statistics display.

    Replaces newlines and pipe characters, strips whitespace, and
    truncates with an ellipsis if the value exceeds *cell_limit*.

    Args:
        value: Raw cell value string.
        cell_limit: Maximum character length for the output.

    Returns:
        The cleaned and possibly truncated string.
    """
    text = value.replace("\r", " ").replace("\n", " ").replace("|", r"\|").strip()
    if len(text) <= cell_limit:
        return text
    if cell_limit <= 3:
        return text[:cell_limit]
    return f"{text[: cell_limit - 3]}..."


def sanitize_filename(value: str) -> str:
    """Sanitize a string for use as a safe filename.

    Args:
        value: Raw string to sanitize.

    Returns:
        A filesystem-safe filename string, or ``"artifact"`` if empty.
    """
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_")
    return cleaned or "artifact"


def truncate_for_prompt(value: str, limit: int) -> str:
    """Truncate a string to fit within a character limit for prompt inclusion.

    Args:
        value: The string to truncate.
        limit: Maximum allowed character count.

    Returns:
        The original string if it fits, or a truncated version.
    """
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    if limit <= 20:
        return text[:limit]
    return f"{text[: limit - 14].rstrip()} ... [truncated]"


def unique_preserve_order(values: Iterable[str]) -> list[str]:
    """Deduplicate strings while preserving first-occurrence order.

    Values are stripped, surrounding quotes/brackets are removed, and
    trailing punctuation is trimmed before deduplication (case-insensitive).

    Args:
        values: Iterable of raw string values to deduplicate.

    Returns:
        A list of cleaned, unique strings in their original order.
    """
    unique: list[str] = []
    seen: set[str] = set()
    for raw_value in values:
        value = str(raw_value).strip()
        value = value.strip("\"'()[]{}<>")
        value = value.rstrip(".,;:")
        if not value:
            continue
        key = value.lower()
        if key in seen:
            continue
        seen.add(key)
        unique.append(value)
    return unique


# ---------------------------------------------------------------------------
# Datetime helpers
# ---------------------------------------------------------------------------

def build_datetime(year: str, month: str, day: str) -> datetime | None:
    """Construct a datetime from string year, month, and day components.

    Args:
        year: Year string (e.g., ``"2025"``).
        month: Month string (``"1"`` through ``"12"``).
        day: Day string (``"1"`` through ``"31"``).

    Returns:
        A ``datetime`` at midnight for the given date, or ``None``.
    """
    try:
        return datetime(int(year), int(month), int(day))
    except ValueError:
        return None


def normalize_datetime(value: datetime) -> datetime:
    """Convert a datetime to a naive UTC datetime.

    Args:
        value: Datetime to normalize.

    Returns:
        A naive ``datetime`` representing the same instant in UTC.
    """
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def parse_int(value: str) -> int | None:
    """Extract and parse the first integer from a string.

    Args:
        value: String that may contain an integer.

    Returns:
        The parsed integer, or ``None``.
    """
    if not value:
        return None
    match = INTEGER_RE.search(value)
    if not match:
        return None
    try:
        return int(match.group())
    except ValueError:
        return None


def parse_datetime_value(value: str, *, allow_epoch: bool = True) -> datetime | None:
    """Attempt to parse a string value into a naive UTC datetime.

    Tries ISO format first, then common date/time formats, and optionally
    epoch timestamps (seconds or milliseconds).

    Args:
        value: Raw string that may contain a date or timestamp.
        allow_epoch: If ``True`` (default), bare integers in the plausible
            epoch range are accepted.  Set to ``False`` when scanning
            columns that are not known to hold timestamps, to avoid
            misinterpreting numeric IDs or counters as dates.

    Returns:
        A naive ``datetime`` in UTC, or ``None`` if parsing fails.
    """
    text = stringify_value(value)
    if not text:
        return None

    cleaned = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(cleaned)
        return normalize_datetime(parsed)
    except ValueError:
        pass

    for fmt in (
        "%Y-%m-%d %H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%d-%m-%Y",
        "%d/%m/%Y",
        "%m/%d/%Y",
        "%B %d, %Y",
        "%b %d, %Y",
        "%B %d %Y",
        "%b %d %Y",
    ):
        try:
            parsed = datetime.strptime(cleaned, fmt)
            return normalize_datetime(parsed)
        except ValueError:
            continue

    if not allow_epoch:
        return None

    int_value = parse_int(cleaned)
    if int_value is not None:
        if int_value > 1_000_000_000_000:
            int_value //= 1000
        if 946684800 <= int_value <= 4_102_444_800:
            try:
                parsed = datetime.fromtimestamp(int_value, tz=timezone.utc)
                return normalize_datetime(parsed)
            except (ValueError, OSError):
                return None

    return None


def looks_like_timestamp_column(column_name: str) -> bool:
    """Check whether a column name suggests it contains timestamp data.

    Args:
        column_name: CSV column header name.

    Returns:
        ``True`` if the lowercased name contains any timestamp hint substring.
    """
    lowered = column_name.strip().lower()
    return any(hint in lowered for hint in TIMESTAMP_COLUMN_HINTS)


def is_dedup_safe_identifier_column(column_name: str) -> bool:
    """Return True only for auto-incremented record IDs safe for dedup.

    Args:
        column_name: CSV column header name.

    Returns:
        ``True`` if the column is a safe dedup identifier.
    """
    from .constants import DEDUP_SAFE_IDENTIFIER_HINTS
    lowered = column_name.strip().lower().replace("-", "_").replace(" ", "_")
    return lowered in DEDUP_SAFE_IDENTIFIER_HINTS


def extract_row_datetime(row: dict[str, str], columns: list[str] | None = None) -> datetime | None:
    """Extract the first parseable timestamp from a CSV row.

    Prioritizes columns whose names look like timestamps (with full
    parsing including epoch integers).  Falls back to remaining columns
    but only accepts string-format dates — bare numeric values are
    **not** treated as epoch timestamps in the fallback pass, to avoid
    misinterpreting IDs or counters as dates.

    Args:
        row: Normalized row dict.
        columns: Optional column list to constrain the search.

    Returns:
        The first successfully parsed ``datetime``, or ``None``.
    """
    all_columns = columns if columns else list(row.keys())
    timestamp_columns = [c for c in all_columns if looks_like_timestamp_column(c)]

    # Pass 1: timestamp-named columns — full parsing including epochs.
    for column in timestamp_columns:
        parsed = parse_datetime_value(row.get(column, ""), allow_epoch=True)
        if parsed is not None:
            return parsed

    # Pass 2: remaining columns — string dates only, no epoch integers.
    timestamp_set = set(timestamp_columns)
    for column in all_columns:
        if column in timestamp_set:
            continue
        parsed = parse_datetime_value(row.get(column, ""), allow_epoch=False)
        if parsed is not None:
            return parsed

    return None


def time_range_for_rows(rows: Iterable[dict[str, str]]) -> tuple[datetime | None, datetime | None]:
    """Compute the earliest and latest timestamps across all rows.

    Args:
        rows: Iterable of row dicts to scan for timestamp values.

    Returns:
        A ``(min_time, max_time)`` tuple.
    """
    min_time: datetime | None = None
    max_time: datetime | None = None
    for row in rows:
        parsed = extract_row_datetime(row=row)
        if parsed is None:
            continue
        if min_time is None or parsed < min_time:
            min_time = parsed
        if max_time is None or parsed > max_time:
            max_time = parsed
    return min_time, max_time


# ---------------------------------------------------------------------------
# Artifact key normalisation
# ---------------------------------------------------------------------------

def normalize_artifact_key(artifact_key: str) -> str:
    """Normalize an artifact key to its canonical short form.

    Args:
        artifact_key: Raw artifact key string.

    Returns:
        The lowercased, normalized artifact key.
    """
    key = artifact_key.strip().lower()
    if key == "mft":
        return "mft"
    if key.startswith("evtx") or key.endswith(".evtx") or ".evtx" in key:
        return "evtx"
    if key.startswith("shimcache"):
        return "shimcache"
    if key.startswith("amcache"):
        return "amcache"
    if key.startswith("prefetch"):
        return "prefetch"
    if key.startswith("services"):
        return "services"
    if key.startswith("tasks"):
        return "tasks"
    if key.startswith("userassist"):
        return "userassist"
    if key.startswith("runkeys"):
        return "runkeys"
    return key


# ---------------------------------------------------------------------------
# URL host extraction
# ---------------------------------------------------------------------------

def extract_url_host(url: str) -> str:
    """Extract the lowercase hostname from a URL string.

    Args:
        url: A URL string.

    Returns:
        The lowercased hostname portion without scheme, port, or path.
    """
    text = url.strip()
    if "://" in text:
        text = text.split("://", 1)[1]
    text = text.split("/", 1)[0]
    text = text.split(":", 1)[0]
    return text.lower().strip()


# ---------------------------------------------------------------------------
# CSV normalisation
# ---------------------------------------------------------------------------

def normalize_csv_row(row: dict[str | None, str | None | list[str]], columns: list[str]) -> dict[str, str]:
    """Normalize a raw CSV DictReader row to a clean string-to-string dict.

    Args:
        row: Raw row dict from ``csv.DictReader``.
        columns: Expected column names in the CSV.

    Returns:
        A normalized dict mapping column names to stripped string values.
    """
    normalized: dict[str, str] = {}
    for column in columns:
        normalized[column] = stringify_value(row.get(column))

    extras = row.get(None)
    if extras:
        extra_values = [stringify_value(value) for value in extras]
        normalized["__extra__"] = " | ".join(value for value in extra_values if value)

    return normalized


def coerce_projection_columns(value: Any) -> list[str]:
    """Coerce a raw YAML value into a deduplicated list of column names.

    Args:
        value: Raw value from the YAML config (string, list, or other).

    Returns:
        A deduplicated list of non-empty column name strings.
    """
    if isinstance(value, str):
        candidates = [part.strip() for part in value.split(",")]
    elif isinstance(value, list):
        candidates = [str(item).strip() for item in value]
    else:
        return []

    deduplicated: list[str] = []
    for candidate in candidates:
        if candidate and candidate not in deduplicated:
            deduplicated.append(candidate)
    return deduplicated


# ---------------------------------------------------------------------------
# Progress callback
# ---------------------------------------------------------------------------

def emit_analysis_progress(
    progress_callback: Any,
    artifact_key: str,
    status: str,
    payload: dict[str, Any],
) -> None:
    """Emit a progress event to the frontend via the callback.

    Args:
        progress_callback: The user-supplied progress callback.
        artifact_key: Artifact identifier for the event.
        status: Event status.
        payload: Event payload dict.
    """
    try:
        progress_callback(artifact_key, status, payload)
        return
    except TypeError:
        pass
    except Exception:
        return

    try:
        progress_callback({
            "artifact_key": artifact_key,
            "status": status,
            "result": payload,
        })
    except Exception:
        return


# ---------------------------------------------------------------------------
# Token estimation
# ---------------------------------------------------------------------------

def estimate_tokens(text: str, model_info: Mapping[str, str] | None = None) -> int:
    """Estimate the token count of a text string.

    When ``tiktoken`` is available and the provider is OpenAI-compatible,
    an exact BPE token count is returned.  Otherwise a heuristic is used.

    Args:
        text: The text to estimate token count for.
        model_info: Optional dict with ``provider`` and ``model`` keys.

    Returns:
        Estimated number of tokens (minimum 1).
    """
    if not text:
        return 1

    if _TIKTOKEN_AVAILABLE and model_info is not None:
        provider_name = str(model_info.get("provider", "")).lower()
        if provider_name in {"openai", "local", "custom"}:
            model_name = str(model_info.get("model", ""))
            try:
                enc = tiktoken.encoding_for_model(model_name)
            except KeyError:
                try:
                    enc = tiktoken.get_encoding("cl100k_base")
                except Exception:
                    enc = None
            if enc is not None:
                try:
                    return max(1, len(enc.encode(text)))
                except Exception:
                    pass

    ascii_chars: list[str] = []
    non_ascii_count = 0
    for ch in text:
        if ord(ch) < 128:
            ascii_chars.append(ch)
        else:
            non_ascii_count += 1

    ascii_tokens = len(ascii_chars) / max(1, TOKEN_CHAR_RATIO)
    non_ascii_tokens = non_ascii_count * 1.5
    raw_estimate = ascii_tokens + non_ascii_tokens
    with_margin = raw_estimate * 1.1

    return max(1, int(with_margin))


# ---------------------------------------------------------------------------
# Config setting readers
# ---------------------------------------------------------------------------

def read_int_setting(
    analysis_config: Mapping[str, Any], key: str, default: int,
    minimum: int = 1, maximum: int | None = None,
) -> int:
    """Read an integer setting with bounds clamping.

    Args:
        analysis_config: The ``analysis`` sub-dictionary.
        key: Configuration key name.
        default: Default value.
        minimum: Lower bound (inclusive).
        maximum: Optional upper bound (inclusive).

    Returns:
        The parsed and clamped integer value.
    """
    raw_value = analysis_config.get(key, default)
    try:
        parsed_value = int(raw_value)
    except (TypeError, ValueError):
        parsed_value = default
    if parsed_value < minimum:
        parsed_value = minimum
    if maximum is not None and parsed_value > maximum:
        parsed_value = maximum
    return parsed_value


def read_bool_setting(analysis_config: Mapping[str, Any], key: str, default: bool) -> bool:
    """Read a boolean setting from the analysis config.

    Args:
        analysis_config: The ``analysis`` sub-dictionary.
        key: Configuration key name.
        default: Default value.

    Returns:
        The parsed boolean value.
    """
    raw_value = analysis_config.get(key, default)
    if isinstance(raw_value, bool):
        return raw_value
    if isinstance(raw_value, str):
        lowered = raw_value.strip().lower()
        if lowered in {"true", "1", "yes", "on"}:
            return True
        if lowered in {"false", "0", "no", "off"}:
            return False
    if isinstance(raw_value, (int, float)):
        return bool(raw_value)
    return default


def read_path_setting(analysis_config: Mapping[str, Any], key: str, default: str) -> str:
    """Read a file-path setting from the analysis config.

    Args:
        analysis_config: The ``analysis`` sub-dictionary.
        key: Configuration key name.
        default: Default value.

    Returns:
        The cleaned path string.
    """
    raw_value = analysis_config.get(key, default)
    if isinstance(raw_value, (str, Path)):
        cleaned = str(raw_value).strip()
        if cleaned:
            return cleaned
    return default
