"""Constants, regex patterns, and prompt templates for the analyzer module.

This module centralises all compile-time constants used by the forensic
analysis pipeline so they can be imported by multiple sub-modules without
circular dependencies.

Attributes:
    TOKEN_CHAR_RATIO (int): Approximate characters per token for ASCII text.
    DATE_BUFFER_DAYS (int): Default days to pad around context-extracted dates.
    AI_MAX_TOKENS (int): Default AI context window size in tokens.
    DEFAULT_SHORTENED_PROMPT_CUTOFF_TOKENS (int): Token threshold for
        switching to the small-context prompt template.
    AI_RETRY_ATTEMPTS (int): Maximum retry attempts for transient AI failures.
    AI_RETRY_BASE_DELAY (float): Base delay in seconds for retry backoff.
    MAX_MERGE_ROUNDS (int): Maximum hierarchical merge iterations.
    ARTIFACT_DEDUPLICATION_ENABLED (bool): Default deduplication toggle.
    DEDUPLICATED_PARSED_DIRNAME (str): Directory name for deduplicated CSVs.
    DEDUP_COMMENT_COLUMN (str): Column name for deduplication annotations.
    CITATION_SPOT_CHECK_LIMIT (int): Max citations to validate per artifact.
    PROJECT_ROOT (Path): Absolute path to the project root directory.
    DEFAULT_ARTIFACT_AI_COLUMNS_CONFIG_PATH (Path): Default column projection
        YAML config path.
"""

from __future__ import annotations

import re
from pathlib import Path

from .ai_providers import AIProviderError

__all__ = [
    "TOKEN_CHAR_RATIO",
    "DATE_BUFFER_DAYS",
    "AI_MAX_TOKENS",
    "DEFAULT_SHORTENED_PROMPT_CUTOFF_TOKENS",
    "AI_RETRY_ATTEMPTS",
    "AI_RETRY_BASE_DELAY",
    "MAX_MERGE_ROUNDS",
    "ARTIFACT_DEDUPLICATION_ENABLED",
    "DEDUPLICATED_PARSED_DIRNAME",
    "DEDUP_COMMENT_COLUMN",
    "CITATION_SPOT_CHECK_LIMIT",
    "PROJECT_ROOT",
    "DEFAULT_ARTIFACT_AI_COLUMNS_CONFIG_PATH",
    "UnavailableProvider",
]

# ---------------------------------------------------------------------------
# Numeric / string constants
# ---------------------------------------------------------------------------

TOKEN_CHAR_RATIO = 4
DATE_BUFFER_DAYS = 7
AI_MAX_TOKENS = 128000
DEFAULT_SHORTENED_PROMPT_CUTOFF_TOKENS = 64000
AI_RETRY_ATTEMPTS = 3
AI_RETRY_BASE_DELAY = 1.0
MAX_MERGE_ROUNDS = 5
ARTIFACT_DEDUPLICATION_ENABLED = True
DEDUPLICATED_PARSED_DIRNAME = "parsed_deduplicated"
DEDUP_COMMENT_COLUMN = "_dedup_comment"
CITATION_SPOT_CHECK_LIMIT = 20
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARTIFACT_AI_COLUMNS_CONFIG_PATH = PROJECT_ROOT / "config" / "artifact_ai_columns.yaml"

# ---------------------------------------------------------------------------
# Date-extraction regex patterns
# ---------------------------------------------------------------------------

CONTEXT_ISO_DATE_RE = re.compile(r"\b(?P<year>\d{4})-(?P<month>\d{1,2})-(?P<day>\d{1,2})\b")
CONTEXT_DMY_DASH_RE = re.compile(r"\b(?P<day>\d{1,2})-(?P<month>\d{1,2})-(?P<year>\d{4})\b")
CONTEXT_DMY_SLASH_RE = re.compile(r"\b(?P<day>\d{1,2})/(?P<month>\d{1,2})/(?P<year>\d{4})\b")
CONTEXT_TEXTUAL_RANGE_RE = re.compile(
    r"\b(?P<month_name>"
    r"jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|"
    r"sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
    r"\s+(?P<day_start>\d{1,2})(?:st|nd|rd|th)?\s*(?:-|\u2013|\u2014|to)\s*"
    r"(?P<day_end>\d{1,2})(?:st|nd|rd|th)?(?:,\s*|\s+)(?P<year>\d{4})\b",
    flags=re.IGNORECASE,
)
CONTEXT_TEXTUAL_DATE_RE = re.compile(
    r"\b(?P<month_name>"
    r"jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|"
    r"sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
    r"\s+(?P<day>\d{1,2})(?:st|nd|rd|th)?(?:,\s*|\s+)(?P<year>\d{4})\b",
    flags=re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# IOC-extraction regex patterns
# ---------------------------------------------------------------------------

IOC_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]+", flags=re.IGNORECASE)
IOC_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
IOC_HASH_RE = re.compile(r"\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b")
IOC_DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}\b")
IOC_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b")
IOC_FILENAME_RE = re.compile(
    r"\b[A-Za-z0-9_.-]+\.(?:exe|dll|sys|bat|cmd|ps1|vbs|vbe|msi|msp|scr|cpl|lnk|jar)\b",
    flags=re.IGNORECASE,
)

KNOWN_MALICIOUS_TOOL_KEYWORDS = (
    "mimikatz",
    "rubeus",
    "psexec",
    "procdump",
    "nanodump",
    "comsvcs",
    "secretsdump",
    "wmiexec",
    "atexec",
    "cobalt strike",
    "beacon",
    "bloodhound",
    "adfind",
    "ligolo",
    "metasploit",
)

DOMAIN_EXCLUDED_SUFFIXES = {".local", ".lan", ".internal"}

# ---------------------------------------------------------------------------
# Citation-validation regex patterns
# ---------------------------------------------------------------------------

CITED_ISO_TIMESTAMP_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\b"
)
CITED_ROW_REF_RE = re.compile(r"\brow[_ ]?(?:ref(?:erence)?)?[:\s#]*(\d+)\b", re.IGNORECASE)
CITED_COLUMN_REF_RE = re.compile(
    r"(?:`([^`]{2,60})`"
    r"|(?:column|field)\s+[\"']([^\"']{2,60})[\"']"
    r"|[\"']([^\"']{2,60})[\"']\s+(?:column|field))",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# CSV / prompt section regex patterns
# ---------------------------------------------------------------------------

CSV_DATA_SECTION_RE = re.compile(
    r"#{2,3}\s+Full\s+Data\s+\(CSV\)\s*\n(?:```\s*\n)?",
    flags=re.IGNORECASE,
)
CSV_TRAILING_FENCE_RE = re.compile(r"\n```\s*$")
WINDOWS_PATH_RE = re.compile(r"[A-Za-z]:\\[^\"'\s,;)]*")
INTEGER_RE = re.compile(r"-?\d+")

# ---------------------------------------------------------------------------
# Lookup tables
# ---------------------------------------------------------------------------

MONTH_LOOKUP = {
    "jan": 1, "january": 1,
    "feb": 2, "february": 2,
    "mar": 3, "march": 3,
    "apr": 4, "april": 4,
    "may": 5,
    "jun": 6, "june": 6,
    "jul": 7, "july": 7,
    "aug": 8, "august": 8,
    "sep": 9, "sept": 9, "september": 9,
    "oct": 10, "october": 10,
    "nov": 11, "november": 11,
    "dec": 12, "december": 12,
}

TIMESTAMP_COLUMN_HINTS = (
    "ts", "timestamp", "time", "date", "created",
    "modified", "last", "first", "written",
)

DEDUP_SAFE_IDENTIFIER_HINTS = {
    "recordid", "record_id", "entryid", "entry_id",
    "index", "row_id", "rowid", "sequence_number", "sequencenumber",
}

METADATA_COLUMNS = {
    "_source", "_classification", "_generated", "_version",
    "source", "row_ref", "_row_ref",
}

LOW_SIGNAL_VALUES = {"", "none", "null", "n/a", "na", "unknown", "-"}

# ---------------------------------------------------------------------------
# Default prompt templates
# ---------------------------------------------------------------------------

DEFAULT_SYSTEM_PROMPT = (
    "You are a digital forensic analyst. "
    "Analyze ONLY the data provided to you. "
    "Do not fabricate evidence. "
    "Prioritize incident-relevant findings and response actions; use baseline only as supporting context."
)

DEFAULT_ARTIFACT_PROMPT_TEMPLATE = (
    "## Priority Directives\n{{priority_directives}}\n\n"
    "## Investigation Context\n{{investigation_context}}\n\n"
    "## IOC Targets\n{{ioc_targets}}\n\n"
    "## Artifact\n- Key: {{artifact_key}}\n- Name: {{artifact_name}}\n- Description: {{artifact_description}}\n\n"
    "## Dataset Scope\n- Total records: {{total_records}}\n"
    "- Time range start: {{time_range_start}}\n- Time range end: {{time_range_end}}\n\n"
    "## Statistics\n{{statistics}}\n\n"
    "## Incident Focus\n"
    "- Prioritize suspicious activity that advances detection, scoping, containment, or remediation.\n"
    "- Use baseline and statistics only as supporting context for behavior shifts.\n\n"
    "## Analysis Instructions\n{{analysis_instructions}}\n\n"
    "## Full Data (CSV)\n{{data_csv}}\n"
)

DEFAULT_ARTIFACT_PROMPT_TEMPLATE_SMALL_CONTEXT = (
    "## Priority Directives\n{{priority_directives}}\n\n"
    "## Investigation Context\n{{investigation_context}}\n\n"
    "## IOC Targets\n{{ioc_targets}}\n\n"
    "## Artifact\n- Key: {{artifact_key}}\n- Name: {{artifact_name}}\n- Description: {{artifact_description}}\n\n"
    "## Dataset Scope\n- Total records: {{total_records}}\n"
    "- Time range start: {{time_range_start}}\n- Time range end: {{time_range_end}}\n\n"
    "## Incident Focus\n"
    "- Prioritize suspicious activity that advances detection, scoping, containment, or remediation.\n"
    "- Use baseline references only as supporting context for behavior shifts.\n\n"
    "## Analysis Instructions\n{{analysis_instructions}}\n\n"
    "## Full Data (CSV)\n{{data_csv}}\n"
)

DEFAULT_SUMMARY_PROMPT_TEMPLATE = (
    "## Priority Directives\n{{priority_directives}}\n\n"
    "## Investigation Context\n{{investigation_context}}\n\n"
    "## IOC Targets\n{{ioc_targets}}\n\n"
    "## Host Context\n- Hostname: {{hostname}}\n- OS Version: {{os_version}}\n- Domain: {{domain}}\n\n"
    "## Per-Artifact Findings\n{{per_artifact_findings}}\n\n"
    "## Incident Focus\n"
    "- Correlate findings to identify likely intrusion activity, scope, and priority response actions.\n"
    "- Use baseline references only when they strengthen incident conclusions.\n"
)

DEFAULT_CHUNK_MERGE_PROMPT_TEMPLATE = (
    "You analyzed the same artifact dataset in {{chunk_count}} separate chunks "
    "because the data was too large for a single pass.\n"
    "Below are your findings from each chunk. Merge them into one final analysis.\n\n"
    "## Investigation Context\n{{investigation_context}}\n\n"
    "## Artifact: {{artifact_name}} ({{artifact_key}})\n\n"
    "## Per-Chunk Findings\n{{per_chunk_findings}}\n\n"
    "## Task\n"
    "Merge the above chunk analyses into one coherent analysis. "
    "Deduplicate repeated findings, reconcile contradictions, "
    "and re-rank by severity then confidence. "
    "Use the same output format as a single-pass artifact analysis:\n"
    "- **Findings** (severity/confidence, evidence, alternative explanation, verify)\n"
    "- **IOC Status** (if applicable)\n"
    "- **Data Gaps**\n"
)


# ---------------------------------------------------------------------------
# Fallback AI provider
# ---------------------------------------------------------------------------

class UnavailableProvider:
    """Fallback AI provider used when the configured provider fails to initialize.

    This sentinel object implements the same interface as a real AI provider
    but raises ``AIProviderError`` on every ``analyze`` call, ensuring that
    the analyzer reports a clear error instead of crashing with an
    ``AttributeError``.

    Attributes:
        _error_message: Human-readable description of why the real provider
            could not be created.
    """

    def __init__(self, error_message: str) -> None:
        """Initialize the unavailable provider with an error message.

        Args:
            error_message: Description of the initialization failure to
                surface when ``analyze`` is called.
        """
        self._error_message = error_message or "AI provider is unavailable."

    def analyze(self, system_prompt: str, user_prompt: str, max_tokens: int = AI_MAX_TOKENS) -> str:
        """Always raises ``AIProviderError`` with the stored error message.

        Args:
            system_prompt: The system prompt (unused).
            user_prompt: The user prompt (unused).
            max_tokens: Maximum response tokens (unused).

        Raises:
            AIProviderError: Always raised with the initialization error.
        """
        raise AIProviderError(self._error_message)

    def get_model_info(self) -> dict[str, str]:
        """Return placeholder model info indicating unavailability.

        Returns:
            A dict with ``provider`` and ``model`` both set to
            ``"unavailable"``.
        """
        return {"provider": "unavailable", "model": "unavailable"}
