"""AI analysis orchestration module."""

from __future__ import annotations

from collections import Counter
import csv
from datetime import datetime, timedelta, timezone
import io
from pathlib import Path
import logging
import random
import re
from time import perf_counter, sleep
from typing import Any, Callable, Iterable, Mapping

import yaml

from .ai_providers import AIProviderError, create_provider

LOGGER = logging.getLogger(__name__)

try:
    from .parser import ARTIFACT_REGISTRY
except Exception as error:
    LOGGER.warning(
        "Failed to import artifact registry from app.parser: %s. "
        "Artifact metadata lookups will be unavailable.",
        error,
    )
    ARTIFACT_REGISTRY: dict[str, dict[str, str]] = {}

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
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_ARTIFACT_AI_COLUMNS_CONFIG_PATH = PROJECT_ROOT / "config" / "artifact_ai_columns.yaml"

_CONTEXT_ISO_DATE_RE = re.compile(r"\b(?P<year>\d{4})-(?P<month>\d{1,2})-(?P<day>\d{1,2})\b")
_CONTEXT_DMY_DASH_RE = re.compile(r"\b(?P<day>\d{1,2})-(?P<month>\d{1,2})-(?P<year>\d{4})\b")
_CONTEXT_DMY_SLASH_RE = re.compile(r"\b(?P<day>\d{1,2})/(?P<month>\d{1,2})/(?P<year>\d{4})\b")
_CONTEXT_TEXTUAL_RANGE_RE = re.compile(
    r"\b(?P<month_name>"
    r"jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|"
    r"sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
    r"\s+(?P<day_start>\d{1,2})(?:st|nd|rd|th)?\s*(?:-|\u2013|\u2014|to)\s*"
    r"(?P<day_end>\d{1,2})(?:st|nd|rd|th)?(?:,\s*|\s+)(?P<year>\d{4})\b",
    flags=re.IGNORECASE,
)
_CONTEXT_TEXTUAL_DATE_RE = re.compile(
    r"\b(?P<month_name>"
    r"jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|"
    r"sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
    r"\s+(?P<day>\d{1,2})(?:st|nd|rd|th)?(?:,\s*|\s+)(?P<year>\d{4})\b",
    flags=re.IGNORECASE,
)

_IOC_URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]+", flags=re.IGNORECASE)
_IOC_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
_IOC_HASH_RE = re.compile(r"\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b")
_IOC_DOMAIN_RE = re.compile(r"\b(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}\b")
_IOC_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b")
_IOC_FILENAME_RE = re.compile(
    r"\b[A-Za-z0-9_.-]+\.(?:exe|dll|sys|bat|cmd|ps1|vbs|vbe|msi|msp|scr|cpl|lnk|jar)\b",
    flags=re.IGNORECASE,
)

_KNOWN_MALICIOUS_TOOL_KEYWORDS = (
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

_DOMAIN_EXCLUDED_SUFFIXES = {".local", ".lan", ".internal"}

_MONTH_LOOKUP = {
    "jan": 1,
    "january": 1,
    "feb": 2,
    "february": 2,
    "mar": 3,
    "march": 3,
    "apr": 4,
    "april": 4,
    "may": 5,
    "jun": 6,
    "june": 6,
    "jul": 7,
    "july": 7,
    "aug": 8,
    "august": 8,
    "sep": 9,
    "sept": 9,
    "september": 9,
    "oct": 10,
    "october": 10,
    "nov": 11,
    "november": 11,
    "dec": 12,
    "december": 12,
}

_TIMESTAMP_COLUMN_HINTS = (
    "ts",
    "timestamp",
    "time",
    "date",
    "created",
    "modified",
    "last",
    "first",
    "written",
)

# Narrow subset of identifier columns that are safe to treat as dedup
# variants — these are auto-incremented record/row IDs with no forensic
# meaning beyond ordering.  Semantic identifiers like EventID, ProcessID,
# SessionID etc. are intentionally excluded: they carry forensic meaning
# and rows differing only in those fields are genuinely different events.
_DEDUP_SAFE_IDENTIFIER_HINTS = {
    "recordid",
    "record_id",
    "entryid",
    "entry_id",
    "index",
    "row_id",
    "rowid",
    "sequence_number",
    "sequencenumber",
}

_METADATA_COLUMNS = {
    "_source",
    "_classification",
    "_generated",
    "_version",
    "source",
    "row_ref",
    "_row_ref",
}

_LOW_SIGNAL_VALUES = {"", "none", "null", "n/a", "na", "unknown", "-"}

_WINDOWS_PATH_RE = re.compile(r"[A-Za-z]:\\[^\"'\s,;)]*")
_INTEGER_RE = re.compile(r"-?\d+")

# Patterns for extracting AI-cited values during post-processing validation.
_CITED_ISO_TIMESTAMP_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\b"
)
_CITED_ROW_REF_RE = re.compile(r"\brow[_ ]?(?:ref(?:erence)?)?[:\s#]*(\d+)\b", re.IGNORECASE)
CITATION_SPOT_CHECK_LIMIT = 20

_DEFAULT_SYSTEM_PROMPT = (
    "You are a digital forensic analyst. "
    "Analyze ONLY the data provided to you. "
    "Do not fabricate evidence. "
    "Prioritize incident-relevant findings and response actions; use baseline only as supporting context."
)

_DEFAULT_ARTIFACT_PROMPT_TEMPLATE = (
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

_DEFAULT_ARTIFACT_PROMPT_TEMPLATE_SMALL_CONTEXT = (
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

_DEFAULT_SUMMARY_PROMPT_TEMPLATE = (
    "## Priority Directives\n{{priority_directives}}\n\n"
    "## Investigation Context\n{{investigation_context}}\n\n"
    "## IOC Targets\n{{ioc_targets}}\n\n"
    "## Host Context\n- Hostname: {{hostname}}\n- OS Version: {{os_version}}\n- Domain: {{domain}}\n\n"
    "## Per-Artifact Findings\n{{per_artifact_findings}}\n\n"
    "## Incident Focus\n"
    "- Correlate findings to identify likely intrusion activity, scope, and priority response actions.\n"
    "- Use baseline references only when they strengthen incident conclusions.\n"
)

_DEFAULT_CHUNK_MERGE_PROMPT_TEMPLATE = (
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

# Regex that matches the CSV data section heading used in prompt templates.
# Handles both hardcoded defaults ("## Full Data (CSV)\n") and file-based
# templates ("### Full Data (CSV)\n```\n").  The match includes everything
# up to the start of the actual CSV rows.
_CSV_DATA_SECTION_RE = re.compile(
    r"#{2,3}\s+Full\s+Data\s+\(CSV\)\s*\n(?:```\s*\n)?",
    flags=re.IGNORECASE,
)
# Trailing code fence that file-based templates append after {{data_csv}}.
_CSV_TRAILING_FENCE_RE = re.compile(r"\n```\s*$")


class _UnavailableProvider:
    """Fallback provider used when provider initialization fails."""

    def __init__(self, error_message: str) -> None:
        self._error_message = error_message or "AI provider is unavailable."

    def analyze(self, system_prompt: str, user_prompt: str, max_tokens: int = AI_MAX_TOKENS) -> str:
        raise AIProviderError(self._error_message)

    def get_model_info(self) -> dict[str, str]:
        return {"provider": "unavailable", "model": "unavailable"}


class ForensicAnalyzer:
    """Prepare artifact CSV data into bounded prompts for AI analysis."""

    def __init__(
        self,
        case_dir: str | Path | Mapping[str, str | Path] | None = None,
        config: Mapping[str, Any] | None = None,
        audit_logger: Any | None = None,
        artifact_csv_paths: Mapping[str, str | Path] | None = None,
        prompts_dir: str | Path = "prompts",
        random_seed: int | None = None,
    ) -> None:
        if (
            isinstance(case_dir, Mapping)
            and config is None
            and audit_logger is None
            and artifact_csv_paths is None
        ):
            artifact_csv_paths = case_dir
            case_dir = None

        self.case_dir = Path(case_dir) if case_dir is not None and not isinstance(case_dir, Mapping) else None
        self.logger = LOGGER
        self.config = dict(config) if isinstance(config, Mapping) else {}
        self.audit_logger = audit_logger
        self.artifact_csv_paths = {
            str(artifact_key): Path(csv_path)
            for artifact_key, csv_path in (artifact_csv_paths or {}).items()
        }
        self._analysis_input_csv_paths: dict[str, Path] = {}
        self.prompts_dir = Path(prompts_dir)
        self._random = random.Random(random_seed)
        self._load_analysis_settings()
        self.artifact_ai_column_projections = self._load_artifact_ai_column_projections()
        self.system_prompt = self._load_prompt_template(
            "system_prompt.md",
            default=_DEFAULT_SYSTEM_PROMPT,
        )
        self.artifact_prompt_template = self._load_prompt_template(
            "artifact_analysis.md",
            default=_DEFAULT_ARTIFACT_PROMPT_TEMPLATE,
        )
        self.artifact_prompt_template_small_context = self._load_prompt_template(
            "artifact_analysis_small_context.md",
            default=_DEFAULT_ARTIFACT_PROMPT_TEMPLATE_SMALL_CONTEXT,
        )
        self.artifact_instruction_prompts = self._load_artifact_instruction_prompts()
        self.summary_prompt_template = self._load_prompt_template(
            "summary_prompt.md",
            default=_DEFAULT_SUMMARY_PROMPT_TEMPLATE,
        )
        self.chunk_merge_prompt_template = self._load_prompt_template(
            "chunk_merge.md",
            default=_DEFAULT_CHUNK_MERGE_PROMPT_TEMPLATE,
        )
        self.ai_provider = self._create_ai_provider()
        self.model_info = self._read_model_info()
        self._explicit_analysis_date_range: tuple[datetime, datetime] | None = None
        self._explicit_analysis_date_range_label: tuple[str, str] | None = None

    def _load_analysis_settings(self) -> None:
        analysis_config = self.config.get("analysis")
        if not isinstance(analysis_config, Mapping):
            analysis_config = {}

        self.ai_max_tokens = self._read_int_setting(
            analysis_config=analysis_config,
            key="ai_max_tokens",
            default=AI_MAX_TOKENS,
            minimum=1,
        )
        # ai_max_tokens = context window (input + output).
        # Reserve 80% for prompt, 20% for the AI response.
        self.ai_response_max_tokens = max(1, int(self.ai_max_tokens * 0.2))
        legacy_shortened_prompt_cutoff = self._read_int_setting(
            analysis_config=analysis_config,
            key="statistics_section_cutoff_tokens",
            default=DEFAULT_SHORTENED_PROMPT_CUTOFF_TOKENS,
            minimum=1,
        )
        self.shortened_prompt_cutoff_tokens = self._read_int_setting(
            analysis_config=analysis_config,
            key="shortened_prompt_cutoff_tokens",
            default=legacy_shortened_prompt_cutoff,
            minimum=1,
        )
        # Budget for CSV data per chunk when using chunked analysis.
        # Reserves ~40% of the context window for instructions + response.
        self.chunk_csv_budget = int(self.ai_max_tokens * TOKEN_CHAR_RATIO * 0.6)
        self.date_buffer_days = self._read_int_setting(
            analysis_config=analysis_config,
            key="date_buffer_days",
            default=DATE_BUFFER_DAYS,
            minimum=0,
        )
        self.citation_spot_check_limit = self._read_int_setting(
            analysis_config=analysis_config,
            key="citation_spot_check_limit",
            default=CITATION_SPOT_CHECK_LIMIT,
            minimum=1,
        )
        self.max_merge_rounds = self._read_int_setting(
            analysis_config=analysis_config,
            key="max_merge_rounds",
            default=MAX_MERGE_ROUNDS,
            minimum=1,
        )
        self.artifact_deduplication_enabled = self._read_bool_setting(
            analysis_config=analysis_config,
            key="artifact_deduplication_enabled",
            default=ARTIFACT_DEDUPLICATION_ENABLED,
        )
        self.artifact_ai_columns_config_path = self._read_path_setting(
            analysis_config=analysis_config,
            key="artifact_ai_columns_config_path",
            default=str(DEFAULT_ARTIFACT_AI_COLUMNS_CONFIG_PATH),
        )

    @staticmethod
    def _read_int_setting(
        analysis_config: Mapping[str, Any],
        key: str,
        default: int,
        minimum: int = 1,
        maximum: int | None = None,
    ) -> int:
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

    @staticmethod
    def _read_bool_setting(
        analysis_config: Mapping[str, Any],
        key: str,
        default: bool,
    ) -> bool:
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

    @staticmethod
    def _read_path_setting(
        analysis_config: Mapping[str, Any],
        key: str,
        default: str,
    ) -> str:
        raw_value = analysis_config.get(key, default)
        if isinstance(raw_value, (str, Path)):
            cleaned = str(raw_value).strip()
            if cleaned:
                return cleaned
        return default

    def _resolve_artifact_ai_columns_config_path(self) -> Path:
        configured = Path(self.artifact_ai_columns_config_path).expanduser()
        if configured.is_absolute():
            return configured

        candidates: list[Path] = []
        if self.case_dir is not None:
            candidates.append(self.case_dir / configured)
        candidates.append(Path.cwd() / configured)
        candidates.append(PROJECT_ROOT / configured)

        for candidate in candidates:
            if candidate.exists():
                return candidate
        return candidates[-1]

    def _load_artifact_ai_column_projections(self) -> dict[str, tuple[str, ...]]:
        config_path = self._resolve_artifact_ai_columns_config_path()
        try:
            with config_path.open("r", encoding="utf-8") as handle:
                parsed = yaml.safe_load(handle) or {}
        except (OSError, yaml.YAMLError) as error:
            self.logger.warning(
                "Failed to load AI column projection config from %s: %s. "
                "AI column projection is disabled.",
                config_path,
                error,
            )
            return {}

        if not isinstance(parsed, Mapping):
            self.logger.warning(
                "Invalid AI column projection config in %s: expected a mapping at the document root, "
                "got %s. AI column projection is disabled.",
                config_path,
                type(parsed).__name__,
            )
            return {}

        source: Any = parsed.get("artifact_ai_columns", parsed)
        if not isinstance(source, Mapping):
            self.logger.warning(
                "Invalid AI column projection config in %s: 'artifact_ai_columns' must be a mapping, "
                "got %s. AI column projection is disabled.",
                config_path,
                type(source).__name__,
            )
            return {}

        projections: dict[str, tuple[str, ...]] = {}
        for artifact_key, raw_columns in source.items():
            if artifact_key is None:
                continue
            normalized_key = self._normalize_artifact_key(str(artifact_key))
            columns = self._coerce_projection_columns(raw_columns)
            if columns:
                projections[normalized_key] = tuple(columns)
        return projections

    @staticmethod
    def _coerce_projection_columns(value: Any) -> list[str]:
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

    def _load_prompt_template(self, filename: str, default: str) -> str:
        """Read a prompt template file from the prompts directory, falling back to default."""
        try:
            prompt_path = self.prompts_dir / filename
            return prompt_path.read_text(encoding="utf-8")
        except OSError:
            return default

    def _load_artifact_instruction_prompts(self) -> dict[str, str]:
        """Load per-artifact analysis instruction prompts from prompts/artifact_instructions."""
        instructions_dir = self.prompts_dir / "artifact_instructions"
        if not instructions_dir.exists() or not instructions_dir.is_dir():
            return {}

        prompts: dict[str, str] = {}
        for prompt_path in sorted(instructions_dir.glob("*.md")):
            try:
                prompt_text = prompt_path.read_text(encoding="utf-8").strip()
            except OSError:
                continue
            if not prompt_text:
                continue
            prompts[prompt_path.stem.strip().lower()] = prompt_text
        return prompts

    def _create_ai_provider(self) -> Any:
        provider_config: Mapping[str, Any]
        if self.config:
            provider_config = self.config
        else:
            provider_config = {
                "ai": {
                    "provider": "local",
                    "local": {
                        "base_url": "http://localhost:11434/v1",
                        "model": "llama3.1:70b",
                        "api_key": "not-needed",
                    },
                }
            }

        try:
            return create_provider(dict(provider_config))
        except Exception as error:
            return _UnavailableProvider(str(error))

    def _read_model_info(self) -> dict[str, str]:
        try:
            model_info = self.ai_provider.get_model_info()
        except Exception:
            return {"provider": "unknown", "model": "unknown"}

        if not isinstance(model_info, Mapping):
            return {"provider": "unknown", "model": "unknown"}

        return {
            str(key): str(value)
            for key, value in model_info.items()
        }

    def _call_ai_with_retry(self, call: Callable[[], str]) -> str:
        """Call the AI provider with retry on transient failures.

        Retries up to AI_RETRY_ATTEMPTS times with exponential backoff.
        """
        last_error: Exception | None = None
        for attempt in range(AI_RETRY_ATTEMPTS):
            try:
                return call()
            except AIProviderError:
                raise
            except Exception as error:
                last_error = error
                if attempt < AI_RETRY_ATTEMPTS - 1:
                    delay = AI_RETRY_BASE_DELAY * (2 ** attempt)
                    self.logger.warning(
                        "AI provider call failed (attempt %d/%d), retrying in %.1fs: %s",
                        attempt + 1,
                        AI_RETRY_ATTEMPTS,
                        delay,
                        error,
                    )
                    sleep(delay)
        raise last_error  # type: ignore[misc]

    def _audit_log(self, action: str, details: dict[str, Any]) -> None:
        if self.audit_logger is None:
            return

        logger = getattr(self.audit_logger, "log", None)
        if not callable(logger):
            return

        try:
            logger(action, details)
        except Exception:
            return

    def _save_case_prompt(
        self,
        filename: str,
        system_prompt: str,
        user_prompt: str,
    ) -> None:
        """Save a prompt to the case prompts directory for audit purposes."""
        if self.case_dir is None:
            return

        prompts_dir = self.case_dir / "prompts"
        try:
            prompts_dir.mkdir(parents=True, exist_ok=True)
            prompt_path = prompts_dir / filename
            prompt_path.write_text(
                f"# System Prompt\n\n{system_prompt}\n\n---\n\n# User Prompt\n\n{user_prompt}\n",
                encoding="utf-8",
            )
        except OSError:
            self.logger.warning("Failed to save prompt to %s", prompts_dir / filename)

    @staticmethod
    def _split_csv_into_chunks(csv_text: str, max_chars: int) -> list[str]:
        """Split CSV text into chunks that each fit within *max_chars*.

        Every chunk retains the original header row so the AI can interpret
        the data without extra context.  Splits on row boundaries only.
        """
        if max_chars <= 0 or len(csv_text) <= max_chars:
            return [csv_text]

        lines = csv_text.split("\n")
        if not lines:
            return [csv_text]

        header = lines[0]
        data_lines = lines[1:]
        if not data_lines:
            return [csv_text]

        # Reserve space for the header in each chunk.
        header_overhead = len(header) + 1  # +1 for newline
        chunk_data_budget = max_chars - header_overhead
        if chunk_data_budget <= 0:
            # Header alone exceeds budget; return the whole thing as one chunk.
            return [csv_text]

        chunks: list[str] = []
        current_lines: list[str] = []
        current_size = 0

        for line in data_lines:
            line_size = len(line) + 1  # +1 for newline
            if current_lines and current_size + line_size > chunk_data_budget:
                chunks.append(header + "\n" + "\n".join(current_lines))
                current_lines = []
                current_size = 0
            current_lines.append(line)
            current_size += line_size

        if current_lines:
            chunks.append(header + "\n" + "\n".join(current_lines))

        return chunks if chunks else [csv_text]

    @staticmethod
    def _split_csv_and_suffix(raw_csv_tail: str) -> tuple[str, str]:
        """Separate CSV rows from trailing content (code fences, context reminders).

        Returns ``(csv_data, suffix)`` where *suffix* contains any trailing
        code fence and/or Final Context Reminder text that should be appended
        to every chunk prompt.
        """
        text = raw_csv_tail

        # 1. Extract the Final Context Reminder (appended after CSV + fence).
        reminder_marker = "## Final Context Reminder"
        reminder_pos = text.find(reminder_marker)
        context_suffix = ""
        if reminder_pos >= 0:
            context_suffix = "\n\n" + text[reminder_pos:].strip()
            text = text[:reminder_pos]

        # 2. Strip a trailing markdown code fence from file-based templates.
        #    Now that the reminder is removed, the fence (if any) is at the end.
        trailing_fence = ""
        fence_match = _CSV_TRAILING_FENCE_RE.search(text)
        if fence_match:
            trailing_fence = fence_match.group()
            text = text[: fence_match.start()]

        csv_data = text.strip()

        # Reassemble the suffix: fence first (closes the code block around
        # each chunk), then the context reminder.
        suffix = ""
        if trailing_fence:
            suffix += trailing_fence
        if context_suffix:
            suffix += context_suffix
        return csv_data, suffix

    def _analyze_artifact_chunked(
        self,
        artifact_prompt: str,
        artifact_key: str,
        artifact_name: str,
        investigation_context: str,
        model: str,
        progress_callback: Any | None = None,
    ) -> str:
        """Analyze an artifact in multiple chunks when data exceeds the context budget.

        Splits the CSV portion of the prompt into chunks, analyzes each
        independently, then merges the per-chunk findings with a final AI call.
        """
        # Split the prompt into the instruction portion and the CSV data.
        # Handles both hardcoded ("## Full Data (CSV)") and file-based
        # ("### Full Data (CSV)\n```") template styles.
        marker_match = _CSV_DATA_SECTION_RE.search(artifact_prompt)
        if marker_match is None:
            # No CSV section found — fall back to single call.
            return self._call_ai_with_retry(
                lambda: self.ai_provider.analyze(
                    system_prompt=self.system_prompt,
                    user_prompt=artifact_prompt,
                    max_tokens=self.ai_response_max_tokens,
                )
            )

        instructions_portion = artifact_prompt[: marker_match.end()]
        raw_csv_tail = artifact_prompt[marker_match.end():]

        # Separate the CSV data from any trailing content (code fences,
        # Final Context Reminder) so that only actual CSV rows are chunked
        # and the reminder is appended to every chunk.
        csv_data, context_suffix = self._split_csv_and_suffix(raw_csv_tail)

        # Determine how much space is left for CSV data in each chunk.
        suffix_chars = len(context_suffix)
        instructions_chars = len(instructions_portion) + len(self.system_prompt) + suffix_chars
        csv_budget = max(1000, self.chunk_csv_budget - instructions_chars)

        chunks = self._split_csv_into_chunks(csv_data, csv_budget)
        total_chunks = len(chunks)

        if total_chunks <= 1:
            return self._call_ai_with_retry(
                lambda: self.ai_provider.analyze(
                    system_prompt=self.system_prompt,
                    user_prompt=artifact_prompt,
                    max_tokens=self.ai_response_max_tokens,
                )
            )

        self.logger.info(
            "Chunked analysis for %s: splitting into %d chunks (budget %d chars/chunk).",
            artifact_key,
            total_chunks,
            csv_budget,
        )
        self._audit_log(
            "chunked_analysis_started",
            {
                "artifact_key": artifact_key,
                "total_chunks": total_chunks,
                "csv_budget_per_chunk": csv_budget,
            },
        )

        chunk_findings: list[str] = []
        for chunk_index, chunk_csv in enumerate(chunks, start=1):
            chunk_prompt = f"{instructions_portion}{chunk_csv}{context_suffix}"
            chunk_label = f"chunk {chunk_index}/{total_chunks}"

            if progress_callback is not None:
                self._emit_analysis_progress(
                    progress_callback,
                    artifact_key,
                    "thinking",
                    {
                        "artifact_key": artifact_key,
                        "artifact_name": artifact_name,
                        "thinking_text": f"Analyzing {chunk_label}...",
                        "partial_text": "",
                        "model": model,
                    },
                )

            safe_key = self._sanitize_filename(artifact_key)
            self._save_case_prompt(
                f"artifact_{safe_key}_chunk_{chunk_index}.md",
                self.system_prompt,
                chunk_prompt,
            )

            self.logger.info("Analyzing %s %s...", artifact_key, chunk_label)
            chunk_text = self._call_ai_with_retry(
                lambda prompt=chunk_prompt: self.ai_provider.analyze(
                    system_prompt=self.system_prompt,
                    user_prompt=prompt,
                    max_tokens=self.ai_response_max_tokens,
                )
            )
            chunk_findings.append(f"### Chunk {chunk_index} of {total_chunks}\n{chunk_text}")

        # Hierarchical merge: group findings into batches that fit the
        # context window, merge each batch via AI, then repeat until one
        # result remains.  This preserves all information instead of
        # truncating findings.
        merged_text = self._hierarchical_merge_findings(
            chunk_findings=chunk_findings,
            artifact_key=artifact_key,
            artifact_name=artifact_name,
            investigation_context=investigation_context,
            model=model,
            progress_callback=progress_callback,
        )
        self.logger.info(
            "Chunked analysis for %s complete: %d chunks merged.",
            artifact_key,
            total_chunks,
        )
        return merged_text

    def _merge_findings_budget(self) -> int:
        """Character budget available for per-chunk findings in a merge prompt."""
        overhead = len(self.chunk_merge_prompt_template) + len(self.system_prompt) + 500
        return max(2000, self.chunk_csv_budget - overhead)

    def _build_merge_prompt(
        self,
        findings_text: str,
        batch_count: int,
        artifact_key: str,
        artifact_name: str,
        investigation_context: str,
    ) -> str:
        """Fill the chunk-merge template with the given findings."""
        prompt = self.chunk_merge_prompt_template
        for placeholder, value in {
            "chunk_count": str(batch_count),
            "investigation_context": investigation_context.strip() or "No investigation context provided.",
            "artifact_name": artifact_name,
            "artifact_key": artifact_key,
            "per_chunk_findings": findings_text,
        }.items():
            prompt = prompt.replace(f"{{{{{placeholder}}}}}", value)
        return prompt

    def _hierarchical_merge_findings(
        self,
        chunk_findings: list[str],
        artifact_key: str,
        artifact_name: str,
        investigation_context: str,
        model: str,
        progress_callback: Any | None = None,
    ) -> str:
        """Merge chunk findings hierarchically until one result remains.

        Groups findings into batches that fit the context window, merges
        each batch via an AI call, then repeats on the merged results.
        This preserves all information — nothing is truncated.
        """
        findings_budget = self._merge_findings_budget()
        current_findings = list(chunk_findings)
        merge_round = 0

        while len(current_findings) > 1:
            merge_round += 1

            # Fallback: after max_merge_rounds, stop recursing and just
            # concatenate the remaining findings (capped proportionally
            # to fit the context window).
            if merge_round > self.max_merge_rounds:
                self.logger.warning(
                    "Hierarchical merge for %s hit %d-round limit with %d findings remaining. "
                    "Falling back to concatenation.",
                    artifact_key,
                    self.max_merge_rounds,
                    len(current_findings),
                )
                if progress_callback is not None:
                    self._emit_analysis_progress(
                        progress_callback,
                        artifact_key,
                        "thinking",
                        {
                            "artifact_key": artifact_key,
                            "artifact_name": artifact_name,
                            "thinking_text": (
                                f"Merge round limit reached ({self.max_merge_rounds}). "
                                f"Concatenating {len(current_findings)} remaining findings..."
                            ),
                            "partial_text": "",
                            "model": model,
                        },
                    )
                total_chars = sum(len(f) for f in current_findings)
                if total_chars > findings_budget:
                    # Cap each finding proportionally to fit the budget.
                    per_finding_budget = max(200, findings_budget // len(current_findings))
                    capped = []
                    for f in current_findings:
                        if len(f) > per_finding_budget:
                            capped.append(f[:per_finding_budget] + "\n[... truncated ...]")
                        else:
                            capped.append(f)
                    concatenated = "\n\n".join(capped)
                else:
                    concatenated = "\n\n".join(current_findings)

                # One final merge call on the concatenated findings.
                merge_prompt = self._build_merge_prompt(
                    findings_text=concatenated,
                    batch_count=len(current_findings),
                    artifact_key=artifact_key,
                    artifact_name=artifact_name,
                    investigation_context=investigation_context,
                )
                safe_key = self._sanitize_filename(artifact_key)
                self._save_case_prompt(
                    f"artifact_{safe_key}_merge_fallback.md",
                    self.system_prompt,
                    merge_prompt,
                )
                return self._call_ai_with_retry(
                    lambda prompt=merge_prompt: self.ai_provider.analyze(
                        system_prompt=self.system_prompt,
                        user_prompt=prompt,
                        max_tokens=self.ai_response_max_tokens,
                    )
                )

            # Group findings into batches that fit within the budget.
            batches: list[list[str]] = []
            current_batch: list[str] = []
            current_batch_size = 0

            for finding in current_findings:
                entry_size = len(finding) + 2  # +2 for "\n\n" separator
                if current_batch and current_batch_size + entry_size > findings_budget:
                    batches.append(current_batch)
                    current_batch = []
                    current_batch_size = 0
                current_batch.append(finding)
                current_batch_size += entry_size

            if current_batch:
                batches.append(current_batch)

            # If everything fits in one batch, do the final merge.
            if len(batches) == 1 and merge_round == 1:
                # All findings fit — single merge call.
                pass

            # Safety: if batching didn't reduce the count (single finding
            # too large), force it into one batch to avoid infinite loop.
            if len(batches) >= len(current_findings):
                batches = [current_findings]

            total_batches = len(batches)
            label_prefix = f"merge round {merge_round}" if merge_round > 1 else "merge"

            self.logger.info(
                "Hierarchical %s for %s: %d batches from %d findings (budget %d chars).",
                label_prefix,
                artifact_key,
                total_batches,
                len(current_findings),
                findings_budget,
            )

            if progress_callback is not None:
                self._emit_analysis_progress(
                    progress_callback,
                    artifact_key,
                    "thinking",
                    {
                        "artifact_key": artifact_key,
                        "artifact_name": artifact_name,
                        "thinking_text": (
                            f"Merging findings ({label_prefix}: "
                            f"{len(current_findings)} findings into {total_batches} groups)..."
                        ),
                        "partial_text": "",
                        "model": model,
                    },
                )

            next_findings: list[str] = []
            for batch_index, batch in enumerate(batches, start=1):
                batch_text = "\n\n".join(batch)
                merge_prompt = self._build_merge_prompt(
                    findings_text=batch_text,
                    batch_count=len(batch),
                    artifact_key=artifact_key,
                    artifact_name=artifact_name,
                    investigation_context=investigation_context,
                )

                safe_key = self._sanitize_filename(artifact_key)
                self._save_case_prompt(
                    f"artifact_{safe_key}_merge_r{merge_round}_b{batch_index}.md",
                    self.system_prompt,
                    merge_prompt,
                )

                merged = self._call_ai_with_retry(
                    lambda prompt=merge_prompt: self.ai_provider.analyze(
                        system_prompt=self.system_prompt,
                        user_prompt=prompt,
                        max_tokens=self.ai_response_max_tokens,
                    )
                )
                next_findings.append(f"### Merged batch {batch_index}\n{merged}")

            current_findings = next_findings

        return current_findings[0] if current_findings else ""

    def analyze_artifact(
        self,
        artifact_key: str,
        investigation_context: str,
        progress_callback: Any | None = None,
    ) -> dict[str, Any]:
        """Analyze one artifact and return AI findings."""
        artifact_metadata = self._resolve_artifact_metadata(artifact_key)
        artifact_name = artifact_metadata.get("name", artifact_key)
        model = self.model_info.get("model", "unknown")
        provider = self.model_info.get("provider", "unknown")

        self._audit_log(
            "analysis_started",
            {
                "artifact_key": artifact_key,
                "artifact_name": artifact_name,
                "provider": provider,
                "model": model,
            },
        )

        start_time = perf_counter()
        try:
            csv_path = self._resolve_artifact_csv_path(artifact_key)
            artifact_prompt = self._prepare_artifact_data(
                artifact_key=artifact_key,
                investigation_context=investigation_context,
                csv_path=csv_path,
            )
            analysis_csv_path = self._resolve_analysis_input_csv_path(artifact_key=artifact_key, fallback=csv_path)
            attachments = [
                self._build_artifact_csv_attachment(
                    artifact_key=artifact_key,
                    csv_path=analysis_csv_path,
                )
            ]

            safe_key = self._sanitize_filename(artifact_key)
            self._save_case_prompt(
                f"artifact_{safe_key}.md",
                self.system_prompt,
                artifact_prompt,
            )

            # When the prompt exceeds the context budget, use chunked analysis
            # to ensure every row of data is seen by the model.
            prompt_tokens_estimate = self._estimate_tokens(artifact_prompt) + self._estimate_tokens(self.system_prompt)
            if prompt_tokens_estimate > self.ai_max_tokens:
                self.logger.info(
                    "Prompt for %s (~%d tokens) exceeds ai_max_tokens (%d); using chunked analysis.",
                    artifact_key,
                    prompt_tokens_estimate,
                    self.ai_max_tokens,
                )
                if progress_callback is not None:
                    self._emit_analysis_progress(
                        progress_callback,
                        artifact_key,
                        "started",
                        {
                            "artifact_key": artifact_key,
                            "artifact_name": artifact_name,
                            "model": model,
                        },
                    )
                analysis_text = self._analyze_artifact_chunked(
                    artifact_prompt=artifact_prompt,
                    artifact_key=artifact_key,
                    artifact_name=artifact_name,
                    investigation_context=investigation_context,
                    model=model,
                    progress_callback=progress_callback,
                )
                duration_seconds = perf_counter() - start_time
                self._audit_log(
                    "analysis_completed",
                    {
                        "artifact_key": artifact_key,
                        "artifact_name": artifact_name,
                        "token_count": self._estimate_tokens(analysis_text),
                        "duration_seconds": round(duration_seconds, 6),
                        "status": "success",
                        "chunked": True,
                    },
                )
                citation_warnings = self._validate_citations(artifact_key, analysis_text)
                result: dict[str, Any] = {
                    "artifact_key": artifact_key,
                    "artifact_name": artifact_name,
                    "analysis": analysis_text,
                    "model": model,
                }
                if citation_warnings:
                    result["citation_warnings"] = citation_warnings
                return result

            analyze_with_progress = getattr(self.ai_provider, "analyze_with_progress", None)
            if callable(analyze_with_progress) and progress_callback is not None:
                self._emit_analysis_progress(
                    progress_callback,
                    artifact_key,
                    "started",
                    {
                        "artifact_key": artifact_key,
                        "artifact_name": artifact_name,
                        "model": model,
                    },
                )

                def _provider_progress(payload: Mapping[str, Any]) -> None:
                    if not isinstance(payload, Mapping):
                        return
                    thinking_payload = {
                        "artifact_key": artifact_key,
                        "artifact_name": artifact_name,
                        "thinking_text": str(payload.get("thinking_text", "")),
                        "partial_text": str(payload.get("partial_text", "")),
                        "model": model,
                    }
                    self._emit_analysis_progress(
                        progress_callback,
                        artifact_key,
                        "thinking",
                        thinking_payload,
                    )

                try:
                    analysis_text = analyze_with_progress(
                        system_prompt=self.system_prompt,
                        user_prompt=artifact_prompt,
                        progress_callback=_provider_progress,
                        attachments=attachments,
                        max_tokens=self.ai_response_max_tokens,
                    )
                except TypeError:
                    analysis_text = analyze_with_progress(
                        system_prompt=self.system_prompt,
                        user_prompt=artifact_prompt,
                        progress_callback=_provider_progress,
                        max_tokens=self.ai_response_max_tokens,
                    )
            else:
                analyze_with_attachments = getattr(self.ai_provider, "analyze_with_attachments", None)
                if callable(analyze_with_attachments):
                    analysis_text = self._call_ai_with_retry(
                        lambda: analyze_with_attachments(
                            system_prompt=self.system_prompt,
                            user_prompt=artifact_prompt,
                            attachments=attachments,
                            max_tokens=self.ai_response_max_tokens,
                        )
                    )
                else:
                    analysis_text = self._call_ai_with_retry(
                        lambda: self.ai_provider.analyze(
                            system_prompt=self.system_prompt,
                            user_prompt=artifact_prompt,
                            max_tokens=self.ai_response_max_tokens,
                        )
                    )
            duration_seconds = perf_counter() - start_time
            self._audit_log(
                "analysis_completed",
                {
                    "artifact_key": artifact_key,
                    "artifact_name": artifact_name,
                    "token_count": self._estimate_tokens(analysis_text),
                    "duration_seconds": round(duration_seconds, 6),
                    "status": "success",
                },
            )
        except Exception as error:
            duration_seconds = perf_counter() - start_time
            analysis_text = f"Analysis failed: {error}"
            self._audit_log(
                "analysis_completed",
                {
                    "artifact_key": artifact_key,
                    "artifact_name": artifact_name,
                    "token_count": 0,
                    "duration_seconds": round(duration_seconds, 6),
                    "status": "failed",
                    "error": str(error),
                },
            )

        citation_warnings = self._validate_citations(artifact_key, analysis_text)

        result: dict[str, Any] = {
            "artifact_key": artifact_key,
            "artifact_name": artifact_name,
            "analysis": analysis_text,
            "model": model,
        }
        if citation_warnings:
            result["citation_warnings"] = citation_warnings
        return result

    def generate_summary(
        self,
        per_artifact_results: list[Mapping[str, Any]],
        investigation_context: str,
        metadata: Mapping[str, Any] | None,
    ) -> str:
        """Generate the cross-artifact summary."""
        metadata_map = metadata if isinstance(metadata, Mapping) else {}
        findings_blocks: list[str] = []
        for result in per_artifact_results:
            artifact_key = str(result.get("artifact_key", "unknown"))
            artifact_name = str(result.get("artifact_name", artifact_key))
            analysis = str(result.get("analysis", "")).strip()
            findings_blocks.append(f"### {artifact_name} ({artifact_key})\n{analysis}")

        findings_text = "\n\n".join(findings_blocks) if findings_blocks else "No per-artifact findings available."
        summary_prompt = self.summary_prompt_template
        priority_directives = self._build_priority_directives(investigation_context)
        ioc_targets = self._format_ioc_targets(investigation_context)
        replacements = {
            "priority_directives": priority_directives,
            "investigation_context": investigation_context.strip() or "No investigation context provided.",
            "ioc_targets": ioc_targets,
            "hostname": str(metadata_map.get("hostname", "Unknown")),
            "os_version": str(metadata_map.get("os_version", "Unknown")),
            "domain": str(metadata_map.get("domain", "Unknown")),
            "per_artifact_findings": findings_text,
        }
        for placeholder, value in replacements.items():
            summary_prompt = summary_prompt.replace(f"{{{{{placeholder}}}}}", value)

        model = self.model_info.get("model", "unknown")
        provider = self.model_info.get("provider", "unknown")
        summary_artifact_key = "cross_artifact_summary"
        summary_artifact_name = "Cross-Artifact Summary"
        summary_prompt_filename = f"{self._sanitize_filename(summary_artifact_key)}.md"

        self._audit_log(
            "analysis_started",
            {
                "artifact_key": summary_artifact_key,
                "artifact_name": summary_artifact_name,
                "provider": provider,
                "model": model,
            },
        )

        self._save_case_prompt(
            summary_prompt_filename,
            self.system_prompt,
            summary_prompt,
        )

        start_time = perf_counter()
        try:
            summary = self._call_ai_with_retry(
                lambda: self.ai_provider.analyze(
                    system_prompt=self.system_prompt,
                    user_prompt=summary_prompt,
                    max_tokens=self.ai_response_max_tokens,
                )
            )
            duration_seconds = perf_counter() - start_time
            self._audit_log(
                "analysis_completed",
                {
                    "artifact_key": summary_artifact_key,
                    "artifact_name": summary_artifact_name,
                    "token_count": self._estimate_tokens(summary),
                    "duration_seconds": round(duration_seconds, 6),
                    "status": "success",
                },
            )
            return summary
        except Exception as error:
            duration_seconds = perf_counter() - start_time
            summary = f"Analysis failed: {error}"
            self._audit_log(
                "analysis_completed",
                {
                    "artifact_key": summary_artifact_key,
                    "artifact_name": summary_artifact_name,
                    "token_count": 0,
                    "duration_seconds": round(duration_seconds, 6),
                    "status": "failed",
                    "error": str(error),
                },
            )
            return summary

    def run_full_analysis(
        self,
        artifact_keys: Iterable[str],
        investigation_context: str,
        metadata: Mapping[str, Any] | None,
        progress_callback: Any | None = None,
    ) -> dict[str, Any]:
        """Run per-artifact analysis sequentially and then generate summary."""
        self._register_artifact_paths_from_metadata(metadata)
        self._configure_explicit_analysis_date_range(metadata)
        per_artifact_results: list[dict[str, Any]] = []
        for artifact_key in artifact_keys:
            result = self.analyze_artifact(
                artifact_key=str(artifact_key),
                investigation_context=investigation_context,
                progress_callback=progress_callback,
            )
            per_artifact_results.append(result)
            if progress_callback is not None:
                self._emit_analysis_progress(
                    progress_callback,
                    str(artifact_key),
                    "complete",
                    result,
                )

        summary = self.generate_summary(
            per_artifact_results=per_artifact_results,
            investigation_context=investigation_context,
            metadata=metadata,
        )
        return {
            "per_artifact": per_artifact_results,
            "summary": summary,
            "model_info": dict(self.model_info),
        }

    @staticmethod
    def _emit_analysis_progress(
        progress_callback: Any,
        artifact_key: str,
        status: str,
        payload: dict[str, Any],
    ) -> None:
        try:
            progress_callback(artifact_key, status, payload)
            return
        except TypeError:
            pass
        except Exception:
            return

        try:
            progress_callback(
                {
                    "artifact_key": artifact_key,
                    "status": status,
                    "result": payload,
                }
            )
        except Exception:
            return

    def _validate_citations(self, artifact_key: str, analysis_text: str) -> list[str]:
        """Spot-check timestamps and row references cited by the AI against source CSV.

        Returns a list of human-readable warning strings for values that could
        not be verified.  An empty list means all checked citations were found.
        """
        if analysis_text.startswith("Analysis failed:"):
            return []

        try:
            csv_path = self._resolve_artifact_csv_path(artifact_key)
        except FileNotFoundError:
            return []

        # --- Extract cited timestamps ---
        cited_timestamps: list[str] = _CITED_ISO_TIMESTAMP_RE.findall(analysis_text)

        # --- Extract cited row references ---
        cited_row_refs: list[str] = _CITED_ROW_REF_RE.findall(analysis_text)

        if not cited_timestamps and not cited_row_refs:
            return []

        # Build lookup sets from the source CSV (only the columns/rows we need).
        csv_timestamp_lookup: set[str] = set()
        csv_row_refs: set[str] = set()
        try:
            with csv_path.open("r", newline="", encoding="utf-8-sig", errors="replace") as fh:
                reader = csv.DictReader(fh)
                columns = [str(c) for c in (reader.fieldnames or []) if c not in (None, "")]
                ts_columns = [c for c in columns if self._looks_like_timestamp_column(c)]
                for row_number, raw_row in enumerate(reader, start=1):
                    csv_row_refs.add(str(row_number))
                    for col in ts_columns:
                        val = self._stringify_value(raw_row.get(col))
                        if val:
                            csv_timestamp_lookup.update(self._timestamp_lookup_keys(val))
        except OSError:
            return []

        warnings: list[str] = []

        # Spot-check timestamps (up to limit).
        for ts in cited_timestamps[: self.citation_spot_check_limit]:
            if not self._timestamp_found_in_csv(ts, csv_timestamp_lookup):
                warnings.append(
                    f"Note: AI cited timestamp {ts} which could not be verified in the source data."
                )

        # Spot-check row references (up to limit).
        for ref in cited_row_refs[: self.citation_spot_check_limit]:
            if ref not in csv_row_refs:
                warnings.append(
                    f"Note: AI cited row {ref} which could not be verified in the source data."
                )

        if warnings:
            self._audit_log(
                "citation_validation",
                {
                    "artifact_key": artifact_key,
                    "citation_validation": "warnings_found",
                    "warning_count": len(warnings),
                    "warnings": warnings[:10],
                },
            )

        return warnings

    @staticmethod
    def _timestamp_lookup_keys(value: str) -> set[str]:
        """Build comparable lookup keys for a timestamp string."""
        text = value.strip()
        if not text:
            return set()

        normalized = text.replace(" ", "T")
        keys: set[str] = {text, normalized}

        match = _CITED_ISO_TIMESTAMP_RE.search(normalized)
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

    @staticmethod
    def _timestamp_found_in_csv(cited: str, csv_timestamp_lookup: set[str]) -> bool:
        """Check whether a cited timestamp matches preloaded CSV timestamp lookup keys.

        Lookup keys are generated once from CSV data, so each citation check is
        a small constant-time membership test.
        """
        if not csv_timestamp_lookup:
            return False
        return any(
            key in csv_timestamp_lookup
            for key in ForensicAnalyzer._timestamp_lookup_keys(cited)
        )

    def _register_artifact_paths_from_metadata(self, metadata: Mapping[str, Any] | None) -> None:
        if not isinstance(metadata, Mapping):
            return

        artifact_csv_paths = metadata.get("artifact_csv_paths")
        if isinstance(artifact_csv_paths, Mapping):
            for artifact_key, csv_path in artifact_csv_paths.items():
                self.artifact_csv_paths[str(artifact_key)] = Path(str(csv_path))

        for container_key in ("artifacts", "artifact_results", "parse_results", "parsed_artifacts"):
            container = metadata.get(container_key)
            if isinstance(container, Mapping):
                for artifact_key, value in container.items():
                    self._register_artifact_path_entry(artifact_key=artifact_key, value=value)
            elif isinstance(container, list):
                for item in container:
                    if isinstance(item, Mapping):
                        artifact_key = item.get("artifact_key") or item.get("key")
                        if artifact_key:
                            self._register_artifact_path_entry(artifact_key=str(artifact_key), value=item)

    def _register_artifact_path_entry(self, artifact_key: Any, value: Any) -> None:
        if artifact_key in (None, ""):
            return

        if isinstance(value, Mapping):
            csv_path = value.get("csv_path")
            if csv_path:
                self.artifact_csv_paths[str(artifact_key)] = Path(str(csv_path))
                return
            csv_paths = value.get("csv_paths")
            if isinstance(csv_paths, list) and csv_paths:
                self.artifact_csv_paths[str(artifact_key)] = Path(str(csv_paths[0]))
                return

        if isinstance(value, (str, Path)):
            self.artifact_csv_paths[str(artifact_key)] = Path(str(value))

    def _configure_explicit_analysis_date_range(self, metadata: Mapping[str, Any] | None) -> None:
        self._explicit_analysis_date_range = None
        self._explicit_analysis_date_range_label = None
        if not isinstance(metadata, Mapping):
            return

        raw_range = metadata.get("analysis_date_range")
        if not isinstance(raw_range, Mapping):
            return

        start_text = self._stringify_value(raw_range.get("start_date"))
        end_text = self._stringify_value(raw_range.get("end_date"))
        if not start_text or not end_text:
            return

        try:
            start_date = datetime.strptime(start_text, "%Y-%m-%d")
            end_date = datetime.strptime(end_text, "%Y-%m-%d")
        except ValueError:
            return

        if start_date > end_date:
            return

        self._explicit_analysis_date_range = (
            start_date,
            end_date + timedelta(days=1) - timedelta(microseconds=1),
        )
        self._explicit_analysis_date_range_label = (
            start_date.date().isoformat(),
            end_date.date().isoformat(),
        )

    def _artifact_uses_explicit_date_range(self, artifact_key: str) -> bool:
        normalized_key = self._normalize_artifact_key(artifact_key)
        return normalized_key in {"mft", "evtx"}

    def _extract_dates_from_context(self, text: str) -> list[datetime]:
        """Extract date references from free-text context."""
        if not text:
            return []

        dates: list[datetime] = []
        seen_keys: set[tuple[int, int, int]] = set()

        def _append_unique(parsed: datetime | None) -> None:
            if parsed is None:
                return
            key = (parsed.year, parsed.month, parsed.day)
            if key in seen_keys:
                return
            seen_keys.add(key)
            dates.append(parsed)

        for match in _CONTEXT_TEXTUAL_RANGE_RE.finditer(text):
            month_name = match.group("month_name").lower()
            month = _MONTH_LOOKUP.get(month_name)
            if month is None:
                continue
            year = match.group("year")
            _append_unique(
                self._build_datetime(
                    year=year,
                    month=str(month),
                    day=match.group("day_start"),
                )
            )
            _append_unique(
                self._build_datetime(
                    year=year,
                    month=str(month),
                    day=match.group("day_end"),
                )
            )

        for match in _CONTEXT_ISO_DATE_RE.finditer(text):
            _append_unique(
                self._build_datetime(
                    year=match.group("year"),
                    month=match.group("month"),
                    day=match.group("day"),
                )
            )

        for match in _CONTEXT_DMY_DASH_RE.finditer(text):
            _append_unique(
                self._build_datetime(
                    year=match.group("year"),
                    month=match.group("month"),
                    day=match.group("day"),
                )
            )

        for match in _CONTEXT_DMY_SLASH_RE.finditer(text):
            _append_unique(
                self._build_datetime(
                    year=match.group("year"),
                    month=match.group("month"),
                    day=match.group("day"),
                )
            )

        for match in _CONTEXT_TEXTUAL_DATE_RE.finditer(text):
            month_name = match.group("month_name").lower()
            month = _MONTH_LOOKUP.get(month_name)
            if month is None:
                continue
            _append_unique(
                self._build_datetime(
                    year=match.group("year"),
                    month=str(month),
                    day=match.group("day"),
                )
            )

        dates.sort()
        return dates

    def _compute_statistics(
        self,
        rows: list[dict[str, str]],
        columns: list[str],
    ) -> tuple[str, datetime | None, datetime | None]:
        """Compute record count, time range, and top-20 frequent values per key column.

        Returns a tuple of (statistics_text, min_time, max_time).
        """
        total_records = len(rows)
        min_time, max_time = self._time_range_for_rows(rows)
        counters: dict[str, Counter[str]] = {column: Counter() for column in columns}

        for row in rows:
            for column in columns:
                value = self._counter_normalize(row.get(column, ""))
                if value:
                    counters[column][value] += 1

        lines = [
            f"Record count: {total_records}",
            f"Time range start: {self._format_datetime(min_time)}",
            f"Time range end: {self._format_datetime(max_time)}",
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

    def _should_use_shortened_prompt(self) -> bool:
        return self.ai_max_tokens < self.shortened_prompt_cutoff_tokens

    def _extract_ioc_targets(self, investigation_context: str) -> dict[str, list[str]]:
        text = self._stringify_value(investigation_context)
        if not text:
            return {}

        urls = self._unique_preserve_order(_IOC_URL_RE.findall(text))
        ips = self._unique_preserve_order(_IOC_IPV4_RE.findall(text))
        hashes = self._unique_preserve_order(_IOC_HASH_RE.findall(text))
        emails = self._unique_preserve_order(_IOC_EMAIL_RE.findall(text))
        windows_paths = self._unique_preserve_order(_WINDOWS_PATH_RE.findall(text))
        file_names = self._unique_preserve_order(_IOC_FILENAME_RE.findall(text))
        file_names_lower = {value.lower() for value in file_names}
        tools = self._extract_tool_keywords(text)

        domain_candidates = self._unique_preserve_order(_IOC_DOMAIN_RE.findall(text))
        domains: list[str] = []
        url_hosts = {
            self._extract_url_host(url)
            for url in urls
        }
        for domain in domain_candidates:
            lowered = domain.lower()
            if lowered in url_hosts:
                continue
            if lowered in file_names_lower:
                # Prevent executable-like IOC tokens (e.g., abc.exe) from
                # being incorrectly classified as domains.
                continue
            if any(lowered.endswith(suffix) for suffix in _DOMAIN_EXCLUDED_SUFFIXES):
                continue
            domains.append(domain)
        domains = self._unique_preserve_order(domains)

        iocs: dict[str, list[str]] = {}
        if urls:
            iocs["URLs"] = urls
        if ips:
            iocs["IPv4"] = ips
        if domains:
            iocs["Domains"] = domains
        if hashes:
            iocs["Hashes"] = hashes
        if emails:
            iocs["Emails"] = emails
        if windows_paths:
            iocs["FilePaths"] = windows_paths
        if file_names:
            iocs["FileNames"] = file_names
        if tools:
            iocs["SuspiciousTools"] = tools
        return iocs

    def _format_ioc_targets(self, investigation_context: str) -> str:
        ioc_map = self._extract_ioc_targets(investigation_context)
        if not ioc_map:
            return "No explicit IOC patterns were extracted from the investigation context."

        lines = []
        for category, values in ioc_map.items():
            limited = values[:20]
            suffix = "" if len(values) <= 20 else " ... [truncated]"
            lines.append(f"- {category}: {', '.join(limited)}{suffix}")
        return "\n".join(lines)

    def _build_priority_directives(self, investigation_context: str) -> str:
        ioc_map = self._extract_ioc_targets(investigation_context)
        has_iocs = bool(ioc_map)
        lines = [
            "1. Treat the user investigation context as highest priority and address it before generic hunting.",
            (
                "2. For each IOC listed below, explicitly classify it as Observed, Not Observed, or Not Assessable "
                "in this artifact."
                if has_iocs
                else "2. No explicit IOC was extracted; still prioritize user-stated hypotheses and suspicious themes."
            ),
            "3. Always run default DFIR checks: privilege escalation, credential access tooling (including Mimikatz-like activity), persistence, defense evasion, lateral movement, and potential exfiltration.",
            "4. Focus on evidence that improves triage or containment decisions; keep baseline/statistical context secondary.",
        ]
        return "\n".join(lines)

    def _build_artifact_final_context_reminder(
        self,
        artifact_key: str,
        artifact_name: str,
        investigation_context: str,
    ) -> str:
        """Append a short end-of-prompt reminder that survives left-side truncation."""
        context_text = self._stringify_value(investigation_context)
        if context_text:
            context_text = self._truncate_for_prompt(context_text, limit=1200)
        else:
            context_text = "No investigation context provided."

        ioc_targets = self._format_ioc_targets(investigation_context)
        ioc_targets = self._truncate_for_prompt(ioc_targets, limit=1200)

        lines = [
            "## Final Context Reminder (Do Not Ignore)",
            f"- Artifact key: {artifact_key}",
            f"- Artifact name: {artifact_name}",
            f"- Investigation context (mandatory): {context_text}",
            f"- IOC targets (mandatory follow-through): {ioc_targets}",
            "- Always run default DFIR checks: privilege escalation, credential-access/Mimikatz-like behavior, malicious program execution, persistence/evasion/lateral movement/exfiltration.",
            "- If evidence is insufficient, mark IOC or DFIR check as Not Assessable.",
        ]
        return "\n".join(lines)

    @staticmethod
    def _extract_url_host(url: str) -> str:
        text = url.strip()
        if "://" in text:
            text = text.split("://", 1)[1]
        text = text.split("/", 1)[0]
        text = text.split(":", 1)[0]
        return text.lower().strip()

    def _extract_tool_keywords(self, text: str) -> list[str]:
        lowered = text.lower()
        hits: list[str] = []
        for keyword in _KNOWN_MALICIOUS_TOOL_KEYWORDS:
            if keyword in lowered:
                hits.append(keyword)
        return self._unique_preserve_order(hits)

    @staticmethod
    def _truncate_for_prompt(value: str, limit: int) -> str:
        text = str(value or "").strip()
        if len(text) <= limit:
            return text
        if limit <= 20:
            return text[:limit]
        return f"{text[: limit - 14].rstrip()} ... [truncated]"

    @staticmethod
    def _unique_preserve_order(values: Iterable[str]) -> list[str]:
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

    def _prepare_artifact_data(
        self,
        artifact_key: str,
        investigation_context: str,
        csv_path: Path | None = None,
    ) -> str:
        """Prepare one artifact CSV as a bounded, analysis-ready prompt."""
        resolved_csv_path = csv_path if csv_path is not None else self._resolve_artifact_csv_path(artifact_key)
        include_statistics = not self._should_use_shortened_prompt()
        template = self.artifact_prompt_template if include_statistics else self.artifact_prompt_template_small_context
        artifact_metadata = self._resolve_artifact_metadata(artifact_key)

        context_dates = self._extract_dates_from_context(investigation_context)
        filter_start: datetime | None = None
        filter_end: datetime | None = None
        filter_source = ""
        if self._explicit_analysis_date_range and self._artifact_uses_explicit_date_range(artifact_key):
            filter_start, filter_end = self._explicit_analysis_date_range
            filter_source = "step_2_selection"
        elif context_dates:
            filter_start = min(context_dates) - timedelta(days=self.date_buffer_days)
            filter_end = max(context_dates) + timedelta(days=self.date_buffer_days)
            filter_source = "investigation_context"
        if filter_start is not None and filter_end is not None:
            # Normalize both bounds in case any upstream caller provided
            # timezone-aware datetimes.
            filter_start = self._normalize_datetime(filter_start)
            filter_end = self._normalize_datetime(filter_end)

        rows: list[dict[str, str]] = []
        source_row_count = 0
        rows_without_timestamp = 0
        columns: list[str] = []

        with resolved_csv_path.open("r", newline="", encoding="utf-8-sig", errors="replace") as handle:
            reader = csv.DictReader(handle)
            columns = [
                str(column)
                for column in (reader.fieldnames or [])
                if column not in (None, "")
            ]

            for source_row_count, raw_row in enumerate(reader, start=1):
                row = self._normalize_csv_row(raw_row, columns=columns)
                row["_row_ref"] = str(source_row_count)

                if filter_start is not None and filter_end is not None:
                    row_timestamp = self._extract_row_datetime(row, columns=columns)
                    if row_timestamp is None:
                        # Keep rows without timestamps — they can't be placed
                        # outside the window and may contain relevant evidence
                        # (e.g. registry persistence entries without write times).
                        rows_without_timestamp += 1
                        rows.append(row)
                        continue
                    normalized_row_timestamp = self._normalize_datetime(row_timestamp)
                    if not (filter_start <= normalized_row_timestamp <= filter_end):
                        continue

                rows.append(row)

        analysis_columns, projection_applied = self._select_ai_columns(
            artifact_key=artifact_key,
            available_columns=columns,
        )
        analysis_rows = self._project_rows_for_analysis(rows=rows, columns=analysis_columns)
        deduplicated_records = 0
        dedup_annotated_rows = 0
        dedup_variant_columns: list[str] = []
        analysis_csv_path = resolved_csv_path

        dedup_write_error = ""
        if self.artifact_deduplication_enabled:
            analysis_rows, analysis_columns, deduplicated_records, dedup_annotated_rows, dedup_variant_columns = (
                self._deduplicate_rows_for_analysis(rows=analysis_rows, columns=analysis_columns)
            )

        if projection_applied or self.artifact_deduplication_enabled:
            try:
                analysis_csv_path = self._write_analysis_input_csv(
                    source_csv_path=resolved_csv_path,
                    rows=analysis_rows,
                    columns=analysis_columns,
                )
            except OSError as error:
                analysis_csv_path = resolved_csv_path
                dedup_write_error = str(error)
        self._set_analysis_input_csv_path(artifact_key=artifact_key, csv_path=analysis_csv_path)

        if projection_applied:
            projection_details = {
                "artifact_key": artifact_key,
                "source_csv": str(resolved_csv_path),
                "analysis_csv": str(analysis_csv_path),
                "projection_columns": list(analysis_columns),
            }
            if dedup_write_error and not self.artifact_deduplication_enabled:
                projection_details["write_error"] = dedup_write_error
            self._audit_log("artifact_ai_projection", projection_details)

        if self.artifact_deduplication_enabled:
            dedup_audit_details: dict[str, Any] = {
                "artifact_key": artifact_key,
                "source_csv": str(resolved_csv_path),
                "analysis_csv": str(analysis_csv_path),
                "removed_records": deduplicated_records,
                "annotated_rows": dedup_annotated_rows,
                "variant_columns": list(dedup_variant_columns),
            }
            if dedup_write_error:
                dedup_audit_details["write_error"] = dedup_write_error
            self._audit_log("artifact_deduplicated", dedup_audit_details)

        statistics = ""
        if include_statistics:
            statistics, min_time, max_time = self._compute_statistics(rows=analysis_rows, columns=analysis_columns)
            stats_prefix: list[str] = []
            if filter_start and filter_end:
                if filter_source == "step_2_selection" and self._explicit_analysis_date_range_label:
                    start_date, end_date = self._explicit_analysis_date_range_label
                    filter_details = (
                        "Date filter applied from Step 2 selection: "
                        f"{start_date} to {end_date} (inclusive).\n"
                        f"Rows kept after filter: {len(analysis_rows)} of {source_row_count}.\n"
                        f"Rows without parseable timestamp (included unfiltered): {rows_without_timestamp}.\n"
                    )
                else:
                    filter_details = (
                        "Date filter applied from investigation context: "
                        f"{self._format_datetime(filter_start)} to {self._format_datetime(filter_end)} "
                        f"(+/- {self.date_buffer_days} days).\n"
                        f"Rows kept after filter: {len(analysis_rows)} of {source_row_count}.\n"
                        f"Rows without parseable timestamp (included unfiltered): {rows_without_timestamp}.\n"
                    )
                stats_prefix.append(filter_details.rstrip())

            if self.artifact_deduplication_enabled:
                dedup_details = [
                    "Artifact deduplication enabled.",
                    f"Rows removed as timestamp/ID-only duplicates: {deduplicated_records}.",
                    f"Rows annotated with deduplication comment: {dedup_annotated_rows}.",
                ]
                if dedup_variant_columns:
                    dedup_details.append(
                        "Dedup variant columns: " + ", ".join(dedup_variant_columns) + "."
                    )
                stats_prefix.append("\n".join(dedup_details))

            if projection_applied:
                stats_prefix.append(
                    "AI column projection applied: " + ", ".join(analysis_columns) + "."
                )

            if stats_prefix:
                prefix_text = "\n".join(stats_prefix)
                statistics = f"{prefix_text}\n{statistics}"
        else:
            min_time, max_time = self._time_range_for_rows(analysis_rows)

        full_data_csv = self._build_full_data_csv(
            rows=analysis_rows,
            columns=analysis_columns,
        )
        priority_directives = self._build_priority_directives(investigation_context)
        ioc_targets = self._format_ioc_targets(investigation_context)
        artifact_guidance = self._resolve_analysis_instructions(
            artifact_key=artifact_key,
            artifact_metadata=artifact_metadata,
        )

        replacements = {
            "priority_directives": priority_directives,
            "investigation_context": investigation_context.strip() or "No investigation context provided.",
            "ioc_targets": ioc_targets,
            "artifact_key": artifact_key,
            "artifact_name": artifact_metadata.get("name", artifact_key),
            "artifact_description": artifact_metadata.get(
                "description", "No artifact description available."
            ),
            "total_records": str(len(analysis_rows)),
            "time_range_start": self._format_datetime(min_time),
            "time_range_end": self._format_datetime(max_time),
            "statistics": statistics,
            "analysis_instructions": artifact_guidance,
            "artifact_guidance": artifact_guidance,
            "data_csv": full_data_csv,
        }

        filled = template
        for placeholder, value in replacements.items():
            filled = filled.replace(f"{{{{{placeholder}}}}}", value)

        final_context_reminder = self._build_artifact_final_context_reminder(
            artifact_key=artifact_key,
            artifact_name=artifact_metadata.get("name", artifact_key),
            investigation_context=investigation_context,
        )
        if final_context_reminder:
            filled = f"{filled.rstrip()}\n\n{final_context_reminder}\n"

        return filled

    @staticmethod
    def _build_datetime(year: str, month: str, day: str) -> datetime | None:
        try:
            return datetime(int(year), int(month), int(day))
        except ValueError:
            return None

    @staticmethod
    def _normalize_artifact_key(artifact_key: str) -> str:
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

    def _resolve_artifact_metadata(self, artifact_key: str) -> dict[str, str]:
        if artifact_key in ARTIFACT_REGISTRY:
            metadata = ARTIFACT_REGISTRY[artifact_key]
            return {str(key): str(value) for key, value in metadata.items()}

        normalized = self._normalize_artifact_key(artifact_key)
        if normalized in ARTIFACT_REGISTRY:
            metadata = ARTIFACT_REGISTRY[normalized]
            return {str(key): str(value) for key, value in metadata.items()}

        return {
            "name": artifact_key,
            "description": "No artifact description available.",
            "analysis_hint": "No specific analysis guidance is available for this artifact.",
        }

    def _resolve_analysis_instructions(
        self,
        artifact_key: str,
        artifact_metadata: Mapping[str, str],
    ) -> str:
        normalized_key = self._normalize_artifact_key(artifact_key)
        for key in (artifact_key, normalized_key):
            prompt = self.artifact_instruction_prompts.get(key.strip().lower(), "").strip()
            if prompt:
                return prompt

        metadata_guidance = self._stringify_value(artifact_metadata.get("artifact_guidance", ""))
        if metadata_guidance:
            return metadata_guidance

        metadata_instructions = self._stringify_value(artifact_metadata.get("analysis_instructions", ""))
        if metadata_instructions:
            return metadata_instructions

        metadata_hint = self._stringify_value(artifact_metadata.get("analysis_hint", ""))
        if metadata_hint:
            return metadata_hint

        return "No specific analysis instructions are available for this artifact."

    def _resolve_artifact_csv_path(self, artifact_key: str) -> Path:
        mapped = self.artifact_csv_paths.get(artifact_key)
        if mapped is not None:
            return mapped

        normalized = self._normalize_artifact_key(artifact_key)
        mapped_normalized = self.artifact_csv_paths.get(normalized)
        if mapped_normalized is not None:
            return mapped_normalized

        candidate_path = Path(artifact_key)
        if candidate_path.exists():
            return candidate_path

        if self.case_dir is not None:
            parsed_dir = self.case_dir / "parsed"
            if parsed_dir.exists():
                normalized = self._normalize_artifact_key(artifact_key)
                file_stubs = {
                    artifact_key,
                    normalized,
                    self._sanitize_filename(artifact_key),
                    self._sanitize_filename(normalized),
                }
                for file_stub in file_stubs:
                    direct_csv_path = parsed_dir / f"{file_stub}.csv"
                    if direct_csv_path.exists():
                        return direct_csv_path
                for file_stub in file_stubs:
                    prefixed_paths = sorted(parsed_dir.glob(f"{file_stub}_*.csv"))
                    if prefixed_paths:
                        return prefixed_paths[0]

        raise FileNotFoundError(
            f"No CSV path mapped for artifact '{artifact_key}'. "
            "Provide it in ForensicAnalyzer(artifact_csv_paths=...) or use case_dir/parsed CSV paths."
        )

    def _set_analysis_input_csv_path(self, artifact_key: str, csv_path: Path) -> None:
        self._analysis_input_csv_paths[artifact_key] = csv_path
        normalized = self._normalize_artifact_key(artifact_key)
        self._analysis_input_csv_paths[normalized] = csv_path

    def _resolve_analysis_input_csv_path(self, artifact_key: str, fallback: Path) -> Path:
        mapped = self._analysis_input_csv_paths.get(artifact_key)
        if mapped is not None:
            return mapped
        normalized = self._normalize_artifact_key(artifact_key)
        mapped = self._analysis_input_csv_paths.get(normalized)
        if mapped is not None:
            return mapped
        return fallback

    def _resolve_analysis_input_output_dir(self, source_csv_path: Path) -> Path:
        if self.case_dir is not None:
            return self.case_dir / DEDUPLICATED_PARSED_DIRNAME

        parent = source_csv_path.parent
        if parent.name.strip().lower() == "parsed":
            return parent.parent / DEDUPLICATED_PARSED_DIRNAME
        return parent / DEDUPLICATED_PARSED_DIRNAME

    def _write_analysis_input_csv(
        self,
        source_csv_path: Path,
        rows: list[dict[str, str]],
        columns: list[str],
    ) -> Path:
        output_dir = self._resolve_analysis_input_output_dir(source_csv_path=source_csv_path)
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / source_csv_path.name

        with output_path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            for row in rows:
                writer.writerow({column: row.get(column, "") for column in columns})

        return output_path

    def _build_artifact_csv_attachment(self, artifact_key: str, csv_path: Path) -> dict[str, str]:
        filename_stem = self._sanitize_filename(artifact_key)
        filename = f"{filename_stem}.csv" if not filename_stem.lower().endswith(".csv") else filename_stem
        return {
            "path": str(csv_path),
            "name": filename,
            "mime_type": "text/csv",
        }

    @staticmethod
    def _sanitize_filename(value: str) -> str:
        cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_")
        return cleaned or "artifact"

    def _normalize_csv_row(self, row: dict[str | None, str | None | list[str]], columns: list[str]) -> dict[str, str]:
        normalized: dict[str, str] = {}
        for column in columns:
            normalized[column] = self._stringify_value(row.get(column))

        extras = row.get(None)
        if extras:
            extra_values = [self._stringify_value(value) for value in extras]
            normalized["__extra__"] = " | ".join(value for value in extra_values if value)

        return normalized

    @staticmethod
    def _stringify_value(value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, str):
            return value.strip()
        return str(value).strip()

    @staticmethod
    def _format_datetime(value: datetime | None) -> str:
        if value is None:
            return "N/A"
        return value.isoformat()

    def _counter_normalize(self, value: str) -> str:
        cleaned = self._normalize_table_cell(value=value, cell_limit=120)
        if cleaned.lower() in _LOW_SIGNAL_VALUES:
            return ""
        return cleaned

    def _time_range_for_rows(self, rows: Iterable[dict[str, str]]) -> tuple[datetime | None, datetime | None]:
        min_time: datetime | None = None
        max_time: datetime | None = None
        for row in rows:
            parsed = self._extract_row_datetime(row=row)
            if parsed is None:
                continue
            if min_time is None or parsed < min_time:
                min_time = parsed
            if max_time is None or parsed > max_time:
                max_time = parsed
        return min_time, max_time

    def _extract_row_datetime(self, row: dict[str, str], columns: list[str] | None = None) -> datetime | None:
        candidate_columns: list[str] = []
        if columns:
            candidate_columns.extend(
                column
                for column in columns
                if self._looks_like_timestamp_column(column)
            )
        else:
            candidate_columns.extend(
                column
                for column in row.keys()
                if self._looks_like_timestamp_column(column)
            )

        for column in candidate_columns:
            parsed = self._parse_datetime_value(row.get(column, ""))
            if parsed is not None:
                return parsed

        for value in row.values():
            parsed = self._parse_datetime_value(value)
            if parsed is not None:
                return parsed

        return None

    @staticmethod
    def _looks_like_timestamp_column(column_name: str) -> bool:
        lowered = column_name.strip().lower()
        return any(hint in lowered for hint in _TIMESTAMP_COLUMN_HINTS)

    def _parse_datetime_value(self, value: str) -> datetime | None:
        text = self._stringify_value(value)
        if not text:
            return None

        cleaned = text.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(cleaned)
            return self._normalize_datetime(parsed)
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
                return self._normalize_datetime(parsed)
            except ValueError:
                continue

        int_value = self._parse_int(cleaned)
        if int_value is not None:
            # Handle epoch timestamp values commonly found in some artifacts.
            if int_value > 1_000_000_000_000:
                int_value //= 1000
            if 946684800 <= int_value <= 4_102_444_800:
                try:
                    parsed = datetime.fromtimestamp(int_value, tz=timezone.utc)
                    return self._normalize_datetime(parsed)
                except (ValueError, OSError):
                    return None

        return None

    @staticmethod
    def _normalize_datetime(value: datetime) -> datetime:
        if value.tzinfo is None:
            return value
        return value.astimezone(timezone.utc).replace(tzinfo=None)

    @staticmethod
    def _parse_int(value: str) -> int | None:
        if not value:
            return None
        match = _INTEGER_RE.search(value)
        if not match:
            return None
        try:
            return int(match.group())
        except ValueError:
            return None

    def _select_ai_columns(self, artifact_key: str, available_columns: list[str]) -> tuple[list[str], bool]:
        normalized_key = self._normalize_artifact_key(artifact_key)
        configured_columns = self.artifact_ai_column_projections.get(normalized_key)
        if not configured_columns:
            return list(available_columns), False

        lookup = {column.strip().lower(): column for column in available_columns}
        projected_columns: list[str] = []
        missing_columns: list[str] = []
        for column_name in configured_columns:
            matched = lookup.get(column_name.strip().lower())
            if matched is not None:
                projected_columns.append(matched)
            else:
                missing_columns.append(column_name)

        if missing_columns:
            self._audit_log(
                "artifact_ai_projection_warning",
                {
                    "artifact_key": artifact_key,
                    "missing_columns": missing_columns,
                    "available_columns": available_columns,
                },
            )

        if not projected_columns:
            return list(available_columns), False

        return projected_columns, True

    @staticmethod
    def _is_dedup_safe_identifier_column(column_name: str) -> bool:
        """Return True only for auto-incremented record IDs safe for dedup.

        This excludes semantically meaningful identifiers (EventID, ProcessID,
        SessionID, ...) that distinguish genuinely different events.
        """
        lowered = column_name.strip().lower().replace("-", "_").replace(" ", "_")
        return lowered in _DEDUP_SAFE_IDENTIFIER_HINTS

    def _project_rows_for_analysis(
        self,
        rows: list[dict[str, str]],
        columns: list[str],
    ) -> list[dict[str, str]]:
        projected_rows: list[dict[str, str]] = []
        for row in rows:
            projected: dict[str, str] = {
                column: self._stringify_value(row.get(column, ""))
                for column in columns
            }
            row_ref = self._stringify_value(row.get("_row_ref", ""))
            if row_ref:
                projected["_row_ref"] = row_ref
            projected_rows.append(projected)
        return projected_rows

    def _deduplicate_rows_for_analysis(
        self,
        rows: list[dict[str, str]],
        columns: list[str],
    ) -> tuple[list[dict[str, str]], list[str], int, int, list[str]]:
        if not rows or not columns:
            return list(rows), list(columns), 0, 0, []

        # Only timestamps and auto-incremented record IDs are safe dedup
        # variants.  Semantic identifiers (EventID, ProcessID, SessionID …)
        # are intentionally kept as base columns because rows differing
        # only in those fields represent genuinely different events.
        variant_columns = [
            column
            for column in columns
            if self._looks_like_timestamp_column(column) or self._is_dedup_safe_identifier_column(column)
        ]
        if not variant_columns:
            return [dict(row) for row in rows], list(columns), 0, 0, []

        variant_set = set(variant_columns)
        base_columns = [
            column
            for column in columns
            if column not in variant_set and column.lower() not in _METADATA_COLUMNS and column != DEDUP_COMMENT_COLUMN
        ]
        if not base_columns:
            return [dict(row) for row in rows], list(columns), 0, 0, variant_columns

        kept_rows: list[dict[str, str]] = []
        representative_by_key: dict[tuple[tuple[str, str], ...], int] = {}
        dedup_counts: Counter[int] = Counter()

        for row in rows:
            normalized_row = {str(key): self._stringify_value(value) for key, value in row.items()}
            key = tuple((column, normalized_row.get(column, "")) for column in base_columns)
            representative_index = representative_by_key.get(key)
            if representative_index is None:
                representative_by_key[key] = len(kept_rows)
                kept_rows.append(normalized_row)
                continue

            # Base columns match a previous row.  Whether variant columns
            # differ (same event recorded at different times / record IDs)
            # or are identical (exact duplicate row), this row is redundant.
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

    def _build_full_data_csv(
        self,
        rows: list[dict[str, str]],
        columns: list[str],
    ) -> str:
        """Serialize rows to inline CSV text.

        Always produces the complete CSV — truncation is never acceptable
        in DFIR.  When the data exceeds the model context window, the
        caller uses chunked analysis instead.
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
            return "No rows available after date filtering."

        return full_csv

    @staticmethod
    def _normalize_table_cell(value: str, cell_limit: int) -> str:
        text = value.replace("\r", " ").replace("\n", " ").replace("|", r"\|").strip()
        if len(text) <= cell_limit:
            return text
        if cell_limit <= 3:
            return text[:cell_limit]
        return f"{text[: cell_limit - 3]}..."

    def _estimate_tokens(self, text: str) -> int:
        ratio = max(1, TOKEN_CHAR_RATIO)
        return max(1, len(text) // ratio)
