"""AI analysis orchestration module for forensic triage.

Implements the ``ForensicAnalyzer`` class that orchestrates the full analysis
pipeline: token budgeting, date filtering, column projection, deduplication,
chunked analysis, citation validation, IOC extraction, and audit logging.

Sub-module organisation:

- ``analyzer_constants``: Compile-time constants, regex, prompt templates.
- ``analyzer_utils``: Pure utility functions (string, datetime, CSV).
- ``analyzer_ioc``: IOC extraction and prompt-building helpers.
- ``analyzer_citations``: Citation validation against source CSV.
- ``analyzer_data_prep``: Date filtering, dedup, statistics, prompt assembly.
- ``analyzer_chunking``: Chunked analysis and hierarchical merge.
- ``analyzer_prompts``: Prompt template loading and construction.

Attributes:
    PROJECT_ROOT (Path): Re-exported from ``analyzer_constants``.
"""

from __future__ import annotations

import logging
from pathlib import Path
from time import perf_counter, sleep
from typing import Any, Callable, Iterable, Mapping

from ..ai_providers import AIProviderError, create_provider
from .chunking import analyze_artifact_chunked, split_csv_and_suffix, split_csv_into_chunks
from .citations import match_column_name, timestamp_found_in_csv, timestamp_lookup_keys, validate_citations
from .constants import (
    AI_MAX_TOKENS, AI_RETRY_ATTEMPTS, AI_RETRY_BASE_DELAY,
    ARTIFACT_DEDUPLICATION_ENABLED, CITATION_SPOT_CHECK_LIMIT, DATE_BUFFER_DAYS,
    DEFAULT_ARTIFACT_AI_COLUMNS_CONFIG_PATH, DEFAULT_ARTIFACT_PROMPT_TEMPLATE,
    DEFAULT_ARTIFACT_PROMPT_TEMPLATE_SMALL_CONTEXT, DEFAULT_CHUNK_MERGE_PROMPT_TEMPLATE,
    DEFAULT_SHORTENED_PROMPT_CUTOFF_TOKENS, DEFAULT_SUMMARY_PROMPT_TEMPLATE,
    DEFAULT_SYSTEM_PROMPT, MAX_MERGE_ROUNDS, PROJECT_ROOT, TOKEN_CHAR_RATIO,
    UnavailableProvider,
)
from .data_prep import (
    build_artifact_csv_attachment, build_full_data_csv, compute_statistics,
    deduplicate_rows_for_analysis, extract_dates_from_context, prepare_artifact_data,
)
from .ioc import build_priority_directives, extract_ioc_targets, format_ioc_targets
from .prompts import (
    build_summary_prompt, load_artifact_ai_column_projections,
    load_artifact_instruction_prompts, load_prompt_template,
    resolve_artifact_ai_columns_config_path,
)
from .utils import (
    build_datetime, coerce_projection_columns, emit_analysis_progress,
    estimate_tokens, is_dedup_safe_identifier_column, normalize_artifact_key,
    read_bool_setting, read_int_setting, read_path_setting,
    sanitize_filename, stringify_value,
)

LOGGER = logging.getLogger(__name__)

try:
    from ..parser import LINUX_ARTIFACT_REGISTRY, WINDOWS_ARTIFACT_REGISTRY
except Exception as error:
    LOGGER.warning(
        "Failed to import artifact registries from app.parser: %s. "
        "Artifact metadata lookups will be unavailable.",
        error,
    )
    WINDOWS_ARTIFACT_REGISTRY: dict[str, dict[str, str]] = {}
    LINUX_ARTIFACT_REGISTRY: dict[str, dict[str, str]] = {}

__all__ = ["AnalysisCancelledError", "ForensicAnalyzer"]


class AnalysisCancelledError(Exception):
    """Raised when analysis is cancelled by the user."""


class ForensicAnalyzer:
    """Orchestrates AI-powered forensic analysis of parsed artifact CSV data.

    Central analysis engine for AIFT: reads parsed artifact CSV files, applies
    date filtering, column projection, and deduplication, builds token-budgeted
    prompts, sends them to a configured AI provider, and validates citations.

    Attributes:
        case_dir: Path to the case directory, or ``None``.
        config: Merged configuration dictionary.
        ai_provider: The configured AI provider instance.
        model_info: Dict with ``provider`` and ``model`` keys.
    """

    # Expose extracted functions as static methods for backward compatibility
    # with tests and callers that use ForensicAnalyzer._method_name().
    _stringify_value = staticmethod(stringify_value)
    _build_datetime = staticmethod(build_datetime)
    _normalize_artifact_key = staticmethod(normalize_artifact_key)
    _sanitize_filename = staticmethod(sanitize_filename)
    _split_csv_into_chunks = staticmethod(split_csv_into_chunks)
    _split_csv_and_suffix = staticmethod(split_csv_and_suffix)
    _coerce_projection_columns = staticmethod(coerce_projection_columns)
    _is_dedup_safe_identifier_column = staticmethod(is_dedup_safe_identifier_column)
    _timestamp_lookup_keys = staticmethod(timestamp_lookup_keys)
    _timestamp_found_in_csv = staticmethod(timestamp_found_in_csv)
    _match_column_name = staticmethod(match_column_name)
    _emit_analysis_progress = staticmethod(emit_analysis_progress)

    def __init__(
        self,
        case_dir: str | Path | Mapping[str, str | Path] | None = None,
        config: Mapping[str, Any] | None = None,
        audit_logger: Any | None = None,
        artifact_csv_paths: Mapping[str, str | Path] | None = None,
        prompts_dir: str | Path | None = None,
        random_seed: int | None = None,
    ) -> None:
        """Initialize the forensic analyzer with case context and configuration.

        Args:
            case_dir: Path to the case directory, or a mapping of artifact
                keys to CSV paths (convenience shorthand).
            config: Application configuration dictionary.
            audit_logger: Optional object with a ``log(action, details)``
                method.
            artifact_csv_paths: Mapping of artifact keys to CSV paths.
            prompts_dir: Directory containing prompt template files.
            random_seed: Optional seed for the internal RNG.
        """
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
        self.artifact_csv_paths: dict[str, Path | list[Path]] = {}
        for artifact_key, csv_path in (artifact_csv_paths or {}).items():
            key = str(artifact_key)
            if isinstance(csv_path, list):
                self.artifact_csv_paths[key] = [Path(str(p)) for p in csv_path]
            else:
                self.artifact_csv_paths[key] = Path(str(csv_path))
        self._analysis_input_csv_paths: dict[str, Path] = {}
        self.prompts_dir = Path(prompts_dir) if prompts_dir is not None else PROJECT_ROOT / "prompts"
        import random
        self._random = random.Random(random_seed)
        self._load_analysis_settings()
        self.artifact_ai_column_projections = self._load_artifact_ai_column_projections()
        self.system_prompt = self._load_prompt_template("system_prompt.md", default=DEFAULT_SYSTEM_PROMPT)
        self.artifact_prompt_template = self._load_prompt_template(
            "artifact_analysis.md", default=DEFAULT_ARTIFACT_PROMPT_TEMPLATE,
        )
        self.artifact_prompt_template_small_context = self._load_prompt_template(
            "artifact_analysis_small_context.md", default=DEFAULT_ARTIFACT_PROMPT_TEMPLATE_SMALL_CONTEXT,
        )
        self.artifact_instruction_prompts = self._load_artifact_instruction_prompts()
        self.summary_prompt_template = self._load_prompt_template(
            "summary_prompt.md", default=DEFAULT_SUMMARY_PROMPT_TEMPLATE,
        )
        self.chunk_merge_prompt_template = self._load_prompt_template(
            "chunk_merge.md", default=DEFAULT_CHUNK_MERGE_PROMPT_TEMPLATE,
        )
        self.ai_provider = self._create_ai_provider()
        self.model_info = self._read_model_info()
        self._explicit_analysis_date_range: tuple = None  # type: ignore[assignment]
        self._explicit_analysis_date_range_label: tuple | None = None

    # ------------------------------------------------------------------
    # Configuration loading
    # ------------------------------------------------------------------

    def _load_analysis_settings(self) -> None:
        """Load and validate analysis tuning parameters from the config dict."""
        analysis_config = self.config.get("analysis")
        if not isinstance(analysis_config, Mapping):
            analysis_config = {}

        self.ai_max_tokens = read_int_setting(analysis_config, "ai_max_tokens", AI_MAX_TOKENS, minimum=1)
        self.ai_response_max_tokens = max(1, int(self.ai_max_tokens * 0.2))
        legacy_shortened = read_int_setting(
            analysis_config, "statistics_section_cutoff_tokens", DEFAULT_SHORTENED_PROMPT_CUTOFF_TOKENS, minimum=1,
        )
        self.shortened_prompt_cutoff_tokens = read_int_setting(
            analysis_config, "shortened_prompt_cutoff_tokens", legacy_shortened, minimum=1,
        )
        self.chunk_csv_budget = int(self.ai_max_tokens * TOKEN_CHAR_RATIO * 0.6)
        self.date_buffer_days = read_int_setting(analysis_config, "date_buffer_days", DATE_BUFFER_DAYS, minimum=0)
        self.citation_spot_check_limit = read_int_setting(
            analysis_config, "citation_spot_check_limit", CITATION_SPOT_CHECK_LIMIT, minimum=1,
        )
        self.max_merge_rounds = read_int_setting(analysis_config, "max_merge_rounds", MAX_MERGE_ROUNDS, minimum=1)
        self.artifact_deduplication_enabled = read_bool_setting(
            analysis_config, "artifact_deduplication_enabled", ARTIFACT_DEDUPLICATION_ENABLED,
        )
        self.artifact_ai_columns_config_path = read_path_setting(
            analysis_config, "artifact_ai_columns_config_path", str(DEFAULT_ARTIFACT_AI_COLUMNS_CONFIG_PATH),
        )

    # Backward-compatible aliases for the extracted config readers.
    _read_int_setting = staticmethod(read_int_setting)
    _read_bool_setting = staticmethod(read_bool_setting)
    _read_path_setting = staticmethod(read_path_setting)

    def _resolve_artifact_ai_columns_config_path(self) -> Path:
        """Resolve the artifact AI columns config path to an absolute Path.

        Delegates to :func:`prompts.resolve_artifact_ai_columns_config_path`.

        Returns:
            Resolved absolute ``Path`` to the YAML config file.
        """
        return resolve_artifact_ai_columns_config_path(
            self.artifact_ai_columns_config_path, self.case_dir,
        )

    def _load_artifact_ai_column_projections(self) -> dict[str, tuple[str, ...]]:
        """Load per-artifact column projection configuration from YAML.

        Delegates to :func:`prompts.load_artifact_ai_column_projections`.

        Returns:
            A dict mapping normalized artifact keys to tuples of column names.
        """
        config_path = self._resolve_artifact_ai_columns_config_path()
        return load_artifact_ai_column_projections(config_path)

    def _load_prompt_template(self, filename: str, default: str) -> str:
        """Read a prompt template file from the prompts directory.

        Delegates to :func:`prompts.load_prompt_template`.

        Args:
            filename: Name of the template file.
            default: Fallback template string.

        Returns:
            The template text.
        """
        return load_prompt_template(self.prompts_dir, filename, default)

    def _load_artifact_instruction_prompts(self) -> dict[str, str]:
        """Load per-artifact analysis instruction prompts.

        Delegates to :func:`prompts.load_artifact_instruction_prompts`.

        Returns:
            A dict mapping artifact keys to instruction prompt text.
        """
        return load_artifact_instruction_prompts(self.prompts_dir)

    # ------------------------------------------------------------------
    # AI provider
    # ------------------------------------------------------------------

    def _create_ai_provider(self) -> Any:
        """Instantiate the configured AI provider, or a fallback on failure.

        Returns:
            An AI provider instance, or an ``UnavailableProvider``.
        """
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
            return UnavailableProvider(str(error))

    def _read_model_info(self) -> dict[str, str]:
        """Read provider and model metadata from the AI provider.

        Returns:
            A dict with at least ``provider`` and ``model`` keys.
        """
        try:
            model_info = self.ai_provider.get_model_info()
        except Exception:
            return {"provider": "unknown", "model": "unknown"}

        if not isinstance(model_info, Mapping):
            return {"provider": "unknown", "model": "unknown"}

        return {str(key): str(value) for key, value in model_info.items()}

    def _call_ai_with_retry(self, call: Callable[[], str]) -> str:
        """Call the AI provider with retry on transient failures.

        Args:
            call: A zero-argument callable that invokes the AI provider.

        Returns:
            The AI provider's response string.

        Raises:
            AIProviderError: If the provider raises a permanent error.
            Exception: The last transient error after all retries.
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
                        attempt + 1, AI_RETRY_ATTEMPTS, delay, error,
                    )
                    sleep(delay)
        raise last_error  # type: ignore[misc]

    # ------------------------------------------------------------------
    # Audit / prompt saving
    # ------------------------------------------------------------------

    def _audit_log(self, action: str, details: dict[str, Any]) -> None:
        """Write an entry to the forensic audit trail.

        Args:
            action: The audit action name.
            details: Key-value details for the audit entry.
        """
        if self.audit_logger is None:
            return
        logger = getattr(self.audit_logger, "log", None)
        if not callable(logger):
            return
        try:
            logger(action, details)
        except Exception:
            return

    def _save_case_prompt(self, filename: str, system_prompt: str, user_prompt: str) -> None:
        """Save a prompt to the case prompts directory for audit.

        Args:
            filename: Output filename.
            system_prompt: The system prompt text.
            user_prompt: The user prompt text.
        """
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

    # ------------------------------------------------------------------
    # Delegation methods — thin wrappers for backward compatibility.
    # Methods that don't use self are exposed as staticmethod assignments
    # at the class level (see above).  The methods below need self.
    # ------------------------------------------------------------------

    def _estimate_tokens(self, text: str) -> int:
        """Estimate the token count of *text* using model-specific info."""
        return estimate_tokens(text, model_info=self.model_info)

    # These are also exposed as staticmethods on the class (see above)
    # but tests may call them on instances, so they work either way.
    _extract_dates_from_context = staticmethod(extract_dates_from_context)
    _extract_ioc_targets = staticmethod(extract_ioc_targets)
    _format_ioc_targets = staticmethod(format_ioc_targets)
    _build_priority_directives = staticmethod(build_priority_directives)
    _compute_statistics = staticmethod(compute_statistics)
    _build_full_data_csv = staticmethod(build_full_data_csv)
    _deduplicate_rows_for_analysis = staticmethod(deduplicate_rows_for_analysis)

    def _validate_citations(self, artifact_key: str, analysis_text: str) -> list[str]:
        """Spot-check AI-cited values against source CSV.

        Args:
            artifact_key: Artifact identifier.
            analysis_text: The AI's analysis text.

        Returns:
            List of warning strings.
        """
        if analysis_text.startswith("Analysis failed:"):
            return []
        try:
            original_path = self._resolve_artifact_csv_path(artifact_key)
        except FileNotFoundError:
            return []
        csv_path = self._resolve_analysis_input_csv_path(
            artifact_key, fallback=original_path,
        )
        return validate_citations(
            artifact_key=artifact_key,
            analysis_text=analysis_text,
            csv_path=csv_path,
            citation_spot_check_limit=self.citation_spot_check_limit,
            audit_log_fn=self._audit_log,
        )

    # ------------------------------------------------------------------
    # Path resolution
    # ------------------------------------------------------------------

    def _resolve_artifact_csv_path(self, artifact_key: str) -> Path:
        """Resolve the CSV file path for a given artifact key.

        For split artifacts with multiple CSV files, returns the first
        path.  Use :meth:`_resolve_all_artifact_csv_paths` to get every
        path for a split artifact.

        Args:
            artifact_key: Artifact identifier to resolve.

        Returns:
            A ``Path`` to the artifact's CSV file.

        Raises:
            FileNotFoundError: If no CSV path can be found.
        """
        mapped = self.artifact_csv_paths.get(artifact_key)
        if mapped is not None:
            if isinstance(mapped, list):
                return mapped[0]
            return mapped

        normalized = normalize_artifact_key(artifact_key)
        mapped_normalized = self.artifact_csv_paths.get(normalized)
        if mapped_normalized is not None:
            if isinstance(mapped_normalized, list):
                return mapped_normalized[0]
            return mapped_normalized

        candidate_path = Path(artifact_key)
        if candidate_path.exists():
            return candidate_path

        if self.case_dir is not None:
            parsed_dir = self.case_dir / "parsed"
            if parsed_dir.exists():
                normalized = normalize_artifact_key(artifact_key)
                file_stubs = {
                    artifact_key, normalized,
                    sanitize_filename(artifact_key),
                    sanitize_filename(normalized),
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

    def _resolve_all_artifact_csv_paths(self, artifact_key: str) -> list[Path]:
        """Resolve all CSV file paths for a given artifact key.

        For single-file artifacts returns a one-element list.  For split
        artifacts (e.g. EVTX) returns all constituent CSV paths.

        Args:
            artifact_key: Artifact identifier to resolve.

        Returns:
            A non-empty list of ``Path`` objects.

        Raises:
            FileNotFoundError: If no CSV path can be found.
        """
        for key in (artifact_key, normalize_artifact_key(artifact_key)):
            mapped = self.artifact_csv_paths.get(key)
            if mapped is not None:
                if isinstance(mapped, list):
                    return list(mapped)
                return [mapped]

        # Filesystem fallback: search case_dir/parsed for all matching parts.
        if self.case_dir is not None:
            parsed_dir = self.case_dir / "parsed"
            if parsed_dir.exists():
                normalized = normalize_artifact_key(artifact_key)
                file_stubs = {
                    artifact_key, normalized,
                    sanitize_filename(artifact_key),
                    sanitize_filename(normalized),
                }
                for file_stub in file_stubs:
                    direct_csv_path = parsed_dir / f"{file_stub}.csv"
                    combined_csv_path = parsed_dir / f"{file_stub}_combined.csv"
                    prefixed_paths = sorted(
                        path
                        for path in parsed_dir.glob(f"{file_stub}_*.csv")
                        if path != combined_csv_path
                    )
                    if direct_csv_path.exists() and prefixed_paths:
                        return sorted([direct_csv_path] + prefixed_paths)
                    if prefixed_paths:
                        return prefixed_paths
                    if direct_csv_path.exists():
                        return [direct_csv_path]

        # Final fallback: delegate to single-path resolver.
        return [self._resolve_artifact_csv_path(artifact_key)]

    def _combine_csv_files(self, artifact_key: str, csv_paths: list[Path]) -> Path:
        """Concatenate multiple CSV files into a single combined CSV.

        All input files are assumed to share the same schema (column names).
        The combined file is written to the case's ``parsed/`` directory (or
        next to the first input file) with a ``_combined`` suffix.

        Args:
            artifact_key: Artifact identifier (used for the output filename).
            csv_paths: List of CSV file paths to combine.

        Returns:
            Path to the combined CSV file.
        """
        import csv as csv_mod

        output_dir = csv_paths[0].parent
        safe_key = sanitize_filename(artifact_key)
        combined_path = output_dir / f"{safe_key}_combined.csv"

        fieldnames: list[str] = []
        fieldnames_set: set[str] = set()

        for csv_path in csv_paths:
            if not csv_path.exists():
                continue
            with csv_path.open("r", newline="", encoding="utf-8") as fh:
                reader = csv_mod.DictReader(fh)
                if reader.fieldnames:
                    for fn in reader.fieldnames:
                        if fn not in fieldnames_set:
                            fieldnames.append(fn)
                            fieldnames_set.add(fn)

        with combined_path.open("w", newline="", encoding="utf-8") as out:
            writer = csv_mod.DictWriter(out, fieldnames=fieldnames, restval="", extrasaction="ignore")
            writer.writeheader()
            for csv_path in csv_paths:
                if not csv_path.exists():
                    continue
                with csv_path.open("r", newline="", encoding="utf-8") as fh:
                    reader = csv_mod.DictReader(fh)
                    for row in reader:
                        writer.writerow(row)

        return combined_path

    def _set_analysis_input_csv_path(self, artifact_key: str, csv_path: Path) -> None:
        """Store the analysis-input CSV path for an artifact.

        Args:
            artifact_key: Artifact identifier.
            csv_path: Path to the analysis-input CSV.
        """
        self._analysis_input_csv_paths[artifact_key] = csv_path
        normalized = normalize_artifact_key(artifact_key)
        self._analysis_input_csv_paths[normalized] = csv_path

    def _resolve_analysis_input_csv_path(self, artifact_key: str, fallback: Path) -> Path:
        """Retrieve the analysis-input CSV path, with fallback.

        Args:
            artifact_key: Artifact identifier.
            fallback: Default path if not stored.

        Returns:
            The stored analysis-input CSV path, or *fallback*.
        """
        mapped = self._analysis_input_csv_paths.get(artifact_key)
        if mapped is not None:
            return mapped
        normalized = normalize_artifact_key(artifact_key)
        mapped = self._analysis_input_csv_paths.get(normalized)
        if mapped is not None:
            return mapped
        return fallback

    def _resolve_artifact_metadata(self, artifact_key: str) -> dict[str, str]:
        """Look up artifact metadata from the Windows and Linux registries.

        Searches both OS-specific registries so that metadata resolution
        works regardless of which OS the evidence originated from.

        Args:
            artifact_key: Artifact identifier.

        Returns:
            A dict with at least ``name``, ``description``, and
            ``analysis_hint`` keys.
        """
        for registry in (WINDOWS_ARTIFACT_REGISTRY, LINUX_ARTIFACT_REGISTRY):
            if artifact_key in registry:
                metadata = registry[artifact_key]
                return {str(key): str(value) for key, value in metadata.items()}

        normalized = normalize_artifact_key(artifact_key)
        for registry in (WINDOWS_ARTIFACT_REGISTRY, LINUX_ARTIFACT_REGISTRY):
            if normalized in registry:
                metadata = registry[normalized]
                return {str(key): str(value) for key, value in metadata.items()}

        return {
            "name": artifact_key,
            "description": "No artifact description available.",
            "analysis_hint": "No specific analysis guidance is available for this artifact.",
        }

    # ------------------------------------------------------------------
    # Metadata registration
    # ------------------------------------------------------------------

    def _register_artifact_paths_from_metadata(self, metadata: Mapping[str, Any] | None) -> None:
        """Extract and register artifact CSV paths from run metadata.

        Args:
            metadata: Optional metadata mapping.
        """
        if not isinstance(metadata, Mapping):
            return

        artifact_csv_paths = metadata.get("artifact_csv_paths")
        if isinstance(artifact_csv_paths, Mapping):
            for artifact_key, csv_path in artifact_csv_paths.items():
                if isinstance(csv_path, list) and len(csv_path) > 1:
                    self.artifact_csv_paths[str(artifact_key)] = [
                        Path(str(p)) for p in csv_path
                    ]
                elif isinstance(csv_path, list) and csv_path:
                    self.artifact_csv_paths[str(artifact_key)] = Path(str(csv_path[0]))
                else:
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
        """Register a single artifact CSV path from a metadata entry.

        Args:
            artifact_key: Artifact identifier.
            value: Metadata entry (mapping, string, or Path).
        """
        if artifact_key in (None, ""):
            return

        if isinstance(value, Mapping):
            csv_path = value.get("csv_path")
            csv_paths = value.get("csv_paths")
            if isinstance(csv_paths, list) and len(csv_paths) > 1:
                self.artifact_csv_paths[str(artifact_key)] = [
                    Path(str(p)) for p in csv_paths
                ]
                return
            if csv_path:
                self.artifact_csv_paths[str(artifact_key)] = Path(str(csv_path))
                return
            if isinstance(csv_paths, list) and csv_paths:
                self.artifact_csv_paths[str(artifact_key)] = Path(str(csv_paths[0]))
                return

        if isinstance(value, (str, Path)):
            self.artifact_csv_paths[str(artifact_key)] = Path(str(value))

    def _configure_explicit_analysis_date_range(self, metadata: Mapping[str, Any] | None) -> None:
        """Set explicit analysis date range from metadata if present.

        Args:
            metadata: Optional metadata mapping.
        """
        from datetime import datetime, timedelta
        self._explicit_analysis_date_range = None
        self._explicit_analysis_date_range_label = None
        if not isinstance(metadata, Mapping):
            return

        raw_range = metadata.get("analysis_date_range")
        if not isinstance(raw_range, Mapping):
            return

        start_text = stringify_value(raw_range.get("start_date"))
        end_text = stringify_value(raw_range.get("end_date"))
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

    # ------------------------------------------------------------------
    # Core analysis pipeline
    # ------------------------------------------------------------------

    def _prepare_artifact_data(
        self, artifact_key: str, investigation_context: str, csv_path: Path | None = None,
    ) -> str:
        """Prepare one artifact CSV as a bounded, analysis-ready prompt.

        Args:
            artifact_key: Unique identifier for the artifact.
            investigation_context: Free-text investigation context.
            csv_path: Explicit path to the artifact CSV.

        Returns:
            The fully rendered prompt string.

        Raises:
            FileNotFoundError: If the artifact CSV cannot be located.
        """
        resolved_csv_path = csv_path if csv_path is not None else self._resolve_artifact_csv_path(artifact_key)
        artifact_metadata = self._resolve_artifact_metadata(artifact_key)

        prompt_text, analysis_csv_path, _ = prepare_artifact_data(
            artifact_key=artifact_key,
            investigation_context=investigation_context,
            csv_path=resolved_csv_path,
            artifact_metadata=artifact_metadata,
            artifact_prompt_template=self.artifact_prompt_template,
            artifact_prompt_template_small_context=self.artifact_prompt_template_small_context,
            artifact_instruction_prompts=self.artifact_instruction_prompts,
            artifact_ai_column_projections=self.artifact_ai_column_projections,
            artifact_deduplication_enabled=self.artifact_deduplication_enabled,
            ai_max_tokens=self.ai_max_tokens,
            shortened_prompt_cutoff_tokens=self.shortened_prompt_cutoff_tokens,
            date_buffer_days=self.date_buffer_days,
            explicit_analysis_date_range=self._explicit_analysis_date_range,
            explicit_analysis_date_range_label=self._explicit_analysis_date_range_label,
            case_dir=self.case_dir,
            audit_log_fn=self._audit_log,
        )
        self._set_analysis_input_csv_path(artifact_key=artifact_key, csv_path=analysis_csv_path)
        return prompt_text

    def analyze_artifact(
        self,
        artifact_key: str,
        investigation_context: str,
        progress_callback: Any | None = None,
    ) -> dict[str, Any]:
        """Analyze a single artifact's CSV data and return AI findings.

        Args:
            artifact_key: Unique identifier for the artifact.
            investigation_context: Free-text investigation context.
            progress_callback: Optional callable for streaming progress.

        Returns:
            A dict with ``artifact_key``, ``artifact_name``, ``analysis``,
            ``model``, and optionally ``citation_warnings``.
        """
        artifact_metadata = self._resolve_artifact_metadata(artifact_key)
        artifact_name = artifact_metadata.get("name", artifact_key)
        model = self.model_info.get("model", "unknown")
        provider = self.model_info.get("provider", "unknown")

        self._audit_log("analysis_started", {
            "artifact_key": artifact_key, "artifact_name": artifact_name,
            "provider": provider, "model": model,
        })

        start_time = perf_counter()
        try:
            all_csv_paths = self._resolve_all_artifact_csv_paths(artifact_key)
            if len(all_csv_paths) > 1:
                csv_path = self._combine_csv_files(artifact_key, all_csv_paths)
            else:
                csv_path = all_csv_paths[0]
            artifact_prompt = self._prepare_artifact_data(
                artifact_key=artifact_key, investigation_context=investigation_context, csv_path=csv_path,
            )
            analysis_csv_path = self._resolve_analysis_input_csv_path(artifact_key=artifact_key, fallback=csv_path)
            attachments = [build_artifact_csv_attachment(artifact_key=artifact_key, csv_path=analysis_csv_path)]

            safe_key = sanitize_filename(artifact_key)
            self._save_case_prompt(f"artifact_{safe_key}.md", self.system_prompt, artifact_prompt)

            prompt_tokens_estimate = self._estimate_tokens(artifact_prompt) + self._estimate_tokens(self.system_prompt)
            if prompt_tokens_estimate > self.ai_max_tokens:
                self.logger.info(
                    "Prompt for %s (~%d tokens) exceeds ai_max_tokens (%d); using chunked analysis.",
                    artifact_key, prompt_tokens_estimate, self.ai_max_tokens,
                )
                if progress_callback is not None:
                    emit_analysis_progress(progress_callback, artifact_key, "started", {
                        "artifact_key": artifact_key, "artifact_name": artifact_name, "model": model,
                    })
                analysis_text = analyze_artifact_chunked(
                    artifact_prompt=artifact_prompt,
                    artifact_key=artifact_key,
                    artifact_name=artifact_name,
                    investigation_context=investigation_context,
                    model=model,
                    system_prompt=self.system_prompt,
                    ai_response_max_tokens=self.ai_response_max_tokens,
                    chunk_csv_budget=self.chunk_csv_budget,
                    chunk_merge_prompt_template=self.chunk_merge_prompt_template,
                    max_merge_rounds=self.max_merge_rounds,
                    call_ai_with_retry_fn=self._call_ai_with_retry,
                    ai_provider=self.ai_provider,
                    audit_log_fn=self._audit_log,
                    save_case_prompt_fn=self._save_case_prompt,
                    progress_callback=progress_callback,
                )
                duration_seconds = perf_counter() - start_time
                self._audit_log("analysis_completed", {
                    "artifact_key": artifact_key, "artifact_name": artifact_name,
                    "token_count": self._estimate_tokens(analysis_text),
                    "duration_seconds": round(duration_seconds, 6),
                    "status": "success", "chunked": True,
                })
                citation_warnings = self._validate_citations(artifact_key, analysis_text)
                result: dict[str, Any] = {
                    "artifact_key": artifact_key, "artifact_name": artifact_name,
                    "analysis": analysis_text, "model": model,
                }
                if citation_warnings:
                    result["citation_warnings"] = citation_warnings
                return result

            analyze_with_progress = getattr(self.ai_provider, "analyze_with_progress", None)
            if callable(analyze_with_progress) and progress_callback is not None:
                emit_analysis_progress(progress_callback, artifact_key, "started", {
                    "artifact_key": artifact_key, "artifact_name": artifact_name, "model": model,
                })

                def _provider_progress(payload: Mapping[str, Any]) -> None:
                    """Forward provider progress to the frontend."""
                    if not isinstance(payload, Mapping):
                        return
                    emit_analysis_progress(progress_callback, artifact_key, "thinking", {
                        "artifact_key": artifact_key, "artifact_name": artifact_name,
                        "thinking_text": str(payload.get("thinking_text", "")),
                        "partial_text": str(payload.get("partial_text", "")),
                        "model": model,
                    })

                try:
                    analysis_text = analyze_with_progress(
                        system_prompt=self.system_prompt, user_prompt=artifact_prompt,
                        progress_callback=_provider_progress, attachments=attachments,
                        max_tokens=self.ai_response_max_tokens,
                    )
                except TypeError:
                    analysis_text = analyze_with_progress(
                        system_prompt=self.system_prompt, user_prompt=artifact_prompt,
                        progress_callback=_provider_progress, max_tokens=self.ai_response_max_tokens,
                    )
            else:
                if progress_callback is not None:
                    emit_analysis_progress(progress_callback, artifact_key, "started", {
                        "artifact_key": artifact_key, "artifact_name": artifact_name, "model": model,
                    })
                analyze_with_attachments = getattr(self.ai_provider, "analyze_with_attachments", None)
                if callable(analyze_with_attachments):
                    analysis_text = self._call_ai_with_retry(
                        lambda: analyze_with_attachments(
                            system_prompt=self.system_prompt, user_prompt=artifact_prompt,
                            attachments=attachments, max_tokens=self.ai_response_max_tokens,
                        )
                    )
                else:
                    analysis_text = self._call_ai_with_retry(
                        lambda: self.ai_provider.analyze(
                            system_prompt=self.system_prompt, user_prompt=artifact_prompt,
                            max_tokens=self.ai_response_max_tokens,
                        )
                    )
            duration_seconds = perf_counter() - start_time
            self._audit_log("analysis_completed", {
                "artifact_key": artifact_key, "artifact_name": artifact_name,
                "token_count": self._estimate_tokens(analysis_text),
                "duration_seconds": round(duration_seconds, 6), "status": "success",
            })
        except Exception as error:
            duration_seconds = perf_counter() - start_time
            analysis_text = f"Analysis failed: {error}"
            self._audit_log("analysis_completed", {
                "artifact_key": artifact_key, "artifact_name": artifact_name,
                "token_count": 0, "duration_seconds": round(duration_seconds, 6),
                "status": "failed", "error": str(error),
            })

        citation_warnings = self._validate_citations(artifact_key, analysis_text)

        result = {
            "artifact_key": artifact_key, "artifact_name": artifact_name,
            "analysis": analysis_text, "model": model,
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
        """Generate a cross-artifact summary by correlating findings.

        Args:
            per_artifact_results: List of per-artifact result dicts.
            investigation_context: The user's investigation context.
            metadata: Optional host metadata mapping.

        Returns:
            The AI-generated summary text, or an error message.
        """
        metadata_map = metadata if isinstance(metadata, Mapping) else {}
        summary_prompt = build_summary_prompt(
            summary_prompt_template=self.summary_prompt_template,
            investigation_context=investigation_context,
            per_artifact_results=per_artifact_results,
            metadata_map=metadata_map,
        )

        model = self.model_info.get("model", "unknown")
        provider = self.model_info.get("provider", "unknown")
        summary_artifact_key = "cross_artifact_summary"
        summary_artifact_name = "Cross-Artifact Summary"
        summary_prompt_filename = f"{sanitize_filename(summary_artifact_key)}.md"

        self._audit_log("analysis_started", {
            "artifact_key": summary_artifact_key, "artifact_name": summary_artifact_name,
            "provider": provider, "model": model,
        })
        self._save_case_prompt(summary_prompt_filename, self.system_prompt, summary_prompt)

        start_time = perf_counter()
        try:
            summary = self._call_ai_with_retry(
                lambda: self.ai_provider.analyze(
                    system_prompt=self.system_prompt, user_prompt=summary_prompt,
                    max_tokens=self.ai_response_max_tokens,
                )
            )
            duration_seconds = perf_counter() - start_time
            self._audit_log("analysis_completed", {
                "artifact_key": summary_artifact_key, "artifact_name": summary_artifact_name,
                "token_count": self._estimate_tokens(summary),
                "duration_seconds": round(duration_seconds, 6), "status": "success",
            })
            return summary
        except Exception as error:
            duration_seconds = perf_counter() - start_time
            summary = f"Analysis failed: {error}"
            self._audit_log("analysis_completed", {
                "artifact_key": summary_artifact_key, "artifact_name": summary_artifact_name,
                "token_count": 0, "duration_seconds": round(duration_seconds, 6),
                "status": "failed", "error": str(error),
            })
            return summary

    def run_full_analysis(
        self,
        artifact_keys: Iterable[str],
        investigation_context: str,
        metadata: Mapping[str, Any] | None,
        progress_callback: Any | None = None,
        cancel_check: Any | None = None,
    ) -> dict[str, Any]:
        """Run the complete analysis pipeline: per-artifact then summary.

        Args:
            artifact_keys: Iterable of artifact key strings.
            investigation_context: The user's investigation context.
            metadata: Optional metadata mapping.
            progress_callback: Optional callable for streaming progress.
            cancel_check: Optional callable returning ``True`` when the
                analysis should be aborted early.

        Returns:
            A dict with ``per_artifact``, ``summary``, and ``model_info``.

        Raises:
            AnalysisCancelledError: If *cancel_check* returns ``True``.
        """
        if isinstance(self.ai_provider, UnavailableProvider):
            raise AIProviderError(self.ai_provider._error_message)

        self._register_artifact_paths_from_metadata(metadata)
        self._configure_explicit_analysis_date_range(metadata)
        per_artifact_results: list[dict[str, Any]] = []
        for artifact_key in artifact_keys:
            if cancel_check is not None and cancel_check():
                raise AnalysisCancelledError("Analysis cancelled by user.")
            result = self.analyze_artifact(
                artifact_key=str(artifact_key),
                investigation_context=investigation_context,
                progress_callback=progress_callback,
            )
            per_artifact_results.append(result)
            if progress_callback is not None:
                emit_analysis_progress(progress_callback, str(artifact_key), "complete", result)

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
