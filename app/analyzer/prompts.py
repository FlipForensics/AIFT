"""Prompt template loading and construction for forensic analysis.

Provides functions for loading prompt templates from disk, loading
per-artifact instruction prompts, resolving AI column projection
configurations, and building the cross-artifact summary prompt.

These were extracted from ``ForensicAnalyzer`` to keep the core
orchestration class focused on pipeline coordination.

Attributes:
    LOGGER: Module-level logger instance.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Mapping

import yaml

from .constants import PROJECT_ROOT
from .ioc import build_priority_directives, extract_ioc_targets, format_ioc_targets
from .utils import coerce_projection_columns, normalize_artifact_key, normalize_os_type

LOGGER = logging.getLogger(__name__)

__all__ = [
    "build_summary_prompt",
    "load_artifact_ai_column_projections",
    "load_artifact_instruction_prompts",
    "load_prompt_template",
    "resolve_artifact_ai_columns_config_path",
]


def load_prompt_template(prompts_dir: Path, filename: str, default: str) -> str:
    """Read a prompt template file from the prompts directory.

    Args:
        prompts_dir: Directory containing prompt template files.
        filename: Name of the template file.
        default: Fallback template string if the file cannot be read.

    Returns:
        The template text, or *default* if reading fails.
    """
    try:
        prompt_path = prompts_dir / filename
        return prompt_path.read_text(encoding="utf-8")
    except OSError:
        return default


def load_artifact_instruction_prompts(
    prompts_dir: Path,
    os_type: str = "windows",
) -> dict[str, str]:
    """Load per-artifact analysis instruction prompts from disk.

    Selects the OS-specific instruction directory based on *os_type*:

    - ``"windows"`` (default): ``artifact_instructions/``
    - ``"linux"``: ``artifact_instructions_linux/``

    For any other OS value the function falls back to the Windows
    directory.

    Args:
        prompts_dir: Directory containing prompt template files.
        os_type: Operating system identifier (e.g. ``"windows"``,
            ``"linux"``).  Determines which sub-directory to scan.

    Returns:
        A dict mapping lowercased artifact keys to instruction prompt text.
    """
    normalized_os = normalize_os_type(os_type)
    if normalized_os == "linux":
        instructions_dir = prompts_dir / "artifact_instructions_linux"
    else:
        instructions_dir = prompts_dir / "artifact_instructions"

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


def resolve_artifact_ai_columns_config_path(
    configured_path: str | Path,
    case_dir: Path | None,
) -> Path:
    """Resolve the artifact AI columns config path to an absolute Path.

    Checks for the file at the configured path, then relative to the
    case directory, and finally relative to the project root.

    Args:
        configured_path: The configured path (may be relative).
        case_dir: Path to the current case directory, or ``None``.

    Returns:
        Resolved absolute ``Path`` to the YAML config file.
    """
    configured = Path(configured_path).expanduser()
    if configured.is_absolute():
        return configured

    candidates: list[Path] = []
    if case_dir is not None:
        candidates.append(case_dir / configured)
    candidates.append(PROJECT_ROOT / configured)

    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[-1]


def load_artifact_ai_column_projections(
    config_path: Path,
    os_type: str = "windows",
) -> dict[str, tuple[str, ...]]:
    """Load per-artifact column projection configuration from YAML.

    Handles OS-suffixed keys (e.g. ``services_linux``) by mapping them
    to the base key only when the active *os_type* matches the suffix.
    This prevents Linux-specific column definitions from overwriting
    their Windows counterparts (and vice-versa).

    Args:
        config_path: Absolute path to the YAML config file.
        os_type: Active operating system type (``"windows"``,
            ``"linux"``, etc.).  Controls which OS-suffixed keys are
            accepted.

    Returns:
        A dict mapping normalized artifact keys to tuples of column names.
    """
    normalized_os = normalize_os_type(os_type)

    try:
        with config_path.open("r", encoding="utf-8") as handle:
            parsed = yaml.safe_load(handle) or {}
    except (OSError, yaml.YAMLError) as error:
        LOGGER.warning(
            "Failed to load AI column projection config from %s: %s. "
            "AI column projection is disabled.", config_path, error,
        )
        return {}

    if not isinstance(parsed, Mapping):
        LOGGER.warning(
            "Invalid AI column projection config in %s: expected a mapping, got %s.",
            config_path, type(parsed).__name__,
        )
        return {}

    source: Any = parsed.get("artifact_ai_columns", parsed)
    if not isinstance(source, Mapping):
        LOGGER.warning(
            "Invalid AI column projection config in %s: 'artifact_ai_columns' must be a mapping, got %s.",
            config_path, type(source).__name__,
        )
        return {}

    projections: dict[str, tuple[str, ...]] = {}
    for artifact_key, raw_columns in source.items():
        if artifact_key is None:
            continue
        raw_key = str(artifact_key)

        # Handle OS-suffixed keys like "services_linux": accept only
        # when the suffix matches the current OS, and store under the
        # base key so the correct projection wins.
        os_suffix = f"_{normalized_os}"
        if raw_key.endswith(os_suffix):
            effective_key = raw_key[: -len(os_suffix)]
        elif raw_key.rsplit("_", 1)[-1] in ("linux", "windows", "esxi"):
            # OS-suffixed key for a *different* OS — skip it.
            continue
        else:
            effective_key = raw_key

        normalized_key = normalize_artifact_key(effective_key)
        columns = coerce_projection_columns(raw_columns)
        if columns:
            projections[normalized_key] = tuple(columns)
    return projections


def build_summary_prompt(
    summary_prompt_template: str,
    investigation_context: str,
    per_artifact_results: list[Mapping[str, Any]],
    metadata_map: Mapping[str, Any],
) -> str:
    """Build the cross-artifact summary prompt from a template.

    Assembles per-artifact findings into a single prompt using the
    summary template, filling in investigation context, IOC targets,
    priority directives, and host metadata placeholders.

    Args:
        summary_prompt_template: The summary template string with
            ``{{placeholder}}`` markers.
        investigation_context: The user's investigation context text.
        per_artifact_results: List of per-artifact result dicts, each
            with ``artifact_key``, ``artifact_name``, and ``analysis``.
        metadata_map: Host metadata mapping with optional ``hostname``,
            ``os_version``, ``os_type``, and ``domain`` keys.

    Returns:
        The fully rendered summary prompt string.
    """
    findings_blocks: list[str] = []
    for result in per_artifact_results:
        artifact_key = str(result.get("artifact_key", "unknown"))
        artifact_name = str(result.get("artifact_name", artifact_key))
        analysis = str(result.get("analysis", "")).strip()
        findings_blocks.append(f"### {artifact_name} ({artifact_key})\n{analysis}")

    findings_text = (
        "\n\n".join(findings_blocks)
        if findings_blocks
        else "No per-artifact findings available."
    )

    extracted_iocs = extract_ioc_targets(investigation_context)
    priority_directives = build_priority_directives(investigation_context, ioc_targets=extracted_iocs)
    ioc_targets = format_ioc_targets(investigation_context, ioc_targets=extracted_iocs)

    summary_prompt = summary_prompt_template
    replacements = {
        "priority_directives": priority_directives,
        "investigation_context": investigation_context.strip() or "No investigation context provided.",
        "ioc_targets": ioc_targets,
        "hostname": str(metadata_map.get("hostname", "Unknown")),
        "os_version": str(metadata_map.get("os_version", "Unknown")),
        "os_type": str(metadata_map.get("os_type", "Unknown")),
        "domain": str(metadata_map.get("domain", "Unknown")),
        "per_artifact_findings": findings_text,
    }
    for placeholder, value in replacements.items():
        summary_prompt = summary_prompt.replace(f"{{{{{placeholder}}}}}", value)

    return summary_prompt
