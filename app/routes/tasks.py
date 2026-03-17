"""Background task runners for parsing, analysis, and chat.

This module contains the long-running functions that execute on background
``threading.Thread`` instances:

* ``run_parse`` -- Parse forensic artifacts via Dissect.
* ``run_analysis`` -- AI-powered analysis of parsed CSV artifacts.
* ``run_chat`` -- Follow-up chat with the AI about analysis results.

Each runner emits SSE progress events through the shared progress stores
defined in :mod:`routes_state` and uses a case-log-context wrapper to
ensure log messages are tagged with the case ID.

Attributes:
    _COMPRESS_FINDINGS_FALLBACK_PROMPT: Fallback prompt for findings
        compression when the prompt file is missing.
"""

from __future__ import annotations

import copy
import json
import logging
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ..ai_providers import AIProviderError, create_provider
from ..analyzer import ForensicAnalyzer
from ..case_logging import case_log_context
from ..chat import ChatManager
from ..parser import ForensicParser
from .state import (
    LOGGER as _ROUTES_LOGGER,
    PROJECT_ROOT,
    CHAT_HISTORY_MAX_PAIRS,
    DEFAULT_FORENSIC_SYSTEM_PROMPT,
    MODE_PARSE_AND_AI,
    ANALYSIS_PROGRESS,
    CHAT_PROGRESS,
    PARSE_PROGRESS,
    STATE_LOCK,
    emit_progress,
    get_case,
    mark_case_status,
    new_progress,
    safe_int,
    set_progress_status,
)
from .artifacts import (
    extract_parse_progress,
    sanitize_prompt,
    normalize_artifact_mode,
)
from .evidence import (
    build_csv_map,
    collect_case_csv_paths,
    resolve_case_csv_output_dir,
)

__all__ = [
    "run_task_with_case_log_context",
    "run_parse",
    "run_analysis",
    "run_chat",
    "load_case_analysis_results",
    "resolve_case_investigation_context",
    "resolve_case_parsed_dir",
]

LOGGER = logging.getLogger(__name__)

_COMPRESS_FINDINGS_FALLBACK_PROMPT = (
    "You are a forensic analysis assistant. Compress per-artifact findings "
    "while preserving all critical forensic details. Return only the "
    "compressed text in bullet-point format, no preamble."
)


# ---------------------------------------------------------------------------
# Prompt / context helpers
# ---------------------------------------------------------------------------

def _load_forensic_system_prompt() -> str:
    """Load the forensic AI system prompt from the ``prompts/`` directory.

    Returns:
        The system prompt string, or the default fallback.
    """
    prompt_path = PROJECT_ROOT / "prompts" / "system_prompt.md"
    try:
        prompt_text = prompt_path.read_text(encoding="utf-8").strip()
    except OSError:
        LOGGER.warning("Failed to read system prompt from %s; using fallback prompt.", prompt_path)
        return DEFAULT_FORENSIC_SYSTEM_PROMPT
    return prompt_text or DEFAULT_FORENSIC_SYSTEM_PROMPT


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


def _render_chat_messages_for_provider(messages: list[dict[str, str]]) -> str:
    """Render chat messages into a single prompt string for the AI.

    Args:
        messages: Ordered list of message dicts with ``role`` and ``content``.

    Returns:
        Formatted multi-section prompt string.
    """
    rendered_sections: list[str] = []
    first_user_rendered = False
    last_user_index = -1
    for index, message in enumerate(messages):
        role = str(message.get("role", "")).strip().lower()
        content = str(message.get("content", "")).strip()
        if role == "user" and content:
            last_user_index = index

    for index, message in enumerate(messages):
        role = str(message.get("role", "")).strip().lower()
        content = str(message.get("content", "")).strip()
        if not content or role == "system":
            continue

        if role == "user" and not first_user_rendered:
            rendered_sections.append(f"Context Block:\n{content}")
            first_user_rendered = True
            continue

        if role == "user" and index == last_user_index:
            rendered_sections.append(f"New User Question:\n{content}")
            continue

        label = "User" if role == "user" else "Assistant" if role == "assistant" else role.title()
        rendered_sections.append(f"{label}:\n{content}")

    return "\n\n".join(rendered_sections).strip()


def _load_compress_findings_prompt() -> str:
    """Load the prompt used to compress per-artifact findings with AI.

    Returns:
        The compression system prompt string.
    """
    prompt_path = PROJECT_ROOT / "prompts" / "compress_findings.md"
    try:
        prompt_text = prompt_path.read_text(encoding="utf-8").strip()
    except OSError:
        LOGGER.warning("Failed to read compress findings prompt from %s; using fallback.", prompt_path)
        return _COMPRESS_FINDINGS_FALLBACK_PROMPT
    return prompt_text or _COMPRESS_FINDINGS_FALLBACK_PROMPT


def _compress_findings_with_ai(
    provider: Any,
    findings_text: str,
    max_tokens: int,
) -> str | None:
    """Use the AI provider to compress per-artifact findings.

    Args:
        provider: AI provider instance with an ``analyze`` method.
        findings_text: Full per-artifact findings text.
        max_tokens: Configured max token budget.

    Returns:
        Compressed findings text, or ``None`` on failure.
    """
    if not findings_text or not findings_text.strip():
        return None

    target_tokens = max(200, int(max_tokens * 0.25))
    try:
        compressed = provider.analyze(
            system_prompt=_load_compress_findings_prompt(),
            user_prompt=(
                f"Compress the following per-artifact forensic findings to "
                f"roughly {target_tokens} tokens. Keep the bullet-point "
                f"format (\"- artifact: summary\"). Preserve every "
                f"suspicious indicator, timestamp, path, and conclusion.\n\n"
                f"{findings_text}"
            ),
            max_tokens=target_tokens,
        )
        result = str(compressed).strip()
        return result if result else None
    except (AIProviderError, Exception):
        LOGGER.warning(
            "AI-powered findings compression failed; falling back to full context.",
            exc_info=True,
        )
        return None


def _resolve_chat_max_tokens(config: dict[str, Any]) -> int:
    """Resolve the maximum token count for chat from config.

    Args:
        config: Full application configuration dict.

    Returns:
        Positive integer token limit.

    Raises:
        ValueError: If the setting is missing or invalid.
    """
    analysis_config = config.get("analysis", {})
    if not isinstance(analysis_config, dict):
        raise ValueError(
            "Chat max tokens are not configured. Set `analysis.ai_max_tokens` in Settings."
        )

    if "ai_max_tokens" not in analysis_config:
        raise ValueError(
            "Chat max tokens are not configured. Set `analysis.ai_max_tokens` in Settings."
        )

    try:
        resolved = int(analysis_config.get("ai_max_tokens"))
    except (TypeError, ValueError):
        raise ValueError(
            "Invalid `analysis.ai_max_tokens` value in Settings. Provide a positive integer."
        ) from None

    if resolved <= 0:
        raise ValueError(
            "Invalid `analysis.ai_max_tokens` value in Settings. Provide a positive integer."
        )
    return resolved


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
        csv_output_dir = resolve_case_csv_output_dir(case_snapshot, config_snapshot=config_snapshot)
        with ForensicParser(
            evidence_path=evidence_path,
            case_dir=case_dir,
            audit_logger=audit_logger,
            parsed_dir=csv_output_dir,
        ) as parser:
            results: list[dict[str, Any]] = []
            total = len(parse_artifacts)

            for index, artifact in enumerate(parse_artifacts, start=1):
                emit_progress(
                    PARSE_PROGRESS, case_id,
                    {"type": "artifact_started", "artifact_key": artifact, "index": index, "total": total},
                )

                def _progress_callback(*args: Any, **_kwargs: Any) -> None:
                    """Emit per-artifact parse progress events."""
                    artifact_key, record_count = extract_parse_progress(artifact, args)
                    emit_progress(
                        PARSE_PROGRESS, case_id,
                        {"type": "artifact_progress", "artifact_key": artifact_key, "record_count": record_count},
                    )

                result = parser.parse_artifact(artifact, progress_callback=_progress_callback)
                result_entry = {"artifact_key": artifact, **result}
                results.append(result_entry)

                emit_progress(
                    PARSE_PROGRESS, case_id,
                    {
                        "type": "artifact_completed" if result.get("success") else "artifact_failed",
                        "artifact_key": artifact,
                        "record_count": safe_int(result.get("record_count", 0)),
                        "duration_seconds": float(result.get("duration_seconds", 0.0)),
                        "csv_path": str(result.get("csv_path", "")),
                        "error": result.get("error"),
                    },
                )

            csv_map = build_csv_map(results)
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

def run_analysis(case_id: str, prompt: str, config_snapshot: dict[str, Any]) -> None:
    """Execute background AI-powered forensic analysis.

    Args:
        case_id: UUID of the case.
        prompt: Investigation context / user prompt.
        config_snapshot: Deep copy of application config.
    """
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
        )
        metadata = dict(image_metadata_snapshot)
        metadata["artifact_csv_paths"] = csv_map
        metadata["parse_results"] = parse_results_snapshot
        metadata["analysis_artifacts"] = list(artifacts)
        metadata["artifact_options"] = artifact_options_snapshot
        if isinstance(analysis_date_range, dict):
            metadata["analysis_date_range"] = {
                "start_date": str(analysis_date_range.get("start_date", "")).strip(),
                "end_date": str(analysis_date_range.get("end_date", "")).strip(),
            }

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

        output = analyzer.run_full_analysis(
            artifact_keys=artifacts,
            investigation_context=prompt,
            metadata=metadata,
            progress_callback=_analysis_progress,
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
    except Exception:
        LOGGER.exception("Background analysis failed for case %s", case_id)
        user_message = (
            "Analysis failed due to an internal error. "
            "Verify provider settings and retry."
        )
        mark_case_status(case_id, "error")
        set_progress_status(ANALYSIS_PROGRESS, case_id, "failed", user_message)
        emit_progress(ANALYSIS_PROGRESS, case_id, {"type": "analysis_failed", "error": user_message})


# ---------------------------------------------------------------------------
# Background task: chat
# ---------------------------------------------------------------------------

def run_chat(case_id: str, message: str, config_snapshot: dict[str, Any]) -> None:
    """Execute a background chat interaction about analysis results.

    Args:
        case_id: UUID of the case.
        message: The user's chat message.
        config_snapshot: Deep copy of application config.
    """
    case = get_case(case_id)
    if case is None:
        set_progress_status(CHAT_PROGRESS, case_id, "failed", "Case not found.")
        emit_progress(CHAT_PROGRESS, case_id, {"type": "error", "message": "Case not found."})
        return

    with STATE_LOCK:
        case_snapshot = dict(case)
        audit_logger = case["audit"]

    analysis_results = load_case_analysis_results(case_snapshot)
    if not analysis_results:
        message_text = "No analysis results available for this case. Run analysis first."
        set_progress_status(CHAT_PROGRESS, case_id, "failed", message_text)
        emit_progress(CHAT_PROGRESS, case_id, {"type": "error", "message": message_text})
        return

    if not isinstance(config_snapshot, dict):
        set_progress_status(CHAT_PROGRESS, case_id, "failed", "Invalid in-memory configuration state.")
        emit_progress(CHAT_PROGRESS, case_id, {"type": "error", "message": "Invalid in-memory configuration state."})
        return

    try:
        chat_max_tokens = _resolve_chat_max_tokens(config_snapshot)
    except ValueError as error:
        message_text = str(error)
        LOGGER.warning("Chat configuration rejected for case %s: %s", case_id, message_text)
        set_progress_status(CHAT_PROGRESS, case_id, "failed", message_text)
        emit_progress(CHAT_PROGRESS, case_id, {"type": "error", "message": message_text})
        return

    case_dir = case_snapshot["case_dir"]
    chat_manager = ChatManager(case_dir, max_context_tokens=chat_max_tokens)
    history_snapshot = chat_manager.get_history()
    message_index = (
        sum(1 for entry in history_snapshot if str(entry.get("role", "")).strip().lower() == "user") + 1
    )
    audit_logger.log(
        "chat_message_sent",
        {
            "message_index": message_index,
            "message": sanitize_prompt(message, max_chars=8000),
        },
    )

    try:
        prompt_budget = int(chat_max_tokens * 0.8)
        provider = create_provider(copy.deepcopy(config_snapshot))

        investigation_context = resolve_case_investigation_context(case_snapshot)
        image_metadata = dict(case_snapshot.get("image_metadata", {}))

        context_block = chat_manager.build_chat_context(
            analysis_results=analysis_results,
            investigation_context=investigation_context,
            metadata=image_metadata,
        )

        if chat_manager.context_needs_compression(context_block, prompt_budget):
            per_artifact_text = chat_manager._format_per_artifact_findings(
                analysis_results if isinstance(analysis_results, Mapping) else {},
            )
            compressed = _compress_findings_with_ai(provider, per_artifact_text, chat_max_tokens)
            if compressed:
                context_block = chat_manager.rebuild_context_with_compressed_findings(
                    analysis_results=analysis_results,
                    investigation_context=investigation_context,
                    metadata=image_metadata,
                    compressed_findings=compressed,
                )

        retrieved_payload = chat_manager.retrieve_csv_data(
            question=message,
            parsed_dir=resolve_case_parsed_dir(case_snapshot),
        )
        retrieved_artifacts: list[str] = []
        if isinstance(retrieved_payload.get("artifacts"), list):
            retrieved_artifacts = [
                str(item).strip()
                for item in retrieved_payload.get("artifacts", [])
                if str(item).strip()
            ]

        message_for_ai = message
        retrieved_data = str(retrieved_payload.get("data", "")).strip()
        if bool(retrieved_payload.get("retrieved")) and retrieved_data:
            message_for_ai = (
                "Retrieved CSV data for this question:\n"
                f"{retrieved_data}\n\n"
                "User question:\n"
                f"{message}"
            )
            audit_logger.log(
                "chat_data_retrieval",
                {
                    "message_index": message_index,
                    "artifacts": list(retrieved_artifacts),
                    "rows_returned": retrieved_data.count("\n"),
                },
            )

        system_prompt = _load_forensic_system_prompt()

        fixed_tokens = (
            chat_manager.estimate_token_count(system_prompt)
            + chat_manager.estimate_token_count(context_block)
            + chat_manager.estimate_token_count(message_for_ai)
        )
        history_budget = max(0, prompt_budget - fixed_tokens)

        recent_history = chat_manager.get_recent_history(max_pairs=CHAT_HISTORY_MAX_PAIRS)
        fitted_history = chat_manager.fit_history(recent_history, history_budget)

        ai_messages: list[dict[str, str]] = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": context_block},
        ]
        for history_message in fitted_history:
            role = str(history_message.get("role", "")).strip().lower()
            content = str(history_message.get("content", "")).strip()
            if role in {"user", "assistant"} and content:
                ai_messages.append({"role": role, "content": content})
        ai_messages.append({"role": "user", "content": message_for_ai})
        chat_user_prompt = _render_chat_messages_for_provider(ai_messages)
        if not chat_user_prompt:
            chat_user_prompt = (
                f"Context Block:\n{context_block}\n\n"
                f"New User Question:\n{message_for_ai}"
            )
        started_at = time.perf_counter()
        chunks: list[str] = []
        chat_response_max_tokens = max(1, int(chat_max_tokens * 0.2))
        for chunk in provider.analyze_stream(
            system_prompt=system_prompt,
            user_prompt=chat_user_prompt,
            max_tokens=chat_response_max_tokens,
        ):
            chunk_text = str(chunk)
            if not chunk_text:
                continue
            chunks.append(chunk_text)
            emit_progress(CHAT_PROGRESS, case_id, {"type": "token", "content": chunk_text})

        response_text = "".join(chunks).strip()
        duration_ms = int((time.perf_counter() - started_at) * 1000)
        if not response_text:
            raise AIProviderError("Provider returned an empty response.")

        chat_manager.add_message("user", message, metadata={"message_index": message_index})
        assistant_metadata: dict[str, Any] = {"message_index": message_index}
        if retrieved_artifacts:
            assistant_metadata["data_retrieved"] = list(retrieved_artifacts)
        chat_manager.add_message("assistant", response_text, metadata=assistant_metadata)

        audit_logger.log(
            "chat_response_received",
            {
                "message_index": message_index,
                "duration_ms": duration_ms,
                "response_tokens_estimate": chat_manager.estimate_token_count(response_text),
                "data_retrieved": bool(retrieved_artifacts),
                "retrieved_artifacts": list(retrieved_artifacts),
            },
        )

        set_progress_status(CHAT_PROGRESS, case_id, "completed")
        emit_progress(CHAT_PROGRESS, case_id, {
            "type": "done",
            "data_retrieved": list(retrieved_artifacts),
        })
    except ValueError as error:
        LOGGER.warning("Chat request rejected for case %s: %s", case_id, error)
        set_progress_status(CHAT_PROGRESS, case_id, "failed", str(error))
        emit_progress(CHAT_PROGRESS, case_id, {"type": "error", "message": str(error)})
    except AIProviderError as error:
        LOGGER.warning("Chat provider request failed for case %s: %s", case_id, error)
        set_progress_status(CHAT_PROGRESS, case_id, "failed", str(error))
        emit_progress(CHAT_PROGRESS, case_id, {"type": "error", "message": str(error)})
    except Exception:
        LOGGER.exception("Unexpected failure during chat for case %s", case_id)
        error_message = "Unexpected error while generating chat response."
        set_progress_status(CHAT_PROGRESS, case_id, "failed", error_message)
        emit_progress(CHAT_PROGRESS, case_id, {"type": "error", "message": error_message})
