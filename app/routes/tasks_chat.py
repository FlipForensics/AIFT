"""Background chat task runner and chat-specific prompt helpers.

This module contains the ``run_chat`` background task and supporting
functions for rendering chat messages, compressing findings, and
resolving chat token limits.

Attributes:
    COMPRESS_FINDINGS_FALLBACK_PROMPT: Fallback prompt for findings
        compression when the prompt file is missing.
"""

from __future__ import annotations

import copy
import logging
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ..ai_providers import AIProviderError, create_provider
from ..chat import ChatManager
from .state import (
    PROJECT_ROOT,
    CHAT_HISTORY_MAX_PAIRS,
    CHAT_PROGRESS,
    DEFAULT_FORENSIC_SYSTEM_PROMPT,
    STATE_LOCK,
    emit_progress,
    get_case,
    set_progress_status,
)
from .artifacts import sanitize_prompt

__all__ = [
    "run_chat",
    "render_chat_messages_for_provider",
    "load_compress_findings_prompt",
    "compress_findings_with_ai",
    "resolve_chat_max_tokens",
]

LOGGER = logging.getLogger(__name__)

COMPRESS_FINDINGS_FALLBACK_PROMPT = (
    "You are a forensic analysis assistant. Compress per-artifact findings "
    "while preserving all critical forensic details. Return only the "
    "compressed text in bullet-point format, no preamble."
)


# ---------------------------------------------------------------------------
# Prompt / context helpers (chat-specific)
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


def render_chat_messages_for_provider(messages: list[dict[str, str]]) -> str:
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


def load_compress_findings_prompt() -> str:
    """Load the prompt used to compress per-artifact findings with AI.

    Returns:
        The compression system prompt string.
    """
    prompt_path = PROJECT_ROOT / "prompts" / "compress_findings.md"
    try:
        prompt_text = prompt_path.read_text(encoding="utf-8").strip()
    except OSError:
        LOGGER.warning("Failed to read compress findings prompt from %s; using fallback.", prompt_path)
        return COMPRESS_FINDINGS_FALLBACK_PROMPT
    return prompt_text or COMPRESS_FINDINGS_FALLBACK_PROMPT


def compress_findings_with_ai(
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
            system_prompt=load_compress_findings_prompt(),
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


def resolve_chat_max_tokens(config: dict[str, Any]) -> int:
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
# Background task: chat
# ---------------------------------------------------------------------------

def run_chat(case_id: str, message: str, config_snapshot: dict[str, Any]) -> None:
    """Execute a background chat interaction about analysis results.

    Args:
        case_id: UUID of the case.
        message: The user's chat message.
        config_snapshot: Deep copy of application config.
    """
    # Import here to avoid circular dependency with tasks.py.
    from .tasks import load_case_analysis_results, resolve_case_investigation_context, resolve_case_parsed_dir

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
        chat_max_tokens = resolve_chat_max_tokens(config_snapshot)
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
            compressed = compress_findings_with_ai(provider, per_artifact_text, chat_max_tokens)
            if compressed:
                context_block = chat_manager.rebuild_context_with_compressed_findings(
                    analysis_results=analysis_results,
                    investigation_context=investigation_context,
                    metadata=image_metadata,
                    compressed_findings=compressed,
                )

        # Collect additional parsed directories from multi-image state.
        additional_parsed_dirs: list[str] = []
        image_states = case_snapshot.get("image_states", {})
        if isinstance(image_states, dict) and len(image_states) > 1:
            for img_state in image_states.values():
                if isinstance(img_state, dict):
                    csv_dir = str(img_state.get("csv_output_dir", "")).strip()
                    if csv_dir:
                        additional_parsed_dirs.append(csv_dir)

        retrieved_payload = chat_manager.retrieve_csv_data(
            question=message,
            parsed_dir=resolve_case_parsed_dir(case_snapshot),
            additional_parsed_dirs=additional_parsed_dirs if additional_parsed_dirs else None,
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
        chat_user_prompt = render_chat_messages_for_provider(ai_messages)
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
