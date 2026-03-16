"""Chunked analysis and hierarchical merge for large artifact datasets.

When artifact CSV data exceeds the AI model's context window, this module
splits the data into row-boundary-aligned chunks, analyses each chunk
independently, and hierarchically merges the per-chunk findings via
additional AI calls until a single consolidated analysis remains.

Attributes:
    LOGGER: Module-level logger instance.
"""

from __future__ import annotations

import logging
from typing import Any

from .analyzer_constants import CSV_DATA_SECTION_RE, CSV_TRAILING_FENCE_RE
from .analyzer_utils import sanitize_filename, emit_analysis_progress

LOGGER = logging.getLogger(__name__)

__all__ = [
    "analyze_artifact_chunked",
    "split_csv_and_suffix",
    "split_csv_into_chunks",
]


def split_csv_into_chunks(csv_text: str, max_chars: int) -> list[str]:
    """Split CSV text into chunks that each fit within *max_chars*.

    Every chunk retains the original header row.

    Args:
        csv_text: Full CSV text including the header row.
        max_chars: Maximum character count per chunk (including header).

    Returns:
        A list of CSV text chunks, each starting with the header row.
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

    header_overhead = len(header) + 1
    chunk_data_budget = max_chars - header_overhead
    if chunk_data_budget <= 0:
        return [csv_text]

    chunks: list[str] = []
    current_lines: list[str] = []
    current_size = 0

    for line in data_lines:
        line_size = len(line) + 1
        if current_lines and current_size + line_size > chunk_data_budget:
            chunks.append(header + "\n" + "\n".join(current_lines))
            current_lines = []
            current_size = 0
        current_lines.append(line)
        current_size += line_size

    if current_lines:
        chunks.append(header + "\n" + "\n".join(current_lines))

    return chunks if chunks else [csv_text]


def split_csv_and_suffix(raw_csv_tail: str) -> tuple[str, str]:
    """Separate CSV rows from trailing content in a rendered prompt.

    File-based templates may append a Markdown code fence and/or a
    Final Context Reminder section after the CSV data placeholder.
    This method extracts the actual CSV rows from those trailing
    elements so that only the data is chunked, while the suffix is
    appended to every chunk prompt.

    Args:
        raw_csv_tail: The portion of the rendered prompt that follows
            the ``## Full Data (CSV)`` heading.

    Returns:
        A ``(csv_data, suffix)`` tuple.
    """
    text = raw_csv_tail

    reminder_marker = "## Final Context Reminder"
    reminder_pos = text.find(reminder_marker)
    context_suffix = ""
    if reminder_pos >= 0:
        context_suffix = "\n\n" + text[reminder_pos:].strip()
        text = text[:reminder_pos]

    trailing_fence = ""
    fence_match = CSV_TRAILING_FENCE_RE.search(text)
    if fence_match:
        trailing_fence = fence_match.group()
        text = text[: fence_match.start()]

    csv_data = text.strip()

    suffix = ""
    if trailing_fence:
        suffix += trailing_fence
    if context_suffix:
        suffix += context_suffix
    return csv_data, suffix


def analyze_artifact_chunked(
    artifact_prompt: str,
    artifact_key: str,
    artifact_name: str,
    investigation_context: str,
    model: str,
    *,
    system_prompt: str,
    ai_response_max_tokens: int,
    chunk_csv_budget: int,
    chunk_merge_prompt_template: str,
    max_merge_rounds: int,
    call_ai_with_retry_fn: Any,
    ai_provider: Any,
    audit_log_fn: Any = None,
    save_case_prompt_fn: Any = None,
    progress_callback: Any | None = None,
) -> str:
    """Analyze an artifact in multiple chunks when data exceeds context budget.

    Splits the CSV portion of the prompt into row-boundary-aligned
    chunks, analyzes each independently via the AI provider, then
    merges the per-chunk findings hierarchically.

    Args:
        artifact_prompt: The fully rendered artifact analysis prompt.
        artifact_key: Unique identifier for the artifact.
        artifact_name: Human-readable artifact name.
        investigation_context: The user's investigation context text.
        model: AI model identifier for progress reporting.
        system_prompt: The system prompt sent to the AI provider.
        ai_response_max_tokens: Token budget for the AI response.
        chunk_csv_budget: Character budget for CSV data per chunk.
        chunk_merge_prompt_template: Template for merging chunk findings.
        max_merge_rounds: Maximum hierarchical merge iterations.
        call_ai_with_retry_fn: Callable wrapping AI calls with retry.
        ai_provider: The AI provider instance.
        audit_log_fn: Optional callable ``(action, details)`` for audit.
        save_case_prompt_fn: Optional callable ``(filename, system, user)``
            for saving prompts.
        progress_callback: Optional callback for streaming progress.

    Returns:
        The merged analysis text from all chunks.
    """
    marker_match = CSV_DATA_SECTION_RE.search(artifact_prompt)
    if marker_match is None:
        return call_ai_with_retry_fn(
            lambda: ai_provider.analyze(
                system_prompt=system_prompt,
                user_prompt=artifact_prompt,
                max_tokens=ai_response_max_tokens,
            )
        )

    instructions_portion = artifact_prompt[: marker_match.end()]
    raw_csv_tail = artifact_prompt[marker_match.end():]

    csv_data, context_suffix = split_csv_and_suffix(raw_csv_tail)

    suffix_chars = len(context_suffix)
    instructions_chars = len(instructions_portion) + len(system_prompt) + suffix_chars
    csv_budget = max(1000, chunk_csv_budget - instructions_chars)

    chunks = split_csv_into_chunks(csv_data, csv_budget)
    total_chunks = len(chunks)

    if total_chunks <= 1:
        return call_ai_with_retry_fn(
            lambda: ai_provider.analyze(
                system_prompt=system_prompt,
                user_prompt=artifact_prompt,
                max_tokens=ai_response_max_tokens,
            )
        )

    LOGGER.info(
        "Chunked analysis for %s: splitting into %d chunks (budget %d chars/chunk).",
        artifact_key, total_chunks, csv_budget,
    )
    if audit_log_fn is not None:
        audit_log_fn(
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
            emit_analysis_progress(
                progress_callback, artifact_key, "thinking",
                {
                    "artifact_key": artifact_key,
                    "artifact_name": artifact_name,
                    "thinking_text": f"Analyzing {chunk_label}...",
                    "partial_text": "",
                    "model": model,
                },
            )

        safe_key = sanitize_filename(artifact_key)
        if save_case_prompt_fn is not None:
            save_case_prompt_fn(
                f"artifact_{safe_key}_chunk_{chunk_index}.md",
                system_prompt,
                chunk_prompt,
            )

        LOGGER.info("Analyzing %s %s...", artifact_key, chunk_label)
        chunk_text = call_ai_with_retry_fn(
            lambda prompt=chunk_prompt: ai_provider.analyze(
                system_prompt=system_prompt,
                user_prompt=prompt,
                max_tokens=ai_response_max_tokens,
            )
        )
        chunk_findings.append(f"### Chunk {chunk_index} of {total_chunks}\n{chunk_text}")

    merged_text = _hierarchical_merge_findings(
        chunk_findings=chunk_findings,
        artifact_key=artifact_key,
        artifact_name=artifact_name,
        investigation_context=investigation_context,
        model=model,
        system_prompt=system_prompt,
        ai_response_max_tokens=ai_response_max_tokens,
        chunk_csv_budget=chunk_csv_budget,
        chunk_merge_prompt_template=chunk_merge_prompt_template,
        max_merge_rounds=max_merge_rounds,
        call_ai_with_retry_fn=call_ai_with_retry_fn,
        ai_provider=ai_provider,
        save_case_prompt_fn=save_case_prompt_fn,
        progress_callback=progress_callback,
    )
    LOGGER.info(
        "Chunked analysis for %s complete: %d chunks merged.",
        artifact_key, total_chunks,
    )
    return merged_text


def _build_merge_prompt(
    findings_text: str,
    batch_count: int,
    artifact_key: str,
    artifact_name: str,
    investigation_context: str,
    chunk_merge_prompt_template: str,
) -> str:
    """Fill the chunk-merge template with the given findings.

    Args:
        findings_text: Combined text of per-chunk findings to merge.
        batch_count: Number of chunks/batches.
        artifact_key: Unique identifier for the artifact.
        artifact_name: Human-readable artifact name.
        investigation_context: The user's investigation context text.
        chunk_merge_prompt_template: The merge template string.

    Returns:
        The fully rendered merge prompt string.
    """
    prompt = chunk_merge_prompt_template
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
    chunk_findings: list[str],
    artifact_key: str,
    artifact_name: str,
    investigation_context: str,
    model: str,
    *,
    system_prompt: str,
    ai_response_max_tokens: int,
    chunk_csv_budget: int,
    chunk_merge_prompt_template: str,
    max_merge_rounds: int,
    call_ai_with_retry_fn: Any,
    ai_provider: Any,
    save_case_prompt_fn: Any = None,
    progress_callback: Any | None = None,
) -> str:
    """Merge chunk findings hierarchically until one result remains.

    Args:
        chunk_findings: List of per-chunk finding texts to merge.
        artifact_key: Unique identifier for the artifact.
        artifact_name: Human-readable artifact name.
        investigation_context: The user's investigation context text.
        model: AI model identifier for progress reporting.
        system_prompt: The system prompt sent to the AI provider.
        ai_response_max_tokens: Token budget for the AI response.
        chunk_csv_budget: Character budget for CSV data per chunk.
        chunk_merge_prompt_template: Template for merging findings.
        max_merge_rounds: Maximum merge iterations.
        call_ai_with_retry_fn: Callable wrapping AI calls with retry.
        ai_provider: The AI provider instance.
        save_case_prompt_fn: Optional callable for saving prompts.
        progress_callback: Optional callback for streaming progress.

    Returns:
        A single merged analysis text.
    """
    overhead = len(chunk_merge_prompt_template) + len(system_prompt) + 500
    findings_budget = max(2000, chunk_csv_budget - overhead)
    current_findings = list(chunk_findings)
    merge_round = 0

    while len(current_findings) > 1:
        merge_round += 1

        if merge_round > max_merge_rounds:
            LOGGER.warning(
                "Hierarchical merge for %s hit %d-round limit with %d findings remaining. "
                "Falling back to concatenation.",
                artifact_key, max_merge_rounds, len(current_findings),
            )
            if progress_callback is not None:
                emit_analysis_progress(
                    progress_callback, artifact_key, "thinking",
                    {
                        "artifact_key": artifact_key,
                        "artifact_name": artifact_name,
                        "thinking_text": (
                            f"Merge round limit reached ({max_merge_rounds}). "
                            f"Concatenating {len(current_findings)} remaining findings..."
                        ),
                        "partial_text": "",
                        "model": model,
                    },
                )
            total_chars = sum(len(f) for f in current_findings)
            if total_chars > findings_budget:
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

            merge_prompt = _build_merge_prompt(
                findings_text=concatenated,
                batch_count=len(current_findings),
                artifact_key=artifact_key,
                artifact_name=artifact_name,
                investigation_context=investigation_context,
                chunk_merge_prompt_template=chunk_merge_prompt_template,
            )
            safe_key = sanitize_filename(artifact_key)
            if save_case_prompt_fn is not None:
                save_case_prompt_fn(
                    f"artifact_{safe_key}_merge_fallback.md",
                    system_prompt,
                    merge_prompt,
                )
            return call_ai_with_retry_fn(
                lambda prompt=merge_prompt: ai_provider.analyze(
                    system_prompt=system_prompt,
                    user_prompt=prompt,
                    max_tokens=ai_response_max_tokens,
                )
            )

        batches: list[list[str]] = []
        current_batch: list[str] = []
        current_batch_size = 0

        for finding in current_findings:
            entry_size = len(finding) + 2
            if current_batch and current_batch_size + entry_size > findings_budget:
                batches.append(current_batch)
                current_batch = []
                current_batch_size = 0
            current_batch.append(finding)
            current_batch_size += entry_size

        if current_batch:
            batches.append(current_batch)

        if len(batches) == 1 and merge_round == 1:
            pass

        if len(batches) >= len(current_findings):
            batches = [current_findings]

        total_batches = len(batches)
        label_prefix = f"merge round {merge_round}" if merge_round > 1 else "merge"

        LOGGER.info(
            "Hierarchical %s for %s: %d batches from %d findings (budget %d chars).",
            label_prefix, artifact_key, total_batches,
            len(current_findings), findings_budget,
        )

        if progress_callback is not None:
            emit_analysis_progress(
                progress_callback, artifact_key, "thinking",
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
            merge_prompt = _build_merge_prompt(
                findings_text=batch_text,
                batch_count=len(batch),
                artifact_key=artifact_key,
                artifact_name=artifact_name,
                investigation_context=investigation_context,
                chunk_merge_prompt_template=chunk_merge_prompt_template,
            )

            safe_key = sanitize_filename(artifact_key)
            if save_case_prompt_fn is not None:
                save_case_prompt_fn(
                    f"artifact_{safe_key}_merge_r{merge_round}_b{batch_index}.md",
                    system_prompt,
                    merge_prompt,
                )

            merged = call_ai_with_retry_fn(
                lambda prompt=merge_prompt: ai_provider.analyze(
                    system_prompt=system_prompt,
                    user_prompt=prompt,
                    max_tokens=ai_response_max_tokens,
                )
            )
            next_findings.append(f"### Merged batch {batch_index}\n{merged}")

        current_findings = next_findings

    return current_findings[0] if current_findings else ""
