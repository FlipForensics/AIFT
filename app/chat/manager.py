"""Chat history storage and context management for post-analysis Q&A.

Provides the :class:`ChatManager` class that persists per-case chat
conversations as JSONL files and builds context blocks for AI follow-up
questions after an analysis is complete.

Key responsibilities:

* **Message persistence** -- Append-only JSONL storage of user/assistant
  message pairs with UTC timestamps, analogous to the audit trail but
  scoped to interactive chat.
* **Context assembly** -- Combines investigation context, system metadata,
  executive summary, and per-artifact findings into a single text block
  suitable for injection into an AI system prompt.
* **Token budgeting** -- Estimates token counts and trims conversation
  history to fit within a configurable context window, dropping the oldest
  pairs first.
* **CSV data retrieval** -- Delegates to :mod:`~app.chat.csv_retrieval`
  for heuristic matching of user questions to parsed artifact CSV files.

Attributes:
    VALID_ROLES: Frozenset of accepted message role strings
        (``"user"`` and ``"assistant"``).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Mapping

from ..audit import _utc_now_iso8601_ms
from .csv_retrieval import retrieve_csv_data as _retrieve_csv_data

__all__ = ["ChatManager"]

log = logging.getLogger(__name__)

VALID_ROLES = frozenset({"user", "assistant"})


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


class ChatManager:
    """Persist and retrieve case-scoped chat history records.

    Each instance is bound to a single case directory and manages a
    ``chat_history.jsonl`` file containing timestamped user/assistant
    message pairs.  The manager also assembles context blocks for AI
    prompts by combining analysis results, investigation context, and
    system metadata.

    Attributes:
        MAX_CONTEXT_TOKENS: Maximum token budget for chat context assembly.
        case_dir: Resolved path to the case directory.
        chat_file: Path to the ``chat_history.jsonl`` file.
    """

    MAX_CONTEXT_TOKENS = 100000

    def __init__(self, case_dir: str | Path, max_context_tokens: int | None = None) -> None:
        """Initialise the chat manager for a case directory.

        Args:
            case_dir: Path to the case directory.  Created if it does
                not exist when messages are first written.
            max_context_tokens: Optional override for the maximum token
                budget.  Falls back to :attr:`MAX_CONTEXT_TOKENS` when
                *None* or invalid.
        """
        self.case_dir = Path(case_dir)
        self.chat_file = self.case_dir / "chat_history.jsonl"
        self.MAX_CONTEXT_TOKENS = self._resolve_max_context_tokens(max_context_tokens)

    # ------------------------------------------------------------------
    # Message persistence
    # ------------------------------------------------------------------

    def add_message(
        self,
        role: str,
        content: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Append one message entry to the case chat JSONL history.

        The message is written as a single JSON line with a UTC ISO 8601
        timestamp.  The file is opened, written, and flushed for each call
        to minimise data loss on unexpected termination.

        Args:
            role: Message role -- must be ``"user"`` or ``"assistant"``.
            content: The message text.
            metadata: Optional dictionary of extra metadata to attach to
                the record (e.g. token counts, retrieval info).

        Raises:
            ValueError: If *role* is not in :data:`VALID_ROLES`.
            TypeError: If *content* is not a string or *metadata* is not a
                dict when provided.
        """
        normalized_role = str(role).strip().lower()
        if normalized_role not in VALID_ROLES:
            allowed = ", ".join(sorted(VALID_ROLES))
            raise ValueError(f"Unsupported role '{role}'. Allowed values: {allowed}.")
        if not isinstance(content, str):
            raise TypeError("content must be a string.")
        if metadata is not None and not isinstance(metadata, dict):
            raise TypeError("metadata must be a dictionary when provided.")

        message: dict[str, Any] = {
            "timestamp": _utc_now_iso8601_ms(),
            "role": normalized_role,
            "content": content,
        }
        if metadata is not None:
            message["metadata"] = metadata

        line = json.dumps(message, separators=(",", ":")) + "\n"
        self.chat_file.parent.mkdir(parents=True, exist_ok=True)
        with self.chat_file.open("ab", buffering=0) as chat_stream:
            chat_stream.write(line.encode("utf-8"))
            chat_stream.flush()

    def get_history(self) -> list[dict[str, Any]]:
        """Load the full chat history in insertion order.

        Reads every line from ``chat_history.jsonl``, skipping blank lines
        and malformed JSON entries (which are logged as warnings).

        Returns:
            A list of message dictionaries, each containing at least
            ``timestamp``, ``role``, and ``content`` keys.
        """
        if not self.chat_file.exists():
            return []

        history: list[dict[str, Any]] = []
        with self.chat_file.open("r", encoding="utf-8") as chat_stream:
            for line_no, raw_line in enumerate(chat_stream, 1):
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    log.warning("Skipping malformed JSON on line %d of %s", line_no, self.chat_file)
                    continue
                if isinstance(record, dict):
                    history.append(record)
        return history

    def get_recent_history(self, max_pairs: int = 20) -> list[dict[str, Any]]:
        """Return the most recent complete user/assistant message pairs.

        Messages are paired in order: a ``user`` message followed by the
        next ``assistant`` message forms a pair.  Only the last
        *max_pairs* complete pairs are returned.

        Args:
            max_pairs: Maximum number of user/assistant pairs to return.

        Returns:
            A flat list of message dictionaries alternating
            ``[user, assistant, user, assistant, ...]``.
        """
        if max_pairs <= 0:
            return []

        history = self.get_history()
        paired_messages: list[tuple[dict[str, Any], dict[str, Any]]] = []
        pending_user: dict[str, Any] | None = None

        for message in history:
            role = message.get("role")
            if role == "user":
                pending_user = message
                continue
            if role == "assistant" and pending_user is not None:
                paired_messages.append((pending_user, message))
                pending_user = None

        recent_pairs = paired_messages[-max_pairs:]
        recent_history: list[dict[str, Any]] = []
        for user_message, assistant_message in recent_pairs:
            recent_history.append(user_message)
            recent_history.append(assistant_message)
        return recent_history

    def clear(self) -> None:
        """Delete the chat history file when present.

        This is a destructive operation -- all chat messages for this
        case are permanently removed.
        """
        if self.chat_file.exists():
            self.chat_file.unlink()

    # ------------------------------------------------------------------
    # Context assembly
    # ------------------------------------------------------------------

    def build_chat_context(
        self,
        analysis_results: Mapping[str, Any] | None,
        investigation_context: str,
        metadata: Mapping[str, Any] | None,
    ) -> str:
        """Build a compact, complete context block for chat prompts.

        Assembles investigation context, system metadata (hostname, OS,
        domain), executive summary, and per-artifact findings into a
        single multi-section text string suitable for injection into an
        AI system prompt.

        Args:
            analysis_results: The full analysis results mapping (may
                contain ``summary`` and ``per_artifact`` keys).
            investigation_context: Free-text investigation context
                provided by the analyst.
            metadata: Evidence metadata mapping (hostname, os_version,
                domain, etc.).

        Returns:
            A formatted multi-section context string.
        """
        analysis = analysis_results if isinstance(analysis_results, Mapping) else {}
        per_artifact_lines = self._format_per_artifact_findings(analysis)
        findings_section = f"Per-Artifact Findings:\n{per_artifact_lines}"
        return self._assemble_context(
            analysis_results, investigation_context, metadata, findings_section,
        )

    def rebuild_context_with_compressed_findings(
        self,
        analysis_results: Mapping[str, Any] | None,
        investigation_context: str,
        metadata: Mapping[str, Any] | None,
        compressed_findings: str,
    ) -> str:
        """Rebuild the context block using pre-compressed per-artifact findings.

        Identical to :meth:`build_chat_context` except that the
        per-artifact section is replaced with an externally compressed
        version of the findings, used when the full context exceeds the
        token budget.

        Args:
            analysis_results: The full analysis results mapping.
            investigation_context: Free-text investigation context.
            metadata: Evidence metadata mapping.
            compressed_findings: Pre-compressed per-artifact findings
                text to substitute into the context block.

        Returns:
            A formatted multi-section context string with compressed
            findings.
        """
        findings_section = f"Per-Artifact Findings (compressed):\n{compressed_findings}"
        return self._assemble_context(
            analysis_results, investigation_context, metadata, findings_section,
        )

    def context_needs_compression(self, context_block: str, token_budget: int) -> bool:
        """Return *True* when the context block exceeds 80 % of the token budget.

        Args:
            context_block: The assembled context text to measure.
            token_budget: Maximum token allowance for the context window.

        Returns:
            *True* if the estimated token count of *context_block* exceeds
            80 % of *token_budget*, *False* otherwise.
        """
        if token_budget <= 0:
            return False
        return self.estimate_token_count(context_block) > int(token_budget * 0.8)

    # ------------------------------------------------------------------
    # CSV data retrieval (delegates to csv_retrieval module)
    # ------------------------------------------------------------------

    def retrieve_csv_data(self, question: str, parsed_dir: str | Path) -> dict[str, Any]:
        """Best-effort retrieval of raw CSV rows for data-centric chat questions.

        Delegates to :func:`~app.chat.csv_retrieval.retrieve_csv_data`.

        Args:
            question: The user's chat question text.
            parsed_dir: Path to the directory containing parsed artifact
                CSV files.

        Returns:
            A dictionary with a ``retrieved`` boolean.  When *True*, also
            includes ``artifacts`` (list of matched CSV filenames) and
            ``data`` (formatted row text).
        """
        return _retrieve_csv_data(question, parsed_dir)

    # ------------------------------------------------------------------
    # Token budgeting
    # ------------------------------------------------------------------

    def estimate_token_count(self, text: str) -> int:
        """Estimate token count using a rough 4-characters-per-token ratio.

        Args:
            text: The string to estimate tokens for.

        Returns:
            Approximate token count (integer).
        """
        if not text:
            return 0
        return int(len(text) / 4)

    def fit_history(
        self,
        history: list[dict[str, Any]],
        max_tokens: int,
    ) -> list[dict[str, Any]]:
        """Trim conversation history to fit within *max_tokens*.

        Pairs up user/assistant messages and drops the oldest complete
        pairs first until the estimated total token count fits within
        the budget.

        Args:
            history: Flat list of message dictionaries to trim.
            max_tokens: Maximum token budget for the returned history.

        Returns:
            A (possibly shorter) flat list of message dictionaries that
            fits within *max_tokens*.
        """
        if max_tokens <= 0:
            return []
        if not history:
            return []

        # Pair up messages so we can drop oldest pairs.
        pairs: list[tuple[dict[str, Any], dict[str, Any]]] = []
        pending_user: dict[str, Any] | None = None
        for msg in history:
            role = msg.get("role")
            if role == "user":
                pending_user = msg
            elif role == "assistant" and pending_user is not None:
                pairs.append((pending_user, msg))
                pending_user = None

        # Drop oldest pairs until total fits.
        while pairs:
            total = sum(
                self.estimate_token_count(str(u.get("content", "")))
                + self.estimate_token_count(str(a.get("content", "")))
                for u, a in pairs
            )
            if total <= max_tokens:
                break
            pairs.pop(0)

        result: list[dict[str, Any]] = []
        for user_msg, assistant_msg in pairs:
            result.append(user_msg)
            result.append(assistant_msg)
        return result

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @classmethod
    def _resolve_max_context_tokens(cls, value: Any) -> int:
        """Coerce *value* to a positive integer token limit.

        Falls back to :attr:`MAX_CONTEXT_TOKENS` when *value* is *None*
        or cannot be converted to an integer.

        Args:
            value: Candidate token limit value.

        Returns:
            A positive integer (minimum 1).
        """
        try:
            resolved = int(value) if value is not None else int(cls.MAX_CONTEXT_TOKENS)
        except (TypeError, ValueError):
            resolved = int(cls.MAX_CONTEXT_TOKENS)
        return max(1, resolved)

    def _assemble_context(
        self,
        analysis_results: Mapping[str, Any] | None,
        investigation_context: str,
        metadata: Mapping[str, Any] | None,
        findings_section: str,
    ) -> str:
        """Assemble context sections shared by build and rebuild methods.

        Extracts metadata fields, formats the standard sections, and
        appends the caller-provided findings section.

        Args:
            analysis_results: The full analysis results mapping.
            investigation_context: Free-text investigation context.
            metadata: Evidence metadata mapping.
            findings_section: Pre-formatted findings section string
                (including its header line).

        Returns:
            A formatted multi-section context string.
        """
        analysis = analysis_results if isinstance(analysis_results, Mapping) else {}
        metadata_map = metadata if isinstance(metadata, Mapping) else {}

        hostname = _stringify(metadata_map.get("hostname"), default="Unknown")
        os_value = _stringify(
            metadata_map.get("os_version") or metadata_map.get("os"),
            default="Unknown",
        )
        domain = _stringify(metadata_map.get("domain"), default="Unknown")
        summary = _stringify(analysis.get("summary"), default="No executive summary available.")
        context_text = _stringify(
            investigation_context,
            default="No investigation context provided.",
        )

        sections = [
            f"Investigation Context:\n{context_text}",
            (
                "System Under Analysis:\n"
                f"- Hostname: {hostname}\n"
                f"- OS: {os_value}\n"
                f"- Domain: {domain}"
            ),
            f"Executive Summary:\n{summary}",
            findings_section,
        ]
        return "\n\n".join(sections)

    def _format_per_artifact_findings(self, analysis_results: Mapping[str, Any]) -> str:
        """Format per-artifact findings as a bulleted text block.

        Handles multiple input shapes (dict keyed by artifact name, list
        of finding dicts, or list of raw strings) and normalises them
        into ``- artifact_name: analysis_text`` lines.

        Args:
            analysis_results: The full analysis results mapping.

        Returns:
            A newline-joined string of bullet-pointed findings, or a
            placeholder message when no findings are available.
        """
        raw_findings = analysis_results.get("per_artifact")
        if raw_findings is None:
            raw_findings = analysis_results.get("per_artifact_findings")

        findings: list[tuple[str, str]] = []
        if isinstance(raw_findings, Mapping):
            items: list[Any] = []
            for artifact_name, value in raw_findings.items():
                if isinstance(value, Mapping):
                    merged = dict(value)
                    merged.setdefault("artifact_name", artifact_name)
                    items.append(merged)
                else:
                    items.append({"artifact_name": artifact_name, "analysis": value})
        elif isinstance(raw_findings, list):
            items = list(raw_findings)
        else:
            items = []

        for item in items:
            if isinstance(item, Mapping):
                artifact_name = _stringify(
                    item.get("artifact_name") or item.get("name") or item.get("artifact_key"),
                    default="Unknown Artifact",
                )
                analysis_text = _stringify(
                    item.get("analysis")
                    or item.get("finding")
                    or item.get("summary")
                    or item.get("text"),
                )
            else:
                artifact_name = "Unknown Artifact"
                analysis_text = _stringify(item)

            if analysis_text:
                findings.append((artifact_name, analysis_text))

        if not findings:
            return "- No per-artifact findings available."

        return "\n".join(
            f"- {artifact_name}: {analysis_text}"
            for artifact_name, analysis_text in findings
        )
