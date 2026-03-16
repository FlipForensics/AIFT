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
* **CSV data retrieval** -- Heuristically matches user questions to parsed
  artifact CSV files and injects relevant rows into the prompt so the AI
  can answer data-specific queries (e.g. "show me the prefetch entries").

Attributes:
    VALID_ROLES: Frozenset of accepted message role strings
        (``"user"`` and ``"assistant"``).
"""

from __future__ import annotations

import csv
import json
import logging
from pathlib import Path
import re
from typing import Any, Mapping

from .audit import _utc_now_iso8601_ms

log = logging.getLogger(__name__)

VALID_ROLES = frozenset({"user", "assistant"})


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
    _CSV_RETRIEVAL_KEYWORDS = (
        "show me",
        "list",
        "csv",
        "rows",
        "records",
        "check the",
        "look in",
    )
    _CSV_ROW_LIMIT = 500

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
        metadata_map = metadata if isinstance(metadata, Mapping) else {}

        hostname = self._stringify(metadata_map.get("hostname"), default="Unknown")
        os_value = self._stringify(metadata_map.get("os_version") or metadata_map.get("os"), default="Unknown")
        domain = self._stringify(metadata_map.get("domain"), default="Unknown")
        summary = self._stringify(analysis.get("summary"), default="No executive summary available.")
        context_text = self._stringify(
            investigation_context,
            default="No investigation context provided.",
        )

        per_artifact_lines = self._format_per_artifact_findings(analysis)
        sections = [
            f"Investigation Context:\n{context_text}",
            (
                "System Under Analysis:\n"
                f"- Hostname: {hostname}\n"
                f"- OS: {os_value}\n"
                f"- Domain: {domain}"
            ),
            f"Executive Summary:\n{summary}",
            f"Per-Artifact Findings:\n{per_artifact_lines}",
        ]
        return "\n\n".join(sections)

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
        analysis = analysis_results if isinstance(analysis_results, Mapping) else {}
        metadata_map = metadata if isinstance(metadata, Mapping) else {}

        hostname = self._stringify(metadata_map.get("hostname"), default="Unknown")
        os_value = self._stringify(metadata_map.get("os_version") or metadata_map.get("os"), default="Unknown")
        domain = self._stringify(metadata_map.get("domain"), default="Unknown")
        summary = self._stringify(analysis.get("summary"), default="No executive summary available.")
        context_text = self._stringify(
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
            f"Per-Artifact Findings (compressed):\n{compressed_findings}",
        ]
        return "\n\n".join(sections)

    def retrieve_csv_data(self, question: str, parsed_dir: str | Path) -> dict[str, Any]:
        """Best-effort retrieval of raw CSV rows for data-centric chat questions.

        Heuristically matches the user's *question* against parsed artifact
        CSV filenames and column headers.  When a match is found, up to
        :attr:`_CSV_ROW_LIMIT` rows are read and formatted as a structured
        text block for injection into the AI prompt.

        Args:
            question: The user's chat question text.
            parsed_dir: Path to the directory containing parsed artifact
                CSV files.

        Returns:
            A dictionary with a ``retrieved`` boolean.  When *True*, also
            includes ``artifacts`` (list of matched CSV filenames) and
            ``data`` (formatted row text).
        """
        question_text = self._stringify(question)
        if not question_text:
            return {"retrieved": False}

        parsed_path = Path(parsed_dir)
        if not parsed_path.exists() or not parsed_path.is_dir():
            return {"retrieved": False}

        csv_paths = sorted(path for path in parsed_path.glob("*.csv") if path.is_file())
        if not csv_paths:
            return {"retrieved": False}

        question_lower = question_text.lower()
        keyword_detected = any(keyword in question_lower for keyword in self._CSV_RETRIEVAL_KEYWORDS)

        aliases_by_path = {path: self._build_csv_aliases(path) for path in csv_paths}
        artifact_matches = [
            path
            for path, aliases in aliases_by_path.items()
            if any(self._contains_heuristic_term(question_lower, alias) for alias in aliases)
        ]

        if artifact_matches:
            target_paths = artifact_matches
        else:
            # Only scan CSV headers when artifact-name matching didn't find anything,
            # to avoid reading every CSV file on every chat message.
            headers_by_path = {path: self._read_csv_headers(path) for path in csv_paths}
            matched_columns = {
                header.lower()
                for headers in headers_by_path.values()
                for header in headers
                if self._contains_heuristic_term(question_lower, header.lower())
            }
            if matched_columns:
                target_paths = [
                    path
                    for path, headers in headers_by_path.items()
                    if any(header.lower() in matched_columns for header in headers)
                ]
            elif keyword_detected:
                # Keywords detected but no specific artifact/column identified —
                # return all CSVs only if the collection is small, otherwise skip
                # to avoid blowing up the context window with irrelevant data.
                if len(csv_paths) <= 3:
                    target_paths = csv_paths
                else:
                    return {"retrieved": False}
            else:
                return {"retrieved": False}

        target_paths = list(dict.fromkeys(target_paths))
        artifacts = [path.name for path in target_paths]
        formatted_blocks: list[str] = []
        rows_remaining = self._CSV_ROW_LIMIT

        for csv_path in target_paths:
            if rows_remaining <= 0:
                break
            headers, rows, total_row_count = self._read_csv_rows(
                csv_path=csv_path, limit=rows_remaining,
            )
            if not headers and not rows:
                continue

            rows_remaining -= len(rows)
            block_lines = [f"Artifact: {csv_path.name}"]
            # Show total vs sampled row counts so the AI knows how much
            # data was omitted.  This limit exists to prevent memory
            # exhaustion on large artifacts (e.g. EVTX with millions of
            # rows).
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
            formatted_blocks.append("\n".join(block_lines))

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

    @staticmethod
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
                artifact_name = self._stringify(
                    item.get("artifact_name") or item.get("name") or item.get("artifact_key"),
                    default="Unknown Artifact",
                )
                analysis_text = self._stringify(
                    item.get("analysis")
                    or item.get("finding")
                    or item.get("summary")
                    or item.get("text"),
                )
            else:
                artifact_name = "Unknown Artifact"
                analysis_text = self._stringify(item)

            if analysis_text:
                findings.append((artifact_name, analysis_text))

        if not findings:
            return "- No per-artifact findings available."

        return "\n".join(f"- {artifact_name}: {analysis_text}" for artifact_name, analysis_text in findings)

    @staticmethod
    def _build_csv_aliases(csv_path: Path) -> set[str]:
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

    @staticmethod
    def _contains_heuristic_term(question_lower: str, term: str) -> bool:
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

    def _read_csv_headers(self, csv_path: Path) -> list[str]:
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

        headers: list[str] = []
        for header in header_row:
            normalized = self._stringify(header)
            if normalized:
                headers.append(normalized)
        return headers

    def _read_csv_rows(
        self, csv_path: Path, limit: int,
    ) -> tuple[list[str], list[dict[str, str]], int]:
        """Read up to *limit* data rows from a CSV file.

        Values are whitespace-collapsed and truncated to 240 characters
        to keep the resulting text compact for AI prompt injection.

        After reading the sampled rows, the remainder of the file is
        consumed (without storing data) to obtain an accurate total row
        count.  This avoids loading the entire file into memory while
        still letting callers report how much data was omitted.

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
                headers = [self._stringify(field) for field in (reader.fieldnames or []) if self._stringify(field)]

                rows: list[dict[str, str]] = []
                total_row_count = 0
                for row in reader:
                    total_row_count += 1
                    if len(rows) < limit:
                        compact_row: dict[str, str] = {}
                        for column in headers:
                            value = self._stringify(row.get(column, ""))
                            value = re.sub(r"\s+", " ", value)
                            if len(value) > 240:
                                value = f"{value[:237]}..."
                            compact_row[column] = value
                        rows.append(compact_row)
        except Exception:
            log.warning("Failed to read CSV rows from %s", csv_path, exc_info=True)
            return [], [], 0

        return headers, rows, total_row_count


if __name__ == "__main__":
    from tempfile import TemporaryDirectory
    with TemporaryDirectory(prefix="aift-chat-test-") as temp_dir:
        manager = ChatManager(temp_dir)
        for pair_index in range(1, 6):
            manager.add_message("user", f"Question {pair_index}?")
            manager.add_message(
                "assistant",
                f"Answer {pair_index}.",
                metadata={"pair_index": pair_index},
            )

        recent = manager.get_recent_history(max_pairs=2)

        assert len(recent) == 4, f"Expected 4 messages (2 pairs), got {len(recent)}."
        assert [message.get("role") for message in recent] == [
            "user",
            "assistant",
            "user",
            "assistant",
        ], "Recent history did not contain complete user/assistant pairs."
        assert recent[0].get("content") == "Question 4?"
        assert recent[1].get("content") == "Answer 4."
        assert recent[2].get("content") == "Question 5?"
        assert recent[3].get("content") == "Answer 5."

    print("ChatManager quick test passed.")
