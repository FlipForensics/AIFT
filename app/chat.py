"""Chat history storage for post-analysis Q&A."""

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
    """Persist and retrieve case-scoped chat history records."""

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
        self.case_dir = Path(case_dir)
        self.chat_file = self.case_dir / "chat_history.jsonl"
        self.MAX_CONTEXT_TOKENS = self._resolve_max_context_tokens(max_context_tokens)

    def add_message(
        self,
        role: str,
        content: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Append one message entry to the case chat JSONL history."""
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
        """Load the full chat history in insertion order."""
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
        """Return the most recent complete user/assistant message pairs."""
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
        """Delete the chat history file when present."""
        if self.chat_file.exists():
            self.chat_file.unlink()

    def build_chat_context(
        self,
        analysis_results: Mapping[str, Any] | None,
        investigation_context: str,
        metadata: Mapping[str, Any] | None,
    ) -> str:
        """Build a compact, complete context block for chat prompts."""
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

    def retrieve_csv_data(self, question: str, parsed_dir: str | Path) -> dict[str, Any]:
        """Best-effort retrieval of raw CSV rows for data-centric chat questions."""
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

        headers_by_path = {path: self._read_csv_headers(path) for path in csv_paths}
        matched_columns = {
            header.lower()
            for headers in headers_by_path.values()
            for header in headers
            if self._contains_heuristic_term(question_lower, header.lower())
        }

        if artifact_matches:
            target_paths = artifact_matches
        elif matched_columns:
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
            headers, rows = self._read_csv_rows(csv_path=csv_path, limit=rows_remaining)
            if not headers and not rows:
                continue

            rows_remaining -= len(rows)
            block_lines = [f"Artifact: {csv_path.name}"]
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
        """Estimate token count using a rough 4-characters-per-token ratio."""
        if not text:
            return 0
        return int(len(text) / 4)

    @classmethod
    def _resolve_max_context_tokens(cls, value: Any) -> int:
        try:
            resolved = int(value) if value is not None else int(cls.MAX_CONTEXT_TOKENS)
        except (TypeError, ValueError):
            resolved = int(cls.MAX_CONTEXT_TOKENS)
        return max(1, resolved)

    @staticmethod
    def _stringify(value: Any, default: str = "") -> str:
        text = str(value).strip() if value is not None else ""
        return text or default

    def _format_per_artifact_findings(self, analysis_results: Mapping[str, Any]) -> str:
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
        normalized = term.strip().lower()
        if len(normalized) < 3:
            return False
        pattern = rf"(?<![a-z0-9]){re.escape(normalized)}(?![a-z0-9])"
        return re.search(pattern, question_lower) is not None

    def _read_csv_headers(self, csv_path: Path) -> list[str]:
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

    def _read_csv_rows(self, csv_path: Path, limit: int) -> tuple[list[str], list[dict[str, str]]]:
        if limit <= 0:
            return [], []

        try:
            with csv_path.open("r", encoding="utf-8-sig", newline="", errors="replace") as csv_stream:
                reader = csv.DictReader(csv_stream)
                headers = [self._stringify(field) for field in (reader.fieldnames or []) if self._stringify(field)]

                rows: list[dict[str, str]] = []
                for row in reader:
                    if len(rows) >= limit:
                        break
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
            return [], []

        return headers, rows


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
