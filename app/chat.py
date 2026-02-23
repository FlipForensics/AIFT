"""Chat history storage for post-analysis Q&A."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from .audit import _utc_now_iso8601_ms

log = logging.getLogger(__name__)

VALID_ROLES = frozenset({"user", "assistant"})


class ChatManager:
    """Persist and retrieve case-scoped chat history records."""

    def __init__(self, case_dir: str | Path) -> None:
        self.case_dir = Path(case_dir)
        self.chat_file = self.case_dir / "chat_history.jsonl"

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
