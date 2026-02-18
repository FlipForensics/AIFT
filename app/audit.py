"""Audit trail logging utilities."""

from __future__ import annotations

from datetime import date, datetime, time, timezone
from importlib import metadata
import json
from pathlib import Path
from typing import Any
from uuid import uuid4

ACTION_TYPES = frozenset(
    {
        "case_created",
        "evidence_intake",
        "image_opened",
        "parsing_started",
        "parsing_completed",
        "parsing_failed",
        "analysis_started",
        "analysis_completed",
        "prompt_submitted",
        "report_generated",
        "hash_verification",
        "config_changed",
    }
)
DEFAULT_TOOL_VERSION = "1.0.0"


def _utc_now_iso8601_ms() -> str:
    """Return UTC timestamp in ISO 8601 format with millisecond precision."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _resolve_dissect_version() -> str:
    """Best-effort detection of the installed Dissect version."""
    for pkg in ("dissect", "dissect.target"):
        try:
            return metadata.version(pkg)
        except metadata.PackageNotFoundError:
            continue
    return "unknown"


def _json_default(value: Any) -> str:
    """Best-effort conversion for non-JSON-native audit detail values."""
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    return str(value)


class AuditLogger:
    """Append-only forensic audit logger writing JSONL entries per action."""

    def __init__(
        self,
        case_directory: str | Path,
        tool_version: str = DEFAULT_TOOL_VERSION,
        dissect_version: str | None = None,
    ) -> None:
        self.case_directory = Path(case_directory)
        self.case_directory.mkdir(parents=True, exist_ok=True)

        self.audit_file = self.case_directory / "audit.jsonl"
        self.session_id = str(uuid4())
        self.tool_version = tool_version
        self.dissect_version = dissect_version or _resolve_dissect_version()

        # Ensure the audit file exists immediately when the logger is created.
        with self.audit_file.open("ab", buffering=0) as audit_stream:
            audit_stream.flush()

    def log(self, action: str, details: dict[str, Any]) -> None:
        """Append one audit line for the provided action."""
        if action not in ACTION_TYPES:
            allowed = ", ".join(sorted(ACTION_TYPES))
            raise ValueError(f"Unsupported action '{action}'. Allowed values: {allowed}.")

        if not isinstance(details, dict):
            raise TypeError("details must be a dictionary.")

        record = {
            "timestamp": _utc_now_iso8601_ms(),
            "action": action,
            "details": details,
            "session_id": self.session_id,
            "tool_version": self.tool_version,
            "dissect_version": self.dissect_version,
        }

        line = json.dumps(record, separators=(",", ":"), default=_json_default) + "\n"
        with self.audit_file.open("ab", buffering=0) as audit_stream:
            audit_stream.write(line.encode("utf-8"))
            audit_stream.flush()
