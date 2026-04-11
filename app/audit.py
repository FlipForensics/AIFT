"""Append-only forensic audit trail logging.

Every significant action during an AIFT session (evidence intake, parsing,
AI analysis, report generation, etc.) is recorded as a single-line JSON
object in ``audit.jsonl`` inside the case directory.  This module provides
the :class:`AuditLogger` that writes those entries and enforces a
closed set of allowed action types via :data:`ACTION_TYPES`.

The audit log is designed for forensic defensibility:

* Entries are append-only and never overwritten.
* Timestamps use UTC ISO 8601 with millisecond precision.
* Each session receives a unique UUID so concurrent sessions are
  distinguishable.
* Tool and Dissect versions are embedded in every record.

Attributes:
    ACTION_TYPES: Closed set of valid action strings accepted by
        :meth:`AuditLogger.log`.
    DEFAULT_TOOL_VERSION: Version string embedded in audit records when
        none is explicitly provided.
"""

from __future__ import annotations

from datetime import date, datetime, time, timezone
from importlib import metadata
import json
import os
from pathlib import Path
import threading
from typing import Any
from uuid import uuid4

from .version import TOOL_VERSION

__all__ = ["AuditLogger"]

ACTION_TYPES = frozenset(
    {
        "case_created",
        "evidence_intake",
        "image_opened",
        "parsing_started",
        "parsing_completed",
        "parsing_failed",
        "parsing_capped",
        "analysis_started",
        "analysis_completed",
        "citation_validation",
        "artifact_ai_projection",
        "artifact_deduplicated",
        "inline_csv_truncated",
        "chunked_analysis_started",
        "artifact_ai_projection_warning",
        "prompt_submitted",
        "chat_message_sent",
        "chat_response_received",
        "chat_data_retrieval",
        "chat_history_cleared",
        "report_generated",
        "hash_verification",
        "config_changed",
        "image_added",
        "image_deleted",
        "legacy_case_migrated",
    }
)
DEFAULT_TOOL_VERSION = TOOL_VERSION


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
    """Append-only forensic audit logger writing JSONL entries per action.

    Each instance is bound to a single case directory and creates (or
    appends to) ``audit.jsonl`` in that directory.  A unique session ID
    is generated on construction and embedded in every record, allowing
    multiple runs against the same case to be differentiated.

    Attributes:
        case_directory: Resolved path to the case directory.
        audit_file: Path to the ``audit.jsonl`` file.
        session_id: UUID string identifying this logger session.
        tool_version: AIFT version recorded in every audit entry.
        dissect_version: Dissect framework version string.
    """

    def __init__(
        self,
        case_directory: str | Path,
        tool_version: str = DEFAULT_TOOL_VERSION,
        dissect_version: str | None = None,
        session_id: str | None = None,
    ) -> None:
        """Initialise the audit logger for a case directory.

        Args:
            case_directory: Path to the case directory.  Created if it
                does not exist.
            tool_version: AIFT version string to embed in records.
            dissect_version: Explicit Dissect version.  Auto-detected
                from installed packages when *None*.
            session_id: Optional session UUID.  A new UUID is generated
                when *None*, ensuring consistent session identity when
                the caller supplies an existing ID.
        """
        self.case_directory = Path(case_directory)
        self.case_directory.mkdir(parents=True, exist_ok=True)

        self.audit_file = self.case_directory / "audit.jsonl"
        self.session_id = session_id or str(uuid4())
        self.tool_version = tool_version
        self.dissect_version = dissect_version or _resolve_dissect_version()
        self._write_lock = threading.Lock()

        # Ensure the audit file exists immediately when the logger is created.
        with self.audit_file.open("ab", buffering=0) as audit_stream:
            audit_stream.flush()

    def log(self, action: str, details: dict[str, Any]) -> None:
        """Append one JSON-line audit record for *action*.

        The record includes a UTC timestamp, session ID, tool and Dissect
        versions, and the caller-supplied *details* dictionary.  The file
        is opened, written, and flushed for each call to minimise data
        loss on unexpected termination.

        Args:
            action: One of the strings in :data:`ACTION_TYPES`.
            details: Arbitrary dictionary of action-specific metadata.

        Raises:
            ValueError: If *action* is not in :data:`ACTION_TYPES`.
            TypeError: If *details* is not a dictionary.
        """
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
        with self._write_lock:
            with self.audit_file.open("ab", buffering=0) as audit_stream:
                audit_stream.write(line.encode("utf-8"))
                audit_stream.flush()
                os.fsync(audit_stream.fileno())
