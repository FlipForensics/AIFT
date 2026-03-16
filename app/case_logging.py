"""Case-scoped application logging helpers.

Routes Python :mod:`logging` records to per-case log files so that each
forensic case maintains its own ``logs/application.log``.  This is separate
from the forensic audit trail (``audit.jsonl``) and is intended for
developer-facing diagnostic output.

The mechanism works by attaching a :class:`logging.Handler` to the root
logger for every active case.  A :class:`~contextvars.ContextVar` tracks
which case ID is active on the current thread / coroutine so that log
records are routed to the correct file without requiring callers to pass
case references explicitly.

Typical usage::

    register_case_log_handler(case_id, case_dir)
    with case_log_context(case_id):
        logging.getLogger("app").info("Parsing started")

Attributes:
    CASE_LOGS_DIRNAME: Subdirectory name for case log files.
    CASE_LOG_FILENAME: Name of the per-case application log file.
    CASE_LOG_FORMAT: :mod:`logging` format string for case log entries.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar, Token
import logging
from pathlib import Path
import threading
from typing import Iterator

__all__ = [
    "push_case_log_context",
    "pop_case_log_context",
    "case_log_context",
    "register_case_log_handler",
    "unregister_case_log_handler",
    "unregister_all_case_log_handlers",
]

CASE_LOGS_DIRNAME = "logs"
CASE_LOG_FILENAME = "application.log"
CASE_LOG_FORMAT = "%(asctime)s %(levelname)s [%(name)s] %(message)s"

_ACTIVE_CASE_ID: ContextVar[str | None] = ContextVar("aift_active_case_id", default=None)
_HANDLER_LOCK = threading.RLock()
_CASE_HANDLERS: dict[str, logging.Handler] = {}


class _CasePathLogHandler(logging.Handler):
    """Logging handler that appends formatted records to a file path.

    The file is opened and closed for each record to avoid holding file
    descriptors open across long-lived operations.

    Args:
        log_path: Destination file path for log output.
    """

    def __init__(self, log_path: Path) -> None:
        super().__init__()
        self.log_path = Path(log_path)

    def emit(self, record: logging.LogRecord) -> None:
        """Write a single formatted log record to :attr:`log_path`."""
        try:
            rendered = self.format(record)
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as stream:
                stream.write(f"{rendered}\n")
        except OSError:
            return


class _CaseLogFilter(logging.Filter):
    """Logging filter that passes only records matching a specific case ID.

    If the record does not carry a ``case_id`` attribute, the filter
    falls back to the context variable set via :func:`push_case_log_context`.

    Args:
        case_id: The case identifier this filter accepts.
    """

    def __init__(self, case_id: str) -> None:
        super().__init__()
        self.case_id = case_id

    def filter(self, record: logging.LogRecord) -> bool:
        """Return *True* when the record belongs to this filter's case."""
        record_case_id = getattr(record, "case_id", None)
        if not record_case_id:
            record_case_id = _ACTIVE_CASE_ID.get()
            if record_case_id:
                setattr(record, "case_id", record_case_id)
        return str(record_case_id or "").strip() == self.case_id


def push_case_log_context(case_id: str | None) -> Token[str | None]:
    """Bind a case ID to the current execution context for log routing.

    Args:
        case_id: Case identifier to set, or *None* to clear.

    Returns:
        A :class:`~contextvars.Token` that can be passed to
        :func:`pop_case_log_context` to restore the previous value.
    """
    normalized = str(case_id).strip() if case_id is not None else None
    return _ACTIVE_CASE_ID.set(normalized or None)


def pop_case_log_context(token: Token[str | None]) -> None:
    """Restore the previous case log context.

    Args:
        token: Token returned by a prior :func:`push_case_log_context` call.
    """
    _ACTIVE_CASE_ID.reset(token)


@contextmanager
def case_log_context(case_id: str | None) -> Iterator[None]:
    """Context manager that binds *case_id* for logs emitted within its scope.

    Args:
        case_id: Case identifier to bind, or *None* to clear.

    Yields:
        Nothing.  The context variable is restored on exit.
    """
    token = push_case_log_context(case_id)
    try:
        yield
    finally:
        pop_case_log_context(token)


def register_case_log_handler(case_id: str, case_dir: str | Path) -> Path:
    """Attach a per-case file handler to the root logger.

    Creates a ``logs/application.log`` file inside *case_dir* and installs
    a :class:`_CasePathLogHandler` with a :class:`_CaseLogFilter` so that
    only records matching *case_id* are written there.  Duplicate
    registrations for the same case are silently ignored.

    Args:
        case_id: Non-empty case identifier string.
        case_dir: Path to the case directory where logs will be stored.

    Returns:
        The :class:`~pathlib.Path` to the created log file.

    Raises:
        ValueError: If *case_id* is empty or whitespace-only.
    """
    normalized_case_id = str(case_id).strip()
    if not normalized_case_id:
        raise ValueError("case_id must be a non-empty string.")

    root_logger = logging.getLogger()
    app_logger = logging.getLogger("app")
    logs_dir = Path(case_dir) / CASE_LOGS_DIRNAME
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_path = logs_dir / CASE_LOG_FILENAME

    with _HANDLER_LOCK:
        existing = _CASE_HANDLERS.get(normalized_case_id)
        if existing is not None:
            return log_path

        handler = _CasePathLogHandler(log_path)
        handler.setLevel(logging.INFO)
        handler.setFormatter(logging.Formatter(CASE_LOG_FORMAT))
        handler.addFilter(_CaseLogFilter(normalized_case_id))
        root_logger.addHandler(handler)
        _CASE_HANDLERS[normalized_case_id] = handler

        if app_logger.level == logging.NOTSET or app_logger.level > logging.INFO:
            app_logger.setLevel(logging.INFO)

    return log_path


def unregister_case_log_handler(case_id: str) -> None:
    """Detach and close the file handler for *case_id* if it exists.

    Args:
        case_id: Case identifier whose handler should be removed.
    """
    normalized_case_id = str(case_id).strip()
    if not normalized_case_id:
        return

    with _HANDLER_LOCK:
        handler = _CASE_HANDLERS.pop(normalized_case_id, None)
        if handler is None:
            return
        root_logger = logging.getLogger()
        root_logger.removeHandler(handler)
        handler.close()


def unregister_all_case_log_handlers() -> None:
    """Detach and close all case file handlers."""
    with _HANDLER_LOCK:
        handlers = list(_CASE_HANDLERS.values())
        _CASE_HANDLERS.clear()
        root_logger = logging.getLogger()
        for handler in handlers:
            root_logger.removeHandler(handler)
            handler.close()
