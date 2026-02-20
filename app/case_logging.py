"""Case-scoped logging helpers."""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar, Token
import logging
from pathlib import Path
import threading
from typing import Iterator

CASE_LOGS_DIRNAME = "logs"
CASE_LOG_FILENAME = "application.log"
CASE_LOG_FORMAT = "%(asctime)s %(levelname)s [%(name)s] %(message)s"

_ACTIVE_CASE_ID: ContextVar[str | None] = ContextVar("aift_active_case_id", default=None)
_HANDLER_LOCK = threading.RLock()
_CASE_HANDLERS: dict[str, logging.Handler] = {}


class _CasePathLogHandler(logging.Handler):
    """Append records to a path without keeping the file descriptor open."""

    def __init__(self, log_path: Path) -> None:
        super().__init__()
        self.log_path = Path(log_path)

    def emit(self, record: logging.LogRecord) -> None:
        try:
            rendered = self.format(record)
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            with self.log_path.open("a", encoding="utf-8") as stream:
                stream.write(f"{rendered}\n")
        except OSError:
            return


class _CaseLogFilter(logging.Filter):
    """Allow records only for one case, using context when `case_id` is absent."""

    def __init__(self, case_id: str) -> None:
        super().__init__()
        self.case_id = case_id

    def filter(self, record: logging.LogRecord) -> bool:
        record_case_id = getattr(record, "case_id", None)
        if not record_case_id:
            record_case_id = _ACTIVE_CASE_ID.get()
            if record_case_id:
                setattr(record, "case_id", record_case_id)
        return str(record_case_id or "").strip() == self.case_id


def push_case_log_context(case_id: str | None) -> Token[str | None]:
    """Bind a case id to the current execution context for log routing."""
    normalized = str(case_id).strip() if case_id is not None else None
    return _ACTIVE_CASE_ID.set(normalized or None)


def pop_case_log_context(token: Token[str | None]) -> None:
    """Restore the previous case log context."""
    _ACTIVE_CASE_ID.reset(token)


@contextmanager
def case_log_context(case_id: str | None) -> Iterator[None]:
    """Temporarily bind a case id for logs emitted in this context."""
    token = push_case_log_context(case_id)
    try:
        yield
    finally:
        pop_case_log_context(token)


def register_case_log_handler(case_id: str, case_dir: str | Path) -> Path:
    """Attach a per-case file handler on the root logger."""
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
    """Detach and close a case file handler if it exists."""
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
