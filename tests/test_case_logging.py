"""Tests for app.case_logging module.

Covers the per-case logging handler, filter, context management, and
handler registration/unregistration lifecycle.
"""

from __future__ import annotations

import logging
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import MagicMock, patch
import unittest

from app.case_logging import (
    CASE_LOG_FILENAME,
    CASE_LOG_FORMAT,
    CASE_LOGS_DIRNAME,
    _CaseLogFilter,
    _CasePathLogHandler,
    _ACTIVE_CASE_ID,
    _CASE_HANDLERS,
    case_log_context,
    push_case_log_context,
    pop_case_log_context,
    register_case_log_handler,
    unregister_case_log_handler,
    unregister_all_case_log_handlers,
)


class CasePathLogHandlerTests(unittest.TestCase):
    """Tests for _CasePathLogHandler."""

    def test_emit_writes_formatted_record_to_file(self) -> None:
        with TemporaryDirectory(prefix="aift-log-test-") as temp_dir:
            log_path = Path(temp_dir) / "logs" / "test.log"
            handler = _CasePathLogHandler(log_path)
            handler.setFormatter(logging.Formatter("%(message)s"))

            record = logging.LogRecord(
                name="test", level=logging.INFO, pathname="",
                lineno=0, msg="hello world", args=(), exc_info=None,
            )
            handler.emit(record)

            content = log_path.read_text(encoding="utf-8")
            self.assertEqual(content.strip(), "hello world")

    def test_emit_creates_parent_directories(self) -> None:
        with TemporaryDirectory(prefix="aift-log-test-") as temp_dir:
            log_path = Path(temp_dir) / "deep" / "nested" / "test.log"
            handler = _CasePathLogHandler(log_path)
            handler.setFormatter(logging.Formatter("%(message)s"))

            record = logging.LogRecord(
                name="test", level=logging.INFO, pathname="",
                lineno=0, msg="msg", args=(), exc_info=None,
            )
            handler.emit(record)

            self.assertTrue(log_path.exists())

    def test_emit_appends_multiple_records(self) -> None:
        with TemporaryDirectory(prefix="aift-log-test-") as temp_dir:
            log_path = Path(temp_dir) / "test.log"
            handler = _CasePathLogHandler(log_path)
            handler.setFormatter(logging.Formatter("%(message)s"))

            for i in range(3):
                record = logging.LogRecord(
                    name="test", level=logging.INFO, pathname="",
                    lineno=0, msg=f"line {i}", args=(), exc_info=None,
                )
                handler.emit(record)

            lines = log_path.read_text(encoding="utf-8").splitlines()
            self.assertEqual(len(lines), 3)
            self.assertEqual(lines[0], "line 0")
            self.assertEqual(lines[2], "line 2")

    def test_emit_silences_os_errors(self) -> None:
        handler = _CasePathLogHandler(Path("/nonexistent_root_xyz/impossible/test.log"))
        handler.setFormatter(logging.Formatter("%(message)s"))

        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="",
            lineno=0, msg="should not crash", args=(), exc_info=None,
        )
        # Should not raise
        handler.emit(record)

    def test_log_path_stored_as_path_object(self) -> None:
        handler = _CasePathLogHandler(Path("/some/path.log"))
        self.assertIsInstance(handler.log_path, Path)

    def test_log_path_accepts_string(self) -> None:
        handler = _CasePathLogHandler("/some/path.log")  # type: ignore[arg-type]
        self.assertIsInstance(handler.log_path, Path)


class CaseLogFilterTests(unittest.TestCase):
    """Tests for _CaseLogFilter."""

    def _make_record(self, case_id: str | None = None) -> logging.LogRecord:
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="",
            lineno=0, msg="test", args=(), exc_info=None,
        )
        if case_id is not None:
            record.case_id = case_id  # type: ignore[attr-defined]
        return record

    def test_filter_matches_record_with_case_id_attribute(self) -> None:
        f = _CaseLogFilter("case-001")
        record = self._make_record("case-001")
        self.assertTrue(f.filter(record))

    def test_filter_rejects_mismatched_case_id(self) -> None:
        f = _CaseLogFilter("case-001")
        record = self._make_record("case-999")
        self.assertFalse(f.filter(record))

    def test_filter_falls_back_to_context_var(self) -> None:
        f = _CaseLogFilter("ctx-case")
        record = self._make_record()  # No case_id attribute
        token = push_case_log_context("ctx-case")
        try:
            result = f.filter(record)
        finally:
            pop_case_log_context(token)
        self.assertTrue(result)
        # Filter should have set case_id on the record
        self.assertEqual(getattr(record, "case_id", None), "ctx-case")

    def test_filter_rejects_when_no_case_id_anywhere(self) -> None:
        f = _CaseLogFilter("case-001")
        record = self._make_record()
        # Ensure context var is clear
        token = push_case_log_context(None)
        try:
            result = f.filter(record)
        finally:
            pop_case_log_context(token)
        self.assertFalse(result)

    def test_filter_rejects_empty_string_case_id_attribute(self) -> None:
        f = _CaseLogFilter("case-001")
        record = self._make_record("")
        # Empty string is falsy, so filter falls back to context var
        token = push_case_log_context(None)
        try:
            result = f.filter(record)
        finally:
            pop_case_log_context(token)
        self.assertFalse(result)


class PushPopCaseLogContextTests(unittest.TestCase):
    """Tests for push_case_log_context and pop_case_log_context."""

    def test_push_sets_and_pop_restores(self) -> None:
        original = _ACTIVE_CASE_ID.get()
        token = push_case_log_context("test-case")
        self.assertEqual(_ACTIVE_CASE_ID.get(), "test-case")
        pop_case_log_context(token)
        self.assertEqual(_ACTIVE_CASE_ID.get(), original)

    def test_push_none_clears_context(self) -> None:
        token1 = push_case_log_context("some-case")
        token2 = push_case_log_context(None)
        self.assertIsNone(_ACTIVE_CASE_ID.get())
        pop_case_log_context(token2)
        pop_case_log_context(token1)

    def test_push_strips_whitespace(self) -> None:
        token = push_case_log_context("  case-ws  ")
        self.assertEqual(_ACTIVE_CASE_ID.get(), "case-ws")
        pop_case_log_context(token)

    def test_push_empty_string_sets_none(self) -> None:
        token = push_case_log_context("   ")
        self.assertIsNone(_ACTIVE_CASE_ID.get())
        pop_case_log_context(token)

    def test_nested_push_pop(self) -> None:
        t1 = push_case_log_context("outer")
        self.assertEqual(_ACTIVE_CASE_ID.get(), "outer")
        t2 = push_case_log_context("inner")
        self.assertEqual(_ACTIVE_CASE_ID.get(), "inner")
        pop_case_log_context(t2)
        self.assertEqual(_ACTIVE_CASE_ID.get(), "outer")
        pop_case_log_context(t1)


class CaseLogContextManagerTests(unittest.TestCase):
    """Tests for the case_log_context context manager."""

    def test_context_manager_sets_and_restores(self) -> None:
        original = _ACTIVE_CASE_ID.get()
        with case_log_context("cm-case"):
            self.assertEqual(_ACTIVE_CASE_ID.get(), "cm-case")
        self.assertEqual(_ACTIVE_CASE_ID.get(), original)

    def test_context_manager_restores_on_exception(self) -> None:
        original = _ACTIVE_CASE_ID.get()
        with self.assertRaises(RuntimeError):
            with case_log_context("err-case"):
                self.assertEqual(_ACTIVE_CASE_ID.get(), "err-case")
                raise RuntimeError("boom")
        self.assertEqual(_ACTIVE_CASE_ID.get(), original)

    def test_context_manager_with_none(self) -> None:
        t = push_case_log_context("before")
        try:
            with case_log_context(None):
                self.assertIsNone(_ACTIVE_CASE_ID.get())
            self.assertEqual(_ACTIVE_CASE_ID.get(), "before")
        finally:
            pop_case_log_context(t)


class RegisterCaseLogHandlerTests(unittest.TestCase):
    """Tests for register_case_log_handler."""

    def tearDown(self) -> None:
        unregister_all_case_log_handlers()

    def test_register_creates_log_directory_and_returns_path(self) -> None:
        with TemporaryDirectory(prefix="aift-reg-test-") as temp_dir:
            log_path = register_case_log_handler("reg-001", temp_dir)
            expected = Path(temp_dir) / CASE_LOGS_DIRNAME / CASE_LOG_FILENAME
            self.assertEqual(log_path, expected)
            self.assertTrue(log_path.parent.exists())

    def test_register_adds_handler_to_root_logger(self) -> None:
        with TemporaryDirectory(prefix="aift-reg-test-") as temp_dir:
            register_case_log_handler("reg-002", temp_dir)
            root = logging.getLogger()
            handler_types = [type(h).__name__ for h in root.handlers]
            self.assertIn("_CasePathLogHandler", handler_types)

    def test_register_duplicate_is_idempotent(self) -> None:
        with TemporaryDirectory(prefix="aift-reg-test-") as temp_dir:
            path1 = register_case_log_handler("reg-dup", temp_dir)
            root_handlers_before = len(logging.getLogger().handlers)
            path2 = register_case_log_handler("reg-dup", temp_dir)
            root_handlers_after = len(logging.getLogger().handlers)
            self.assertEqual(path1, path2)
            self.assertEqual(root_handlers_before, root_handlers_after)

    def test_register_raises_on_empty_case_id(self) -> None:
        with TemporaryDirectory(prefix="aift-reg-test-") as temp_dir:
            with self.assertRaises(ValueError):
                register_case_log_handler("", temp_dir)

    def test_register_raises_on_whitespace_only_case_id(self) -> None:
        with TemporaryDirectory(prefix="aift-reg-test-") as temp_dir:
            with self.assertRaises(ValueError):
                register_case_log_handler("   ", temp_dir)

    def test_register_sets_app_logger_level_to_info(self) -> None:
        app_logger = logging.getLogger("app")
        original_level = app_logger.level
        try:
            app_logger.setLevel(logging.NOTSET)
            with TemporaryDirectory(prefix="aift-reg-test-") as temp_dir:
                register_case_log_handler("reg-level", temp_dir)
            self.assertLessEqual(app_logger.level, logging.INFO)
        finally:
            app_logger.setLevel(original_level)

    def test_handler_stores_in_case_handlers_dict(self) -> None:
        with TemporaryDirectory(prefix="aift-reg-test-") as temp_dir:
            register_case_log_handler("reg-dict", temp_dir)
            self.assertIn("reg-dict", _CASE_HANDLERS)


class UnregisterCaseLogHandlerTests(unittest.TestCase):
    """Tests for unregister_case_log_handler."""

    def tearDown(self) -> None:
        unregister_all_case_log_handlers()

    def test_unregister_removes_handler(self) -> None:
        with TemporaryDirectory(prefix="aift-unreg-test-") as temp_dir:
            register_case_log_handler("unreg-001", temp_dir)
            self.assertIn("unreg-001", _CASE_HANDLERS)
            unregister_case_log_handler("unreg-001")
            self.assertNotIn("unreg-001", _CASE_HANDLERS)

    def test_unregister_removes_from_root_logger(self) -> None:
        with TemporaryDirectory(prefix="aift-unreg-test-") as temp_dir:
            register_case_log_handler("unreg-002", temp_dir)
            handler = _CASE_HANDLERS["unreg-002"]
            root = logging.getLogger()
            self.assertIn(handler, root.handlers)
            unregister_case_log_handler("unreg-002")
            self.assertNotIn(handler, root.handlers)

    def test_unregister_nonexistent_is_noop(self) -> None:
        # Should not raise
        unregister_case_log_handler("does-not-exist")

    def test_unregister_empty_case_id_is_noop(self) -> None:
        unregister_case_log_handler("")

    def test_unregister_whitespace_case_id_is_noop(self) -> None:
        unregister_case_log_handler("   ")


class UnregisterAllCaseLogHandlersTests(unittest.TestCase):
    """Tests for unregister_all_case_log_handlers."""

    def tearDown(self) -> None:
        unregister_all_case_log_handlers()

    def test_unregister_all_clears_handlers(self) -> None:
        with TemporaryDirectory(prefix="aift-unreg-all-") as temp_dir:
            register_case_log_handler("all-001", Path(temp_dir) / "c1")
            register_case_log_handler("all-002", Path(temp_dir) / "c2")
            self.assertEqual(len(_CASE_HANDLERS), 2)
            unregister_all_case_log_handlers()
            self.assertEqual(len(_CASE_HANDLERS), 0)

    def test_unregister_all_removes_from_root_logger(self) -> None:
        with TemporaryDirectory(prefix="aift-unreg-all-") as temp_dir:
            register_case_log_handler("all-003", Path(temp_dir) / "c3")
            handler = _CASE_HANDLERS["all-003"]
            root = logging.getLogger()
            self.assertIn(handler, root.handlers)
            unregister_all_case_log_handlers()
            self.assertNotIn(handler, root.handlers)

    def test_unregister_all_when_empty_is_noop(self) -> None:
        _CASE_HANDLERS.clear()
        unregister_all_case_log_handlers()
        self.assertEqual(len(_CASE_HANDLERS), 0)


class IntegrationTests(unittest.TestCase):
    """End-to-end tests verifying log routing through the full stack."""

    def tearDown(self) -> None:
        unregister_all_case_log_handlers()

    def test_log_message_routed_to_correct_case_file(self) -> None:
        with TemporaryDirectory(prefix="aift-integ-") as temp_dir:
            case_dir = Path(temp_dir) / "case-integ"
            log_path = register_case_log_handler("integ-001", case_dir)

            logger = logging.getLogger("app.test")
            with case_log_context("integ-001"):
                logger.info("Integration test message")

            content = log_path.read_text(encoding="utf-8")
            self.assertIn("Integration test message", content)

    def test_log_message_not_routed_to_wrong_case(self) -> None:
        with TemporaryDirectory(prefix="aift-integ-") as temp_dir:
            case1_dir = Path(temp_dir) / "case1"
            case2_dir = Path(temp_dir) / "case2"
            log_path1 = register_case_log_handler("integ-a", case1_dir)
            log_path2 = register_case_log_handler("integ-b", case2_dir)

            logger = logging.getLogger("app.test")
            with case_log_context("integ-a"):
                logger.info("Message for case A")

            content1 = log_path1.read_text(encoding="utf-8")
            self.assertIn("Message for case A", content1)

            # Case B log should either not exist or not contain the message
            if log_path2.exists():
                content2 = log_path2.read_text(encoding="utf-8")
                self.assertNotIn("Message for case A", content2)


class ConstantsTests(unittest.TestCase):
    """Tests for module-level constants."""

    def test_case_logs_dirname(self) -> None:
        self.assertEqual(CASE_LOGS_DIRNAME, "logs")

    def test_case_log_filename(self) -> None:
        self.assertEqual(CASE_LOG_FILENAME, "application.log")

    def test_case_log_format_contains_expected_fields(self) -> None:
        self.assertIn("%(asctime)s", CASE_LOG_FORMAT)
        self.assertIn("%(levelname)s", CASE_LOG_FORMAT)
        self.assertIn("%(name)s", CASE_LOG_FORMAT)
        self.assertIn("%(message)s", CASE_LOG_FORMAT)


if __name__ == "__main__":
    unittest.main()
