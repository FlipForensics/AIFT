from __future__ import annotations

import unittest
from unittest.mock import patch

from runtime_compat import (
    SUPPORTED_PYTHON_MAX_EXCLUSIVE,
    SUPPORTED_PYTHON_MIN,
    UnsupportedPythonVersionError,
    _format_version,
    _supported_range_label,
    assert_supported_python_version,
)


class TestModuleConstants(unittest.TestCase):
    """Verify module-level constants are set correctly."""

    def test_supported_min_is_3_10(self) -> None:
        assert SUPPORTED_PYTHON_MIN == (3, 10)

    def test_supported_max_exclusive_is_3_14(self) -> None:
        assert SUPPORTED_PYTHON_MAX_EXCLUSIVE == (3, 14)


class TestUnsupportedPythonVersionError(unittest.TestCase):
    """Verify the custom exception inherits from RuntimeError."""

    def test_is_runtime_error_subclass(self) -> None:
        assert issubclass(UnsupportedPythonVersionError, RuntimeError)

    def test_can_be_raised_and_caught(self) -> None:
        with self.assertRaises(UnsupportedPythonVersionError):
            raise UnsupportedPythonVersionError("test message")

    def test_message_is_preserved(self) -> None:
        err = UnsupportedPythonVersionError("custom msg")
        assert str(err) == "custom msg"


class TestFormatVersion(unittest.TestCase):
    """Tests for _format_version."""

    def test_typical_version(self) -> None:
        assert _format_version((3, 10, 12)) == "3.10.12"

    def test_zero_micro(self) -> None:
        assert _format_version((3, 13, 0)) == "3.13.0"

    def test_large_micro(self) -> None:
        assert _format_version((3, 11, 99)) == "3.11.99"

    def test_python_2_style(self) -> None:
        assert _format_version((2, 7, 18)) == "2.7.18"


class TestSupportedRangeLabel(unittest.TestCase):
    """Tests for _supported_range_label."""

    def test_returns_expected_label(self) -> None:
        assert _supported_range_label() == "3.10-3.13"

    def test_label_format_matches_constants(self) -> None:
        label = _supported_range_label()
        min_part, max_part = label.split("-")
        assert min_part == f"{SUPPORTED_PYTHON_MIN[0]}.{SUPPORTED_PYTHON_MIN[1]}"
        expected_max_minor = SUPPORTED_PYTHON_MAX_EXCLUSIVE[1] - 1
        assert max_part == f"{SUPPORTED_PYTHON_MAX_EXCLUSIVE[0]}.{expected_max_minor}"


class TestAssertSupportedPythonVersion(unittest.TestCase):
    """Tests for assert_supported_python_version."""

    # --- Supported versions (should not raise) ---

    def test_python_3_10_is_supported(self) -> None:
        assert_supported_python_version((3, 10, 0))

    def test_python_3_11_is_supported(self) -> None:
        assert_supported_python_version((3, 11, 5))

    def test_python_3_12_is_supported(self) -> None:
        assert_supported_python_version((3, 12, 0))

    def test_python_3_13_is_supported(self) -> None:
        assert_supported_python_version((3, 13, 9))

    def test_python_3_13_0_is_supported(self) -> None:
        assert_supported_python_version((3, 13, 0))

    # --- Unsupported versions (should raise) ---

    def test_python_3_9_is_unsupported(self) -> None:
        with self.assertRaises(UnsupportedPythonVersionError) as context:
            assert_supported_python_version((3, 9, 18))
        error_message = str(context.exception)
        self.assertIn("3.9.18", error_message)
        self.assertIn("3.10-3.13", error_message)

    def test_python_3_14_is_unsupported(self) -> None:
        with self.assertRaises(UnsupportedPythonVersionError) as context:
            assert_supported_python_version((3, 14, 3))
        error_message = str(context.exception)
        self.assertIn("3.14.3", error_message)
        self.assertIn("3.10-3.13", error_message)

    def test_python_2_7_is_unsupported(self) -> None:
        with self.assertRaises(UnsupportedPythonVersionError):
            assert_supported_python_version((2, 7, 18))

    def test_python_3_8_is_unsupported(self) -> None:
        with self.assertRaises(UnsupportedPythonVersionError):
            assert_supported_python_version((3, 8, 0))

    def test_python_4_0_is_unsupported(self) -> None:
        with self.assertRaises(UnsupportedPythonVersionError):
            assert_supported_python_version((4, 0, 0))

    # --- Boundary: exact lower bound is included ---

    def test_exact_lower_bound_included(self) -> None:
        assert_supported_python_version((3, 10, 0))

    # --- Boundary: exact upper bound is excluded ---

    def test_exact_upper_bound_excluded(self) -> None:
        with self.assertRaises(UnsupportedPythonVersionError):
            assert_supported_python_version((3, 14, 0))

    # --- Error message content ---

    def test_error_message_contains_install_hint(self) -> None:
        with self.assertRaises(UnsupportedPythonVersionError) as context:
            assert_supported_python_version((3, 9, 0))
        error_message = str(context.exception)
        self.assertIn("Install Python 3.13", error_message)
        self.assertIn(".venv", error_message)

    def test_error_message_contains_detected_version(self) -> None:
        with self.assertRaises(UnsupportedPythonVersionError) as context:
            assert_supported_python_version((3, 8, 17))
        assert "3.8.17" in str(context.exception)

    # --- Default version_info (None) uses sys.version_info ---

    @patch("runtime_compat.sys")
    def test_none_uses_sys_version_info_supported(self, mock_sys: unittest.mock.MagicMock) -> None:
        mock_sys.version_info = (3, 12, 1, "final", 0)
        # Should not raise when sys reports a supported version
        assert_supported_python_version(None)

    @patch("runtime_compat.sys")
    def test_none_uses_sys_version_info_unsupported(self, mock_sys: unittest.mock.MagicMock) -> None:
        mock_sys.version_info = (3, 9, 0, "final", 0)
        with self.assertRaises(UnsupportedPythonVersionError):
            assert_supported_python_version(None)

    @patch("runtime_compat.sys")
    def test_default_arg_uses_sys_version_info(self, mock_sys: unittest.mock.MagicMock) -> None:
        mock_sys.version_info = (3, 11, 4, "final", 0)
        # Calling with no argument should also work (defaults to None)
        assert_supported_python_version()


if __name__ == "__main__":
    unittest.main()
