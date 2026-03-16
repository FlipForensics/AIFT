"""Runtime compatibility checks for supported Python versions.

Ensures that AIFT is only executed under a supported Python interpreter
(currently 3.10 through 3.13 inclusive). This module is imported early in
the startup sequence -- before any third-party packages -- so that users
receive a clear error message instead of cryptic import failures.

Attributes:
    SUPPORTED_PYTHON_MIN: Minimum supported Python version as a ``(major, minor)`` tuple.
    SUPPORTED_PYTHON_MAX_EXCLUSIVE: First unsupported Python version (exclusive upper bound).
"""

from __future__ import annotations

import sys

SUPPORTED_PYTHON_MIN = (3, 10)
SUPPORTED_PYTHON_MAX_EXCLUSIVE = (3, 14)


class UnsupportedPythonVersionError(RuntimeError):
    """Raised when the active Python runtime is unsupported."""


def _format_version(version_info: tuple[int, int, int]) -> str:
    """Format a version tuple as a dotted string (e.g. ``3.10.12``)."""
    return f"{version_info[0]}.{version_info[1]}.{version_info[2]}"


def _supported_range_label() -> str:
    """Return a human-readable label for the supported version range (e.g. ``3.10-3.13``)."""
    max_minor = SUPPORTED_PYTHON_MAX_EXCLUSIVE[1] - 1
    return f"{SUPPORTED_PYTHON_MIN[0]}.{SUPPORTED_PYTHON_MIN[1]}-{SUPPORTED_PYTHON_MAX_EXCLUSIVE[0]}.{max_minor}"


def assert_supported_python_version(version_info: tuple[int, int, int] | None = None) -> None:
    """Validate that the current Python version is within the supported range.

    Args:
        version_info: Optional explicit version tuple ``(major, minor, micro)``.
            Defaults to ``sys.version_info[:3]`` when *None*.

    Raises:
        UnsupportedPythonVersionError: If the version falls outside the
            ``[SUPPORTED_PYTHON_MIN, SUPPORTED_PYTHON_MAX_EXCLUSIVE)`` range.
    """
    current_version = tuple(version_info or sys.version_info[:3])
    if current_version < SUPPORTED_PYTHON_MIN or current_version >= SUPPORTED_PYTHON_MAX_EXCLUSIVE:
        detected = _format_version(current_version)
        supported = _supported_range_label()
        raise UnsupportedPythonVersionError(
            f"Unsupported Python version detected: {detected}. "
            f"AIFT currently supports Python {supported}. "
            "Install Python 3.13 and recreate the virtual environment (.venv)."
        )
