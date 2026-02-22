"""Runtime compatibility checks for supported Python versions."""

from __future__ import annotations

import sys

SUPPORTED_PYTHON_MIN = (3, 10)
SUPPORTED_PYTHON_MAX_EXCLUSIVE = (3, 14)


class UnsupportedPythonVersionError(RuntimeError):
    """Raised when the active Python runtime is unsupported."""


def _format_version(version_info: tuple[int, int, int]) -> str:
    return f"{version_info[0]}.{version_info[1]}.{version_info[2]}"


def _supported_range_label() -> str:
    max_minor = SUPPORTED_PYTHON_MAX_EXCLUSIVE[1] - 1
    return f"{SUPPORTED_PYTHON_MIN[0]}.{SUPPORTED_PYTHON_MIN[1]}-{SUPPORTED_PYTHON_MAX_EXCLUSIVE[0]}.{max_minor}"


def assert_supported_python_version(version_info: tuple[int, int, int] | None = None) -> None:
    """Raise when Python is outside AIFT's supported runtime range."""
    current_version = tuple(version_info or sys.version_info[:3])
    if current_version < SUPPORTED_PYTHON_MIN or current_version >= SUPPORTED_PYTHON_MAX_EXCLUSIVE:
        detected = _format_version(current_version)
        supported = _supported_range_label()
        raise UnsupportedPythonVersionError(
            f"Unsupported Python version detected: {detected}. "
            f"AIFT currently supports Python {supported}. "
            "Install Python 3.13 and recreate the virtual environment (.venv)."
        )
