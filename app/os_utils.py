"""Shared OS-type utility functions.

Provides lightweight, dependency-free helpers for normalizing operating
system identifiers.  Both the parser and analyzer packages import from
this module so that OS-type normalisation is defined once and reused
everywhere.

Attributes:
    SUPPORTED_OS_TYPES: Tuple of OS identifiers with dedicated artifact
        registries.
"""

from __future__ import annotations

__all__ = [
    "SUPPORTED_OS_TYPES",
    "normalize_os_type",
]

SUPPORTED_OS_TYPES: tuple[str, ...] = ("windows", "linux")


def normalize_os_type(os_type: str | None) -> str:
    """Normalize an OS type identifier to its canonical lowercase form.

    Args:
        os_type: Operating system identifier (e.g. ``"windows"``,
            ``"linux"``, ``"Linux "``).  ``None`` or empty values
            default to ``"windows"``.

    Returns:
        The lowercased, stripped OS type string, defaulting to
        ``"windows"`` when *os_type* is falsy.
    """
    return str(os_type).strip().lower() if os_type else "windows"
