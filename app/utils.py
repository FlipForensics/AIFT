"""Shared utility helpers for the ``app`` package.

Small, dependency-free functions used by multiple sub-packages
(``chat``, ``reporter``, etc.).  This module imports nothing from
within the ``app`` package to avoid circular dependencies.

Attributes:
    stringify: Canonical string-coercion helper used across the
        entire application.
"""

from __future__ import annotations

from typing import Any

__all__ = ["stringify"]


def stringify(value: Any, default: str = "") -> str:
    """Convert *value* to a stripped string, returning *default* when empty.

    This is the single canonical implementation of the stringify helper
    used across the application.  All sub-packages should import this
    function rather than maintaining their own duplicate definitions.

    Args:
        value: Arbitrary value to stringify.
        default: Fallback string when *value* is *None* or blank.

    Returns:
        The stripped string representation or *default*.
    """
    if value is None:
        return default
    text = str(value).strip()
    return text if text else default
