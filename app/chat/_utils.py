"""Shared utility helpers for the ``chat`` package.

Small, dependency-free functions used by multiple sibling modules
(``manager`` and ``csv_retrieval``).  Keeping them here avoids
circular imports -- this module imports nothing from within the
``chat`` package.

Attributes:
    stringify_chat_value: Canonical string-coercion helper for the
        chat package.
"""

from __future__ import annotations

from typing import Any

__all__ = ["stringify_chat_value"]


def stringify_chat_value(value: Any, default: str = "") -> str:
    """Convert *value* to a stripped string, returning *default* when empty.

    This is the single canonical implementation of the stringify helper
    shared across the ``chat`` package.  Both :mod:`~app.chat.manager`
    and :mod:`~app.chat.csv_retrieval` import this function instead of
    maintaining their own duplicate definitions.

    Args:
        value: Arbitrary value to stringify.
        default: Fallback string when *value* is *None* or blank.

    Returns:
        The stripped string representation or *default*.
    """
    text = str(value).strip() if value is not None else ""
    return text or default
