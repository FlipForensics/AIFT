"""Shared utility helpers for the ``chat`` package.

Small, dependency-free functions used by multiple sibling modules
(``manager`` and ``csv_retrieval``).  Keeping them here avoids
circular imports -- this module imports nothing from within the
``chat`` package.

The canonical ``stringify`` implementation now lives in
:mod:`app.utils`.  This module re-exports it under the legacy
``stringify_chat_value`` alias so existing callers are unaffected.

Attributes:
    stringify_chat_value: Re-exported string-coercion helper from
        :mod:`app.utils`.
"""

from __future__ import annotations

from ..utils import stringify as stringify_chat_value

__all__ = ["stringify_chat_value"]
