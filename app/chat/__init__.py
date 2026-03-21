"""Chat history storage and CSV retrieval for post-analysis Q&A.

This package provides the :class:`ChatManager` class for persisting
per-case chat conversations and assembling AI prompt context, as well
as CSV retrieval utilities for injecting artifact data into chat prompts.

Modules:
    manager: Core ChatManager class (history, context, token budgeting).
    csv_retrieval: Heuristic CSV matching and row formatting.
"""

from .manager import ChatManager

__all__ = ["ChatManager", "csv_retrieval", "manager"]
