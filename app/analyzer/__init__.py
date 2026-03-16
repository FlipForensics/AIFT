"""AI analysis orchestration package for forensic triage.

Provides the ``ForensicAnalyzer`` class and supporting sub-modules for
token budgeting, date filtering, column projection, deduplication,
chunked analysis, citation validation, IOC extraction, and audit logging.

Sub-modules:

- ``constants``: Compile-time constants, regex, prompt templates.
- ``utils``: Pure utility functions (string, datetime, CSV, config readers).
- ``ioc``: IOC extraction and prompt-building helpers.
- ``citations``: Citation validation against source CSV.
- ``data_prep``: Date filtering, dedup, statistics, prompt assembly.
- ``chunking``: Chunked analysis and hierarchical merge.
- ``core``: The ``ForensicAnalyzer`` class itself.
"""

from __future__ import annotations

from .constants import PROJECT_ROOT
from .core import ForensicAnalyzer

__all__ = [
    "ForensicAnalyzer",
    "PROJECT_ROOT",
]
