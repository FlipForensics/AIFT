"""Reporter package for HTML forensic report generation.

Re-exports :class:`ReportGenerator` from :mod:`app.reporter.generator` so
that existing ``from app.reporter import ReportGenerator`` imports continue
to work without modification.
"""

from .generator import ReportGenerator

__all__ = ["ReportGenerator"]
