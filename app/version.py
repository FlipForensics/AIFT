"""Centralized application version metadata.

This module is the single source of truth for the AIFT version string.
It is referenced by the audit logger, HTML report generator, and the
settings/about UI so that version numbers stay consistent across all
outputs.

Attributes:
    TOOL_VERSION: Semantic version string for the current AIFT release.
"""

TOOL_VERSION = "1.5"