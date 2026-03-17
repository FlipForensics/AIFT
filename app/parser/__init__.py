"""Forensic artifact parsing package.

Re-exports the public API so that existing ``from app.parser import ...``
statements continue to work after the module was split into a package.
"""

from dissect.target.exceptions import UnsupportedPluginError

from .core import (
    EVTX_MAX_RECORDS_PER_FILE,
    MAX_RECORDS_PER_ARTIFACT,
    UNKNOWN_VALUE,
    ForensicParser,
)
from .registry import ARTIFACT_REGISTRY

__all__ = [
    "ARTIFACT_REGISTRY",
    "EVTX_MAX_RECORDS_PER_FILE",
    "ForensicParser",
    "MAX_RECORDS_PER_ARTIFACT",
    "UNKNOWN_VALUE",
    "UnsupportedPluginError",
]
