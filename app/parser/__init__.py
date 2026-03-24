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
from .registry import (
    LINUX_ARTIFACT_REGISTRY,
    WINDOWS_ARTIFACT_REGISTRY,
    get_artifact_registry,
)

__all__ = [
    "EVTX_MAX_RECORDS_PER_FILE",
    "ForensicParser",
    "LINUX_ARTIFACT_REGISTRY",
    "MAX_RECORDS_PER_ARTIFACT",
    "UNKNOWN_VALUE",
    "UnsupportedPluginError",
    "WINDOWS_ARTIFACT_REGISTRY",
    "core",
    "get_artifact_registry",
    "registry",
]
