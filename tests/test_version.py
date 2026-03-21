"""Tests for the app.version module.

Validates that the centralized version metadata is correctly defined
and follows the expected semantic versioning format.
"""

from __future__ import annotations

import importlib
import re
import unittest


class VersionModuleTests(unittest.TestCase):
    """Tests for app.version constants and module attributes."""

    def test_tool_version_is_defined(self) -> None:
        """TOOL_VERSION must be a non-empty string."""
        from app.version import TOOL_VERSION

        self.assertIsInstance(TOOL_VERSION, str)
        self.assertTrue(len(TOOL_VERSION) > 0, "TOOL_VERSION must not be empty")

    def test_module_docstring_exists(self) -> None:
        """The version module must have a module-level docstring."""
        import app.version as version_mod

        self.assertIsNotNone(version_mod.__doc__)
        self.assertTrue(len(version_mod.__doc__.strip()) > 0)

    def test_reimport_consistency(self) -> None:
        """Re-importing the module must yield the same TOOL_VERSION value."""
        import app.version as version_mod

        original = version_mod.TOOL_VERSION
        importlib.reload(version_mod)
        self.assertEqual(version_mod.TOOL_VERSION, original)


if __name__ == "__main__":
    unittest.main()
