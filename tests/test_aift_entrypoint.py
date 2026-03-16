from __future__ import annotations

import unittest
from unittest.mock import patch

import aift
from runtime_compat import UnsupportedPythonVersionError


class AiftEntrypointTests(unittest.TestCase):
    def test_main_raises_for_unsupported_python(self) -> None:
        """Verify main() propagates UnsupportedPythonVersionError."""
        error = UnsupportedPythonVersionError(
            "Unsupported Python version detected: 3.14.3. "
            "AIFT currently supports Python 3.10-3.13."
        )

        with patch.object(aift, "assert_supported_python_version", side_effect=error):
            with self.assertRaises(UnsupportedPythonVersionError):
                aift.main()


if __name__ == "__main__":
    unittest.main()
