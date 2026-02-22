from __future__ import annotations

import unittest

from runtime_compat import UnsupportedPythonVersionError, assert_supported_python_version


class RuntimeCompatibilityTests(unittest.TestCase):
    def test_python_3_10_is_supported(self) -> None:
        assert_supported_python_version((3, 10, 0))

    def test_python_3_13_is_supported(self) -> None:
        assert_supported_python_version((3, 13, 9))

    def test_python_3_9_is_unsupported(self) -> None:
        with self.assertRaises(UnsupportedPythonVersionError) as context:
            assert_supported_python_version((3, 9, 18))

        error_message = str(context.exception)
        self.assertIn("3.9.18", error_message)
        self.assertIn("3.10-3.13", error_message)

    def test_python_3_14_is_unsupported(self) -> None:
        with self.assertRaises(UnsupportedPythonVersionError) as context:
            assert_supported_python_version((3, 14, 3))

        error_message = str(context.exception)
        self.assertIn("3.14.3", error_message)
        self.assertIn("3.10-3.13", error_message)


if __name__ == "__main__":
    unittest.main()
