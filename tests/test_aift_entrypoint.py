from __future__ import annotations

import io
from contextlib import redirect_stderr
import unittest
from unittest.mock import patch

import aift
from runtime_compat import UnsupportedPythonVersionError


class AiftEntrypointTests(unittest.TestCase):
    def test_run_exits_with_code_1_for_unsupported_python(self) -> None:
        error = UnsupportedPythonVersionError(
            "Unsupported Python version detected: 3.14.3. "
            "AIFT currently supports Python 3.10-3.13."
        )

        stderr_buffer = io.StringIO()
        with patch.object(aift, "assert_supported_python_version", side_effect=error):
            with self.assertRaises(SystemExit) as context:
                with redirect_stderr(stderr_buffer):
                    aift._run()

        self.assertEqual(context.exception.code, 1)
        stderr_output = stderr_buffer.getvalue()
        self.assertIn("Unsupported Python version detected: 3.14.3", stderr_output)
        self.assertNotIn("Traceback", stderr_output)


if __name__ == "__main__":
    unittest.main()
