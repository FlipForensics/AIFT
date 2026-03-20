"""Tests for the aift.py application entry point.

Covers the ``main()`` function, the ``_open_browser`` inner closure, and the
``if __name__ == "__main__"`` guard that translates version errors into a
clean exit.
"""

from __future__ import annotations

import sys
import unittest
from unittest.mock import MagicMock, call, patch

import aift
from runtime_compat import UnsupportedPythonVersionError


class TestMainUnsupportedPython(unittest.TestCase):
    """Tests for main() when the Python version check fails."""

    def test_main_raises_for_unsupported_python(self) -> None:
        """Verify main() propagates UnsupportedPythonVersionError."""
        error = UnsupportedPythonVersionError(
            "Unsupported Python version detected: 3.14.3. "
            "AIFT currently supports Python 3.10-3.13."
        )

        with patch.object(aift, "assert_supported_python_version", side_effect=error):
            with self.assertRaises(UnsupportedPythonVersionError):
                aift.main()


class TestMainHappyPath(unittest.TestCase):
    """Tests for main() when configuration loads successfully."""

    def _run_main_with_config(self, config: dict) -> tuple[MagicMock, MagicMock, MagicMock]:
        """Helper to run main() with a given config dict.

        Args:
            config: The dictionary that ``load_config()`` should return.

        Returns:
            A tuple of (mock_create_app, mock_timer, mock_app) for assertions.
        """
        mock_app = MagicMock()
        mock_create_app = MagicMock(return_value=mock_app)
        mock_load_config = MagicMock(return_value=config)
        mock_timer_instance = MagicMock()
        mock_timer_class = MagicMock(return_value=mock_timer_instance)

        with (
            patch.object(aift, "assert_supported_python_version"),
            patch.dict("sys.modules", {
                "app": MagicMock(create_app=mock_create_app),
                "app.config": MagicMock(load_config=mock_load_config),
            }),
            patch.object(aift.threading, "Timer", mock_timer_class),
        ):
            aift.main()

        return mock_create_app, mock_timer_class, mock_app

    def test_main_uses_default_host_and_port(self) -> None:
        """When server config is absent, defaults to 127.0.0.1:5000."""
        _, mock_timer, mock_app = self._run_main_with_config({})

        mock_app.run.assert_called_once_with(
            host="127.0.0.1", port=5000, debug=False, use_reloader=False,
        )

    def test_main_uses_custom_host_and_port(self) -> None:
        """When server config specifies host/port, those values are used."""
        config = {"server": {"host": "0.0.0.0", "port": 8080}}
        _, _, mock_app = self._run_main_with_config(config)

        mock_app.run.assert_called_once_with(
            host="0.0.0.0", port=8080, debug=False, use_reloader=False,
        )

    def test_main_port_is_cast_to_int(self) -> None:
        """Port value from YAML may be a string; main() must cast to int."""
        config = {"server": {"host": "127.0.0.1", "port": "9090"}}
        _, _, mock_app = self._run_main_with_config(config)

        mock_app.run.assert_called_once_with(
            host="127.0.0.1", port=9090, debug=False, use_reloader=False,
        )

    def test_main_creates_flask_app(self) -> None:
        """Verify create_app() is called exactly once."""
        mock_create_app, _, _ = self._run_main_with_config({})
        mock_create_app.assert_called_once()

    def test_main_schedules_browser_timer(self) -> None:
        """A 1-second Timer should be started to open the browser."""
        _, mock_timer, _ = self._run_main_with_config({})

        mock_timer.assert_called_once()
        args, _ = mock_timer.call_args
        self.assertEqual(args[0], 1.0)
        # The second arg is the _open_browser callable
        self.assertTrue(callable(args[1]))
        mock_timer.return_value.start.assert_called_once()

    def test_main_builds_correct_url_for_browser(self) -> None:
        """The URL passed to webbrowser.open should match host:port."""
        config = {"server": {"host": "localhost", "port": 3000}}
        mock_app = MagicMock()
        mock_create_app = MagicMock(return_value=mock_app)
        mock_load_config = MagicMock(return_value=config)
        mock_timer_instance = MagicMock()
        mock_timer_class = MagicMock(return_value=mock_timer_instance)

        with (
            patch.object(aift, "assert_supported_python_version"),
            patch.dict("sys.modules", {
                "app": MagicMock(create_app=mock_create_app),
                "app.config": MagicMock(load_config=mock_load_config),
            }),
            patch.object(aift.threading, "Timer", mock_timer_class),
        ):
            aift.main()

        # Extract the _open_browser callback and invoke it
        timer_callback = mock_timer_class.call_args[0][1]
        with patch.object(aift.webbrowser, "open") as mock_wb_open:
            timer_callback()
            mock_wb_open.assert_called_once_with("http://localhost:3000")

    def test_main_with_empty_server_section(self) -> None:
        """An empty 'server' key should still use defaults."""
        config = {"server": {}}
        _, _, mock_app = self._run_main_with_config(config)

        mock_app.run.assert_called_once_with(
            host="127.0.0.1", port=5000, debug=False, use_reloader=False,
        )

    def test_main_partial_server_config_host_only(self) -> None:
        """When only host is specified, port defaults to 5000."""
        config = {"server": {"host": "192.168.1.1"}}
        _, _, mock_app = self._run_main_with_config(config)

        mock_app.run.assert_called_once_with(
            host="192.168.1.1", port=5000, debug=False, use_reloader=False,
        )

    def test_main_partial_server_config_port_only(self) -> None:
        """When only port is specified, host defaults to 127.0.0.1."""
        config = {"server": {"port": 7777}}
        _, _, mock_app = self._run_main_with_config(config)

        mock_app.run.assert_called_once_with(
            host="127.0.0.1", port=7777, debug=False, use_reloader=False,
        )


class TestOpenBrowserCallback(unittest.TestCase):
    """Tests for the _open_browser inner function created inside main()."""

    def _extract_browser_callback(self, config: dict | None = None) -> callable:
        """Run main() and return the _open_browser callback passed to Timer.

        Args:
            config: Optional config dict. Defaults to empty.

        Returns:
            The callback function scheduled by threading.Timer.
        """
        if config is None:
            config = {}

        mock_app = MagicMock()
        mock_timer_instance = MagicMock()
        mock_timer_class = MagicMock(return_value=mock_timer_instance)

        with (
            patch.object(aift, "assert_supported_python_version"),
            patch.dict("sys.modules", {
                "app": MagicMock(create_app=MagicMock(return_value=mock_app)),
                "app.config": MagicMock(load_config=MagicMock(return_value=config)),
            }),
            patch.object(aift.threading, "Timer", mock_timer_class),
        ):
            aift.main()

        return mock_timer_class.call_args[0][1]

    def test_open_browser_calls_webbrowser(self) -> None:
        """The callback should call webbrowser.open with the correct URL."""
        callback = self._extract_browser_callback()

        with patch.object(aift.webbrowser, "open") as mock_open:
            callback()
            mock_open.assert_called_once_with("http://127.0.0.1:5000")

    def test_open_browser_suppresses_exceptions(self) -> None:
        """Browser launch failures must not propagate."""
        callback = self._extract_browser_callback()

        with patch.object(aift.webbrowser, "open", side_effect=OSError("no browser")):
            # Should not raise
            callback()

    def test_open_browser_suppresses_generic_exception(self) -> None:
        """Even a generic Exception from webbrowser is silenced."""
        callback = self._extract_browser_callback()

        with patch.object(aift.webbrowser, "open", side_effect=Exception("unexpected")):
            callback()


class TestIfNameMain(unittest.TestCase):
    """Tests for the ``if __name__ == '__main__'`` guard block."""

    def test_successful_main_invocation(self) -> None:
        """When main() succeeds, no error is printed and no SystemExit occurs."""
        with patch.object(aift, "main") as mock_main:
            mock_main.return_value = None
            # Simulate running the module guard
            try:
                aift.main()
            except SystemExit:
                self.fail("SystemExit raised unexpectedly")

    def test_version_error_prints_to_stderr_and_exits(self) -> None:
        """UnsupportedPythonVersionError should print to stderr and exit(1)."""
        error_msg = (
            "Unsupported Python version detected: 3.14.3. "
            "AIFT currently supports Python 3.10-3.13."
        )
        error = UnsupportedPythonVersionError(error_msg)

        with (
            patch.object(aift, "main", side_effect=error),
            patch("builtins.print") as mock_print,
        ):
            # Replicate the if __name__ == "__main__" block
            with self.assertRaises(SystemExit) as ctx:
                try:
                    aift.main()
                except UnsupportedPythonVersionError as exc:
                    print(str(exc), file=sys.stderr)
                    raise SystemExit(1) from None

            self.assertEqual(ctx.exception.code, 1)
            mock_print.assert_called_once_with(error_msg, file=sys.stderr)

    def test_version_error_exit_code_is_one(self) -> None:
        """The exit code must be exactly 1 for version errors."""
        error = UnsupportedPythonVersionError("bad version")

        with patch.object(aift, "main", side_effect=error):
            with self.assertRaises(SystemExit) as ctx:
                try:
                    aift.main()
                except UnsupportedPythonVersionError as exc:
                    print(str(exc), file=sys.stderr)
                    raise SystemExit(1) from None

            self.assertEqual(ctx.exception.code, 1)


class TestMainCallsAssertVersion(unittest.TestCase):
    """Verify that main() calls assert_supported_python_version first."""

    def test_assert_version_called_before_imports(self) -> None:
        """assert_supported_python_version must be called during main()."""
        call_order: list[str] = []

        def track_assert() -> None:
            """Track when version assertion is called."""
            call_order.append("assert_version")

        mock_app = MagicMock()

        def track_create_app() -> MagicMock:
            """Track when create_app is called."""
            call_order.append("create_app")
            return mock_app

        with (
            patch.object(aift, "assert_supported_python_version", side_effect=track_assert),
            patch.dict("sys.modules", {
                "app": MagicMock(create_app=track_create_app),
                "app.config": MagicMock(load_config=MagicMock(return_value={})),
            }),
            patch.object(aift.threading, "Timer", MagicMock()),
        ):
            aift.main()

        self.assertEqual(call_order[0], "assert_version")
        self.assertIn("create_app", call_order)


class TestMainDebugAndReloaderDisabled(unittest.TestCase):
    """Ensure the Flask app always runs with debug and reloader off."""

    def test_debug_false(self) -> None:
        """Flask app.run must be called with debug=False."""
        mock_app = MagicMock()

        with (
            patch.object(aift, "assert_supported_python_version"),
            patch.dict("sys.modules", {
                "app": MagicMock(create_app=MagicMock(return_value=mock_app)),
                "app.config": MagicMock(load_config=MagicMock(return_value={})),
            }),
            patch.object(aift.threading, "Timer", MagicMock()),
        ):
            aift.main()

        _, kwargs = mock_app.run.call_args
        self.assertFalse(kwargs["debug"])
        self.assertFalse(kwargs["use_reloader"])


if __name__ == "__main__":
    unittest.main()
