"""AIFT application entry point.

This module serves as the main entry point for the AI Forensic Triage (AIFT)
application. It validates the Python runtime version, loads the YAML
configuration, creates the Flask application, and starts the local development
server. A browser window is automatically opened after a short delay.

Usage::

    python aift.py
"""

from __future__ import annotations

import sys
import threading
import webbrowser

from runtime_compat import UnsupportedPythonVersionError, assert_supported_python_version


def main() -> None:
    """Load configuration, create the Flask app, and start the development server.

    Reads server host and port from ``config.yaml``, creates the Flask
    application via the application factory, schedules a browser launch
    after a 1-second delay, and starts the Flask development server with
    the reloader and debug mode disabled.

    Raises:
        UnsupportedPythonVersionError: If the active Python version falls
            outside the supported range (3.10 -- 3.13).
    """
    assert_supported_python_version()

    from app import create_app
    from app.config import load_config

    config = load_config()
    server_config = config.get("server", {})
    host = server_config.get("host", "127.0.0.1")
    port = int(server_config.get("port", 5000))

    app = create_app()
    url = f"http://{host}:{port}"

    def _open_browser() -> None:
        try:
            webbrowser.open(url)
        except Exception:
            # Browser launch failures should not prevent server startup.
            pass

    threading.Timer(1.0, _open_browser).start()
    app.run(host=host, port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    try:
        main()
    except UnsupportedPythonVersionError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from None
