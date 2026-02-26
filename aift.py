"""AIFT application entry point."""

from __future__ import annotations

import sys
import threading
import webbrowser

from runtime_compat import UnsupportedPythonVersionError, assert_supported_python_version


def main() -> None:
    """Load configuration and run the Flask development server."""
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


def _run() -> None:
    try:
        main()
    except UnsupportedPythonVersionError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    _run()
