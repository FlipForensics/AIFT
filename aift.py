"""AIFT application entry point."""

from __future__ import annotations

import threading
import webbrowser

from app import create_app
from app.config import load_config


def main() -> None:
    """Load configuration and run the Flask development server."""
    config = load_config("config.yaml")
    server_config = config.get("server", {})
    host = server_config.get("host", "127.0.0.1")
    port = int(server_config.get("port", 5000))

    app = create_app("config.yaml")
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
    main()
