"""Start the SOC API: `python -m app.api` from the repo root.

Loopback only; there is no authentication in this local lab build.

Port: 8000 by default, overridable with SOC_API_PORT. The Vite dev proxy reads
the same variable, so the console and API always agree. (Splunk Web also
defaults to 8000; on a machine running Splunk, use e.g. SOC_API_PORT=8001.)
"""

import os
import socket
import sys

import uvicorn

HOST = "127.0.0.1"


def _port() -> int:
    raw = os.environ.get("SOC_API_PORT", "8000")
    if not raw.isdigit() or not 1024 <= int(raw) <= 65535:
        sys.exit(f"SOC_API_PORT must be a number between 1024 and 65535 (got {raw!r}).")
    return int(raw)


def _check_free(port: int) -> None:
    """Fail with a clear message instead of a raw socket error."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        try:
            probe.bind((HOST, port))
        except OSError:
            sys.exit(
                f"Port {port} is already in use (Splunk Web uses 8000 by default). "
                f"Start with another port, e.g.  SOC_API_PORT=8001  and run the "
                f"frontend with the same SOC_API_PORT."
            )


if __name__ == "__main__":
    port = _port()
    _check_free(port)
    uvicorn.run("app.api.main:app", host=HOST, port=port, log_level="info")
