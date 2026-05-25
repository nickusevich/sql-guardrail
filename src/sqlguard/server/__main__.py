"""Launcher for the ``sqlguard-server`` console script (and ``python -m sqlguard.server``).

Reads host/port/log-level from env so the Docker image is configurable
without rebuilding. Delegates the actual serving to uvicorn.
"""
from __future__ import annotations

import os

import uvicorn


def main() -> None:
    # Pass the import string (not the app object) so uvicorn's reload /
    # worker machinery can re-import in worker processes if ever enabled.
    uvicorn.run(
        "sqlguard.server:app",
        host=os.environ.get("SQLGUARD_HOST", "0.0.0.0"),  # noqa: S104  # binding inside container
        port=int(os.environ.get("SQLGUARD_PORT", "8000")),
        log_level=os.environ.get("SQLGUARD_LOG_LEVEL", "info"),
    )


if __name__ == "__main__":
    main()
