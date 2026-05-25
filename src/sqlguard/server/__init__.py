"""FastAPI server for sql-guardrail.

Optional. Install with ``uv add "sql-guardrail[server]"`` (or
``pip install "sql-guardrail[server]"``).

The server is a thin HTTP wrapper over :func:`sqlguard.verify` — all
validation logic lives in the core library. Run with the
``sqlguard-server`` console script or ``python -m sqlguard.server``.
"""
from sqlguard.server.app import app

__all__ = ["app"]
