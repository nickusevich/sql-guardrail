"""FastAPI app, lifespan, and route handlers for the sql-guardrail server.

Design notes:

* Policy is loaded ONCE at startup from ``SQLGUARD_POLICY_PATH`` and stashed
  on ``app.state.policy``. This mirrors the recommended integration pattern
  in ``examples/backend_integration.py`` — policy is config, not user input.
* ``/verify`` always returns HTTP 200; the ``allowed`` boolean is in the body.
  This matches the CLI's exit-code convention (0=allowed, 1=denied) and means
  callers branch on a single field rather than mixing HTTP status with policy
  outcome.
* The library guarantees ``verify()`` never raises — we forward that contract
  through the HTTP layer. Adversarial input becomes a ``VerifyResponse``
  with ``allowed=false``, never a 500.
"""
from __future__ import annotations

import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response, status

from sqlguard import Policy, __version__, verify
from sqlguard.server.models import HealthResponse, VerifyRequest, VerifyResponse

_log = logging.getLogger("sqlguard.server")
_POLICY_ENV = "SQLGUARD_POLICY_PATH"


def _load_policy_from_env() -> Policy:
    """Read the policy path from env and load it. Fail-loud on missing or bad.

    Raised exceptions propagate through FastAPI's lifespan and prevent the
    server from starting — a misconfigured server refuses to boot rather
    than serve requests with no policy.
    """
    raw = os.environ.get(_POLICY_ENV)
    if not raw:
        raise RuntimeError(
            f"{_POLICY_ENV} is not set. Point it at a policy YAML file, e.g. "
            f"{_POLICY_ENV}=/etc/sqlguard/policy.yml"
        )
    path = Path(raw)
    if not path.is_file():
        raise RuntimeError(f"{_POLICY_ENV}={raw!r} does not exist or is not a file.")
    return Policy.from_yaml(path)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Boot/shutdown hook. Loads the policy before any request is served."""
    app.state.policy = _load_policy_from_env()
    _log.info(
        "sqlguard server ready (version=%s, policy=%s)",
        __version__,
        os.environ.get(_POLICY_ENV),
    )
    yield


app = FastAPI(
    title="sql-guardrail",
    version=__version__,
    description=(
        "HTTP server for sql-guardrail. POST /verify wraps the library's "
        "verify() function. Policy is loaded at startup from "
        "$SQLGUARD_POLICY_PATH; per-request body carries only SQL and "
        "optional context."
    ),
    lifespan=lifespan,
)


@app.post(
    "/verify",
    response_model=VerifyResponse,
    summary="Validate a SQL string against the loaded policy",
    responses={
        200: {"description": "Validated. Check `allowed` in the body."},
        422: {"description": "Request body failed schema validation."},
    },
)
def verify_endpoint(req: VerifyRequest, request: Request) -> VerifyResponse:
    policy: Policy = request.app.state.policy
    result = verify(req.sql, policy, context=req.context)
    # One structured log line per request. No raw SQL by default — operators
    # who want it can crank up log level and add it back, but the default
    # avoids spilling potentially sensitive query text.
    _log.info(
        "verify allowed=%s kind=%s codes=%s",
        result.allowed,
        result.statement_kind,
        [v.code.value for v in result.violations],
    )
    return VerifyResponse.from_result(result)


@app.get(
    "/health",
    response_model=HealthResponse,
    summary="Liveness probe",
    responses={
        200: {"description": "Policy loaded and ready."},
        503: {"description": "Policy not loaded (boot failure)."},
    },
)
def health(request: Request, response: Response) -> HealthResponse:
    # state.policy is set by the lifespan handler before any request is
    # served, so under normal operation this is always truthy. The 503
    # branch exists for the test that patches state to simulate a
    # degraded server. Returning the model (not JSONResponse) keeps the
    # response_model contract enforced — the OpenAPI schema and the wire
    # body cannot drift apart.
    policy = getattr(request.app.state, "policy", None)
    loaded = policy is not None
    if not loaded:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return HealthResponse(
        status="ok" if loaded else "degraded",
        policy_loaded=loaded,
        version=__version__,
    )
