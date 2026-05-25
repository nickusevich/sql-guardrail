"""Shared fixtures for the FastAPI server tests.

The server reads SQLGUARD_POLICY_PATH at lifespan-start. Tests set the env
var with monkeypatch and enter a TestClient context, which fires the
lifespan against the patched env.
"""
from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest

# Skip cleanly if the [server] extra isn't installed.
pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402,I001

from sqlguard.server import app  # noqa: E402


_POLICY_YAML = """\
read_only: true
tables:
  - name: orders
    allow_columns: [id, product_name, account_id, total]
    require_predicate:
      column: account_id
      op: "="
      value: "${tenant_id}"
forbid:
  always_true_predicates: true
  select_star: true
limits:
  max_sql_length: 5000
  max_limit_value: 1000
allowed_functions: [cast, count, sum, avg, coalesce]
"""


@pytest.fixture(scope="session")
def policy_path(tmp_path_factory: pytest.TempPathFactory) -> Path:
    p = tmp_path_factory.mktemp("sqlguard") / "policy.yml"
    p.write_text(_POLICY_YAML)
    return p


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch, policy_path: Path) -> Iterator[TestClient]:
    """TestClient with a fresh lifespan run per test.

    Each ``with TestClient(app)`` block triggers the lifespan, so
    app.state.policy is freshly loaded from the patched env var.
    """
    monkeypatch.setenv("SQLGUARD_POLICY_PATH", str(policy_path))
    with TestClient(app) as c:
        yield c
