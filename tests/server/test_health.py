from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient


def test_health_ok_when_policy_loaded(client: TestClient) -> None:
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert body["policy_loaded"] is True
    assert "version" in body


def test_health_503_when_policy_missing(client: TestClient) -> None:
    # Simulate a degraded server: blow away the cached policy and re-probe.
    # In real failure modes the lifespan would have raised before any
    # request landed, but this exercises the defensive branch in /health.
    client.app.state.policy = None
    resp = client.get("/health")
    assert resp.status_code == 503
    assert resp.json()["policy_loaded"] is False
