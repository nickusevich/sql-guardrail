from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient


class TestVerifyEndpoint:
    def test_happy_path_returns_allowed(self, client: TestClient) -> None:
        resp = client.post(
            "/verify",
            json={
                "sql": "SELECT id, total FROM orders WHERE account_id = 42",
                "context": {"tenant_id": 42},
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body == {
            "allowed": True,
            "statement_kind": "SELECT",
            "violations": [],
        }

    def test_denied_select_star(self, client: TestClient) -> None:
        resp = client.post(
            "/verify",
            json={
                "sql": "SELECT * FROM orders WHERE account_id = 42",
                "context": {"tenant_id": 42},
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["allowed"] is False
        codes = [v["code"] for v in body["violations"]]
        assert "SELECT_STAR" in codes

    def test_missing_required_predicate(self, client: TestClient) -> None:
        resp = client.post(
            "/verify",
            json={
                "sql": "SELECT id FROM orders",
                "context": {"tenant_id": 42},
            },
        )
        body = resp.json()
        assert body["allowed"] is False
        codes = [v["code"] for v in body["violations"]]
        assert "MISSING_REQUIRED_PREDICATE" in codes
        # Suggestion field is the LLM-feedback payload; verify it's wired through.
        miss = next(v for v in body["violations"] if v["code"] == "MISSING_REQUIRED_PREDICATE")
        assert miss["suggestion"] is not None
        assert "account_id" in miss["suggestion"]

    def test_tautology_caught(self, client: TestClient) -> None:
        resp = client.post(
            "/verify",
            json={
                "sql": "SELECT id FROM orders WHERE 1=1 AND account_id = 42",
                "context": {"tenant_id": 42},
            },
        )
        body = resp.json()
        assert body["allowed"] is False
        assert any(v["code"] == "ALWAYS_TRUE_PREDICATE" for v in body["violations"])

    def test_context_placeholder_resolved(self, client: TestClient) -> None:
        # Same SQL, different tenant_id -> one allowed, one denied.
        ok = client.post(
            "/verify",
            json={
                "sql": "SELECT id FROM orders WHERE account_id = 7",
                "context": {"tenant_id": 7},
            },
        ).json()
        assert ok["allowed"] is True

        bad = client.post(
            "/verify",
            json={
                "sql": "SELECT id FROM orders WHERE account_id = 7",
                "context": {"tenant_id": 99},
            },
        ).json()
        assert bad["allowed"] is False

    def test_missing_sql_field_is_422(self, client: TestClient) -> None:
        resp = client.post("/verify", json={"context": {"tenant_id": 42}})
        assert resp.status_code == 422

    def test_extra_field_rejected(self, client: TestClient) -> None:
        # extra="forbid" catches typos before they silently no-op.
        resp = client.post(
            "/verify",
            json={
                "squl": "SELECT 1",
                "context": {"tenant_id": 42},
            },
        )
        assert resp.status_code == 422

    def test_oversized_sql_denied_not_500(self, client: TestClient) -> None:
        # Policy has max_sql_length=5000; library should return PARSE_ERROR, not crash.
        big = "SELECT id FROM orders WHERE account_id = 42 AND " + ("a=a AND " * 2000) + "1=1"
        resp = client.post("/verify", json={"sql": big, "context": {"tenant_id": 42}})
        assert resp.status_code == 200
        body = resp.json()
        assert body["allowed"] is False
        assert any(v["code"] == "PARSE_ERROR" for v in body["violations"])

    def test_adversarial_input_never_500s(self, client: TestClient) -> None:
        # Deep nesting that could blow recursion in a less defensive validator.
        sql = "SELECT id FROM orders WHERE " + ("(" * 500) + "1=1" + (")" * 500)
        resp = client.post("/verify", json={"sql": sql, "context": {"tenant_id": 42}})
        assert resp.status_code == 200
        assert resp.json()["allowed"] is False

    def test_function_allowlist_blocks_pg_sleep(self, client: TestClient) -> None:
        resp = client.post(
            "/verify",
            json={
                "sql": "SELECT pg_sleep(5) FROM orders WHERE account_id = 42",
                "context": {"tenant_id": 42},
            },
        )
        body = resp.json()
        assert body["allowed"] is False
        assert any(v["code"] == "FUNCTION_NOT_ALLOWED" for v in body["violations"])

    def test_response_shape_matches_cli_json(self, client: TestClient) -> None:
        # The /verify response must be byte-equivalent to the CLI --format json
        # output. Same keys, same nested shape — caller can swap between CLI
        # and REST without changing parsers.
        body = client.post(
            "/verify",
            json={
                "sql": "SELECT id FROM orders WHERE account_id = 42",
                "context": {"tenant_id": 42},
            },
        ).json()
        assert set(body.keys()) == {"allowed", "statement_kind", "violations"}
        # If any violations were emitted they'd carry these four keys.
        # Trigger one to test the violation shape:
        denied = client.post(
            "/verify",
            json={
                "sql": "SELECT * FROM orders WHERE account_id = 42",
                "context": {"tenant_id": 42},
            },
        ).json()
        assert denied["violations"], "expected at least one violation"
        for v in denied["violations"]:
            assert set(v.keys()) == {"code", "category", "message", "suggestion"}
