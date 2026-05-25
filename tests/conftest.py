from __future__ import annotations

import pytest

from sqlguard import Policy


@pytest.fixture
def standard_policy() -> Policy:
    """Strict policy mirroring `examples/policy.yml` — used by the corpus
    tests to ensure malicious files fail under the same setup users would
    deploy."""
    return Policy.from_dict(
        {
            "read_only": True,
            "tables": [
                {
                    "name": "orders",
                    "allow_columns": ["id", "product_name", "account_id", "created_at", "total"],
                    "large": True,
                    "require_predicate": {
                        "column": "account_id",
                        "op": "=",
                        "value": "${tenant_id}",
                    },
                },
                {
                    "name": "users",
                    "allow_columns": ["id", "name"],
                    "deny_columns": ["password_hash", "ssn", "email"],
                },
            ],
            "forbid": {
                "always_true_predicates": True,
                "select_star": True,
                "recursive_cte": True,
                "cartesian_join": True,
            },
            "limits": {
                "max_sql_length": 100_000,
            },
        }
    )


@pytest.fixture
def standard_context() -> dict:
    return {"tenant_id": 42}
