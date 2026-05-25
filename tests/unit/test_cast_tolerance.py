"""CAST tolerance in predicate matching."""
from __future__ import annotations

import pytest
import sqlglot

from sqlguard.config.schema import Policy
from sqlguard.core.rules.predicates import check_predicates
from sqlguard.result import ViolationCode


@pytest.fixture
def tenant_policy() -> Policy:
    return Policy.from_dict(
        {
            "tables": [
                {
                    "name": "orders",
                    "require_predicate": {
                        "column": "account_id",
                        "op": "=",
                        "value": "${tenant_id}",
                    },
                }
            ]
        }
    )


@pytest.mark.parametrize(
    "sql, should_satisfy",
    [
        # direct casts of the column — should satisfy
        ("SELECT id FROM orders WHERE account_id = 42", True),
        ("SELECT id FROM orders WHERE account_id::text = 42", True),
        ("SELECT id FROM orders WHERE account_id::text = '42'", True),
        ("SELECT id FROM orders WHERE account_id::int = 42", True),
        ("SELECT id FROM orders WHERE account_id::bigint = 42", True),
        # casts of an expression — must NOT satisfy (semantics may differ)
        ("SELECT id FROM orders WHERE (account_id + 1)::text = 42", False),
        ("SELECT id FROM orders WHERE (account_id * 2)::int = 42", False),
        # function on column — must NOT satisfy
        ("SELECT id FROM orders WHERE abs(account_id) = 42", False),
        ("SELECT id FROM orders WHERE COALESCE(account_id, 0) = 42", False),
    ],
)
def test_cast_tolerance(tenant_policy: Policy, sql: str, should_satisfy: bool) -> None:
    e = sqlglot.parse_one(sql, dialect="postgres")
    codes = [v.code for v in check_predicates(e, tenant_policy, {"tenant_id": 42})]
    has_missing = ViolationCode.MISSING_REQUIRED_PREDICATE in codes
    assert has_missing == (not should_satisfy)
