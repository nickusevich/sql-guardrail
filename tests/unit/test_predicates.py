from __future__ import annotations

import pytest
import sqlglot

from sqlguard.config.schema import Policy
from sqlguard.core.rules.predicates import check_predicates
from sqlguard.result import ViolationCode


@pytest.fixture
def policy_tenant() -> Policy:
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
                },
            ],
            "forbid": {"always_true_predicates": True},
        }
    )


@pytest.mark.parametrize(
    "sql, ctx, expected",
    [
        ("SELECT id FROM orders WHERE account_id = 42", {"tenant_id": 42}, []),
        (
            "SELECT id FROM orders",
            {"tenant_id": 42},
            [ViolationCode.MISSING_REQUIRED_PREDICATE],
        ),
        (
            "SELECT id FROM orders WHERE account_id = 99",
            {"tenant_id": 42},
            [ViolationCode.MISSING_REQUIRED_PREDICATE],
        ),
        (
            "SELECT id FROM orders WHERE account_id = 42 AND status = 'paid'",
            {"tenant_id": 42},
            [],
        ),
        (
            "SELECT id FROM orders WHERE 1 = 1",
            {"tenant_id": 42},
            [ViolationCode.ALWAYS_TRUE_PREDICATE, ViolationCode.MISSING_REQUIRED_PREDICATE],
        ),
        (
            "SELECT id FROM orders WHERE account_id = 42 OR 1 = 1",
            {"tenant_id": 42},
            [ViolationCode.ALWAYS_TRUE_PREDICATE, ViolationCode.MISSING_REQUIRED_PREDICATE],
        ),
        (
            "SELECT id FROM orders WHERE account_id = 42",
            {},
            [ViolationCode.POLICY_ERROR],
        ),
    ],
)
def test_predicate_cases(
    policy_tenant: Policy, sql: str, ctx: dict, expected: list[ViolationCode]
) -> None:
    e = sqlglot.parse_one(sql, dialect="postgres")
    codes = [v.code for v in check_predicates(e, policy_tenant, ctx)]
    assert codes == expected


def test_in_predicate_for_admin_users() -> None:
    p = Policy.from_dict(
        {
            "tables": [
                {
                    "name": "orders",
                    "require_predicate": {
                        "column": "account_id",
                        "op": "IN",
                        "value": "${tenant_ids}",
                    },
                },
            ],
        }
    )
    e = sqlglot.parse_one(
        "SELECT id FROM orders WHERE account_id IN (1, 2, 5)", dialect="postgres"
    )
    assert check_predicates(e, p, {"tenant_ids": [1, 2, 5]}) == []


def test_in_single_literal_satisfies_equality(policy_tenant: Policy) -> None:
    """Regression: `account_id IN (42)` is semantically equivalent to
    `account_id = 42` and must satisfy a require_predicate with op='='."""
    e = sqlglot.parse_one(
        "SELECT id FROM orders WHERE account_id IN (42)", dialect="postgres"
    )
    codes = [v.code for v in check_predicates(e, policy_tenant, {"tenant_id": 42})]
    assert ViolationCode.MISSING_REQUIRED_PREDICATE not in codes


def test_in_multiple_literals_does_not_satisfy_equality(
    policy_tenant: Policy,
) -> None:
    """`account_id IN (42, 99)` could return tenant 99's data — must NOT
    satisfy `op='=' value=42`."""
    e = sqlglot.parse_one(
        "SELECT id FROM orders WHERE account_id IN (42, 99)", dialect="postgres"
    )
    codes = [v.code for v in check_predicates(e, policy_tenant, {"tenant_id": 42})]
    assert ViolationCode.MISSING_REQUIRED_PREDICATE in codes


@pytest.fixture
def policy_tenant_rw() -> Policy:
    """Read-write variant of policy_tenant — enables INSERT/UPDATE/DELETE/MERGE
    on `orders` so the require_predicate behavior on writes can be tested."""
    return Policy.from_dict(
        {
            "read_only": False,
            "tables": [
                {
                    "name": "orders",
                    "allow_columns": ["id", "account_id", "status"],
                    "require_predicate": {
                        "column": "account_id",
                        "op": "=",
                        "value": "${tenant_id}",
                    },
                },
            ],
            "forbid": {"always_true_predicates": True},
        }
    )


def test_insert_values_does_not_falsely_trigger_require_predicate(
    policy_tenant_rw: Policy,
) -> None:
    """Regression: INSERT has no WHERE on the target — require_predicate
    is WHERE-shaped and cannot apply. Write-side tenant isolation must
    use RLS / CHECK constraints at the DB layer."""
    e = sqlglot.parse_one(
        "INSERT INTO orders (id, account_id) VALUES (1, 42)", dialect="postgres"
    )
    codes = [v.code for v in check_predicates(e, policy_tenant_rw, {"tenant_id": 42})]
    assert ViolationCode.MISSING_REQUIRED_PREDICATE not in codes


def test_insert_select_does_not_double_flag(policy_tenant_rw: Policy) -> None:
    """Regression: `INSERT ... SELECT ... WHERE account_id=42` has the
    predicate at the inner SELECT scope (checked there). The outer
    INSERT DmlScope must NOT fire its own MISSING_REQUIRED_PREDICATE."""
    e = sqlglot.parse_one(
        "INSERT INTO orders (id, account_id) "
        "SELECT id, account_id FROM orders WHERE account_id = 42",
        dialect="postgres",
    )
    codes = [v.code for v in check_predicates(e, policy_tenant_rw, {"tenant_id": 42})]
    assert ViolationCode.MISSING_REQUIRED_PREDICATE not in codes


def test_update_still_enforces_require_predicate(
    policy_tenant_rw: Policy,
) -> None:
    """Guard against the Gap-A fix accidentally relaxing UPDATE checks.
    UPDATE has a WHERE clause on the target — the predicate MUST be
    enforced there."""
    e = sqlglot.parse_one("UPDATE orders SET status = 1", dialect="postgres")
    codes = [v.code for v in check_predicates(e, policy_tenant_rw, {"tenant_id": 42})]
    assert ViolationCode.MISSING_REQUIRED_PREDICATE in codes


def test_delete_still_enforces_require_predicate(
    policy_tenant_rw: Policy,
) -> None:
    """Same as above for DELETE."""
    e = sqlglot.parse_one("DELETE FROM orders", dialect="postgres")
    codes = [v.code for v in check_predicates(e, policy_tenant_rw, {"tenant_id": 42})]
    assert ViolationCode.MISSING_REQUIRED_PREDICATE in codes


def test_merge_on_always_true_is_flagged() -> None:
    """Regression: `MERGE ... ON 1=1` must be caught by the always-true
    rule. Previously only WHERE / JOIN ON were walked; MERGE's `on` arg
    was a different node type and slipped through."""
    p = Policy.from_dict(
        {"read_only": False, "forbid": {"always_true_predicates": True}}
    )
    e = sqlglot.parse_one(
        "MERGE INTO orders o USING (SELECT 1 AS x) s ON 1=1 "
        "WHEN MATCHED THEN UPDATE SET status = 'x'",
        dialect="postgres",
    )
    codes = [v.code for v in check_predicates(e, p)]
    assert ViolationCode.ALWAYS_TRUE_PREDICATE in codes
