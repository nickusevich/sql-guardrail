"""Tests for the limits rule: cartesian, recursive CTE, max joins, max depth,
require LIMIT, max LIMIT value.
"""
from __future__ import annotations

import pytest
import sqlglot

from sqlguard.config.schema import Policy
from sqlguard.core.rules.limits import check_limits
from sqlguard.result import ViolationCode


@pytest.fixture
def default_policy() -> Policy:
    return Policy.from_dict({})  # forbid.cartesian=true, recursive_cte=true by default


# ---------------------------------------------------------------------------
# Cartesian joins
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "sql, expected_cartesian",
    [
        # cartesian patterns
        ("SELECT * FROM a, b WHERE a.id = b.id", True),                # comma-join (still has WHERE but no ON)
        ("SELECT * FROM a CROSS JOIN b", True),                         # explicit CROSS
        ("SELECT * FROM a CROSS JOIN b WHERE a.id = b.id", True),       # still CROSS even with WHERE
        # legit joins
        ("SELECT * FROM a JOIN b ON a.id = b.id", False),
        ("SELECT * FROM a LEFT JOIN b ON a.id = b.id", False),
        ("SELECT * FROM a JOIN b USING (id)", False),
        ("SELECT * FROM a", False),                                     # no join at all
    ],
)
def test_cartesian_detection(
    default_policy: Policy, sql: str, expected_cartesian: bool
) -> None:
    e = sqlglot.parse_one(sql, dialect="postgres")
    codes = [v.code for v in check_limits(e, default_policy)]
    has_cartesian = ViolationCode.CARTESIAN_JOIN in codes
    assert has_cartesian == expected_cartesian


def test_cartesian_disabled() -> None:
    p = Policy.from_dict({"forbid": {"cartesian_join": False}})
    e = sqlglot.parse_one("SELECT * FROM a CROSS JOIN b", dialect="postgres")
    codes = [v.code for v in check_limits(e, p)]
    assert ViolationCode.CARTESIAN_JOIN not in codes


# ---------------------------------------------------------------------------
# Recursive CTE
# ---------------------------------------------------------------------------
def test_recursive_cte_detected(default_policy: Policy) -> None:
    sql = "WITH RECURSIVE r AS (SELECT 1 AS n UNION ALL SELECT n+1 FROM r) SELECT n FROM r"
    e = sqlglot.parse_one(sql, dialect="postgres")
    codes = [v.code for v in check_limits(e, default_policy)]
    assert ViolationCode.RECURSIVE_CTE in codes


def test_non_recursive_cte_allowed(default_policy: Policy) -> None:
    sql = "WITH x AS (SELECT 1) SELECT * FROM x"
    e = sqlglot.parse_one(sql, dialect="postgres")
    codes = [v.code for v in check_limits(e, default_policy)]
    assert ViolationCode.RECURSIVE_CTE not in codes


def test_recursive_cte_can_be_disabled() -> None:
    p = Policy.from_dict({"forbid": {"recursive_cte": False}})
    sql = "WITH RECURSIVE r AS (SELECT 1 AS n UNION ALL SELECT n+1 FROM r) SELECT n FROM r"
    e = sqlglot.parse_one(sql, dialect="postgres")
    codes = [v.code for v in check_limits(e, p)]
    assert ViolationCode.RECURSIVE_CTE not in codes


# ---------------------------------------------------------------------------
# Max joins
# ---------------------------------------------------------------------------
def test_max_joins_enforced() -> None:
    p = Policy.from_dict({"limits": {"max_joins": 2}})
    # 3 joins (a, b, c, d)
    sql = "SELECT * FROM a JOIN b ON a.id=b.id JOIN c ON b.id=c.id JOIN d ON c.id=d.id"
    e = sqlglot.parse_one(sql, dialect="postgres")
    codes = [v.code for v in check_limits(e, p)]
    assert ViolationCode.MAX_JOINS_EXCEEDED in codes


def test_max_joins_under_limit_ok() -> None:
    p = Policy.from_dict({"limits": {"max_joins": 5}})
    sql = "SELECT * FROM a JOIN b ON a.id=b.id JOIN c ON b.id=c.id"
    e = sqlglot.parse_one(sql, dialect="postgres")
    codes = [v.code for v in check_limits(e, p)]
    assert ViolationCode.MAX_JOINS_EXCEEDED not in codes


# ---------------------------------------------------------------------------
# Max subquery depth
# ---------------------------------------------------------------------------
def test_max_subquery_depth_exceeded() -> None:
    p = Policy.from_dict({"limits": {"max_subquery_depth": 2}})
    sql = "SELECT * FROM (SELECT * FROM (SELECT * FROM orders) y) z"  # depth 3
    e = sqlglot.parse_one(sql, dialect="postgres")
    codes = [v.code for v in check_limits(e, p)]
    assert ViolationCode.MAX_SUBQUERY_DEPTH in codes


def test_subquery_depth_within_limit_ok() -> None:
    p = Policy.from_dict({"limits": {"max_subquery_depth": 4}})
    sql = "SELECT * FROM (SELECT * FROM orders) y"  # depth 2
    e = sqlglot.parse_one(sql, dialect="postgres")
    codes = [v.code for v in check_limits(e, p)]
    assert ViolationCode.MAX_SUBQUERY_DEPTH not in codes


# ---------------------------------------------------------------------------
# Require LIMIT on large tables
# ---------------------------------------------------------------------------
@pytest.fixture
def large_table_policy() -> Policy:
    return Policy.from_dict(
        {"tables": [{"name": "orders", "large": True}]}
    )


def test_large_table_without_limit_denied(large_table_policy: Policy) -> None:
    e = sqlglot.parse_one(
        "SELECT id FROM orders WHERE account_id = 42", dialect="postgres"
    )
    codes = [v.code for v in check_limits(e, large_table_policy)]
    assert ViolationCode.LIMIT_REQUIRED in codes


def test_large_table_with_limit_allowed(large_table_policy: Policy) -> None:
    e = sqlglot.parse_one(
        "SELECT id FROM orders WHERE account_id = 42 LIMIT 100", dialect="postgres"
    )
    codes = [v.code for v in check_limits(e, large_table_policy)]
    assert ViolationCode.LIMIT_REQUIRED not in codes


def test_non_large_table_no_limit_required(large_table_policy: Policy) -> None:
    e = sqlglot.parse_one("SELECT id FROM users WHERE id = 1", dialect="postgres")
    codes = [v.code for v in check_limits(e, large_table_policy)]
    assert ViolationCode.LIMIT_REQUIRED not in codes


def test_no_large_tables_skips_check() -> None:
    """If no table has `large: true`, the LIMIT-required rule is a no-op
    even when a table is in the allowlist without a LIMIT."""
    p = Policy.from_dict({"tables": [{"name": "orders"}]})
    e = sqlglot.parse_one("SELECT id FROM orders", dialect="postgres")
    codes = [v.code for v in check_limits(e, p)]
    assert ViolationCode.LIMIT_REQUIRED not in codes


# ---------------------------------------------------------------------------
# Max LIMIT value
# ---------------------------------------------------------------------------
def test_limit_within_max_ok() -> None:
    p = Policy.from_dict({"limits": {"max_limit_value": 1000}})
    e = sqlglot.parse_one("SELECT * FROM a LIMIT 500", dialect="postgres")
    codes = [v.code for v in check_limits(e, p)]
    assert ViolationCode.LIMIT_REQUIRED not in codes


def test_limit_exceeds_max_denied() -> None:
    p = Policy.from_dict({"limits": {"max_limit_value": 1000}})
    e = sqlglot.parse_one("SELECT * FROM a LIMIT 99999", dialect="postgres")
    codes = [v.code for v in check_limits(e, p)]
    assert ViolationCode.LIMIT_EXCEEDED in codes


def test_non_literal_limit_fails_closed() -> None:
    """Regression: a non-literal LIMIT (subquery / parameter) cannot be
    statically capped, so the value must be rejected rather than silently
    allowed."""
    p = Policy.from_dict({"limits": {"max_limit_value": 1000}})
    e = sqlglot.parse_one(
        "SELECT id FROM a LIMIT (SELECT 9999999)", dialect="postgres"
    )
    codes = [v.code for v in check_limits(e, p)]
    assert ViolationCode.LIMIT_EXCEEDED in codes


def test_non_literal_offset_fails_closed() -> None:
    """Same as above for OFFSET — `OFFSET (SELECT ...)` must not bypass
    max_offset_value."""
    p = Policy.from_dict({"limits": {"max_offset_value": 1000}})
    e = sqlglot.parse_one(
        "SELECT id FROM a OFFSET (SELECT 9999999) LIMIT 1",
        dialect="postgres",
    )
    codes = [v.code for v in check_limits(e, p)]
    assert ViolationCode.OFFSET_EXCEEDED in codes


@pytest.mark.parametrize(
    "sql",
    [
        # OFFSET attaches to the set-op node, not the inner Selects. The rule
        # used to walk only Select nodes, which silently let these through.
        "SELECT id FROM a UNION SELECT id FROM a OFFSET 9999999",
        "SELECT id FROM a INTERSECT SELECT id FROM a OFFSET 9999999",
        "SELECT id FROM a EXCEPT SELECT id FROM a OFFSET 9999999",
        "(SELECT id FROM a) UNION (SELECT id FROM a) OFFSET 9999999",
    ],
    ids=["union", "intersect", "except", "paren_union"],
)
def test_offset_on_set_op_is_capped(sql: str) -> None:
    """Regression: ``... UNION ... OFFSET N`` attaches the OFFSET to the
    set-op node (Union/Intersect/Except), not to either inner Select.
    The original implementation iterated only Selects and missed this,
    letting an attacker bypass max_offset_value with a trivial UNION."""
    p = Policy.from_dict({"limits": {"max_offset_value": 1000}})
    e = sqlglot.parse_one(sql, dialect="postgres")
    codes = [v.code for v in check_limits(e, p)]
    assert ViolationCode.OFFSET_EXCEEDED in codes


def test_default_max_limit_value_caps_unconfigured_policy() -> None:
    """The default LimitsPolicy.max_limit_value must reject huge LIMITs
    out of the box so an unconfigured policy isn't satisfied by
    `LIMIT 9999999999`."""
    p = Policy.from_dict({})
    e = sqlglot.parse_one("SELECT id FROM a LIMIT 9999999999", dialect="postgres")
    codes = [v.code for v in check_limits(e, p)]
    assert ViolationCode.LIMIT_EXCEEDED in codes


# ---------------------------------------------------------------------------
# Always-true in JOIN ON (handled by predicates.py but worth verifying here)
# ---------------------------------------------------------------------------
def test_join_on_one_equals_one_caught() -> None:
    """ON 1=1 should be caught by the always-true rule (predicates.py)."""
    from sqlguard.core.rules.predicates import check_predicates

    p = Policy.from_dict({"forbid": {"always_true_predicates": True}})
    e = sqlglot.parse_one(
        "SELECT * FROM a JOIN b ON 1=1 WHERE a.id = 5", dialect="postgres"
    )
    codes = [v.code for v in check_predicates(e, p, {})]
    assert ViolationCode.ALWAYS_TRUE_PREDICATE in codes
