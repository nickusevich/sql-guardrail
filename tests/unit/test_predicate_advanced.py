"""Exhaustive coverage of the per-alias predicate fix and type-coercion fix.

Two fixes under test:
  1. _literal_equals now coerces int↔str↔float so `42` matches `'42'` and `42.0`.
  2. check_predicates now tracks aliases — every alias of a policy-protected
     table needs its own predicate (closes the self-join bypass).
"""
from __future__ import annotations

from typing import Any

import pytest
import sqlglot

from sqlguard.config.schema import Policy
from sqlguard.core.rules.predicates import check_predicates
from sqlguard.result import ViolationCode


# ---------------------------------------------------------------------------
# Per-alias predicate enforcement
# ---------------------------------------------------------------------------
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
                },
            ],
        }
    )


PER_ALIAS_CASES: list[tuple[str, str, list[ViolationCode]]] = [
    # --- No-regression: single table, no alias ---
    (
        "single table no alias",
        "SELECT id FROM orders WHERE account_id = 42",
        [],
    ),
    (
        "single table no alias, qualified column",
        "SELECT id FROM orders WHERE orders.account_id = 42",
        [],
    ),
    # --- No-regression: single table with alias ---
    (
        "single table with alias, qualified column",
        "SELECT o.id FROM orders o WHERE o.account_id = 42",
        [],
    ),
    (
        "single table with alias, unqualified column",
        "SELECT o.id FROM orders o WHERE account_id = 42",
        [],
    ),
    # --- Schema-qualified table ---
    (
        "schema-qualified single table",
        "SELECT id FROM public.orders WHERE account_id = 42",
        [],
    ),
    # --- Self-join: THE BYPASS (must now be denied) ---
    (
        "self-join cartesian, only one alias filtered (BYPASS)",
        "SELECT o2.id FROM orders o1 JOIN orders o2 ON 1=1 WHERE o1.account_id = 42",
        # ON 1=1 is now also flagged as always-true.
        [ViolationCode.ALWAYS_TRUE_PREDICATE, ViolationCode.MISSING_REQUIRED_PREDICATE],
    ),
    (
        "self-join with proper join condition, only one alias filtered",
        "SELECT o2.id FROM orders o1 JOIN orders o2 ON o1.id = o2.id WHERE o1.account_id = 42",
        [ViolationCode.MISSING_REQUIRED_PREDICATE],
    ),
    (
        "self-join, neither alias filtered",
        "SELECT o2.id FROM orders o1 JOIN orders o2 ON o1.id = o2.id",
        [ViolationCode.MISSING_REQUIRED_PREDICATE, ViolationCode.MISSING_REQUIRED_PREDICATE],
    ),
    # --- Self-join: properly filtered ---
    (
        "self-join, both aliases filtered",
        "SELECT o2.id FROM orders o1 JOIN orders o2 ON o1.id = o2.id "
        "WHERE o1.account_id = 42 AND o2.account_id = 42",
        [],
    ),
    # --- Three-way join: all filtered ---
    (
        "three aliases, all filtered",
        "SELECT a.id FROM orders a JOIN orders b ON a.id = b.id JOIN orders c ON b.id = c.id "
        "WHERE a.account_id = 42 AND b.account_id = 42 AND c.account_id = 42",
        [],
    ),
    # --- Three-way join: one missing ---
    (
        "three aliases, middle one missing",
        "SELECT a.id FROM orders a JOIN orders b ON a.id = b.id JOIN orders c ON b.id = c.id "
        "WHERE a.account_id = 42 AND c.account_id = 42",
        [ViolationCode.MISSING_REQUIRED_PREDICATE],
    ),
    # --- Unqualified column in self-join (ambiguous → must not count) ---
    (
        "self-join, unqualified column does not satisfy either alias",
        "SELECT o2.id FROM orders o1 JOIN orders o2 ON o1.id = o2.id WHERE account_id = 42",
        [ViolationCode.MISSING_REQUIRED_PREDICATE, ViolationCode.MISSING_REQUIRED_PREDICATE],
    ),
    # --- Subquery: separate scope, handled independently ---
    (
        "subquery referencing same table with its own filter",
        "SELECT id FROM orders WHERE account_id = 42 "
        "AND id IN (SELECT id FROM orders WHERE account_id = 42)",
        [],
    ),
    (
        "subquery referencing same table with WRONG tenant",
        "SELECT id FROM orders WHERE account_id = 42 "
        "AND id IN (SELECT id FROM orders WHERE account_id = 99)",
        [ViolationCode.MISSING_REQUIRED_PREDICATE],
    ),
    # --- UNION: each arm is its own scope ---
    (
        "UNION, both arms properly filtered",
        "SELECT id FROM orders WHERE account_id = 42 "
        "UNION SELECT id FROM orders WHERE account_id = 42",
        [],
    ),
    (
        "UNION, one arm unfiltered",
        "SELECT id FROM orders WHERE account_id = 42 UNION SELECT id FROM orders",
        [ViolationCode.MISSING_REQUIRED_PREDICATE],
    ),
    # --- CTE: scope-separated, each must be valid ---
    (
        "CTE selects all then outer filters — CTE itself unfiltered",
        "WITH x AS (SELECT id, account_id FROM orders) "
        "SELECT id FROM x WHERE account_id = 42",
        [ViolationCode.MISSING_REQUIRED_PREDICATE],
    ),
    (
        "CTE properly filtered, used in outer",
        "WITH x AS (SELECT id FROM orders WHERE account_id = 42) SELECT id FROM x",
        [],
    ),
    # --- Multiple OR with one tenant value ---
    (
        "OR-wrapped predicate does not count as satisfied",
        "SELECT id FROM orders WHERE account_id = 42 OR id = 5",
        [ViolationCode.MISSING_REQUIRED_PREDICATE],
    ),
]


@pytest.mark.parametrize(
    "label,sql,expected", PER_ALIAS_CASES, ids=[c[0] for c in PER_ALIAS_CASES]
)
def test_per_alias(
    tenant_policy: Policy, label: str, sql: str, expected: list[ViolationCode]
) -> None:
    e = sqlglot.parse_one(sql, dialect="postgres")
    got = sorted(v.code for v in check_predicates(e, tenant_policy, {"tenant_id": 42}))
    assert got == sorted(expected), f"{label}: got {got}, expected {expected}"


# ---------------------------------------------------------------------------
# Type-coercion matrix for _literal_equals
# ---------------------------------------------------------------------------
TYPE_COERCION_CASES: list[tuple[str, Any, str, bool]] = [
    # (label, context_value, sql_literal_text, should_match)
    ("int=int", 42, "42", True),
    ("int=quoted-int", 42, "'42'", True),
    ("quoted-int=int", "42", "42", True),
    ("quoted-int=quoted-int", "42", "'42'", True),
    ("float=int", 42.0, "42", True),
    ("int=float", 42, "42.0", True),
    ("float=float", 42.5, "42.5", True),
    ("int=quoted-float", 42, "'42.0'", True),
    ("zero", 0, "0", True),
    ("negative int", -7, "-7", True),
    ("negative int vs quoted", -7, "'-7'", True),
    # Should NOT match:
    ("int!=wrong int", 42, "43", False),
    ("int!=text", 42, "'abc'", False),
    ("int!=empty string", 42, "''", False),
    ("int!=float-ish-but-different", 42, "42.5", False),
]


@pytest.mark.parametrize(
    "label,ctx_val,sql_literal,should_allow",
    TYPE_COERCION_CASES,
    ids=[c[0] for c in TYPE_COERCION_CASES],
)
def test_literal_coercion(
    tenant_policy: Policy, label: str, ctx_val: Any, sql_literal: str, should_allow: bool
) -> None:
    sql = f"SELECT id FROM orders WHERE account_id = {sql_literal}"
    e = sqlglot.parse_one(sql, dialect="postgres")
    violations = check_predicates(e, tenant_policy, {"tenant_id": ctx_val})
    has_missing = any(v.code == ViolationCode.MISSING_REQUIRED_PREDICATE for v in violations)
    if should_allow:
        assert not has_missing, f"{label}: expected to satisfy, got {violations}"
    else:
        assert has_missing, f"{label}: expected to MISS, got {violations}"


def test_bool_does_not_coerce_to_int(tenant_policy: Policy) -> None:
    """Type-confusion guard: `True == 1` is True in Python but we deliberately
    do not treat boolean context values as matching integer SQL literals."""
    sql = "SELECT id FROM orders WHERE account_id = 1"
    e = sqlglot.parse_one(sql, dialect="postgres")
    violations = check_predicates(e, tenant_policy, {"tenant_id": True})
    assert any(v.code == ViolationCode.MISSING_REQUIRED_PREDICATE for v in violations)


# ---------------------------------------------------------------------------
# IN / BETWEEN with coercion
# ---------------------------------------------------------------------------
def test_in_predicate_coerced_match() -> None:
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
    # Context has ints; SQL has quoted strings — should still match.
    e = sqlglot.parse_one(
        "SELECT id FROM orders WHERE account_id IN ('1', '2', '5')", dialect="postgres"
    )
    assert check_predicates(e, p, {"tenant_ids": [1, 2, 5]}) == []


def test_in_predicate_wrong_set_denied() -> None:
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
        "SELECT id FROM orders WHERE account_id IN (1, 2, 99)", dialect="postgres"
    )
    codes = [v.code for v in check_predicates(e, p, {"tenant_ids": [1, 2, 5]})]
    assert ViolationCode.MISSING_REQUIRED_PREDICATE in codes


# ---------------------------------------------------------------------------
# Error-message quality for the per-alias case
# ---------------------------------------------------------------------------
def test_error_message_names_the_alias(tenant_policy: Policy) -> None:
    sql = "SELECT o2.id FROM orders o1 JOIN orders o2 ON o1.id = o2.id WHERE o1.account_id = 42"
    e = sqlglot.parse_one(sql, dialect="postgres")
    violations = check_predicates(e, tenant_policy, {"tenant_id": 42})
    msgs = [v.message for v in violations]
    assert any("o2" in m for m in msgs), f"expected alias 'o2' in error, got {msgs}"


def test_single_alias_error_message_omits_alias_noise(tenant_policy: Policy) -> None:
    """When there's only one table reference, the error should NOT clutter
    the message with alias qualifiers."""
    sql = "SELECT id FROM orders"
    e = sqlglot.parse_one(sql, dialect="postgres")
    violations = check_predicates(e, tenant_policy, {"tenant_id": 42})
    assert len(violations) == 1
    assert "alias" not in violations[0].message.lower()
