from __future__ import annotations

import pytest
import sqlglot

from sqlguard.config.schema import Policy
from sqlguard.core.rules.allowlist import check_allowlist
from sqlguard.result import ViolationCode


@pytest.fixture
def policy() -> Policy:
    return Policy.from_dict(
        {
            "tables": [
                {
                    "name": "users",
                    "allow_columns": ["id", "name"],
                    "deny_columns": ["password_hash"],
                },
                {"name": "orders", "allow_columns": ["id", "account_id", "total"]},
            ],
            "forbid": {"select_star": True},
        }
    )


@pytest.mark.parametrize(
    "sql, expected",
    [
        ("SELECT id, name FROM users", []),
        ("SELECT id, password_hash FROM users", [ViolationCode.COLUMN_DENIED]),
        ("SELECT * FROM users", [ViolationCode.SELECT_STAR]),
        (
            "SELECT u.id, o.total FROM users u JOIN orders o ON u.id = o.account_id",
            [],
        ),
        (
            "SELECT u.id, o.unknown FROM users u JOIN orders o ON u.id = o.account_id",
            [ViolationCode.COLUMN_DENIED],
        ),
        ("SELECT id FROM forbidden_table", [ViolationCode.TABLE_DENIED]),
        # pg_catalog.pg_user is rejected via TABLE_DENIED now that schemas
        # scoping is gone — pg_user isn't in `tables`, so the table allowlist
        # rejects it regardless of schema.
        ("SELECT id FROM pg_catalog.pg_user", [ViolationCode.TABLE_DENIED]),
        (
            "WITH x AS (SELECT id, name FROM users) SELECT id FROM x",
            [],
        ),
    ],
)
def test_allowlist_cases(
    policy: Policy, sql: str, expected: list[ViolationCode]
) -> None:
    e = sqlglot.parse_one(sql, dialect="postgres")
    codes = [v.code for v in check_allowlist(e, policy)]
    assert codes == expected


def test_unqualified_denied_column_in_multi_table_join_is_blocked(
    policy: Policy,
) -> None:
    """Regression: an unqualified denied column must not slip through just
    because the scope has more than one real table. Previously the rule
    silently returned when `len(table_names) != 1`, allowing
    `SELECT password_hash FROM users u JOIN orders o ON ...` through."""
    e = sqlglot.parse_one(
        "SELECT password_hash FROM users u "
        "JOIN orders o ON u.id = o.account_id",
        dialect="postgres",
    )
    codes = [v.code for v in check_allowlist(e, policy)]
    assert ViolationCode.COLUMN_DENIED in codes


def test_unqualified_allowed_column_in_multi_table_join_is_not_blocked(
    policy: Policy,
) -> None:
    """The multi-table ambiguity guard must not false-positive a column
    that's only missing from one in-scope table's allow_columns."""
    e = sqlglot.parse_one(
        "SELECT name FROM users u JOIN orders o ON u.id = o.account_id",
        dialect="postgres",
    )
    codes = [v.code for v in check_allowlist(e, policy)]
    assert ViolationCode.COLUMN_DENIED not in codes


def test_subquery_alias_does_not_steal_unqualified_column(
    policy: Policy,
) -> None:
    """Regression: when a scope has one real table plus a subquery source,
    an unqualified column must not be forcibly attributed to the real
    table. Previously `SELECT top_prod FROM users, (SELECT max(...) AS
    top_prod FROM products) sub` was flagged as users.top_prod."""
    e = sqlglot.parse_one(
        "SELECT top_prod FROM users u, "
        "(SELECT id AS top_prod FROM forbidden_table) sub",
        dialect="postgres",
    )
    codes = [v.code for v in check_allowlist(e, policy)]
    # `top_prod` is not on users.deny_columns; the ambiguity guard must
    # not flag it as a users column even though users is the only real
    # table in alias_to_table. (The inner subquery's table is checked at
    # its own scope and produces TABLE_DENIED — that's expected and
    # unrelated to the ambiguity fix.)
    assert ViolationCode.COLUMN_DENIED not in codes
