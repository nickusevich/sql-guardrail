"""FOR UPDATE / FOR SHARE detection via check_readonly().

After 0.3 the separate ``forbid.lock_clause`` toggle is gone — locks are
unconditionally blocked under ``read_only=True``. Under ``read_only=False``
the user has opted into writes, so locks (a write-intent operation) are
also allowed.
"""
from __future__ import annotations

import pytest
import sqlglot

from sqlguard.config.schema import Policy
from sqlguard.core.rules.readonly import check_readonly
from sqlguard.result import ViolationCode


@pytest.fixture
def strict_policy() -> Policy:
    return Policy.from_dict({"read_only": True})


@pytest.fixture
def writes_allowed() -> Policy:
    return Policy.from_dict({"read_only": False})


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT id FROM orders WHERE id = 1 FOR UPDATE",
        "SELECT id FROM orders WHERE id = 1 FOR SHARE",
        "SELECT id FROM orders WHERE id = 1 FOR NO KEY UPDATE",
        "SELECT id FROM orders WHERE id = 1 FOR KEY SHARE",
    ],
)
def test_locks_blocked_under_readonly(strict_policy: Policy, sql: str) -> None:
    e = sqlglot.parse_one(sql, dialect="postgres")
    codes = [v.code for v in check_readonly(e, strict_policy)]
    assert ViolationCode.LOCK_FORBIDDEN in codes


def test_locks_allowed_when_writes_allowed(writes_allowed: Policy) -> None:
    sql = "SELECT id FROM orders WHERE id = 1 FOR UPDATE"
    e = sqlglot.parse_one(sql, dialect="postgres")
    assert check_readonly(e, writes_allowed) == []


def test_plain_select_no_lock_violation(strict_policy: Policy) -> None:
    e = sqlglot.parse_one("SELECT id FROM orders WHERE id = 1", dialect="postgres")
    codes = [v.code for v in check_readonly(e, strict_policy)]
    assert ViolationCode.LOCK_FORBIDDEN not in codes
