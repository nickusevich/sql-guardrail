from __future__ import annotations

import pytest
import sqlglot

from sqlguard.config.schema import Policy
from sqlguard.core.rules.readonly import check_readonly
from sqlguard.result import ViolationCode


@pytest.fixture
def readonly_policy() -> Policy:
    return Policy.from_dict({"read_only": True})


@pytest.mark.parametrize(
    "sql, expected_count",
    [
        ("SELECT 1", 0),
        ("SELECT * FROM users WHERE id = 1", 0),
        ("INSERT INTO t VALUES (1)", 1),
        ("UPDATE t SET x = 1", 1),
        ("DELETE FROM t", 1),
        ("DROP TABLE t", 1),
        ("CREATE TABLE t (x int)", 1),
        ("ALTER TABLE t ADD COLUMN y int", 1),
        ("TRUNCATE t", 1),
        ("GRANT SELECT ON t TO u", 1),
        ("REVOKE SELECT ON t FROM u", 1),
        (
            "MERGE INTO t USING s ON s.id = t.id WHEN MATCHED THEN UPDATE SET x = 1",
            1,  # Inner UPDATE deduped under MERGE
        ),
        ("WITH d AS (DELETE FROM t RETURNING 1) SELECT 1", 1),
    ],
)
def test_readonly_cases(readonly_policy: Policy, sql: str, expected_count: int) -> None:
    e = sqlglot.parse_one(sql, dialect="postgres")
    violations = check_readonly(e, readonly_policy)
    assert len(violations) == expected_count
    if expected_count:
        assert all(v.code == ViolationCode.WRITE_FORBIDDEN for v in violations)
