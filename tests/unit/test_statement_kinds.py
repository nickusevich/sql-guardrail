"""Top-level statement-kind blocking — every non-SELECT/DML statement
must be rejected (either as STATEMENT_FORBIDDEN via exp.Command default-deny,
or as PARSE_ERROR when sqlglot can't even parse the syntax).

The "what specific code fired" is secondary; the property we care about is
``can_continue=False`` — i.e. the pipeline bails before the rule walks.
"""
from __future__ import annotations

import pytest

from sqlguard.core.preflight import preflight
from sqlguard.result import ViolationCode

_BLOCKING_CODES = frozenset(
    {ViolationCode.STATEMENT_FORBIDDEN, ViolationCode.PARSE_ERROR}
)


@pytest.mark.parametrize(
    "sql",
    [
        "CALL my_procedure()",
        "CALL my_procedure(1, 2, 3)",
        "SET search_path = 'evil'",
        "SET LOCAL statement_timeout = '1s'",
        "RESET search_path",
        "DISCARD ALL",
        "LISTEN evil_channel",
        "NOTIFY evil_channel, 'payload'",
        "UNLISTEN evil_channel",
        "VACUUM orders",
        "ANALYZE orders",
        "REFRESH MATERIALIZED VIEW mv",
        "CLUSTER orders",
        "REINDEX TABLE orders",
        "CHECKPOINT",
        "PREPARE plan AS SELECT 1",
        "EXPLAIN SELECT * FROM orders",
        "EXPLAIN ANALYZE SELECT * FROM orders",
        "LOAD 'evil_extension'",
        "BEGIN",
        "COMMIT",
        "ROLLBACK",
        "CREATE EXTENSION pg_stat_statements",
        "CREATE ROLE evil WITH SUPERUSER",
        "DROP ROLE alice",
        "ALTER ROLE alice WITH SUPERUSER",
        "CREATE FUNCTION evil() RETURNS void AS $$ BEGIN END $$ LANGUAGE plpgsql",
        "CREATE DATABASE evil",
        "DROP DATABASE production",
    ],
)
def test_forbidden_statement_kinds(sql: str) -> None:
    pre = preflight(sql, read_only=True)
    codes = {v.code for v in pre.violations}
    # Either the parser bailed (PARSE_ERROR) or the default-deny / kind
    # allowlist fired (STATEMENT_FORBIDDEN). Both mean "this query won't
    # reach the rule walks."
    assert pre.can_continue is False
    assert codes & _BLOCKING_CODES, (
        f"{sql!r} should be blocked but no blocking code fired. Got: {codes}"
    )


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 1",
        "SELECT * FROM orders WHERE account_id = 42",
        "WITH x AS (SELECT 1) SELECT * FROM x",
    ],
)
def test_allowed_statement_kinds(sql: str) -> None:
    pre = preflight(sql, read_only=True)
    codes = [v.code for v in pre.violations]
    assert ViolationCode.STATEMENT_FORBIDDEN not in codes
    assert pre.can_continue is True
