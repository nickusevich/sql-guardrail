"""Pre-parse safety checks plus the post-parse data-modifying-CTE walk.

Exercises:
  1. Multi-statement input is unconditionally rejected.
  2. exp.Command default-deny (sqlglot couldn't classify the top-level
     statement — anything that lands here, fail closed).
  3. Top-level statement-kind allowlist (SELECT-like always; DML when
     ``read_only=False``; everything else → STATEMENT_FORBIDDEN).
  4. PARSE_ERROR on empty / unparseable input.
  5. Data-modifying CTE detection (`WITH x AS (INSERT…) SELECT …`).
"""
from __future__ import annotations

import pytest
import sqlglot

from sqlguard.core.preflight import check_data_modifying_cte, preflight
from sqlguard.result import ViolationCode


def _codes(sql: str, *, read_only: bool = True) -> list[str]:
    pre = preflight(sql, read_only=read_only)
    return [v.code.value for v in pre.violations]


def test_select_one_is_clean() -> None:
    pre = preflight("SELECT 1", read_only=True)
    assert pre.violations == ()
    assert pre.statement_kind == "SELECT"
    assert pre.can_continue is True


def test_empty_input_is_parse_error() -> None:
    pre = preflight("", read_only=True)
    assert pre.can_continue is False
    assert pre.statement_kind == "EMPTY"
    assert [v.code for v in pre.violations] == [ViolationCode.PARSE_ERROR]


def test_whitespace_only_is_parse_error() -> None:
    assert _codes("   \n  \t ") == [ViolationCode.PARSE_ERROR.value]


def test_comment_only_is_parse_error() -> None:
    # sqlglot ignores comments; the parser returns no statements.
    assert _codes("-- just a comment") == [ViolationCode.PARSE_ERROR.value]


def test_garbage_is_parse_error() -> None:
    assert _codes("this is not sql at all 12345 !!!") == [
        ViolationCode.PARSE_ERROR.value
    ]


def test_multi_statement_is_flagged() -> None:
    codes = _codes("SELECT 1; SELECT 2")
    assert ViolationCode.MULTI_STATEMENT.value in codes


def test_trailing_semicolon_does_not_count() -> None:
    # sqlglot.parse returns [Select, None] for a trailing `;`; the None
    # is filtered so this counts as one statement.
    pre = preflight("SELECT 1;", read_only=True)
    assert pre.violations == ()


def test_vacuum_is_command_default_deny() -> None:
    pre = preflight("VACUUM users", read_only=True)
    assert pre.can_continue is False
    assert pre.statement_kind == "UNKNOWN"
    assert [v.code for v in pre.violations] == [ViolationCode.STATEMENT_FORBIDDEN]


def test_listen_is_command_default_deny() -> None:
    pre = preflight("LISTEN channel_name", read_only=True)
    assert pre.can_continue is False
    assert [v.code for v in pre.violations] == [ViolationCode.STATEMENT_FORBIDDEN]


def test_insert_under_read_only_emits_statement_forbidden_but_continues() -> None:
    # Emit STATEMENT_FORBIDDEN here so the caller sees the categorical
    # ban, and let check_readonly add WRITE_FORBIDDEN at the rule pass.
    # can_continue=True so the rule pass runs.
    pre = preflight("INSERT INTO t (a) VALUES (1)", read_only=True)
    assert pre.can_continue is True
    assert [v.code for v in pre.violations] == [ViolationCode.STATEMENT_FORBIDDEN]
    assert pre.statement_kind == "INSERT"


def test_dml_under_read_only_false_is_allowed() -> None:
    pre = preflight("DELETE FROM t WHERE id = 1", read_only=False)
    assert pre.can_continue is True
    assert pre.violations == ()
    assert pre.statement_kind == "DELETE"


def test_create_table_is_rejected_even_under_read_only_false() -> None:
    pre = preflight("CREATE TABLE t (a INT)", read_only=False)
    assert pre.can_continue is False
    assert [v.code for v in pre.violations] == [ViolationCode.STATEMENT_FORBIDDEN]


def test_drop_table_is_rejected_even_under_read_only_false() -> None:
    pre = preflight("DROP TABLE t", read_only=False)
    assert pre.can_continue is False
    assert [v.code for v in pre.violations] == [ViolationCode.STATEMENT_FORBIDDEN]


def test_union_is_select_like() -> None:
    pre = preflight("SELECT 1 UNION SELECT 2", read_only=True)
    assert pre.violations == ()
    assert pre.can_continue is True
    assert pre.statement_kind == "SELECT"


def test_with_cte_is_select_like() -> None:
    pre = preflight(
        "WITH x AS (SELECT 1 AS a) SELECT a FROM x",
        read_only=True,
    )
    assert pre.violations == ()
    assert pre.can_continue is True


@pytest.mark.parametrize(
    "ddl",
    [
        "ALTER TABLE t ADD COLUMN c INT",
        "TRUNCATE TABLE t",
        "GRANT SELECT ON t TO somebody",
        "REVOKE SELECT ON t FROM somebody",
    ],
)
def test_other_ddl_dcl_rejected(ddl: str) -> None:
    pre = preflight(ddl, read_only=False)
    assert pre.can_continue is False
    assert [v.code for v in pre.violations] == [ViolationCode.STATEMENT_FORBIDDEN]


# ---------------------------------------------------------------------------
# Data-modifying CTE detection — runs on the parsed AST, NOT in preflight.
# ---------------------------------------------------------------------------


class TestDataModifyingCTE:
    """`WITH x AS (INSERT/UPDATE/DELETE/MERGE …) SELECT … FROM x` hides
    a write under a SELECT top-level — check_readonly's write walk doesn't
    see it. ``check_data_modifying_cte`` catches every DML body in a CTE.
    """

    @pytest.mark.parametrize(
        "sql",
        [
            "WITH x AS (INSERT INTO audit_log VALUES ('owned') RETURNING 1) SELECT * FROM x",
            "WITH x AS (UPDATE orders SET total = 0 RETURNING id) SELECT * FROM x",
            "WITH x AS (DELETE FROM users WHERE id = 1 RETURNING id) SELECT * FROM x",
        ],
    )
    def test_dml_in_cte_is_flagged(self, sql: str) -> None:
        expression = sqlglot.parse_one(sql, dialect=None)
        violations = check_data_modifying_cte(expression)
        assert len(violations) == 1
        assert violations[0].code == ViolationCode.DATA_MODIFYING_CTE

    def test_select_cte_is_clean(self) -> None:
        expression = sqlglot.parse_one(
            "WITH x AS (SELECT 1 AS a) SELECT a FROM x", dialect=None
        )
        violations = check_data_modifying_cte(expression)
        assert violations == []

    def test_nested_dml_cte_is_flagged(self) -> None:
        sql = (
            "WITH a AS (SELECT 1), "
            "b AS (DELETE FROM users WHERE id = 1 RETURNING id) "
            "SELECT * FROM a, b"
        )
        expression = sqlglot.parse_one(sql, dialect=None)
        violations = check_data_modifying_cte(expression)
        assert len(violations) == 1
        assert violations[0].code == ViolationCode.DATA_MODIFYING_CTE

    def test_multiple_dml_ctes_each_flagged(self) -> None:
        sql = (
            "WITH a AS (INSERT INTO t1 VALUES (1) RETURNING 1), "
            "b AS (UPDATE t2 SET x = 1 RETURNING x) "
            "SELECT * FROM a, b"
        )
        expression = sqlglot.parse_one(sql, dialect=None)
        violations = check_data_modifying_cte(expression)
        assert len(violations) == 2
        assert all(v.code == ViolationCode.DATA_MODIFYING_CTE for v in violations)
