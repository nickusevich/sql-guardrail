"""Pre-parse safety checks plus the post-parse data-modifying-CTE walk.

`preflight()` runs before the AST is handed to the rule pipeline. It uses
sqlglot to:

  - Reject empty / unparseable input as PARSE_ERROR.
  - Reject multi-statement input (`SELECT 1; DROP TABLE x`).
  - Default-deny ``exp.Command`` (anything sqlglot couldn't classify —
    DO, COPY, LISTEN, VACUUM, vendor extensions). The rule walks can't
    reason about Commands; fail closed.
  - Enforce the top-level statement-kind allowlist: SELECT-like always;
    DML when ``read_only=False``; DDL/DCL always rejected.

`check_data_modifying_cte()` runs *after* parse and catches:
`WITH x AS (INSERT INTO t VALUES (1)) SELECT * FROM x`. The top-level
is a SELECT, so `check_readonly` doesn't see it — but the CTE body mutates.
"""
from __future__ import annotations

from dataclasses import dataclass

import sqlglot
from sqlglot import expressions as exp
from sqlglot.errors import ParseError

from sqlguard.result import Violation, ViolationCode


@dataclass(frozen=True)
class PreflightResult:
    """Outcome of the pre-parse check.

    ``can_continue`` is False when the rest of the pipeline should bail
    out (unparseable input, categorical ban that makes further analysis
    meaningless). The verify() finalizer respects this and skips the
    sqlglot parse + rule walks.
    """

    violations: tuple[Violation, ...]
    statement_kind: str
    can_continue: bool


# Top-level statement types we allow without any read_only override.
# Set operations (UNION/INTERSECT/EXCEPT) are SELECT-like at the top.
_SELECT_LIKE: tuple[type[exp.Expression], ...] = (
    exp.Select,
    exp.Union,
    exp.Intersect,
    exp.Except,
)

# Top-level DML — allowed only when ``read_only=False``.
_DML_LIKE: tuple[type[exp.Expression], ...] = (
    exp.Insert,
    exp.Update,
    exp.Delete,
    exp.Merge,
)

# Map sqlglot top-level expression class names to the human-readable
# ``statement_kind`` we surface on VerificationResult. Anything not in
# this map gets the uppercased class name as a fallback.
_KIND_LABELS: dict[type[exp.Expression], str] = {
    exp.Select: "SELECT",
    exp.Union: "SELECT",
    exp.Intersect: "SELECT",
    exp.Except: "SELECT",
    exp.Insert: "INSERT",
    exp.Update: "UPDATE",
    exp.Delete: "DELETE",
    exp.Merge: "MERGE",
    exp.Create: "CREATE",
    exp.Drop: "DROP",
    exp.Alter: "ALTER",
    exp.TruncateTable: "TRUNCATE",
    exp.Grant: "GRANT",
    exp.Revoke: "REVOKE",
    exp.Command: "UNKNOWN",
}


def _unwrap_top(node: exp.Expression) -> exp.Expression:
    """Strip the outer wrappers sqlglot puts around a real top-level statement.

    `(SELECT 1)` parses as ``exp.Subquery(this=Select)``; the LLM-friendly
    form is just as much a SELECT as the bare one. Without unwrapping, the
    kind allowlist would reject it as STATEMENT_FORBIDDEN. Handles nested
    parens too (``((SELECT ...))``).
    """
    while isinstance(node, (exp.Subquery, exp.Paren)) and isinstance(
        node.this, exp.Expression
    ):
        node = node.this
    return node


def _kind_of(node: exp.Expression) -> str:
    node = _unwrap_top(node)
    label = _KIND_LABELS.get(type(node))
    if label is not None:
        return label
    return type(node).__name__.upper()


def preflight(sql: str, *, read_only: bool) -> PreflightResult:
    """sqlglot-only preflight. See module docstring for what it catches.

    Multi-statement input is unconditionally rejected — LLM-generated SQL
    should always be a single statement; chained statements are the
    textbook injection attack vector.

    Parses with sqlglot's neutral (dialect-agnostic) parser, which
    handles the common SQL syntax LLMs emit (``::type`` shorthand, JSON
    operators, ``ILIKE``, ``INTERVAL``, ``FILTER``, etc.). Anything
    that doesn't parse fails closed as PARSE_ERROR.
    """
    try:
        parsed_list = sqlglot.parse(
            sql, error_level=sqlglot.ErrorLevel.RAISE
        )
    except ParseError as e:
        return PreflightResult(
            violations=(
                Violation(
                    code=ViolationCode.PARSE_ERROR,
                    message=f"sqlglot parse error: {e}",
                ),
            ),
            statement_kind="UNKNOWN",
            can_continue=False,
        )

    # sqlglot.parse returns ``None`` for trailing semicolons / empty
    # tails. Filter so they don't inflate the statement count.
    stmts = [s for s in parsed_list if isinstance(s, exp.Expression)]

    if not stmts:
        return PreflightResult(
            violations=(
                Violation(
                    code=ViolationCode.PARSE_ERROR,
                    message="SQL is empty or contains no statements (only comments / whitespace).",
                    suggestion="Send a SELECT statement.",
                ),
            ),
            statement_kind="EMPTY",
            can_continue=False,
        )

    violations: list[Violation] = []

    if len(stmts) > 1:
        kinds = [type(s).__name__ for s in stmts]
        violations.append(
            Violation(
                code=ViolationCode.MULTI_STATEMENT,
                message=(
                    f"got {len(stmts)} statements ({', '.join(kinds)}); "
                    "only one statement is allowed per verify() call."
                ),
                suggestion="Send each statement in a separate verify() call.",
            )
        )

    top = stmts[0]
    statement_kind = _kind_of(top)

    # Walk every statement. With multi-statement always rejected above, only
    # one usually remains — but if the user disables that check in a fork or
    # via a future toggle, each statement still gets its kind validated.
    seen_messages: set[str] = set()

    def _emit(violation: Violation) -> None:
        if violation.message in seen_messages:
            return
        seen_messages.add(violation.message)
        violations.append(violation)

    hard_reject = False
    for idx, raw_stmt in enumerate(stmts):
        # `(SELECT 1)` parses as exp.Subquery wrapping a Select. Unwrap so
        # the kind allowlist sees the inner statement type, not the wrapper.
        stmt = _unwrap_top(raw_stmt)
        kind = _kind_of(stmt)
        is_first = idx == 0

        # exp.Command = sqlglot couldn't classify this statement (DO, COPY,
        # LISTEN, ALTER SYSTEM, vendor extensions, ...). Default-deny because
        # the rule walks can't reason about what they would do.
        if isinstance(stmt, exp.Command):
            _emit(
                Violation(
                    code=ViolationCode.STATEMENT_FORBIDDEN,
                    message=(
                        f"statement #{idx + 1} is not recognized by the parser "
                        "and is rejected to fail closed."
                    ) if not is_first else (
                        "statement type is not recognized by the parser "
                        "and is rejected to fail closed."
                    ),
                    suggestion=(
                        "Rewrite as a standard SELECT (or DML if policy.read_only=False)."
                    ),
                )
            )
            if is_first:
                hard_reject = True
                statement_kind = "UNKNOWN"
            continue

        if isinstance(stmt, _SELECT_LIKE):
            continue

        if isinstance(stmt, _DML_LIKE):
            if read_only:
                _emit(
                    Violation(
                        code=ViolationCode.STATEMENT_FORBIDDEN,
                        message=f"{kind} is forbidden under read_only=True.",
                        suggestion="Use SELECT, or set policy.read_only=False.",
                    )
                )
            continue

        # DDL (Create/Drop/Alter/Truncate), DCL (Grant/Revoke), Lock,
        # and anything else. Reject — there's nothing meaningful to validate
        # in the DDL itself, though we keep walking the rest of the Block so
        # later rules can still report violations from sibling statements.
        _emit(
            Violation(
                code=ViolationCode.STATEMENT_FORBIDDEN,
                message=(
                    f"top-level statement {type(stmt).__name__} is not in the "
                    "allowlist (SELECT, or DML when read_only=False)."
                ),
                suggestion=(
                    "Only SELECT and DML statements are validated. "
                    "DDL/DCL must run outside the guardrail's read path."
                ),
            )
        )
        if is_first:
            hard_reject = True

    return PreflightResult(
        violations=tuple(violations),
        statement_kind=statement_kind,
        can_continue=not hard_reject,
    )


def check_data_modifying_cte(expression: exp.Expression) -> list[Violation]:
    """Reject `WITH x AS (INSERT/UPDATE/DELETE/MERGE …) SELECT … FROM x`.

    The top-level statement is a SELECT, so check_readonly's write walk
    doesn't catch it — yet the CTE body mutates. This walks every CTE
    and flags any whose body is a DML node.
    """
    violations: list[Violation] = []
    seen: set[int] = set()
    for cte in expression.find_all(exp.CTE):
        body = cte.this
        if not isinstance(body, _DML_LIKE):
            continue
        if id(cte) in seen:
            continue
        seen.add(id(cte))
        kind = _KIND_LABELS.get(type(body), type(body).__name__.upper())
        violations.append(
            Violation(
                code=ViolationCode.DATA_MODIFYING_CTE,
                message=(
                    f"CTE body contains a {kind} statement — data-modifying "
                    "CTEs are forbidden (the top-level SELECT hides the write)."
                ),
                suggestion=(
                    f"Move the {kind} out of the CTE and run it on a separate "
                    "explicitly-permitted write path."
                ),
            )
        )
    return violations
