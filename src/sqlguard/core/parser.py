"""sqlglot parse wrapper.

Used by the pipeline after :func:`sqlguard.core.preflight.preflight` has
classified the statement kind. Returns the parsed expression or a
PARSE_ERROR via :class:`LoadResult`.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

import sqlglot
from sqlglot import expressions as exp
from sqlglot.errors import ParseError

from sqlguard.result import Violation, ViolationCode

# Silence sqlglot's WARNING-level fallback noise for unrecognized syntax.
# The preflight layer already catches anything that lands as exp.Command.
logging.getLogger("sqlglot").setLevel(logging.ERROR)


@dataclass(frozen=True)
class LoadResult:
    """Outcome of the sqlglot parse.

    ``expression`` is None on parse failure; ``violations`` carries the
    PARSE_ERROR in that case.
    """

    expression: exp.Expression | None
    violations: tuple[Violation, ...]


def load(sql: str) -> LoadResult:
    """Parse SQL with sqlglot's neutral parser. Returns (expression, violations).

    Uses error_level=ErrorLevel.RAISE so any parse problem becomes a
    PARSE_ERROR violation rather than a silent partial AST.
    """
    try:
        expression = sqlglot.parse_one(
            sql, error_level=sqlglot.ErrorLevel.RAISE
        )
    except ParseError as e:
        return LoadResult(
            expression=None,
            violations=(
                Violation(
                    code=ViolationCode.PARSE_ERROR,
                    message=f"sqlglot parse error: {e}",
                ),
            ),
        )

    # sqlglot's stubs claim parse_one never returns None, but the docstring
    # documents it can — keep the defensive branch.
    if not isinstance(expression, exp.Expression):
        return LoadResult(
            expression=None,
            violations=(
                Violation(
                    code=ViolationCode.PARSE_ERROR,
                    message="sqlglot returned no expression.",
                ),
            ),
        )

    return LoadResult(expression=expression, violations=())
