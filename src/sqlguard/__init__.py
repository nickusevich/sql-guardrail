from __future__ import annotations

import logging
from typing import Any

from sqlguard.config.schema import (
    ForbidPolicy,
    LimitsPolicy,
    Policy,
    RequiredPredicate,
    TablePolicy,
)
from sqlguard.core.parser import load
from sqlguard.core.preflight import check_data_modifying_cte, preflight
from sqlguard.core.rules.allowlist import check_allowlist
from sqlguard.core.rules.function_allow import check_function_allow
from sqlguard.core.rules.limits import check_limits
from sqlguard.core.rules.predicates import check_predicates
from sqlguard.core.rules.readonly import check_readonly
from sqlguard.result import (
    VerificationResult,
    Violation,
    ViolationCategory,
    ViolationCode,
)

__all__ = [
    "ForbidPolicy",
    "LimitsPolicy",
    "Policy",
    "RequiredPredicate",
    "TablePolicy",
    "VerificationResult",
    "Violation",
    "ViolationCategory",
    "ViolationCode",
    "verify",
]

__version__ = "0.5.2"

_log = logging.getLogger(__name__)


def verify(
    sql: str,
    policy: Policy,
    *,
    context: dict[str, Any] | None = None,
) -> VerificationResult:
    """Validate `sql` against `policy`.

    Pipeline:
      1. Length cap — reject oversized input before parsing.
      2. Preflight — sqlglot parse, single-statement check,
         ``exp.Command`` default-deny, empty-input rejection.
      3. Parse — sqlglot AST for the rule pipeline.
      4. Data-modifying CTE check on the parsed AST.
      5. AST-size cap.
      6. Rules: read-only, allowlist, predicates, limits, function-allow.

    `context` carries per-request values resolved into policy placeholders
    (e.g. {"tenant_id": 42} resolves "${tenant_id}" in require_predicate values).

    Parsing uses sqlglot's neutral (dialect-agnostic) parser, which
    handles the common SQL syntax LLMs emit (``::type`` shorthand, JSON
    operators, ``ILIKE``, ``INTERVAL``, ``FILTER``, ``DISTINCT ON``, etc.).
    Anything that doesn't parse fails closed as ``PARSE_ERROR``.

    This function NEVER raises. Internal exceptions — including RecursionError
    on adversarially-deep inputs and MemoryError on huge inputs — are caught
    and turned into a PARSE_ERROR violation. The caller can always trust
    `result.allowed` to be a Boolean.
    """
    max_len = policy.limits.max_sql_length
    if len(sql) > max_len:
        return _finalize(
            [
                Violation(
                    code=ViolationCode.PARSE_ERROR,
                    message=(
                        f"SQL length {len(sql)} exceeds "
                        f"policy.limits.max_sql_length={max_len}."
                    ),
                    suggestion="Shorten the query or raise the policy limit.",
                )
            ],
            statement_kind="UNKNOWN",
        )

    try:
        return _run_pipeline(sql, policy, context)
    except (RecursionError, MemoryError) as e:
        return _finalize(
            [
                Violation(
                    code=ViolationCode.PARSE_ERROR,
                    message=f"input rejected: {type(e).__name__} during parsing "
                    "(likely deeply-nested or pathological SQL).",
                    suggestion="Reduce nesting depth or shorten the query.",
                )
            ],
            statement_kind="UNKNOWN",
        )
    except Exception as e:  # last-resort safety net — never crash the caller
        # Log full traceback so an operator can find the real fault. The
        # violation message exposes only the exception class + str() to
        # avoid leaking SQL or policy internals to the caller.
        _log.exception("verify() internal error")
        return _finalize(
            [
                Violation(
                    code=ViolationCode.PARSE_ERROR,
                    message=f"verify() internal error: {type(e).__name__}: {e}",
                    suggestion="Report this as a bug; treat as a denial.",
                )
            ],
            statement_kind="UNKNOWN",
        )


def _run_pipeline(
    sql: str,
    policy: Policy,
    context: dict[str, Any] | None,
) -> VerificationResult:
    pre = preflight(sql, read_only=policy.read_only)
    violations: list[Violation] = list(pre.violations)

    if not pre.can_continue:
        # Fail-closed: if preflight bailed out without emitting any violation
        # (shouldn't happen now that empty-input emits PARSE_ERROR, but
        # defensive), synthesize one so the caller never sees allowed=True
        # for an unparseable input.
        if not violations:
            violations.append(
                Violation(
                    code=ViolationCode.PARSE_ERROR,
                    message="SQL could not be parsed and no specific reason was reported.",
                )
            )
        return _finalize(violations, statement_kind=pre.statement_kind)

    parsed = load(sql)
    violations.extend(parsed.violations)
    if parsed.expression is None:
        if not violations:
            violations.append(
                Violation(
                    code=ViolationCode.PARSE_ERROR,
                    message="sqlglot returned no expression but reported no error.",
                )
            )
        return _finalize(violations, statement_kind=pre.statement_kind)

    expression = parsed.expression

    # Data-modifying CTEs (`WITH x AS (INSERT…) SELECT * FROM x`) hide
    # writes under a SELECT top-level, so check_readonly misses them.
    # Walk every CTE body before the cap so the violation is reported
    # even on adversarially-large inputs that would trip max_ast_nodes.
    if policy.read_only:
        violations.extend(check_data_modifying_cte(expression))

    max_nodes = policy.limits.max_ast_nodes
    if max_nodes is not None:
        # Adversarial inputs can sit under the character cap yet expand to
        # a node tree that's expensive to walk. Count once, fail fast.
        node_count = sum(1 for _ in expression.walk())
        if node_count > max_nodes:
            violations.append(
                Violation(
                    code=ViolationCode.PARSE_ERROR,
                    message=(
                        f"AST has {node_count} nodes; max_ast_nodes={max_nodes}. "
                        "Query rejected to bound validator CPU cost."
                    ),
                    suggestion="Shorten the query or raise policy.limits.max_ast_nodes.",
                )
            )
            return _finalize(violations, statement_kind=pre.statement_kind)

    # Preflight rejects multi-statement input, so `expression` is always a
    # single statement here.
    violations.extend(check_readonly(expression, policy))
    violations.extend(check_allowlist(expression, policy))
    violations.extend(check_predicates(expression, policy, context))
    violations.extend(check_limits(expression, policy))
    violations.extend(check_function_allow(expression, policy))

    return _finalize(violations, statement_kind=pre.statement_kind)


def _finalize(
    violations: list[Violation], *, statement_kind: str
) -> VerificationResult:
    return VerificationResult(
        allowed=not violations,
        violations=tuple(violations),
        statement_kind=statement_kind,
    )
