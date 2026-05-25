from __future__ import annotations

from sqlglot import expressions as exp
from sqlglot.optimizer.scope import Scope, traverse_scope

from sqlguard.config.schema import Policy
from sqlguard.core.idents import schema_name, table_name
from sqlguard.result import Violation, ViolationCode


def check_limits(expression: exp.Expression, policy: Policy) -> list[Violation]:
    """DoS-protection rules: cartesian joins, recursion, query complexity,
    required LIMIT on large tables.
    """
    violations: list[Violation] = []

    if policy.forbid.cartesian_join:
        violations.extend(_check_cartesian(expression))

    # NATURAL JOIN is always rejected — it implicitly joins on every
    # same-named column, which bypasses the column allowlist (the matched
    # columns never appear as Identifier nodes in the AST, so the
    # identifier-name catchall never sees them). No policy toggle; this
    # is in the same class as multi-statement rejection.
    violations.extend(_check_natural_join(expression))

    if policy.forbid.recursive_cte:
        violations.extend(_check_recursive_cte(expression))

    if policy.limits.max_joins is not None:
        violations.extend(_check_max_joins(expression, policy.limits.max_joins))

    if policy.limits.max_subquery_depth is not None:
        violations.extend(_check_max_subquery_depth(expression, policy.limits.max_subquery_depth))

    # `_check_require_limit_on_large` short-circuits when no table has `large: True`.
    violations.extend(_check_require_limit_on_large(expression, policy))

    if policy.limits.max_limit_value is not None:
        violations.extend(_check_max_limit_value(expression, policy.limits.max_limit_value))

    if policy.limits.max_offset_value is not None:
        violations.extend(_check_max_offset_value(expression, policy.limits.max_offset_value))

    return violations


def _check_cartesian(expression: exp.Expression) -> list[Violation]:
    """A Join is cartesian if it has no ON, no USING, and isn't LATERAL
    or NATURAL.

    Explicit CROSS JOIN is flagged. Comma-joined tables (`FROM a, b`) parse
    as a Join with no ON/USING — also flagged. LATERAL joins use the same
    comma syntax but are NOT cartesian (the right side is correlated to the
    left), so they're exempt. NATURAL joins have implicit (by-column-name)
    matching and are NOT cartesian either — they get their own dedicated
    rejection in `_check_natural_join` with a clearer message.
    """
    violations: list[Violation] = []
    for join in expression.find_all(exp.Join):
        kind = (join.args.get("kind") or "").upper()
        side = (join.args.get("side") or "").upper()
        method = (join.args.get("method") or "").upper()
        on = join.args.get("on")
        using = join.args.get("using")

        # LATERAL is correlated, not cartesian — skip.
        if "LATERAL" in {kind, side, method}:
            continue
        if isinstance(join.this, exp.Lateral):
            continue
        # NATURAL JOIN has implicit ON via shared column names — not a
        # cartesian product. Handled by `_check_natural_join`.
        if method == "NATURAL":
            continue

        if kind == "CROSS":
            violations.append(_cartesian_violation("explicit CROSS JOIN"))
        elif on is None and using is None:
            violations.append(
                _cartesian_violation(
                    "JOIN without ON / USING (implicit cross product)"
                )
            )
    return violations


def _cartesian_violation(detail: str) -> Violation:
    return Violation(
        code=ViolationCode.CARTESIAN_JOIN,
        message=f"cartesian join detected: {detail}",
        suggestion="Add an ON / USING condition that relates the two tables.",
    )


def _check_natural_join(expression: exp.Expression) -> list[Violation]:
    """Reject NATURAL JOIN unconditionally.

    NATURAL JOIN implicitly joins on every column with a matching name
    across the two tables. The matched columns never appear as Identifier
    nodes in the AST, so:

      1. The identifier-name catchall in ``allowlist.py`` can't see them
         and any denied column with a matching name on the joined table
         is silently included in the join condition.
      2. ``allow_columns`` enforcement is bypassed for the implicitly
         matched columns.
      3. A future schema change can broaden or break the join silently
         (well-known SQL anti-pattern).

    Rewrite as ``JOIN ... USING (col, ...)`` or ``JOIN ... ON a.col =
    b.col`` to make every joined column explicit and visible to the
    column-allowlist checks.
    """
    violations: list[Violation] = []
    seen: set[int] = set()
    for join in expression.find_all(exp.Join):
        method = (join.args.get("method") or "").upper()
        if method != "NATURAL" or id(join) in seen:
            continue
        seen.add(id(join))
        violations.append(
            Violation(
                code=ViolationCode.NATURAL_JOIN_FORBIDDEN,
                message=(
                    "NATURAL JOIN is forbidden — it implicitly joins on "
                    "every same-named column, which bypasses the column "
                    "allowlist and silently changes meaning when schemas "
                    "evolve."
                ),
                suggestion=(
                    "Rewrite as `JOIN ... USING (col, ...)` or "
                    "`JOIN ... ON a.col = b.col` so every joined column "
                    "is explicit."
                ),
            )
        )
    return violations


def _check_recursive_cte(expression: exp.Expression) -> list[Violation]:
    violations: list[Violation] = []
    for with_node in expression.find_all(exp.With):
        if with_node.args.get("recursive"):
            violations.append(
                Violation(
                    code=ViolationCode.RECURSIVE_CTE,
                    message="WITH RECURSIVE is forbidden (recursion can run unboundedly).",
                    suggestion=(
                        "Rewrite as a plain CTE with explicit termination, or run "
                        "against a smaller bounded dataset."
                    ),
                )
            )
            return violations  # one per query is enough
    return violations


def _check_max_joins(expression: exp.Expression, max_joins: int) -> list[Violation]:
    count = sum(1 for _ in expression.find_all(exp.Join))
    if count <= max_joins:
        return []
    return [
        Violation(
            code=ViolationCode.MAX_JOINS_EXCEEDED,
            message=f"query has {count} joins; max_joins={max_joins}.",
            suggestion="Simplify the query or raise the policy max_joins.",
        )
    ]


def _check_max_subquery_depth(expression: exp.Expression, max_depth: int) -> list[Violation]:
    depth = _max_select_depth(expression, 0)
    # The root SELECT counts as depth 1; depth N means N nested SELECTs.
    if depth <= max_depth:
        return []
    return [
        Violation(
            code=ViolationCode.MAX_SUBQUERY_DEPTH,
            message=f"subquery nesting depth is {depth}; max_subquery_depth={max_depth}.",
            suggestion="Flatten subqueries or refactor with CTEs (which count separately).",
        )
    ]


# Args whose contents are *sibling* SELECTs to the current scope, not nested
# subqueries. Recursing into these without resetting the depth counter would
# inflate `WITH a AS (SELECT ...) SELECT FROM a` to depth 2 (when intuitively
# it's depth 1) and rejects every CTE query under `max_subquery_depth: 1`.
# Note: sqlglot's `Select.with` arg is keyed `with_` (trailing underscore to
# avoid the Python reserved word).
_SIBLING_SCOPE_ARGS: frozenset[str] = frozenset({"with", "with_", "ctes", "cte"})


def _max_select_depth(node: exp.Expression, current: int) -> int:
    if isinstance(node, exp.Select):
        current += 1
    best = current
    for arg_name, child in node.args.items():
        # CTE bodies are sibling scopes, not nested subqueries — recurse
        # with a fresh depth counter so a depth-1 CTE + depth-1 outer
        # query reports depth 1 instead of 2.
        child_start = 0 if arg_name in _SIBLING_SCOPE_ARGS else current
        if isinstance(child, exp.Expression):
            best = max(best, _max_select_depth(child, child_start))
        elif isinstance(child, list):
            for item in child:
                if isinstance(item, exp.Expression):
                    best = max(best, _max_select_depth(item, child_start))
    return best


def _check_require_limit_on_large(
    expression: exp.Expression, policy: Policy
) -> list[Violation]:
    """For each scope that references a large table, require a LIMIT on
    that scope OR on an ancestor scope. A LIMIT on a SIBLING subquery
    does NOT count — that would let `... < (SELECT count(*) FROM users
    LIMIT 1)` satisfy a LIMIT-required check for `orders`.

    Schema-aware: a `large` policy entry for `public.orders` doesn't force
    a LIMIT on `analytics.orders` (different table). Unqualified policies
    still match any schema (current behavior).
    """
    if not any(t.large for t in policy.tables):
        return []

    violations: list[Violation] = []
    # Dedupe by (table, schema) — same-named tables in different schemas
    # (`public.orders`, `analytics.orders`) are distinct policy targets and
    # both must surface a separate violation. Keying on bare name would
    # silently swallow the second one.
    seen: set[tuple[str, str]] = set()

    for scope in traverse_scope(expression):
        cte_names = {name for name, src in scope.sources.items() if isinstance(src, Scope)}
        scope_large: set[tuple[str, str]] = set()
        for t in scope.tables:
            if t.alias_or_name in cte_names:
                continue
            tname = table_name(t)
            tschema = schema_name(t)
            tp = policy.table_by_name(tname, tschema)
            if tp is not None and tp.large:
                scope_large.add((tname, tschema))
        if not scope_large:
            continue

        scope_expr: exp.Expression | None = (
            scope.expression if isinstance(scope.expression, exp.Expression) else None
        )
        if _has_limit_in_lineage(scope_expr):
            continue

        for tname, tschema in scope_large - seen:
            seen.add((tname, tschema))
            display = f"{tschema}.{tname}" if tschema else tname
            violations.append(
                Violation(
                    code=ViolationCode.LIMIT_REQUIRED,
                    message=(
                        f"large table {display!r} is referenced by a SELECT with no "
                        "LIMIT on it or any ancestor SELECT."
                    ),
                    suggestion="Add LIMIT N to this SELECT or to the outer query.",
                )
            )

    return violations


# Node types that can carry a top-level LIMIT/FETCH that bounds the row
# output of the SELECT(s) below them. PG accepts `LIMIT` on plain
# SELECT, UNION, INTERSECT, and EXCEPT (every set-op flavor). sqlglot
# wraps the latter three under exp.Union / exp.Intersect / exp.Except;
# they all subclass exp.Query but checking the concrete trio is more
# explicit than a wider isinstance.
_LIMITABLE: tuple[type[exp.Expression], ...] = (
    exp.Select,
    exp.Union,
    exp.Intersect,
    exp.Except,
)


def _has_limit_in_lineage(node: exp.Expression | None) -> bool:
    """True if `node` or any of its ancestors has an EFFECTIVE LIMIT or FETCH.

    `LIMIT ALL` and `LIMIT 0` do NOT count as effective limits:
      - `LIMIT ALL` is PG syntax for "no limit"
      - `LIMIT 0` returns no rows, which means the user got the SQL wrong
        more often than they meant it; treat as missing.

    `FETCH FIRST N ROWS ONLY` (SQL:2008) is parsed by sqlglot as exp.Fetch
    under the `limit` arg and IS accepted when N is a positive integer.
    """
    cur: exp.Expression | None = node
    while cur is not None:
        if isinstance(cur, _LIMITABLE):
            lim = cur.args.get("limit")
            if isinstance(lim, exp.Expression) and _is_effective_limit(lim):
                return True
        parent = cur.parent
        cur = parent if isinstance(parent, exp.Expression) else None
    return False


def _is_effective_limit(limit: exp.Expression) -> bool:
    """A row-cap is 'effective' if its value is a positive integer literal.

    Accepts exp.Limit and exp.Fetch (FETCH FIRST N ROWS ONLY). Rejects
    LIMIT ALL (sqlglot parses ALL as a Column named 'ALL') and LIMIT 0
    (returns no rows; probably an LLM mistake).
    """
    if isinstance(limit, exp.Fetch):
        val = limit.args.get("count")
    elif isinstance(limit, exp.Limit):
        val = limit.expression
    else:
        return False
    if not isinstance(val, exp.Literal) or not val.is_int:
        return False
    try:
        return int(val.this) > 0
    except (TypeError, ValueError):
        return False


def _check_max_offset_value(expression: exp.Expression, max_value: int) -> list[Violation]:
    """Cap OFFSET to bound scan-and-skip cost.

    Unbounded `OFFSET 99999999` forces PG to read and discard millions of
    rows before returning anything — a textbook DoS / cost-attack vector.
    Non-literal OFFSET expressions (`OFFSET (SELECT 9999999)`, `OFFSET $1`)
    fail closed: the cap can't be statically enforced, so the value is
    rejected rather than silently allowed.

    Walks every ``exp.Offset`` in the tree — set-op queries
    (``SELECT … UNION SELECT … OFFSET N``) attach OFFSET to the
    ``exp.Union`` / ``exp.Intersect`` / ``exp.Except`` node, not to the
    inner Select, so iterating Selects would miss them.
    """
    violations: list[Violation] = []
    seen: set[int] = set()
    for off in expression.find_all(exp.Offset):
        if id(off) in seen:
            continue
        seen.add(id(off))
        val_node = off.expression
        if val_node is None:
            continue
        if not isinstance(val_node, exp.Literal) or not val_node.is_int:
            violations.append(
                Violation(
                    code=ViolationCode.OFFSET_EXCEEDED,
                    message=(
                        f"OFFSET expression {val_node.sql()!r} is not a literal "
                        f"integer; the {max_value}-row cap cannot be enforced."
                    ),
                    suggestion=f"Use a literal OFFSET N where N <= {max_value}.",
                )
            )
            continue
        val = int(val_node.this)
        if val > max_value:
            violations.append(
                Violation(
                    code=ViolationCode.OFFSET_EXCEEDED,
                    message=f"OFFSET {val} exceeds max_offset_value={max_value}.",
                    suggestion=(
                        f"Use OFFSET {max_value} or smaller — high OFFSET values "
                        "force a scan-and-skip on the underlying table."
                    ),
                )
            )
    return violations


def _check_max_limit_value(expression: exp.Expression, max_value: int) -> list[Violation]:
    """Check both `LIMIT N` and `FETCH FIRST N ROWS ONLY` against the cap.

    Non-literal LIMIT (`LIMIT (SELECT ...)`, `LIMIT $1`) fails closed: the
    cap can't be statically enforced, so the value is rejected rather than
    silently allowed.
    """
    violations: list[Violation] = []
    seen: set[int] = set()
    for limit in (*expression.find_all(exp.Limit), *expression.find_all(exp.Fetch)):
        if id(limit) in seen:
            continue
        seen.add(id(limit))
        val_node = limit.args.get("count") if isinstance(limit, exp.Fetch) else limit.expression
        if val_node is None:
            continue
        if not isinstance(val_node, exp.Literal) or not val_node.is_int:
            violations.append(
                Violation(
                    code=ViolationCode.LIMIT_EXCEEDED,
                    message=(
                        f"LIMIT expression {val_node.sql()!r} is not a literal "
                        f"integer; the {max_value}-row cap cannot be enforced."
                    ),
                    suggestion=f"Use a literal LIMIT N where N <= {max_value}.",
                )
            )
            continue
        val = int(val_node.this)
        if val > max_value:
            violations.append(
                Violation(
                    code=ViolationCode.LIMIT_EXCEEDED,
                    message=f"LIMIT {val} exceeds max_limit_value={max_value}.",
                    suggestion=f"Use LIMIT {max_value} or smaller.",
                )
            )
    return violations
