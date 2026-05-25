"""Predicate rules — two responsibilities:

  1. `_check_always_true`: reject leaves in row-filtering clauses that
     can't actually filter data. Applies to every predicate-bearing
     clause sqlglot can emit:

       WHERE, JOIN ON, MERGE ON, MERGE WHEN [NOT ]MATCHED AND <pred>,
       HAVING, QUALIFY, START WITH, CONNECT BY

     Two structural rules cover the whole tautology class:

       a. Catchall — leaf references nothing data-dependent (no Column,
          Table, AggFunc, or Window). Covers `1=1`, `1+1=2`, `abs(1)>0`,
          `true`, `'true'::boolean`, `EXISTS(SELECT 1)`,
          `repeat('a',3)='aaa'`, every shape sqlglot will ever support —
          without enumerating each one. AggFunc / Window are exempted so
          legitimate `HAVING count(*) > 1` / `QUALIFY row_number() OVER
          () = 1` don't false-positive.
       b. Structural self-equality — `id = id`. Has column refs so the
          catchall misses it, but it can't constrain rows.

  2. `_predicate_satisfied` / `_matches`: enforce per-table
     `require_predicate` rules (the multi-tenant guarantee). Every alias
     of a policy-protected table must AND-include the required predicate.

The catchall replaces the per-PG-function constant evaluator the v1-v5
audits built up. Layers 2-4 (least-priv role, RLS, statement_timeout)
catch anything that slips past — the validator is a tripwire, not the
perimeter.
"""
from __future__ import annotations

from typing import Any

from sqlglot import expressions as exp
from sqlglot.optimizer.scope import Scope

from sqlguard.config.schema import Policy, RequiredPredicate, TablePolicy
from sqlguard.core.idents import (
    column_alias,
    column_name,
    schema_name,
    table_alias,
    table_name,
)
from sqlguard.core.scope import iter_scopes
from sqlguard.result import Violation, ViolationCode, _truncate

_SENTINEL = object()
_AGGREGATORS = (exp.And, exp.Or, exp.Not, exp.Paren)

# Nodes that make a sub-expression data-dependent (not a pure constant).
# Column / Table cover real row references. AggFunc covers count/sum/avg/etc.
# whose value is computed from the row set — required because HAVING /
# QUALIFY routinely filter on aggregates (`HAVING count(*) > 1`) and the
# catchall would otherwise false-flag those as tautologies. Window covers
# row_number()/rank()/etc. in QUALIFY.
# Tuple type is intentionally inferred — annotating
# tuple[type[exp.Expression], ...] trips a tuple-invariance error under
# strict mypy because sqlglot exposes these as concrete `type[Column]` /
# `type[AggFunc]` etc. rather than the wider type[Expression].
_DATA_DEPENDENT = (exp.Column, exp.Table, exp.AggFunc, exp.Window)


def check_predicates(
    expression: exp.Expression,
    policy: Policy,
    context: dict[str, Any] | None = None,
) -> list[Violation]:
    """Check always-true predicates and required-WHERE predicates per table.

    Walks each scope. For tables with `require_predicate`, verifies that
    EVERY ALIAS of the table in the scope has its own AND-connected
    matching predicate — this catches the self-join bypass where one
    alias is filtered and another aliasing the same table is not.

    Placeholders like ${tenant_id} in policy values are resolved from
    `context` per request.
    """
    context = context or {}
    violations: list[Violation] = []

    if policy.forbid.always_true_predicates:
        violations.extend(_check_always_true(expression))

    if not policy.tables:
        return violations

    tables_with_required = [t for t in policy.tables if t.require_predicate]
    if not tables_with_required:
        return violations

    seen: set[tuple[str, str, str]] = set()  # (table, alias, column)

    for scope in iter_scopes(expression):
        cte_names = {name for name, src in scope.sources.items() if isinstance(src, Scope)}

        # Group real-table references by (folded table name, folded schema)
        # -> list of folded aliases. Schema is part of the key so the
        # require_predicate matcher picks the right policy entry when
        # two schemas have tables with the same name.
        aliases_by_table: dict[tuple[str, str], list[str]] = {}
        for t in scope.tables:
            if t.alias_or_name in cte_names:
                continue
            aliases_by_table.setdefault(
                (table_name(t), schema_name(t)), []
            ).append(table_alias(t))

        if not aliases_by_table:
            continue

        scope_expr = scope.expression
        if not isinstance(scope_expr, exp.Expression):
            continue
        # INSERT and MERGE have no WHERE on the target — require_predicate
        # is a WHERE-shaped rule and can't apply. For `INSERT ... SELECT`,
        # the source SELECT is its own scope (yielded by traverse_scope)
        # and IS checked there. For bare `INSERT ... VALUES` and MERGE,
        # write-side tenant isolation must be enforced at the DB layer
        # (RLS WITH CHECK / CHECK constraint). See README "layer 3".
        if isinstance(scope_expr, (exp.Insert, exp.Merge)):
            continue
        # For INNER JOINs, an ON-clause condition is semantically equivalent
        # to a WHERE condition (PG can move conditions either direction
        # during planning). LLMs commonly place tenant filters in the ON
        # clause; treat those as satisfying too.
        # OUTER JOINs (LEFT/RIGHT/FULL) are NOT equivalent — an ON filter
        # on the right table preserves the left side with NULL-padded
        # right columns, so it does NOT filter the result set the same way
        # a WHERE clause would. We only harvest ON conditions from INNER
        # joins.
        where_conds = _flatten_and(_get_where(scope_expr)) + _inner_join_on_conds(
            scope_expr
        )

        for table_policy in tables_with_required:
            tname = table_policy.name
            aliases = _aliases_for_policy(table_policy, aliases_by_table)
            if not aliases:
                continue
            n_aliases = len(aliases)

            for alias in aliases:
                for predicate in table_policy.require_predicate:
                    try:
                        resolved = predicate.resolve(context)
                    except KeyError as e:
                        violations.append(
                            Violation(
                                code=ViolationCode.POLICY_ERROR,
                                message=str(e),
                                suggestion=(
                                    "Add the missing placeholder to the context= "
                                    "argument of verify()."
                                ),
                            )
                        )
                        continue

                    if _predicate_satisfied(resolved, alias, where_conds, n_aliases):
                        continue

                    key = (tname, alias, resolved.column)
                    if key in seen:
                        continue
                    seen.add(key)

                    qualifier = f"{alias}." if n_aliases > 1 else ""
                    alias_hint = f" (alias {alias!r})" if n_aliases > 1 else ""
                    violations.append(
                        Violation(
                            code=ViolationCode.MISSING_REQUIRED_PREDICATE,
                            message=(
                                f"table {table_policy.name!r}{alias_hint} requires WHERE "
                                f"{qualifier}{resolved.column} {resolved.op} {resolved.value!r}"
                            ),
                            suggestion=(
                                f"Add `AND {qualifier}{resolved.column} "
                                f"{resolved.op} {resolved.value!r}` to the WHERE clause."
                            ),
                        )
                    )

    return violations


def _aliases_for_policy(
    table_policy: TablePolicy,
    aliases_by_table: dict[tuple[str, str], list[str]],
) -> list[str]:
    """Collect every alias of `table_policy` in this scope.

    Mirrors Policy.table_by_name's matching rules:
      - Schema-qualified policy + schema-qualified query: exact-schema match.
      - Schema-qualified policy + unqualified query: matches (search_path
        is assumed to resolve to the policy's schema).
      - Unqualified policy: matches any schema (and unqualified).
    """
    out: list[str] = []
    for (qname, qschema), aliases in aliases_by_table.items():
        if qname != table_policy.name:
            continue
        if (
            table_policy.schema_name is None
            or not qschema
            or qschema == table_policy.schema_name
        ):
            out.extend(aliases)
    return out


# ---------------------------------------------------------------------------
# Always-true detection — the structural catchall.
# ---------------------------------------------------------------------------


def _check_always_true(expression: exp.Expression) -> list[Violation]:
    """Reject leaves of row-filtering clauses that can't filter data.

    Covers every predicate-bearing clause sqlglot exposes — not just
    WHERE — because the bypass class is "any clause carrying a row
    filter," and every audit round has historically found a new
    "we didn't check clause X" gap. Clauses scanned:

      WHERE, JOIN ON, MERGE ON, MERGE WHEN [NOT ]MATCHED AND <pred>,
      HAVING, QUALIFY, START WITH, CONNECT BY

    Two structural rules — no per-function constant folding required:

      1. **Catchall**: a leaf that references nothing data-dependent
         (Column / Table / AggFunc / Window) is constant. Covers every
         static expression sqlglot will ever support: `1=1`, `1+1=2`,
         `abs(1)>0`, `true`, `'true'::boolean`, `EXISTS(SELECT 1)`,
         `1 IN (1,2,3)`, `repeat('a',3)='aaa'`, `1 = ANY(ARRAY[1])`, etc.

         The `exp.Table` check is what lets `EXISTS (SELECT 1 FROM
         users)` through — it has no Column ref but does reference a
         Table, so it's real data-dependent. AggFunc / Window exempt
         legitimate `HAVING count(*) > 1` / `QUALIFY row_number() OVER
         () = 1`.

      2. **Structural self-equality**: `id = id`, `users.id = users.id`.
         Both sides reference columns so the catchall misses it, but
         the predicate can't constrain rows.

    Aggregator nodes (And/Or/Not/Paren) are skipped — we check the
    boolean LEAVES, since data-dependence is what matters.
    """
    violations: list[Violation] = []
    seen: set[int] = set()

    for node in expression.walk():
        # Each iteration yields (condition_expr, context_label). A single
        # AST node can produce multiple conditions (e.g. CONNECT BY has
        # both START WITH and CONNECT BY predicates).
        conditions: list[tuple[exp.Expression, str]] = []
        if isinstance(node, exp.Where):
            cond = node.this
            if isinstance(cond, exp.Expression):
                conditions.append((cond, "WHERE"))
        elif isinstance(node, exp.Join):
            on = node.args.get("on")
            if isinstance(on, exp.Expression):
                conditions.append((on, "JOIN ON"))
        elif isinstance(node, exp.Merge):
            # MERGE's matching is in its `on` arg (not a Join node); without
            # this branch `MERGE ... ON 1=1 WHEN MATCHED ...` would be
            # silently accepted on read_only=False policies.
            on = node.args.get("on")
            if isinstance(on, exp.Expression):
                conditions.append((on, "MERGE ON"))
        elif isinstance(node, exp.Having):
            cond = node.this
            if isinstance(cond, exp.Expression):
                conditions.append((cond, "HAVING"))
        elif isinstance(node, exp.Qualify):
            cond = node.this
            if isinstance(cond, exp.Expression):
                conditions.append((cond, "QUALIFY"))
        elif isinstance(node, exp.When):
            cond = node.args.get("condition")
            if isinstance(cond, exp.Expression):
                label = (
                    "WHEN MATCHED" if node.args.get("matched") else "WHEN NOT MATCHED"
                )
                conditions.append((cond, label))
        elif isinstance(node, exp.Connect):
            # Oracle hierarchical query: START WITH <pred> CONNECT BY <pred>.
            start = node.args.get("start")
            cby = node.args.get("connect")
            if isinstance(start, exp.Expression):
                conditions.append((start, "START WITH"))
            if isinstance(cby, exp.Expression):
                conditions.append((cby, "CONNECT BY"))

        if not conditions:
            continue

        for condition, context_label in conditions:
            violations.extend(
                _scan_predicate_leaves(condition, context_label, seen)
            )

    return violations


def _scan_predicate_leaves(
    condition: exp.Expression, context_label: str, seen: set[int]
) -> list[Violation]:
    """Run the always-true / self-equality / self-IN / null-complement
    checks on every boolean leaf of `condition`.

    Factored out so every predicate-bearing clause (WHERE, JOIN ON,
    MERGE ON, WHEN [MATCHED|NOT MATCHED], HAVING, QUALIFY, CONNECT BY,
    START WITH) gets the same scrutiny — the bypass class is "any
    clause carrying a row-filtering predicate," not "WHERE."
    """
    violations: list[Violation] = []

    for sub in _walk_boolean(condition):
        if id(sub) in seen or isinstance(sub, _AGGREGATORS):
            continue
        seen.add(id(sub))

        # Catchall: leaf references no data source — pure constant.
        if sub.find(*_DATA_DEPENDENT) is None:
            violations.append(
                Violation(
                    code=ViolationCode.ALWAYS_TRUE_PREDICATE,
                    message=(
                        f"{context_label} leaf {_truncate(sub.sql())!r} references no "
                        "column — a real filter must constrain row data."
                    ),
                    suggestion=(
                        "Remove the constant predicate, or rewrite to filter "
                        "on actual table columns."
                    ),
                )
            )
            continue

        # Column = same column structural tautology.
        if isinstance(sub, exp.EQ) and _same_expression(sub.this, sub.expression):
            violations.append(
                Violation(
                    code=ViolationCode.ALWAYS_TRUE_PREDICATE,
                    message=(
                        f"{context_label} contains structural self-equality: "
                        f"{_truncate(sub.sql())}"
                    ),
                    suggestion=(
                        "Remove the self-comparison — `x = x` doesn't filter."
                    ),
                )
            )

        # `col IN (col, ...)` — column IS one of the IN list members
        # (modulo NULL, which makes the predicate false in WHERE). An
        # attacker writes this as a faux-filter that matches every
        # non-null row.
        if isinstance(sub, exp.In):
            lhs = sub.this
            for item in sub.expressions:
                if _same_expression(lhs, item):
                    violations.append(
                        Violation(
                            code=ViolationCode.ALWAYS_TRUE_PREDICATE,
                            message=(
                                f"{context_label} contains structural self-membership: "
                                f"{_truncate(sub.sql())}"
                            ),
                            suggestion=(
                                "Remove the self-IN — `x IN (x, ...)` matches every "
                                "non-null row regardless of the other IN members."
                            ),
                        )
                    )
                    break

    # OR-tree-level tautology: `X IS NULL OR X IS NOT NULL` covers every
    # possible value of X. The leaves both reference a Column so the
    # catchall correctly skips them, and self-equality doesn't apply —
    # but the OR-pair shape IS structurally always-true. This is the
    # canonical blind-exfil pattern.
    violations.extend(_check_null_complement_or(condition, context_label))

    return violations


def _check_null_complement_or(
    condition: exp.Expression, context_label: str
) -> list[Violation]:
    """Detect `X IS NULL OR X IS NOT NULL` (and the reverse). Walks OR
    nodes — for each OR, checks if its two operands are complementary
    null checks on the same expression.

    Generalizes through nested ORs: `id IS NULL OR (id IS NOT NULL OR foo)`
    still fires because we collect IS NULL / IS NOT NULL leaves across the
    OR tree and look for a matching pair.
    """
    violations: list[Violation] = []
    seen: set[str] = set()
    for or_node in condition.find_all(exp.Or):
        leaves = _walk_boolean(or_node)
        null_targets: list[exp.Expression] = []
        not_null_targets: list[exp.Expression] = []
        for leaf in leaves:
            # `X IS NULL` parses as `exp.Is(this=X, expression=exp.Null())`.
            if isinstance(leaf, exp.Is) and isinstance(leaf.expression, exp.Null):
                null_targets.append(leaf.this)
            # `X IS NOT NULL` parses as `exp.Not(this=Is(...))`.
            elif (
                isinstance(leaf, exp.Not)
                and isinstance(leaf.this, exp.Is)
                and isinstance(leaf.this.expression, exp.Null)
            ):
                not_null_targets.append(leaf.this.this)
        for nl in null_targets:
            for nnl in not_null_targets:
                if not _same_expression(nl, nnl):
                    continue
                sig = nl.sql()
                if sig in seen:
                    continue
                seen.add(sig)
                violations.append(
                    Violation(
                        code=ViolationCode.ALWAYS_TRUE_PREDICATE,
                        message=(
                            f"{context_label} contains complementary null checks "
                            f"on {_truncate(sig)!r} — `X IS NULL OR X IS NOT NULL` "
                            "is always true."
                        ),
                        suggestion=(
                            "Remove the null-complement pair — it doesn't filter rows."
                        ),
                    )
                )
    return violations


def _walk_boolean(node: exp.Expression | None) -> list[exp.Expression]:
    """Yield every boolean sub-expression — operands of AND/OR/NOT trees.

    Paren is unwrapped (not yielded) so a parenthesized leaf doesn't show
    up twice as both `Paren(EQ)` and `EQ`.
    """
    if node is None:
        return []
    if isinstance(node, exp.Paren):
        return _walk_boolean(node.this)
    out = [node]
    if isinstance(node, (exp.And, exp.Or)):
        out.extend(_walk_boolean(node.this))
        out.extend(_walk_boolean(node.expression))
    elif isinstance(node, exp.Not):
        out.extend(_walk_boolean(node.this))
    return out


def _same_expression(a: exp.Expression | None, b: exp.Expression | None) -> bool:
    """Structural equality via SQL rendering — only meaningful for
    column refs. Pure literal=literal is handled by the catchall.

    Unwraps Paren/Cast wrappers on both sides before comparing so trivial
    obfuscations don't defeat the self-equality check:
      - ``id = (id)`` (paren on one side)
      - ``(id) = id``
      - ``id::int = id`` (cast on one side)
      - ``id::text = id::text`` (matching casts; was caught by raw sql()
        compare already, kept correct by mirrored unwrapping)
    """
    a = _unwrap_col_wrapper(a)
    b = _unwrap_col_wrapper(b)
    if a is None or b is None:
        return False
    if isinstance(a, exp.Literal) and isinstance(b, exp.Literal):
        return False
    return bool(a.sql() == b.sql())


# ---------------------------------------------------------------------------
# require_predicate matcher.
# ---------------------------------------------------------------------------


def _get_where(expression: exp.Expression) -> exp.Expression | None:
    if isinstance(expression, (exp.Select, exp.Update, exp.Delete)):
        where = expression.args.get("where")
        if isinstance(where, exp.Where):
            inner = where.this
            return inner if isinstance(inner, exp.Expression) else None
    return None


def _flatten_and(expression: exp.Expression | None) -> list[exp.Expression]:
    """Walk down an AND-tree, returning each leaf condition."""
    if expression is None:
        return []
    if isinstance(expression, exp.And):
        return _flatten_and(expression.this) + _flatten_and(expression.expression)
    if isinstance(expression, exp.Paren):
        return _flatten_and(expression.this)
    return [expression]


# Join kinds whose ON clause is semantically equivalent to a WHERE clause
# (no NULL-padding for non-matching rows). The kind string sqlglot uses
# for plain `JOIN ... ON ...` is empty; explicit `INNER JOIN` also yields
# kind="INNER". Everything else (LEFT/RIGHT/FULL/CROSS/SEMI/ANTI) is NOT
# equivalent and we skip it.
_INNER_JOIN_KINDS: frozenset[str] = frozenset({"", "INNER"})


def _inner_join_on_conds(scope_expr: exp.Expression) -> list[exp.Expression]:
    """Collect AND-leaves from every INNER JOIN's ON clause in this scope.

    Stops at nested SELECT boundaries so a subquery's joins don't leak
    into the outer scope (subqueries are visited as their own scopes).
    """
    if not isinstance(scope_expr, (exp.Select, exp.Update, exp.Delete)):
        return []
    out: list[exp.Expression] = []
    from_clause = scope_expr.args.get("from")
    joins = scope_expr.args.get("joins") or []
    candidates: list[exp.Expression] = []
    if isinstance(from_clause, exp.Expression):
        candidates.append(from_clause)
    candidates.extend(j for j in joins if isinstance(j, exp.Join))
    for cand in candidates:
        for join in cand.find_all(exp.Join):
            # Skip joins that belong to a nested SELECT in the same tree
            # — those are visited at their own scope.
            ancestor = join.parent
            while ancestor is not None and ancestor is not scope_expr:
                if isinstance(ancestor, exp.Select) and ancestor is not scope_expr:
                    break
                ancestor = ancestor.parent
            else:
                ancestor = None  # didn't hit a nested SELECT before scope root
            if ancestor is not None:
                continue
            kind = (join.args.get("kind") or "").upper()
            side = (join.args.get("side") or "").upper()
            # OUTER (LEFT/RIGHT/FULL) joins: ON filters preserve nulls,
            # not equivalent to WHERE.
            if side in ("LEFT", "RIGHT", "FULL"):
                continue
            if kind not in _INNER_JOIN_KINDS:
                continue
            on = join.args.get("on")
            if isinstance(on, exp.Expression):
                out.extend(_flatten_and(on))
    return out


def _predicate_satisfied(
    required: RequiredPredicate,
    alias: str,
    conds: list[exp.Expression],
    n_aliases: int,
) -> bool:
    return any(_matches(required, alias, c, n_aliases) for c in conds)


_BINARY_OPS: dict[str, type[exp.Expression]] = {
    "=": exp.EQ,
    "!=": exp.NEQ,
    "<": exp.LT,
    "<=": exp.LTE,
    ">": exp.GT,
    ">=": exp.GTE,
}


def _matches(
    required: RequiredPredicate,
    alias: str,
    cond: exp.Expression,
    n_aliases: int,
) -> bool:
    op = required.op

    def col_match(node: exp.Expression | None) -> bool:
        return _col_eq(required.column, alias, node, n_aliases)

    cls = _BINARY_OPS.get(op)
    if cls is not None and isinstance(cond, cls):
        if col_match(cond.this) and _literal_equals(required.value, cond.expression):
            return True
        # `=` and `!=` are commutative — accept the flipped form
        # (`42 = account_id`) so an LLM that emits the literal-on-left
        # shape isn't falsely flagged. Order-sensitive operators (<, <=,
        # >, >=) are NOT flipped: `account_id < 42` and `42 < account_id`
        # have different semantics.
        return (
            op in ("=", "!=")
            and col_match(cond.expression)
            and _literal_equals(required.value, cond.this)
        )
    # `col IN (42)` is semantically equivalent to `col = 42`. Accept the
    # single-literal IN form when policy requires equality, so LLMs that
    # emit `IN (tenant)` instead of `= tenant` aren't falsely flagged.
    if op == "=" and isinstance(cond, exp.In) and len(cond.expressions) == 1:
        return col_match(cond.this) and _literal_equals(required.value, cond.expressions[0])
    if op == "IN" and isinstance(cond, exp.In):
        if not col_match(cond.this):
            return False
        expected = required.value if isinstance(required.value, list) else [required.value]
        actual = [_literal_value(v) for v in cond.expressions]
        return _equal_unordered_tolerant(expected, actual)
    if op == "BETWEEN" and isinstance(cond, exp.Between):
        if not col_match(cond.this) or not (
            isinstance(required.value, (list, tuple)) and len(required.value) == 2
        ):
            return False
        return _literal_equals(required.value[0], cond.args.get("low")) and _literal_equals(
            required.value[1], cond.args.get("high")
        )
    return False


def _col_eq(name: str, alias: str, node: exp.Expression | None, n_aliases: int) -> bool:
    """Match a column to (name, alias) using case-folded comparison.

    Qualified columns must use the given alias. Unqualified columns count only
    when this scope has a single alias for the policy table.

    A direct CAST or Paren around the column (`account_id::text`,
    `(account_id)`) is accepted — neither changes the row-set being
    constrained. Casts of expressions (`(account_id + 1)::text`) are NOT
    accepted because they may change semantics.
    """
    node = _unwrap_col_wrapper(node)
    if not isinstance(node, exp.Column):
        return False
    if column_name(node) != name:
        return False
    col_alias = column_alias(node)
    if col_alias:
        return col_alias == alias
    return n_aliases == 1


def _unwrap_col_wrapper(node: exp.Expression | None) -> exp.Expression | None:
    """Peel back Paren / Cast wrappers around a bare Column reference."""
    while node is not None:
        if isinstance(node, exp.Paren):
            node = node.this
            continue
        if isinstance(node, exp.Cast) and isinstance(node.this, (exp.Column, exp.Paren, exp.Cast)):
            node = node.this
            continue
        break
    return node


# ---------------------------------------------------------------------------
# Bare-literal folding for require_predicate RHS matching.
#
# Deliberately tiny. We only need to recognize bare literals (and trivial
# wrappers around them) so `account_id = 42` matches the required value
# from context. Anything more complex returns _SENTINEL and the predicate
# is considered unsatisfied — the LLM can write a plain literal.
# ---------------------------------------------------------------------------


def _literal_value(node: exp.Expression | None) -> Any:
    """Fold a leaf to its Python value. Handles Literal / Boolean / Null
    plus trivial wrappers (Paren / Cast / Neg). Anything else → _SENTINEL."""
    if node is None:
        return _SENTINEL
    if isinstance(node, exp.Paren):
        return _literal_value(node.this)
    if isinstance(node, exp.Cast):
        return _literal_value(node.this)
    if isinstance(node, exp.Neg):
        v = _literal_value(node.this)
        return -v if isinstance(v, (int, float)) else _SENTINEL
    if isinstance(node, exp.Literal):
        if node.is_int:
            return int(node.this)
        if node.is_number:
            try:
                return float(node.this)
            except ValueError:
                return node.this
        return node.this
    if isinstance(node, exp.Boolean):
        return bool(node.this)
    if isinstance(node, exp.Null):
        return None
    return _SENTINEL


def _literal_equals(expected: Any, node: exp.Expression | None) -> bool:
    if node is None:
        return False
    actual = _literal_value(node)
    if actual is _SENTINEL:
        return False
    return _equal_tolerant(expected, actual)


def _equal_tolerant(a: Any, b: Any) -> bool:
    """Equality with int↔str↔float coercion (PG-style)."""
    if a is None or b is None:
        return a is None and b is None
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if a == b:
        return True
    try:
        return float(a) == float(b)
    except (TypeError, ValueError):
        return False


def _equal_unordered_tolerant(expected: list[Any], actual: list[Any]) -> bool:
    if len(expected) != len(actual):
        return False
    remaining = list(actual)
    for e in expected:
        for i, a in enumerate(remaining):
            if _equal_tolerant(e, a):
                remaining.pop(i)
                break
        else:
            return False
    return True
