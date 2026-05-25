from __future__ import annotations

from sqlglot import expressions as exp
from sqlglot.optimizer.scope import Scope

from sqlguard.config.schema import Policy, TablePolicy
from sqlguard.core.idents import (
    column_alias,
    column_name,
    default_fold,
    schema_name,
    table_alias,
    table_name,
)
from sqlguard.core.scope import DmlScope, iter_scopes
from sqlguard.result import Violation, ViolationCode, _truncate


def check_allowlist(
    expression: exp.Expression,
    policy: Policy,
) -> list[Violation]:
    """Validate that every real table and every column is allowed by policy.

    Walks each scope, distinguishes real tables from CTE/subquery references via
    sqlglot's scope analysis, and resolves column aliases back to their source
    table before checking column allow/deny lists.
    """
    violations: list[Violation] = []

    if policy.forbid.select_star:
        violations.extend(_check_select_star(expression))

    # Structural catchall: any Identifier matching a denied column name —
    # in ANY syntactic position, including JOIN USING (which doesn't show
    # up as a Column node and would otherwise slip past the column walk
    # below. Default-deny over arms-race-style per-position rules.
    violations.extend(_check_denied_identifier_names(expression, policy))

    has_table_allowlist = bool(policy.tables)

    seen_table_violations: set[tuple[str, str]] = set()
    # Keyed (table, schema, column) so same-named columns on
    # `public.users` vs `analytics.users` both surface as separate
    # violations instead of one swallowing the other.
    seen_column_violations: set[tuple[str, str, str]] = set()

    for scope in iter_scopes(expression):
        cte_names = {name for name, src in scope.sources.items() if isinstance(src, Scope)}

        for table in scope.tables:
            tname = table_name(table)
            sqlglot_alias = table.alias_or_name  # for cte_names lookup
            if sqlglot_alias in cte_names or tname in cte_names:
                continue

            schema = schema_name(table)
            key = (tname, schema)
            if key in seen_table_violations:
                continue

            display = f"{schema}.{tname}" if schema else tname
            display_short = _truncate(display)

            if has_table_allowlist and policy.table_by_name(tname, schema) is None:
                violations.append(
                    Violation(
                        code=ViolationCode.TABLE_DENIED,
                        message=f"table {display_short!r} is not in the policy allowlist.",
                        suggestion=(
                            "Add the table to policy.tables or rewrite the "
                            "query to use an allowed table."
                        ),
                    )
                )
                seen_table_violations.add(key)

        # Column checks — only meaningful if we have a table allowlist with column rules.
        if has_table_allowlist:
            alias_to_table = _build_alias_map(scope, cte_names)
            # LATERAL / correlated-subquery scopes can reference an ancestor
            # scope's table alias. Pre-compute the merged ancestor alias
            # map once per scope so the column walk can resolve outer-scope
            # qualifiers without falsely flagging them as bogus.
            outer_alias_to_table = _build_outer_alias_map(scope)
            # Total sources in this scope, counting CTEs and subqueries as
            # well as real tables. Used to detect when an unqualified column
            # can't be unambiguously attributed to a single source.
            total_sources = len(getattr(scope, "sources", {})) or len(alias_to_table)

            # sqlglot's scope.columns walks SELECT projections, WHERE, GROUP BY,
            # ORDER BY, OVER(), FILTER, CASE, GROUPING SETS — but NOT HAVING.
            # We need to walk HAVING explicitly or denied columns escape via
            # `HAVING max(password_hash) IS NOT NULL` and similar.
            #
            # We also skip pseudo-columns that sqlglot creates for `LIMIT ALL`
            # (`ALL` is parsed as a Column reference) — those aren't real
            # column references and the LIMIT rule handles them separately.
            columns_to_check: list[exp.Column] = [
                c for c in scope.columns if not _is_limit_all_pseudo(c)
            ]
            select = scope.expression
            if isinstance(select, exp.Select):
                having = select.args.get("having")
                if having is not None:
                    columns_to_check.extend(having.find_all(exp.Column))

            for column in columns_to_check:
                _check_column_against_policy(
                    column,
                    alias_to_table,
                    cte_names,
                    total_sources,
                    policy,
                    seen_column_violations,
                    violations,
                    outer_alias_to_table=outer_alias_to_table,
                )

    return violations


def _emit_bogus_qualifier(
    col_alias: str,
    column: exp.Column,
    seen: set[tuple[str, str, str]],
    violations: list[Violation],
) -> None:
    """Emit COLUMN_DENIED for a qualifier that doesn't resolve in the
    current scope OR any ancestor scope.

    PG would reject at runtime, but the validator must still fail closed —
    in warn mode this would otherwise slip through, and we can't trust that
    PG sees the same identifier we do under every config. The synthetic
    3-tuple key uses a sentinel slot so bogus-qualifier entries can never
    collide with a real (table, schema, column) seen key.
    """
    key = ("\x00bogus", col_alias, column_name(column))
    if key in seen:
        return
    seen.add(key)
    violations.append(
        Violation(
            code=ViolationCode.COLUMN_DENIED,
            message=(
                f"column qualifier {_truncate(col_alias)!r} does not "
                "reference any table or CTE in scope."
            ),
            suggestion=(
                "Qualify the column with a real FROM-clause alias "
                "(e.g. `users.id`), or remove the qualifier."
            ),
        )
    )


def _check_column_against_policy(
    column: exp.Column,
    alias_to_table: dict[str, list[tuple[str, str]]],
    cte_names: set[str],
    total_sources: int,
    policy: Policy,
    seen: set[tuple[str, str, str]],
    violations: list[Violation],
    outer_alias_to_table: dict[str, list[tuple[str, str]]] | None = None,
) -> None:
    col_alias = column_alias(column)
    # The column's own schema qualifier (`public.users.email` → "public").
    # Used to disambiguate when an alias maps to multiple candidates.
    col_db = default_fold(column.args.get("db"))
    schema = ""
    if not col_alias:
        # Flatten every candidate across every alias — an unqualified
        # column can resolve to any table in scope.
        real_tables = [c for cands in alias_to_table.values() for c in cands]
        if not real_tables:
            return
        # Unambiguous: exactly one real table AND no CTE/subquery siblings
        # in this scope. Fall through to the standard check below.
        if len(real_tables) == 1 and total_sources <= 1:
            tname, schema = real_tables[0]
        else:
            _emit_ambiguous_deny(column, real_tables, policy, seen, violations)
            return
    else:
        candidates = alias_to_table.get(col_alias)
        if candidates is None:
            # CTE / subquery alias → not a policy table; rules at the
            # inner scope already cover those references.
            if col_alias in cte_names:
                return
            # LATERAL and correlated subqueries can legitimately reference
            # an outer scope's table alias (`EXISTS (SELECT 1 FROM users u
            # WHERE u.id = orders.id)` — `orders` resolves in the outer
            # scope). Consult ancestor scopes' alias maps before declaring
            # the qualifier bogus; if found, fall through and apply this
            # scope's per-table column check against the resolved outer
            # table's policy.
            if outer_alias_to_table is not None:
                outer_candidates = outer_alias_to_table.get(col_alias)
                if outer_candidates is not None:
                    candidates = outer_candidates
                else:
                    _emit_bogus_qualifier(
                        col_alias, column, seen, violations
                    )
                    return
            else:
                _emit_bogus_qualifier(col_alias, column, seen, violations)
                return
        # Pick the candidate matching the column's schema qualifier when
        # one is present. This is the load-bearing disambiguator for
        # `FROM public.users, analytics.users` — the column's `db` field
        # carries the schema and tells us which Table it references.
        if col_db:
            matching = [c for c in candidates if c[1] == col_db]
            if not matching:
                # Schema qualifier doesn't match any in-scope Table — bogus.
                key = (
                    "\x00bogus",
                    f"{col_db}.{col_alias}",
                    column_name(column),
                )
                if key in seen:
                    return
                seen.add(key)
                violations.append(
                    Violation(
                        code=ViolationCode.COLUMN_DENIED,
                        message=(
                            f"column qualifier "
                            f"{_truncate(f'{col_db}.{col_alias}')!r} does "
                            "not reference any table in scope."
                        ),
                        suggestion=(
                            "Qualify the column with a real FROM-clause "
                            "table reference, or remove the qualifier."
                        ),
                    )
                )
                return
            tname, schema = matching[0]
        elif len(candidates) == 1:
            tname, schema = candidates[0]
        else:
            # Same alias maps to multiple Tables in different schemas and
            # the column wasn't schema-qualified. Fall back to the
            # ambiguous-attribution deny-only check across every candidate
            # — checking allow_columns would false-positive when the
            # different policies have different allow lists.
            _emit_ambiguous_deny(column, candidates, policy, seen, violations)
            return

    table_policy = policy.table_by_name(tname, schema)
    if table_policy is None:
        return

    col_folded = column_name(column)
    key = (tname, schema, col_folded)
    if key in seen:
        return

    if _column_denied(col_folded, table_policy):
        seen.add(key)
        display = f"{schema}.{tname}" if schema else tname
        violations.append(
            Violation(
                code=ViolationCode.COLUMN_DENIED,
                message=(
                    f"column {_truncate(column.name)!r} on table "
                    f"{_truncate(display)!r} is not allowed by policy."
                ),
                suggestion=(
                    f"Allowed columns: {sorted(table_policy.allow_columns or ())}"
                    if table_policy.allow_columns
                    else "Remove the column from the SELECT list."
                ),
            )
        )


def _emit_ambiguous_deny(
    column: exp.Column,
    candidates: list[tuple[str, str]],
    policy: Policy,
    seen: set[tuple[str, str, str]],
    violations: list[Violation],
) -> None:
    """Ambiguous attribution. The column could resolve to any source in
    scope. Without schema info we can't tell which source owns it. Fail
    closed ONLY on explicit `deny_columns` of in-scope policy tables —
    checking `allow_columns` here would false-positive any column not
    present on every in-scope table (e.g. `SELECT name FROM users u
    JOIN orders o ...` where `name` is on users only).
    """
    col_folded = column_name(column)
    for candidate_name, candidate_schema in candidates:
        tp = policy.table_by_name(candidate_name, candidate_schema)
        if tp is None:
            continue
        if col_folded in set(tp.deny_columns):
            key = (candidate_name, candidate_schema, col_folded)
            if key in seen:
                continue
            seen.add(key)
            col_short = _truncate(column.name)
            cand_display = (
                f"{candidate_schema}.{candidate_name}"
                if candidate_schema
                else candidate_name
            )
            cand_short = _truncate(cand_display)
            violations.append(
                Violation(
                    code=ViolationCode.COLUMN_DENIED,
                    message=(
                        f"unqualified column {col_short!r} could "
                        f"resolve to {cand_short!r} where it is denied "
                        "by policy."
                    ),
                    suggestion=(
                        f"Qualify the column (e.g. "
                        f"`{cand_short}.{col_short}`) so the policy "
                        "can check it against a specific table."
                    ),
                )
            )


def _check_select_star(expression: exp.Expression) -> list[Violation]:
    """Flag `SELECT *` projections but NOT `count(*)` and friends.

    A Star inside a function call (count(*), array_agg(*), etc.) is a
    syntactic marker for "all rows", not a column projection. Only Stars
    that appear directly under a Select's expressions list are real
    `SELECT *` violations.
    """
    violations: list[Violation] = []
    for node in expression.walk():
        if not isinstance(node, exp.Star):
            continue
        if _star_inside_function(node):
            continue
        violations.append(
            Violation(
                code=ViolationCode.SELECT_STAR,
                message="SELECT * is forbidden; list columns explicitly.",
                suggestion="Enumerate the columns you actually need.",
            )
        )
        return violations  # one per query is enough
    return violations


def _star_inside_function(star: exp.Star) -> bool:
    """True when `*` is a bare wildcard inside a function — `count(*)`.

    Critically NOT true for `alias.*` wildcards. sqlglot wraps `u.*` as
    Column(this=Star, table=Identifier('u')); the Star then has a
    function ancestor (via the wrapping Column), but `u.*` is a real
    projection of every column of the aliased table — not exempt.
    `to_jsonb(u.*)` expands to every column including denied ones and
    must be rejected.

    Also NOT true for `count(DISTINCT *)`: the DISTINCT keyword forces
    sqlglot to row-expand `*` into all columns (including denied ones)
    rather than treat it as the bare "all rows" marker. So `count(DISTINCT *)`
    is treated as a SELECT-star projection and rejected.
    """
    if isinstance(star.parent, exp.Column):
        return False
    # `count(DISTINCT *)` parses as `Count(Distinct([Star]))` — the Distinct
    # wrapper between the Star and the Func is the signal that the * is being
    # row-expanded (every column counts toward distinctness, including denied
    # ones) instead of acting as the bare "all rows" marker. Treat as
    # SELECT_STAR by NOT exempting it.
    parent = star.parent
    while parent is not None:
        if isinstance(parent, exp.Distinct):
            return False
        if isinstance(parent, (exp.Func, exp.Anonymous, exp.Count)):
            return True
        if isinstance(parent, exp.Select):
            return False
        parent = parent.parent
    return False


def _is_limit_all_pseudo(column: exp.Column) -> bool:
    """sqlglot parses `LIMIT ALL` as a Column named 'ALL'. Detect that
    pseudo-column so we don't emit COLUMN_DENIED for it."""
    if column.name.upper() != "ALL":
        return False
    parent = column.parent
    return isinstance(parent, exp.Limit)


def _build_alias_map(
    scope: Scope | DmlScope, cte_names: set[str]
) -> dict[str, list[tuple[str, str]]]:
    """Map folded alias → list of (folded table name, folded schema)
    candidates for every Table in scope.

    A single alias key can carry multiple candidates when same-named
    tables from different schemas appear in the FROM without distinct
    aliases (`FROM public.users, analytics.users` — both Tables have
    alias_or_name='users'). Without the list, the second entry would
    silently overwrite the first; queries against the lost entry's
    columns would be misattributed and a denied column on one schema
    could slip past if the surviving entry allowed it.
    """
    mapping: dict[str, list[tuple[str, str]]] = {}
    for table in scope.tables:
        if table.alias_or_name in cte_names:
            continue
        mapping.setdefault(table_alias(table), []).append(
            (table_name(table), schema_name(table))
        )
    return mapping


def _build_outer_alias_map(
    scope: Scope | DmlScope,
) -> dict[str, list[tuple[str, str]]]:
    """Walk ancestor scopes and aggregate their real-table aliases.

    LATERAL joins and correlated subqueries (EXISTS, scalar subqueries,
    UPDATE/DELETE correlated subqueries) can legitimately reference an
    outer scope's table alias — e.g. `EXISTS (SELECT 1 FROM users u
    WHERE u.id = orders.id)` references the outer `orders` from the inner
    SELECT. Without this lookup, the inner column walk treats `orders.id`
    as a bogus qualifier and falsely emits COLUMN_DENIED, blocking every
    common correlated-subquery pattern.

    Two ancestor sources are consulted:

    1. **sqlglot's scope tree** via ``Scope.parent`` — covers correlated
       and LATERAL subqueries inside a SELECT-rooted query.
    2. **The expression-tree AST** for DML roots — sqlglot's
       ``traverse_scope`` skips Update/Delete/Insert/Merge roots (which
       is why ``core/scope.py`` synthesizes ``DmlScope``), so a correlated
       subquery inside ``UPDATE … WHERE … IN (SELECT … WHERE
       o.col = orders.col)`` won't find the DML target via ``scope.parent``
       alone. We walk the AST upward to pick up any enclosing DML target
       table.

    CTE names are NOT aggregated here — sqlglot already propagates outer
    CTE names through ``scope.sources``, so the inner scope's own
    ``cte_names`` set already covers them.
    """
    merged: dict[str, list[tuple[str, str]]] = {}

    # Source 1: sqlglot scope-tree ancestors (Select/Subquery roots).
    cur = getattr(scope, "parent", None)
    while cur is not None:
        ancestor_cte_names = {
            n for n, src in cur.sources.items() if isinstance(src, Scope)
        }
        for table in cur.tables:
            if table.alias_or_name in ancestor_cte_names:
                continue
            merged.setdefault(table_alias(table), []).append(
                (table_name(table), schema_name(table))
            )
        cur = getattr(cur, "parent", None)

    # Source 2: enclosing DML target table — Update/Delete/Insert/Merge
    # don't appear as Scope ancestors but are still in semantic scope for
    # any inner subquery's correlated references.
    expr = getattr(scope, "expression", None)
    if isinstance(expr, exp.Expression):
        # Walk up the AST. ``Expression.parent`` is typed by sqlglot's
        # internal ``Expr`` alias which mypy treats as distinct from
        # ``exp.Expression``; the isinstance check below keeps the loop
        # type-safe while accommodating the alias.
        node: object = expr.parent
        while isinstance(node, exp.Expression):
            target = _dml_target_table(node)
            if target is not None:
                merged.setdefault(table_alias(target), []).append(
                    (table_name(target), schema_name(target))
                )
            node = node.parent

    return merged


def _dml_target_table(node: exp.Expression) -> exp.Table | None:
    """Return the target Table of a DML node, or None if `node` isn't DML.

    Handles the sqlglot quirk that INSERT targets are wrapped in
    ``exp.Schema(this=Table, expressions=[Identifier, ...])`` when a
    column list is given (``INSERT INTO orders (id, total) ...``), and
    are bare ``exp.Table`` otherwise.
    """
    if isinstance(node, (exp.Update, exp.Delete, exp.Merge)):
        target = node.this
        return target if isinstance(target, exp.Table) else None
    if isinstance(node, exp.Insert):
        target = node.this
        if isinstance(target, exp.Schema):
            inner = target.this
            return inner if isinstance(inner, exp.Table) else None
        return target if isinstance(target, exp.Table) else None
    return None


def _column_denied(col_folded: str, table_policy: TablePolicy) -> bool:
    """`deny_columns` matches case-INsensitively against the SQL column name.

    Unquoted `password_hash` and quoted `"PASSWORD_HASH"` are technically
    different identifiers under PG (quoted preserves case), but the cost of
    a false positive (a legitimate column literally named differently from
    the denied one but case-folding the same) is far lower than the cost of
    a bypass (`SELECT "PASSWORD_HASH"` slipping past `deny_columns:
    ["password_hash"]` when no allow_columns is set).

    `allow_columns` is compared case-sensitively to preserve the documented
    "case-folded matches case-folded; quoted matches quoted" behavior for
    legitimate allowlisting (a quoted "ID" really is a different column
    from id under PG and shouldn't be silently treated as allowed).
    """
    col_lower = col_folded.lower()
    if any(c.lower() == col_lower for c in table_policy.deny_columns):
        return True
    return (
        table_policy.allow_columns is not None
        and col_folded not in set(table_policy.allow_columns)
    )




def _check_denied_identifier_names(
    expression: exp.Expression, policy: Policy
) -> list[Violation]:
    """Structural catchall — default-deny any Identifier whose value matches
    a column name in ANY table's `deny_columns`, no matter where in the
    AST it appears.

    Why this exists: sqlglot wraps most column references in `exp.Column`,
    which the main allowlist walk catches. But not all — `JOIN ... USING
    (col)`, certain procedural-code references, and PG-specific syntax
    represent the column as a bare `exp.Identifier` under a parent we
    don't enumerate. Every audit round has historically found at least
    one new "Identifier-in-position-X" bypass. Rather than adding a
    per-position rule each time, walk every Identifier and check the
    name. False positives (e.g. a *column alias* literally named
    `password_hash`) are conservative and acceptable — an LLM shouldn't
    alias output to a denied column name anyway.

    Does NOT touch `allow_columns` — that's per-table and ambiguous without
    schema info. Only the explicit `deny_columns` list is enforced here.
    """
    denied: set[str] = set()
    for tp in policy.tables:
        denied |= {c.lower() for c in tp.deny_columns}
    if not denied:
        return []

    violations: list[Violation] = []
    seen_names: set[str] = set()

    for ident in expression.find_all(exp.Identifier):
        parent = ident.parent
        # Column.this is checked by the main scope walk (with full
        # alias / per-table policy context). Skipping here avoids two
        # violations for the same node.
        if isinstance(parent, exp.Column) and parent.this is ident:
            continue
        # Table names are checked by the table allowlist; matching a
        # denied column name in a table-name position is too unlikely
        # to be worth a false-positive risk.
        if isinstance(parent, exp.Table):
            continue
        # exp.Schema wraps INSERT target column lists and CREATE TABLE
        # column definitions. INSERT target columns are visited by the
        # main scope walk via DmlScope's synthesized Column nodes; CREATE
        # TABLE is rejected at preflight. Skipping here avoids a duplicate
        # COLUMN_DENIED for the same INSERT target column.
        if isinstance(parent, exp.Schema):
            continue

        # Lowercase the folded identifier so quoted-uppercase variants
        # (`"PASSWORD_HASH"`) match denied entries (which are stored
        # lowercased above). Without this, a single-quoted reference of a
        # different case bypasses the catchall.
        name = default_fold(ident).lower()
        if name not in denied or name in seen_names:
            continue
        seen_names.add(name)
        parent_kind = type(parent).__name__ if parent is not None else "<root>"
        violations.append(
            Violation(
                code=ViolationCode.COLUMN_DENIED,
                message=(
                    f"identifier {_truncate(name)!r} appears in a {parent_kind} position "
                    "and matches a column denied by policy. Denied as a "
                    "precautionary structural rule."
                ),
                suggestion=(
                    "Remove every reference to the denied column name, "
                    "including in JOIN USING, output aliases, and function "
                    "arguments — the LLM should not need to name this column."
                ),
            )
        )

    return violations
