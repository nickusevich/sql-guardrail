"""Scope-iteration helpers that hide a sqlglot quirk: ``traverse_scope``
returns an empty list for DML root statements (Update/Delete/Insert/Merge),
which silently neutralizes every rule that iterates scopes.

The fix is a thin synthetic ``DmlScope`` that exposes the minimum surface
the rule engine reads (``.tables``, ``.columns``, ``.expression``,
``.sources``). ``iter_scopes`` always yields it for DML roots in addition
to any real scopes ``traverse_scope`` finds — so rules see both the DML
target and any inner SELECT subqueries.
"""
from __future__ import annotations

from collections.abc import Iterator

from sqlglot import expressions as exp
from sqlglot.optimizer.scope import Scope, traverse_scope


class DmlScope:
    """Synthetic scope around a DML root statement.

    Surfaces every Table reference in the DML tree (target plus
    USING/FROM joined tables), every real Column reference, plus
    synthetic Column nodes for INSERT target column lists (which sqlglot
    parses as Identifier under Schema.expressions and would otherwise
    never reach the column-allowlist check).
    """

    def __init__(self, expression: exp.Expression) -> None:
        self._expr = expression
        cte_names = {cte.alias_or_name for cte in expression.find_all(exp.CTE)}
        self.tables: list[exp.Table] = [
            t for t in expression.find_all(exp.Table) if t.alias_or_name not in cte_names
        ]
        cols: list[exp.Column] = list(expression.find_all(exp.Column))
        cols.extend(_insert_target_columns(expression))
        self.columns: list[exp.Column] = cols
        # No CTE-as-scope sources for DML root — actual CTE bodies are
        # visited as their own scopes by traverse_scope (which yields a
        # CTE scope per body). The DmlScope only covers the outer DML.
        self.sources: dict[str, object] = {}

    @property
    def expression(self) -> exp.Expression:
        return self._expr


def _insert_target_columns(expression: exp.Expression) -> list[exp.Column]:
    """Wrap INSERT target identifiers in synthetic Column nodes anchored
    to the target table, so the existing alias-resolution path in
    allowlist.py finds them.
    """
    if not isinstance(expression, exp.Insert):
        return []
    target = expression.this
    if not isinstance(target, exp.Schema):
        return []
    target_table = target.this if isinstance(target.this, exp.Table) else None
    if target_table is None:
        return []
    out: list[exp.Column] = []
    for ident in target.expressions:
        if not isinstance(ident, exp.Identifier):
            continue
        col = exp.Column(
            this=exp.Identifier(this=ident.this, quoted=ident.quoted),
            table=exp.Identifier(
                this=target_table.name, quoted=target_table.this.quoted
            ),
        )
        out.append(col)
    return out


def iter_scopes(expression: exp.Expression) -> Iterator[Scope | DmlScope]:
    """Yield sqlglot Scopes plus a synthetic DmlScope for DML roots.

    sqlglot's ``traverse_scope`` returns [] for Update/Delete/Insert/Merge
    roots — and even when a DML contains a SELECT subquery (whose scope
    IS yielded), the outer DML target is never visited. This wrapper
    appends a single DmlScope for the outer DML so the rule engine
    sees the target table and target columns.
    """
    yield from traverse_scope(expression)
    if isinstance(expression, (exp.Update, exp.Delete, exp.Insert, exp.Merge)):
        yield DmlScope(expression)
