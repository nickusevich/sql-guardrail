"""Identifier case folding — currently PG-style by default (lowercase
unquoted, preserve quoted), which is also correct for MySQL/SQLite/DuckDB
and matches every existing test fixture. A future Snowflake / BigQuery
plugin would override via :meth:`DialectPlugin.fold_identifier`.

Most callers don't fold directly — they go through one of the helper
accessors (:func:`table_name`, :func:`column_name`, ...) which fold the
relevant Identifier subtree.
"""
from __future__ import annotations

from sqlglot import expressions as exp


def default_fold(node: object) -> str:
    """Return the case-folded canonical form of an identifier.

    Handles Identifier nodes (using their .quoted flag), bare strings
    (treated as unquoted → lowercased), and Column/Table nodes (recursing
    into .this).
    """
    if node is None:
        return ""
    if isinstance(node, exp.Identifier):
        return str(node.this) if node.quoted else str(node.this).lower()
    if isinstance(node, str):
        return node.lower()
    inner = getattr(node, "this", None)
    if isinstance(inner, exp.Identifier):
        return default_fold(inner)
    if isinstance(inner, str):
        return inner.lower()
    return str(node).lower()


def table_name(table: exp.Table) -> str:
    """Fold the unqualified table name."""
    return default_fold(table.this) if table.this is not None else ""


def schema_name(table: exp.Table) -> str:
    """Fold the schema qualifier ('' if the table reference is unqualified)."""
    return default_fold(table.args.get("db"))


def column_name(column: exp.Column) -> str:
    """Fold the column name."""
    return default_fold(column.this) if column.this is not None else ""


def column_alias(column: exp.Column) -> str:
    """Fold the column's table-alias qualifier ('' if unqualified)."""
    return default_fold(column.args.get("table"))


def table_alias(table: exp.Table) -> str:
    """Fold a Table's alias (or its name if no alias).

    Mirrors sqlglot's `alias_or_name` but with case folding.
    """
    alias = table.args.get("alias")
    if isinstance(alias, exp.TableAlias):
        return default_fold(alias.this)
    if isinstance(alias, exp.Identifier):
        return default_fold(alias)
    return table_name(table)
