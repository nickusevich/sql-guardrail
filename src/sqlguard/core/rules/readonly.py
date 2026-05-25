from __future__ import annotations

from sqlglot import expressions as exp

from sqlguard.config.schema import Policy
from sqlguard.result import Violation, ViolationCode

_WRITE_TYPES: tuple[type[exp.Expression], ...] = (
    exp.Insert,
    exp.Update,
    exp.Delete,
    exp.Merge,
    exp.Drop,
    exp.Create,
    exp.Alter,
    exp.AlterColumn,
    exp.TruncateTable,
    exp.Grant,
    exp.Revoke,
)

_TYPE_LABELS: dict[type[exp.Expression], str] = {
    exp.Insert: "INSERT",
    exp.Update: "UPDATE",
    exp.Delete: "DELETE",
    exp.Merge: "MERGE",
    exp.Drop: "DROP",
    exp.Create: "CREATE",
    exp.Alter: "ALTER",
    exp.AlterColumn: "ALTER",
    exp.TruncateTable: "TRUNCATE",
    exp.Grant: "GRANT",
    exp.Revoke: "REVOKE",
}


def check_readonly(expression: exp.Expression, policy: Policy) -> list[Violation]:
    """Flag DML/DDL/DCL nodes, row-locking clauses, and SELECT INTO.

    All three are gated on ``policy.read_only`` — locks are write-intent
    operations (acquire row-level write state) and SELECT INTO creates a
    new table (semantically CREATE TABLE AS).
    """
    if not policy.read_only:
        return []
    violations: list[Violation] = []
    violations.extend(_check_writes(expression))
    violations.extend(_check_select_into(expression))
    violations.extend(_check_locks(expression))
    return violations


def _check_select_into(expression: exp.Expression) -> list[Violation]:
    """Detect SELECT ... INTO — a write disguised as a read.

    sqlglot parses `SELECT id INTO new_t FROM t` as exp.Select with an
    `into` arg set. Without this branch, the table allowlist sees only
    the source-table read and the write to `new_t` slips through if
    `new_t` happens to be in the allowlist (or if no allowlist applies).
    `SELECT INTO TEMP foo` is the same attack against a session-private
    schema where no allowlist applies.
    """
    violations: list[Violation] = []
    seen: set[int] = set()
    for select in expression.find_all(exp.Select):
        into = select.args.get("into")
        if into is None or id(select) in seen:
            continue
        seen.add(id(select))
        violations.append(
            Violation(
                code=ViolationCode.WRITE_FORBIDDEN,
                message=(
                    "SELECT ... INTO is forbidden (read-only policy) — "
                    "it creates a new table, semantically a CREATE TABLE AS write."
                ),
                suggestion=(
                    "Rewrite as a plain SELECT, or use CREATE TABLE AS from "
                    "an explicitly-permitted write path."
                ),
            )
        )
    return violations


def _check_writes(expression: exp.Expression) -> list[Violation]:
    violations: list[Violation] = []
    seen: set[int] = set()

    for node in expression.walk():
        if not isinstance(node, _WRITE_TYPES):
            continue
        if _has_write_ancestor(node):
            continue

        label = _TYPE_LABELS[type(node)]

        key = id(node)
        if key in seen:
            continue
        seen.add(key)

        violations.append(
            Violation(
                code=ViolationCode.WRITE_FORBIDDEN,
                message=f"{label} statement is forbidden (read-only policy).",
                suggestion=(
                    "Use SELECT to read data; modifications must go through "
                    "an explicitly-permitted write path."
                ),
            )
        )

    return violations


def _check_locks(expression: exp.Expression) -> list[Violation]:
    """Detect SELECT ... FOR UPDATE / FOR SHARE / FOR NO KEY UPDATE / FOR KEY SHARE."""
    violations: list[Violation] = []
    seen: set[int] = set()

    for node in expression.walk():
        if not isinstance(node, exp.Lock):
            continue
        if id(node) in seen:
            continue
        seen.add(id(node))

        kind = "FOR UPDATE" if node.args.get("update") else "FOR SHARE"
        violations.append(
            Violation(
                code=ViolationCode.LOCK_FORBIDDEN,
                message=f"{kind} clause is forbidden (acquires row locks; not read-only).",
                suggestion=(
                    "Remove the locking clause. Row locks are a write-intent operation "
                    "and can be used to create contention."
                ),
            )
        )

    return violations


def _has_write_ancestor(node: exp.Expression) -> bool:
    parent = node.parent
    while parent is not None:
        if isinstance(parent, _WRITE_TYPES):
            return True
        parent = parent.parent
    return False
