"""Generic opt-in function allowlist (structural defense #4 in the README).

When ``policy.allowed_functions`` is set, every function call must be on the
list — anything else gets FUNCTION_NOT_ALLOWED. This is the "we forgot to add
X to the denylist" defense: instead of growing a denylist over time,
default-deny any function the policy hasn't explicitly approved.

Walks every ``exp.Func`` (the base class), which covers both:

  - ``exp.Anonymous``: function names sqlglot didn't recognize as a built-in
    (``pg_sleep``, ``pg_read_file``, user-defined functions, vendor calls).
  - Concrete ``exp.Func`` subclasses: ~150 built-ins sqlglot models as
    typed nodes — ``exp.Lower``, ``exp.Cast``, ``exp.CurrentUser``,
    ``exp.Coalesce``, ``exp.Extract``, every aggregate and window function.

Without walking the concrete subclasses too, an allowlist of ``["count"]``
silently let through ``lower``, ``upper``, ``abs``, ``length``, ``cast``,
``::cast``, ``current_user``, ``current_database``, ``coalesce``,
``substring``, ``array_agg``, ``replace``, ``trim``, ``concat``, every
aggregate, every window function — which is the entire bypass class the
allowlist exists to close.

The exception is a small set of **operator keywords** (``AND``, ``OR``,
``CASE``, ``EXISTS``, ``IF``/``IIF``, ``XOR``) that sqlglot models as
``exp.Func`` subclasses for AST uniformity but are SQL syntax, not function
calls. Users would never list them in ``allowed_functions``; checking them
would falsely reject every multi-clause WHERE / CASE expression / EXISTS
subquery under a sane policy. They are skipped — see ``_OPERATOR_KEYWORDS``.
"""
from __future__ import annotations

from typing import cast

from sqlglot import expressions as exp

from sqlguard.config.schema import Policy
from sqlguard.result import Violation, ViolationCode, _truncate

# Known divergences between sqlglot's Func class name and the SQL the user
# actually writes. sqlglot normalizes some calls into a canonical class:
# ``date_trunc(...)`` → ``exp.TimestampTrunc``, ``to_char(...)`` →
# ``exp.TimeToStr``, etc. Without these aliases, an allowlist containing
# ``"date_trunc"`` would never match a ``date_trunc(...)`` call.
#
# Add new entries when ``sql_names()`` for a class doesn't match what a
# user reading their SQL would naturally type into ``allowed_functions``.
_CANONICAL_ALIASES: dict[type[exp.Expression], frozenset[str]] = {
    exp.TimestampTrunc: frozenset({"date_trunc", "datetime_trunc", "time_trunc"}),
    exp.TimeToStr: frozenset({"to_char"}),
    exp.StrToTime: frozenset({"to_timestamp", "to_date"}),
    exp.JSONArrayAgg: frozenset({"json_agg", "jsonb_agg", "json_array_agg"}),
    exp.JSONObjectAgg: frozenset({"json_object_agg", "jsonb_object_agg"}),
    exp.GroupConcat: frozenset({"string_agg", "listagg"}),
}

# SQL operator/control-flow keywords that sqlglot models as ``exp.Func``
# subclasses for AST-shape consistency. They are NOT function calls in the
# sense ``allowed_functions`` is meant to gate — a user listing safe
# functions would never write ``and``/``or``/``case`` there, and treating
# them as functions falsely rejects every non-trivial WHERE clause, CASE
# expression, and EXISTS subquery. Walked-but-skipped here.
#
# Verified via ``cls.sql_names()`` against the SQL-keyword set; the list
# below is the full intersection at sqlglot ~26.x. If a future sqlglot
# release adds another keyword-form Func subclass (e.g. ``NULLIF`` is
# already exp.Nullif → ``NULLIF`` is a function name users CAN allowlist,
# so it's correctly NOT exempted), review the diff and update this tuple.
_OPERATOR_KEYWORDS: tuple[type[exp.Expression], ...] = (
    exp.And,
    exp.Or,
    exp.Xor,
    exp.Case,
    exp.If,      # also covers IIF (SQL Server) — same class
    exp.Exists,
)


def _function_names(node: exp.Func) -> set[str]:
    """Return the lowercased set of names this Func node could match against
    ``policy.allowed_functions``. The match passes if ANY of these names is
    on the allowlist — so users can put either the canonical sqlglot name
    or any well-known alias in policy.
    """
    if isinstance(node, exp.Anonymous):
        raw = node.this
        if isinstance(raw, str):
            return {raw.lower()} if raw else set()
        # Defensive: rare cases where Anonymous wraps a non-string expression.
        name = getattr(node, "name", "") or ""
        return {str(name).lower()} if name else set()

    # Concrete Func subclass. ``sql_names()`` returns the SQL alias list
    # sqlglot's parser recognizes for this class. Add canonical aliases
    # for the handful of classes where sqlglot's name diverges from the
    # SQL the user wrote.
    try:
        names = {n.lower() for n in type(node).sql_names()}
    except NotImplementedError:
        # exp.Func itself raises; concrete subclasses always implement.
        names = set()
    # `type(node)` for an exp.Func subclass narrows to type[Func], which
    # mypy then rejects against the dict's invariant type[Expression] key.
    # The runtime value IS a type[Expression] (Func is a subclass) — the
    # cast just tells the type system what we already know.
    names.update(_CANONICAL_ALIASES.get(cast("type[exp.Expression]", type(node)), ()))
    return names


def check_function_allow(
    expression: exp.Expression,
    policy: Policy,
) -> list[Violation]:
    """Walk every ``exp.Func`` and reject names not in the allowlist.

    No-op when ``policy.allowed_functions`` is None (the default). When
    set, every function call must be in the allowlist (case-insensitive).
    """
    if policy.allowed_functions is None:
        return []

    allow_set = frozenset(f.lower() for f in policy.allowed_functions)
    violations: list[Violation] = []
    seen: set[str] = set()

    for node in expression.walk():
        if not isinstance(node, exp.Func):
            continue
        # SQL keyword/operator nodes (AND, OR, CASE, EXISTS, IF, XOR) inherit
        # from exp.Func for AST uniformity but are not function calls users
        # would gate via allowed_functions. See _OPERATOR_KEYWORDS docstring.
        if isinstance(node, _OPERATOR_KEYWORDS):
            continue
        names = _function_names(node)
        if not names:
            continue
        # Pass if any of the recognized names for this Func is allowlisted.
        if names & allow_set:
            continue
        # Pick a stable representative name for the violation message and
        # the dedupe key. ``sorted`` gives a deterministic choice across
        # runs even when a class has multiple aliases.
        primary = sorted(names)[0]
        if primary in seen:
            continue
        seen.add(primary)
        violations.append(
            Violation(
                code=ViolationCode.FUNCTION_NOT_ALLOWED,
                message=(
                    f"function {_truncate(primary)!r} is not in "
                    "policy.allowed_functions."
                ),
                suggestion=(
                    "Add it to the allowlist if it's safe for this "
                    "policy, or remove the call from the SQL."
                ),
            )
        )

    return violations
