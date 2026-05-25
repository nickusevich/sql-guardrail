from __future__ import annotations

import re
import warnings
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

PredicateOp = Literal["=", "!=", "<", "<=", ">", ">=", "IN", "BETWEEN"]
_PLACEHOLDER_RE = re.compile(r"\$\{([a-zA-Z_][a-zA-Z0-9_]*)\}")


class RequiredPredicate(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    column: str
    op: PredicateOp = "="
    value: Any

    def resolve(self, context: dict[str, Any]) -> RequiredPredicate:
        """Substitute ${var} placeholders in `value` from context."""
        resolved = _substitute(self.value, context)
        if resolved is _MISSING:
            raise KeyError(
                "required-predicate value references unresolved placeholder: "
                f"{self.value!r}"
            )
        return RequiredPredicate(column=self.column, op=self.op, value=resolved)


class TablePolicy(BaseModel):
    # populate_by_name lets dict-form callers use either `schema` (YAML alias)
    # or `schema_name` (python field name). extra="forbid" turns typos
    # (`allow_colums`, `denycolumns`) into ValidationError instead of silent
    # acceptance of an unscoped policy.
    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    name: str
    schema_name: str | None = Field(default=None, alias="schema")
    allow_columns: tuple[str, ...] | None = None
    deny_columns: tuple[str, ...] = ()
    require_predicate: tuple[RequiredPredicate, ...] = ()
    # When True, every query referencing this table must have an effective
    # LIMIT (on this scope or an ancestor). Use for tables that can return
    # millions of rows.
    large: bool = False

    @field_validator("require_predicate", mode="before")
    @classmethod
    def _coerce_predicate(cls, v: Any) -> Any:
        if v is None:
            return ()
        if isinstance(v, dict):
            return (v,)
        return v


class ForbidPolicy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    always_true_predicates: bool = True
    select_star: bool = True
    recursive_cte: bool = True
    cartesian_join: bool = True


class LimitsPolicy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    # Defaults chosen to be safe out-of-the-box. A Policy() with no overrides
    # still imposes meaningful DoS caps. Set to None to disable any of these.
    max_joins: int | None = 10
    max_subquery_depth: int | None = 8
    # Default cap so an unconfigured policy can't be satisfied by
    # `LIMIT 9999999999`. Set to None to disable the cap entirely.
    max_limit_value: int | None = 10_000
    # OFFSET cap — `LIMIT 10 OFFSET 99999999` forces PG to scan-and-skip
    # 100M rows. 100k is enough for any realistic pagination use case.
    max_offset_value: int | None = 100_000
    # Char-length cap evaluated before parse. Validator runtime is roughly
    # quadratic in AST size on adversarial inputs; 20k chars is plenty for
    # LLM-generated SQL and protects against validator self-DoS.
    max_sql_length: int = 20_000
    # Hard cap on parsed-AST node count, evaluated after parse but before
    # rules run. Catches expression-tree-bomb inputs that fit under the
    # character cap but explode in AST node count.
    max_ast_nodes: int | None = 5_000


class Policy(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    read_only: bool = True
    tables: tuple[TablePolicy, ...] = ()
    forbid: ForbidPolicy = Field(default_factory=ForbidPolicy)
    limits: LimitsPolicy = Field(default_factory=LimitsPolicy)

    # Opt-in function allowlist. When set, every function call must be a name
    # in this set; everything else gets FUNCTION_NOT_ALLOWED. When None
    # (default), no function-allowlist check runs. Strongly recommended for
    # production — include at least: cast, count, sum, avg, min, max,
    # coalesce, and any other safe functions your workload uses.
    allowed_functions: tuple[str, ...] | None = None

    @model_validator(mode="after")
    def _warn_on_policy_gaps(self) -> Policy:
        """Surface common policy-hygiene gaps at construction time.

        Two warnings, both bias toward making partial protection visible
        rather than silent:

          - Missing `tables` allowlist — without it the guardrail only
            blocks writes, multi-statements, and tautologies. It does
            NOT prevent reads of any application table.
          - Missing `allowed_functions` — without it any SQL function
            call passes, including DB-side helpers (`pg_sleep`,
            `pg_read_file`, vendor extensions) the integrator never
            vetted. Strongly recommended in production.
        """
        if not self.tables:
            warnings.warn(
                "Policy has no `tables` allowlist: reads of any application "
                "table will be allowed. Set `tables: [...]` to scope which "
                "tables an LLM may query.",
                UserWarning,
                stacklevel=3,
            )
        if self.allowed_functions is None:
            warnings.warn(
                "Policy has no `allowed_functions` set: any SQL function "
                "call is allowed, including DB-side helpers like pg_sleep / "
                "pg_read_file. Set `allowed_functions: [...]` "
                "(e.g. [cast, count, sum, avg, coalesce]) to gate function "
                "calls in production.",
                UserWarning,
                stacklevel=3,
            )
        return self

    @classmethod
    def from_yaml(cls, path: str | Path) -> Policy:
        data = yaml.safe_load(Path(path).read_text())
        return cls.model_validate(data or {})

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Policy:
        return cls.model_validate(data)

    def table_by_name(
        self, name: str, schema: str = ""
    ) -> TablePolicy | None:
        """Find the most specific table policy for `name` (and optional `schema`).

        Lookup priority:

          1. Schema-qualified query (`SELECT FROM public.orders`) prefers a
             policy entry with the matching `schema:`. If no schema-specific
             entry exists, falls back to the unqualified entry (`schema_name
             is None`) as a default that applies to any schema.
          2. Schema-unqualified query (`SELECT FROM orders`) matches the
             first policy entry with this `name:`, regardless of `schema:`
             — `schema:` is a filter for qualified queries, not a barrier
             for unqualified ones (the DB's search_path picks the schema).

        Two policies for the same name with different schemas (`public.orders`
        and `analytics.orders`) coexist correctly. Without a query qualifier,
        the first one wins — write the policy schema-qualified if you need
        to scope an unqualified query to a specific schema.

        Caller must apply PG identifier folding first. YAML names are
        treated as already-folded — `name: orders` matches unquoted
        `FROM Orders` (PG folds it to `orders`); `name: Orders` matches
        only quoted `FROM "Orders"`.
        """
        if schema:
            for t in self.tables:
                if t.name == name and t.schema_name == schema:
                    return t
            for t in self.tables:
                if t.name == name and t.schema_name is None:
                    return t
            return None
        for t in self.tables:
            if t.name == name:
                return t
        return None


_MISSING = object()


def _substitute(value: Any, context: dict[str, Any]) -> Any:
    """Resolve ${var} placeholders. Returns _MISSING if any placeholder
    is unresolved (works for both full-string and partial substitution
    so the caller has one error path)."""
    if isinstance(value, str):
        m = _PLACEHOLDER_RE.fullmatch(value)
        if m:
            key = m.group(1)
            if key not in context:
                return _MISSING
            return context[key]
        # partial substitution inside larger string — same sentinel contract
        missing: list[str] = []

        def _sub(match: re.Match[str]) -> str:
            key = match.group(1)
            if key not in context:
                missing.append(key)
                return match.group(0)  # leave as-is; caller sees _MISSING
            return str(context[key])

        substituted = _PLACEHOLDER_RE.sub(_sub, value)
        if missing:
            return _MISSING
        return substituted
    if isinstance(value, list):
        out = []
        for v in value:
            sub = _substitute(v, context)
            if sub is _MISSING:
                return _MISSING
            out.append(sub)
        return out
    return value
