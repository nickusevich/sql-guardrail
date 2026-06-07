# Policy reference & checks

Everything a policy can express, and exactly what each check does. For a
fully-annotated starting point see
[`examples/policy.yml`](../examples/policy.yml); for the high-level pitch
see the [README](../README.md).

A policy is a YAML file or a Python dict. Load it once at startup:

```python
from pathlib import Path
from sqlguard import Policy

policy = Policy.from_yaml(Path("policy.yml"))   # raises now if the YAML is wrong
# or: Policy.from_dict({...})
```

---

## Policy fields

### Top-level

| Field | Type | Default | Meaning |
|---|---|---|---|
| `read_only` | bool | `true` | Block writes, locks, `SELECT INTO`, data-modifying CTEs. |
| `tables` | list | `[]` | Per-table scoping. **Without this the table/column allowlist is a no-op** (you'll get a `UserWarning`). |
| `forbid.always_true_predicates` | bool | `true` | Block `WHERE 1=1` and every constant-folded shape. |
| `forbid.select_star` | bool | `true` | Block `SELECT *` / `alias.*` (but not `count(*)`). |
| `forbid.cartesian_join` | bool | `true` | Block `CROSS JOIN` and comma-joins with no `ON`. |
| `forbid.recursive_cte` | bool | `true` | Block `WITH RECURSIVE`. |
| `limits.max_sql_length` | int | `20000` | Char cap, checked before parsing. |
| `limits.max_ast_nodes` | int\|null | `5000` | Parsed-node cap, checked after parsing. |
| `limits.max_limit_value` | int\|null | `10000` | Reject `LIMIT N` over the cap (and non-literal `LIMIT`). |
| `limits.max_offset_value` | int\|null | `100000` | Reject `OFFSET N` over the cap (scan-and-skip DoS). |
| `limits.max_joins` | int\|null | `10` | Cap distinct joins per query. |
| `limits.max_subquery_depth` | int\|null | `8` | Cap nested-SELECT depth (CTEs reset the counter). |
| `allowed_functions` | list\|null | `null` | Opt-in function allowlist. When `null`, function names aren't checked. |

### Per-table (`tables[*]`)

| Field | Type | Default | Meaning |
|---|---|---|---|
| `name` | str | — | Required. |
| `schema` | str\|null | `null` | Optional schema qualifier. Two entries with the same `name` but different `schema` coexist. |
| `allow_columns` | list\|null | `null` | Column allowlist. `null` means any column on this table. |
| `deny_columns` | list | `[]` | Column denylist, matched in **any** AST position. |
| `require_predicate` | obj or list | `[]` | Forces WHERE / INNER-JOIN-ON to AND-include this predicate. |
| `large` | bool | `false` | When true, every query touching this table must have an effective `LIMIT`. |

### `require_predicate`

`{column, op, value}`. `op` is one of `= != < <= > >= IN BETWEEN` (default
`=`). `value` may contain `${var}` placeholders resolved from the
`context=` argument of `verify()`. For `IN`, `value` is a list; for
`BETWEEN`, `value` is `[low, high]`.

```yaml
require_predicate:
  column: account_id
  op: "="
  value: "${tenant_id}"   # filled per request from context={"tenant_id": ...}
```

> **The tenant value must come from the authenticated session**, never from
> the LLM prompt. If the LLM can choose its own tenant id, every tenant rule
> collapses.

---

## What each check does

### Statement shape

- **Statement-kind allowlist.** `SELECT` / `UNION` / `INTERSECT` / `EXCEPT`
  are always allowed. `INSERT` / `UPDATE` / `DELETE` / `MERGE` only when
  `read_only=false`. Everything else (`DROP`, `ALTER`, `CREATE`, `GRANT`,
  `CALL`, `SET`, `VACUUM`, `LISTEN`, `EXPLAIN ANALYZE`, `DO` blocks, vendor
  commands sqlglot can't classify) is rejected. Unknown kinds are denied,
  not allowed.
- **Multi-statement.** `SELECT 1; DROP TABLE x` is always rejected. One
  call, one statement.
- **Data-modifying CTEs.** `WITH x AS (INSERT INTO y ... RETURNING *) SELECT
  * FROM x` looks like a SELECT but writes underneath — rejected when
  `read_only=true`.
- **Writes and locks under `read_only=true`.** `INSERT`, `UPDATE`, `DELETE`,
  `MERGE`, `DROP`, `CREATE`, `ALTER`, `TRUNCATE`, `GRANT`, `REVOKE`,
  `FOR UPDATE`, `FOR SHARE`, and the sneaky `SELECT ... INTO new_table`.

### Always-true expressions ("tautologies")

A filter that's always true (`WHERE 1=1`) lets the model see every row.
One structural rule covers the whole class:

> If a leaf of a row-filtering clause references no column or table, it's a
> constant. Constants get denied.

This covers `1=1`, `TRUE`, `'true'::boolean`, `abs(1)>0`, `EXISTS (SELECT
1)`, any constant-folded shape, plus three column-side patterns:
self-equality (`id = id`), self-membership (`id IN (id, ...)`), and
null-complement (`X IS NULL OR X IS NOT NULL`). It applies to `WHERE`, `JOIN
ON`, `HAVING`, `QUALIFY`, `MERGE ON`, `WHEN MATCHED`, `START WITH`, and
`CONNECT BY`.

It deliberately does **not** catch column-arithmetic tautologies (`id*0=0`,
`id-id=0`). Those mention a column, so the constant-leaf rule skips them.
This is safe by construction: such a predicate can't defeat
`require_predicate` (which must appear as a top-level `AND` conjunct), and on
a table with no `require_predicate` the rows are already unrestricted. Lean
on `require_predicate` + RLS for anything sensitive.

### Tables and columns

- **Per-table allowlist.** Only tables in `tables` can be queried.
  Schema-qualified entries (`public.orders`) work.
- **Per-column allowlist.** Inside an allowed table, only listed columns
  can be used. `null` means any column.
- **Per-column denylist.** `deny_columns` are denied in **any** position:
  SELECT list, WHERE, ORDER BY, GROUP BY, function arg, alias, `JOIN USING`,
  anywhere an identifier appears. Closes `JOIN USING (password_hash)` and
  `SELECT length(password_hash)`.
- **`SELECT *`.** Flagged, including `alias.*` and `to_jsonb(u.*)`.
  `count(*)` is fine — the `*` there is a special form, not a column.

### Tenant isolation: `require_predicate`

The library walks every `WHERE` and every `INNER JOIN ON` for every alias of
the protected table and confirms each one AND-includes the required
predicate. If any alias is missing it, the query is denied.

- Only WHERE and INNER-JOIN-ON count. **OUTER-JOIN-ON does not** — outer
  joins still emit rows when the condition is false, so move the predicate to
  WHERE.
- For `UPDATE`/`DELETE`, the WHERE is checked. For `INSERT ... SELECT`, the
  source SELECT is checked. **Bare `INSERT ... VALUES` and `MERGE` have no
  WHERE on the target row** — enforce those at the DB layer (`CHECK`
  constraints / RLS write policies).
- Value matching is type-tolerant: `account_id = '42'` satisfies `value: 42`
  and vice versa.

Common uses beyond multi-tenancy: soft-delete (`is_deleted = false`),
lifecycle (`status = 'active'`), region pinning, time scoping.

### Function allowlist (opt-in)

Set `allowed_functions: [...]` and every function call must be on the list.
Without it, function names aren't checked — fine for prototyping, not for
production. This is the main defense against `pg_sleep`, `pg_read_file`,
`lo_export`, and vendor helpers you haven't vetted. Include `cast` if you use
`CAST(...)` or `::`, plus every aggregate your workload uses.

### DoS caps

| Field | Default | Catches |
|---|---|---|
| `max_sql_length` | `20000` | Multi-megabyte SQL before parsing. |
| `max_ast_nodes` | `5000` | Expression bombs that parse small but blow up. |
| `max_joins` | `10` | "Join every table" queries. |
| `max_subquery_depth` | `8` | Deeply nested SELECTs (CTEs reset the counter). |
| `max_limit_value` | `10000` | `LIMIT 1000000`. |
| `max_offset_value` | `100000` | `OFFSET 999999999` scan-and-skip DoS. |

Plus `forbid.cartesian_join`, `forbid.recursive_cte`, and `tables[*].large:
true` (forces an effective `LIMIT` on every query touching the table).

### Fail-closed guarantees

- `verify()` **never raises.** Any internal error — including
  `RecursionError` / `MemoryError` on pathological input — becomes a
  `PARSE_ERROR` violation with `allowed=False`.
- If sqlglot can't classify a statement (`exp.Command`), it's denied.
- If parsing returns no expression but no specific error, a synthetic
  `PARSE_ERROR` is added so you never see `allowed=True` for unparseable
  input.

---

## The result object

```python
result.allowed         # bool: should I run this query?
result.violations      # tuple[Violation, ...]
result.statement_kind  # "SELECT" | "UPDATE" | ...
result.has_category(ViolationCategory.DENIED)
```

Each `Violation` has `.code`, `.category`, `.message`, and `.suggestion`
(feed `suggestion` back to the LLM for a self-correction retry loop).

```python
if result.has_category(ViolationCategory.DENIED):
    audit_security_event(...)
elif result.has_category(ViolationCategory.INVALID):
    return "Bad query, please rephrase"
elif result.has_category(ViolationCategory.LIMIT):
    return "Query too expensive, add LIMIT or narrow filters"
```

**Categories:** `DENIED` (forbidden by policy — the fail-closed default),
`INVALID` (structurally wrong: tautology, missing predicate), `LIMIT` (DoS
cap), `PARSE` (couldn't parse), `POLICY` (the policy itself is
misconfigured — surface to the operator).

**Codes:** `WRITE_FORBIDDEN`, `LOCK_FORBIDDEN`, `DATA_MODIFYING_CTE`,
`STATEMENT_FORBIDDEN`, `MULTI_STATEMENT`, `TABLE_DENIED`, `COLUMN_DENIED`,
`SELECT_STAR`, `ALWAYS_TRUE_PREDICATE`, `MISSING_REQUIRED_PREDICATE`,
`FUNCTION_NOT_ALLOWED`, `RECURSIVE_CTE`, `CARTESIAN_JOIN`,
`NATURAL_JOIN_FORBIDDEN`, `LIMIT_REQUIRED`, `LIMIT_EXCEEDED`,
`OFFSET_EXCEEDED`, `MAX_JOINS_EXCEEDED`, `MAX_SUBQUERY_DEPTH`, `PARSE_ERROR`,
`POLICY_ERROR`.

---

## What this does NOT catch

Pair the library with the database layers (see the README's deployment
diagram).

- **Bare `INSERT ... VALUES` / `MERGE` tenant isolation** — no WHERE on the
  target row. Use DB `CHECK` constraints or RLS write policies.
- **Column-arithmetic tautologies** (`id*0=0`) — see above; safe by
  construction, lean on `require_predicate` + RLS.
- **Plan-time cost surprises** — only the database's planner knows. Use
  `statement_timeout`.
- **Vendor catalog tables** (`pg_shadow`, `information_schema`) — not
  special-cased, but rejected anyway because they're not in your `tables`
  allowlist. Pair with a role that can't read system catalogs.
- **Bugs in your auth** — if `context["tenant_id"]` comes from the LLM
  prompt instead of the session, every tenant rule collapses. That's the
  caller's job.

## SQL dialect

Parsing uses sqlglot's neutral parser, and the **identifier folding is
PostgreSQL-style** (lowercase unquoted, preserve quoted) — which also
matches MySQL, SQLite, and DuckDB folding. This library is developed and
tested Postgres-first. Other engines: anything sqlglot can tokenize reaches
the rule pipeline; anything it can't parse fails closed as `PARSE_ERROR`.
Engine-specific syntax (MySQL backtick identifiers, `#` comments) may not
parse. See [`docs/ARCHITECTURE.md`](ARCHITECTURE.md) for why there's no
dialect knob.
