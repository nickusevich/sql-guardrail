# sql-guardrail

[![CI](https://github.com/nickusevich/sql-guardrail/actions/workflows/ci.yml/badge.svg)](https://github.com/nickusevich/sql-guardrail/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/sql-guardrail.svg)](https://pypi.org/project/sql-guardrail/)
[![Python versions](https://img.shields.io/pypi/pyversions/sql-guardrail.svg)](https://pypi.org/project/sql-guardrail/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**A safety check for SQL that an LLM wrote.**

If your app lets a language model write SQL queries, this library reads
each query first and decides if it's safe to run. If something looks
wrong (a write when only reads are allowed, a `WHERE 1=1`, a missing
tenant filter, a banned column), it blocks the query and tells you why.

This is one guardrail, probably not the only one you need. See
[Where this library fits](#where-this-library-fits) below. The database
itself should still have its own protections.

## Why this exists

SQL injection used to be a solved problem. You wrote the SQL once with
placeholders, then passed the user input as values. The input could
never change the shape of the query.

Text-to-SQL breaks that model. The LLM writes the whole query as text
every time, so there is no "fixed SQL" and no separate "user value" to
keep apart. Prepared statements and ORM escaping can't help here,
because they need something fixed to protect.

You have three options:

1. **Don't let the LLM write SQL.** Give it a small set of safe
   functions and have it call those. Safe, but you lose the flexibility
   that made text-to-SQL useful in the first place.
2. **Trust the LLM and the database.** Make the database user
   read-only, turn on row-level security, and hope. The database will
   catch permission errors, but it won't tell you the LLM wrote
   `WHERE 1=1` or asked for `password_hash`. Silent failures hurt.
3. **Check the SQL against rules before running it.** That's what this
   library does. Use it together with option 2 for defense in depth.

`sql-guardrail` is the fast first check that catches obvious problems
before the query reaches the database.

## What it does

You write a policy (a YAML file or a Python dict) that lists which
tables and columns the LLM can touch, the rules every query must
follow, and the limits you want enforced. Then for each query you call
`verify(sql, policy, context=...)`. It parses the SQL, runs the checks,
and returns a result with `allowed=True` or `allowed=False` plus a list
of reasons. It never raises. It doesn't talk to your database. It
doesn't change your SQL. If it says yes, you run the exact string you
gave it.

## Where this library fits

Think of safety as layers. Each layer catches different problems, so
you want as many as you can reasonably set up. No single layer is
enough on its own.

```
┌──────────────────────────────────────────┐
│  1. Prompt design + tool wrappers        │  Shape what the LLM tries.
└──────────────────────────────────────────┘
                  │
┌──────────────────────────────────────────┐
│  2. sql-guardrail.verify()   ← THIS LIB  │  Check the SQL against a policy.
└──────────────────────────────────────────┘
                  │   (only if allowed)
┌──────────────────────────────────────────┐
│  3. Least-privileged database user       │  Read-only, no catalog access.
└──────────────────────────────────────────┘
                  │
┌──────────────────────────────────────────┐
│  4. Row-level security (RLS)             │  DB rule pinned to the user.
└──────────────────────────────────────────┘
                  │
┌──────────────────────────────────────────┐
│  5. Statement timeout                    │  Slow queries get killed.
└──────────────────────────────────────────┘
                  ▼
              Database
```

Layer 2 (this library) is fast. It runs inside your app, no network
calls. It blocks obviously bad queries and gives you a clear reason
you can show in logs or a 403 response.

Layers 3 to 5 are the hard outer wall. Even if a query slips past this
library, a read-only user can't write, RLS hides other tenants' rows,
and the timeout kills runaway queries.

If you only have this library, you've improved things, but you're not
safe. Set up the database layers too. Every major database has a way
to do read-only roles, row-level access, and per-statement timeouts.
Look them up for your engine and wire them in.

## Install

```bash
uv add sql-guardrail
```

Or with any other Python package manager (`pip install sql-guardrail`,
`poetry add sql-guardrail`, `pdm add sql-guardrail`).

Requires Python 3.10 or newer. Runtime dependencies: `sqlglot` (the
SQL parser), `pydantic` (policy validation), `PyYAML`, `click` (for
the CLI).

## A short example

A small policy for a multi-tenant `orders` table:

```yaml
# policy.yml
read_only: true                   # only reads, no writes

tables:
  - name: orders
    allow_columns: [id, product_name, account_id, total]
    require_predicate:            # every query must filter by tenant
      column: account_id
      op: "="
      value: "${tenant_id}"       # filled in per request from `context=`

forbid:
  select_star: true               # no `SELECT *`
  always_true_predicates: true    # no `WHERE 1=1`

limits:
  max_limit_value: 1000           # no `LIMIT 1000000`
```

Using it in Python:

```python
from pathlib import Path
from sqlguard import Policy, verify

# Load the policy once at startup. If the YAML is broken, this raises
# now, which is a boot-time config bug, not a per-request failure.
POLICY = Policy.from_yaml(Path("policy.yml"))

# For each LLM-generated SQL string:
result = verify(sql, POLICY, context={"tenant_id": user.tenant_id})

if not result.allowed:
    raise PermissionError([v.message for v in result.violations])

conn.execute(sql)
```

`context` carries per-request values that fill in any `${...}`
placeholders in the policy. **The `tenant_id` must come from the
authenticated session, never from the LLM prompt.** If the LLM can
choose its own tenant id, every tenant rule collapses.

See [`examples/backend_integration.py`](examples/backend_integration.py)
for a full FastAPI-style example with request handling.

## How it works, step by step

When you call `verify(sql, policy, context=...)`, the SQL runs through
this pipeline. Each step can stop the pipeline by returning a violation.

```
   SQL string + policy + context
              │
              ▼
   1. Length check         Is the SQL too long? (default cap: 20,000 chars)
              │             Stops oversized inputs before parsing.
              ▼
   2. Parse (sqlglot)      Can sqlglot understand this SQL? If not,
              │             reject with PARSE_ERROR.
              │             Also: is this multiple statements joined by `;`?
              │             Reject that too. Only one statement per call.
              ▼
   3. Statement kind       Is this a SELECT (or UNION / INTERSECT /
              │             EXCEPT)? OK. INSERT / UPDATE / DELETE /
              │             MERGE? Only if `read_only=false`. Anything
              │             sqlglot can't classify (vendor extensions,
              │             stored-procedure calls) gets rejected.
              ▼
   4. Tree-size check      Does the parsed query have too many nodes?
              │             (default: 5,000). Stops "expression bomb"
              │             inputs that explode after parsing.
              ▼
   5. Rules (in order)     Each rule is a pure function. It looks at
              │             the parsed query and returns a list of
              │             violations.
              │
              │   - readonly:   writes, row locks (FOR UPDATE),
              │                 SELECT INTO, DROP, ALTER, ...
              │   - allowlist:  table / column allowlists, SELECT *,
              │                 banned-column-name catchall
              │   - predicates: `WHERE 1=1` and friends, missing
              │                 `require_predicate`
              │   - limits:     too many joins, too deep, LIMIT too
              │                 large, OFFSET too large, cartesian
              │                 joins, recursive CTEs
              │   - functions:  if `allowed_functions` is set, every
              │                 function call must be on the list
              ▼
       VerificationResult(allowed, violations, statement_kind)
```

**`verify()` never raises.** Any internal error, including
`RecursionError` on deeply nested SQL or `MemoryError` on huge inputs,
gets caught and turned into a `PARSE_ERROR` violation with
`allowed=False`. You can always trust `result.allowed` to be a boolean.

A file-by-file walkthrough lives in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## What gets checked

### Statement shape

- **Statement kind allowlist.** `SELECT`, `UNION`, `INTERSECT`,
  `EXCEPT` are always allowed. `INSERT`, `UPDATE`, `DELETE`, `MERGE`
  are allowed only when `read_only=false`. Anything else (`DROP`,
  `ALTER`, `CREATE`, `GRANT`, `CALL`, `SET`, `VACUUM`, `LISTEN`,
  `EXPLAIN ANALYZE`, `DO` blocks, vendor commands sqlglot can't
  classify) gets rejected by default. The rule is: unknown statement
  kinds get denied, not allowed.

- **Multi-statement.** `SELECT 1; DROP TABLE x` is always rejected.
  One call, one statement.

- **Data-modifying CTEs.** A query like
  `WITH x AS (INSERT INTO y VALUES (1) RETURNING *) SELECT * FROM x`
  looks like a SELECT on the outside but writes underneath. These get
  rejected when `read_only=true`.

- **Writes and locks under `read_only=true`.** Includes `INSERT`,
  `UPDATE`, `DELETE`, `MERGE`, `DROP`, `CREATE`, `ALTER`, `TRUNCATE`,
  `GRANT`, `REVOKE`, `FOR UPDATE`, `FOR SHARE`, and the sneaky
  `SELECT ... INTO new_table`.

### Always-true expressions ("tautologies")

A common LLM mistake (and a common attacker trick) is a filter that's
always true. `WHERE 1=1` lets the LLM see every row. The library
catches every shape of this with one simple rule:

> If a leaf of the WHERE clause doesn't mention any column or table,
> it's a constant. Constants get denied.

This one rule covers `1=1`, `TRUE`, `'true'::boolean`, `abs(1)>0`,
`EXISTS (SELECT 1)`, any constant-folded shape, plus three column-side
patterns: self-equality (`id = id`), self-membership
(`id IN (id, ...)`), and null-complement
(`X IS NULL OR X IS NOT NULL`).

It applies to `WHERE`, `JOIN ON`, `HAVING`, `QUALIFY`, `MERGE ON`,
`WHEN MATCHED`, `START WITH`, and `CONNECT BY`.

### Tables and columns

- **Per-table allowlist.** Only tables you list in `policy.tables` can
  be queried. Schema-qualified entries (`public.orders`) work.

- **Per-column allowlist.** Inside an allowed table, only listed
  columns can be used. `null` means any column.

- **Per-column denylist.** Columns in `deny_columns` are denied **in
  any position**: SELECT list, WHERE, ORDER BY, GROUP BY, function
  argument, alias, anywhere an identifier appears. This closes tricks
  like `JOIN USING (password_hash)` and `SELECT length(password_hash)`.

- **`SELECT *`.** Flagged, including `alias.*` and `to_jsonb(u.*)`.
  `count(*)` is fine because the `*` there is a special form, not a
  column reference.

### Tenant isolation: `require_predicate`

This rule enforces "every query must filter by tenant" (or any other
column-based filter you care about).

```yaml
tables:
  - name: orders
    require_predicate:
      column: account_id
      op: "="
      value: "${tenant_id}"
```

The library walks every `WHERE` and every `INNER JOIN ON` for every
alias of `orders` and confirms each one includes
`account_id = <tenant_id>` joined with AND. If any alias is missing
the predicate, the query is denied.

A few things to know:

- It only checks WHERE and INNER-JOIN-ON. **OUTER-JOIN-ON does not
  count.** Outer joins still produce rows when the join condition is
  false, so adding the predicate there isn't enough. Move it to WHERE.
- For `UPDATE` and `DELETE`, the WHERE is checked. For
  `INSERT ... SELECT`, the source SELECT is checked. **Bare
  `INSERT ... VALUES` and `MERGE` have no WHERE on the target row**,
  so this rule can't apply. Enforce isolation for those at the
  database layer (`CHECK` constraints or RLS write-side policies).
- Value matching is type-tolerant: `account_id = '42'` (string literal
  in the SQL) satisfies `value: 42` (Python int) and vice versa.

Common uses beyond multi-tenancy: soft-delete filters
(`is_deleted = false`), lifecycle (`status = 'active'`), region
pinning, time scoping. Anything you want every query to include.

### Function allowlist (opt-in)

Set `policy.allowed_functions: [...]` and every function call in the
SQL must be on that list. Without this opt-in, function names aren't
checked. That's fine for prototyping, but you almost certainly want it
in production.

```yaml
allowed_functions:
  - cast       # required if you ever use `CAST(x AS y)` or `x::y`
  - count
  - sum
  - avg
  - coalesce
  - lower
  - upper
```

This is the main defense against unknown or dangerous function names
(`pg_sleep`, `pg_read_file`, `lo_export`, vendor-specific helpers you
haven't vetted).

### DoS caps

LLMs sometimes write expensive queries. Defaults are conservative.
You can override any of these in `limits:`.

| Field | Default | Catches |
|---|---|---|
| `max_sql_length` | `20000` | Multi-megabyte SQL strings before parsing. |
| `max_ast_nodes` | `5000` | Expression bombs that parse small but blow up. |
| `max_joins` | `10` | "Join every table" queries. |
| `max_subquery_depth` | `8` | Deeply nested SELECTs. (CTEs reset the counter.) |
| `max_limit_value` | `10000` | `LIMIT 1000000`. |
| `max_offset_value` | `100000` | `OFFSET 999999999` scan-and-skip DoS. |

Plus two structural denies:

- `forbid.cartesian_join: true` blocks `CROSS JOIN` and comma-joins
  without an `ON` clause.
- `forbid.recursive_cte: true` blocks `WITH RECURSIVE` (which can run
  forever).

And the `tables[*].large: true` flag forces every query touching that
table to have an effective `LIMIT`.

### Fail-closed guarantees

- `verify()` **never raises.** Any unexpected internal error becomes
  a `PARSE_ERROR` violation with `allowed=False`.
- If sqlglot can't classify a statement (`exp.Command`), it gets
  denied, not allowed.
- If parsing returns no expression but no specific error, a synthetic
  `PARSE_ERROR` gets added so you never see `allowed=True` for
  unparseable input.

## What it does NOT catch

These are the gaps. Pair this library with the database layers above.

- **Bare `INSERT ... VALUES` and `MERGE` tenant isolation.** Neither
  has a WHERE clause on the target row, so the WHERE-shaped
  `require_predicate` rule can't apply. Use DB-layer `CHECK`
  constraints or row-level security write policies.

- **Column-aware tautologies.** `id * 0 = 0`, `id - id = 0`,
  `coalesce(id, 1) IS NOT NULL`. These mention a column, so the
  "constant leaf" rule correctly skips them. Catching them would need
  symbolic math evaluation and would risk false positives on real
  queries. (Note: `id = id`, `id IN (id, ...)`, and
  `X IS NULL OR X IS NOT NULL` ARE caught. Those are structural, not
  arithmetic.) For sensitive data, lean on `require_predicate` and RLS.

- **Plan-time cost surprises.** A join the database's planner thinks
  is cheap but runs expensively. The validator can't guess this; only
  the database knows. Use `statement_timeout`.

- **Vendor catalog tables.** `pg_shadow`, `information_schema`,
  `sys.master_files`, `mysql.user`. The library has no built-in
  knowledge of them, but they get rejected anyway because they're not
  in your `tables` allowlist. Pair with a database role that can't
  read system catalogs.

- **Bugs in your authentication.** If `context["tenant_id"]` ends up
  filled from the LLM prompt instead of the authenticated session,
  every tenant rule collapses. That's the caller's job, not the
  library's. The library has no way to know where you got the value.

- **Things sqlglot can't parse.** Modern sqlglot is broad, but
  bleeding-edge vendor syntax may not parse. In that case the input
  fails closed as `PARSE_ERROR`, which is better than letting it
  through.

## Best practices

1. **Tenant context comes from the authenticated session.** Never
   from the LLM prompt, never from a request header the LLM can
   influence. If the LLM controls the value, every `require_predicate`
   protection collapses.
2. **Set `allowed_functions: [...]` for production.** Without it,
   any function name passes. Include `cast`, `count`, and every
   aggregate your workload uses.
3. **Always include `tables: [...]` in the policy.** Without it the
   per-table allowlist is a no-op (and you'll see a `UserWarning`
   when you construct `Policy()`).
4. **Re-run `verify()` if you change the SQL after validation.** If
   you strip comments or normalize whitespace before execution,
   validate the final string, not the original.
5. **Set up database-layer defenses too.** Least-privileged
   credentials, row-level security, and query timeouts at the
   database. This library is the first check; the database is the
   wall.

## What the test suite covers

The library ships with **519 tests** and **92% line coverage**. Tests
are organized by attack class, not by date, so when you add a new
bypass test you put it next to the others it belongs with.

```
tests/
├── test_security.py        # Security regression, by attack class
├── test_corpus.py          # End-to-end: every .sql file in
│                           #   tests/malicious/ must be denied,
│                           #   every .sql in tests/benign/ must be allowed.
├── malicious/              # 47 hand-curated attack SQL files
├── benign/                 # 10 legitimate SQL files (regression
│                           #   guard against false positives)
└── unit/                   # Per-rule unit tests for development feedback
```

### Attack classes in `test_security.py`

Each class below is one category of attacks the library is designed
to catch. The class names map 1:1 to sections of the file, so it's
easy to see what's covered.

| Class | What it tests |
|---|---|
| `TestRobustness` | Adversarial inputs: huge SQL, deep nesting, `RecursionError` / `MemoryError` paths. Must not crash. |
| `TestStatementKinds` | Only SELECT-shaped (and DML when allowed) get through. DDL, DCL, vendor extensions, unknown statements all denied. |
| `TestCategoricalBans` | Writes under `read_only=true`, row locks, SELECT INTO. |
| `TestFunctionAllowlist` | When `allowed_functions` is set, unknown function names are denied. Including `cast` / `::cast`. |
| `TestMultiStatementEnforcement` | `SELECT 1; DROP TABLE x` and friends. |
| `TestTautologies` | Every shape of always-true expression. The catchall test is parametrized over dozens of constants and constant-folded forms. |
| `TestTenantIsolation` | `require_predicate` on aliases, INNER vs OUTER joins, UPDATE/DELETE WHEREs, `INSERT ... SELECT` source scopes, `${var}` substitution. |
| `TestIdentifiers` | Denied column names blocked in any AST position: JOIN USING, output aliases, function args, quoted vs unquoted. |
| `TestDosCaps` | All the `limits.*` knobs: joins, depth, LIMIT, OFFSET (including on `UNION`/`INTERSECT`/`EXCEPT`), char and node caps. |
| `TestPolicyHygiene` | Boot-time policy validation: bad YAML, unresolved `${var}`, conflicting fields. |
| `TestPublicApi` | The public surface (`verify`, `Policy`, `VerificationResult`, `Violation`) behaves as documented. |
| `TestOuterScopeAliasResolution` | Correlated subqueries: aliases bound in the outer query resolve correctly inside subqueries. |
| `TestNaturalJoin` | `NATURAL JOIN` (which implicitly matches column names and bypasses the column allowlist) gets denied. |

### The corpus tests

`tests/test_corpus.py` exists to catch the worst-case failure mode:
a regression that makes a real attack file pass. It loads every
`.sql` file in `tests/malicious/` and checks that `verify()` denies
it. It also loads every `tests/benign/` file and checks they're
allowed, so the rules can't drift into rejecting real queries.

The 47 malicious files cover, among others:

```
alter_system.sql            DDL on system settings
call_procedure.sql          CALL on stored procedures
copy_from_program.sql       Postgres COPY ... PROGRAM (RCE)
create_policy_disable_rls.sql   DDL that disables row-level security
data_modifying_cte.sql      Hidden writes inside a CTE
do_block.sql                Postgres DO $$ ... $$ block
explain_analyze.sql         EXPLAIN ANALYZE that actually executes
for_update.sql              Row lock disguised as SELECT
having_password_exfil.sql   Pulling a denied column via HAVING
listen_notify.sql           LISTEN / NOTIFY abuse
natural_join.sql            NATURAL JOIN that smuggles columns
pg_hba_file_rules.sql       Reading pg_hba.conf via system function
pg_sleep_blind.sql          Blind timing channel via pg_sleep
offset_setop_bypass.sql     OFFSET on UNION (a real fixed bug)
quoted_different_table.sql  "OrDeRs" with quoting tricks
recursive_cte_dos.sql       WITH RECURSIVE blowup
set_search_path.sql         Changing schema resolution under our feet
sibling_subquery_limit_bypass.sql   LIMIT on inner query, not outer
tautology_arithmetic.sql    abs(1) > 0 and friends
tautology_cast_bool.sql     'true'::boolean
union_pg_shadow.sql         UNION to pg_shadow via numeric-only columns
write_disguised_as_select.sql   INSERT styled to look like SELECT
wrong_tenant.sql            Wrong tenant id supplied
... (and ~25 more)
```

Each one is a one-file proof that a specific attack pattern is
denied. When a bypass shows up in the future, the fix lands together
with a new file here that locks it in.

### What CI runs

`.github/workflows/ci.yml` runs the full suite on **Python 3.10,
3.11, 3.12, 3.13** across **Ubuntu and macOS**. The matrix also runs
`ruff check`, `mypy --strict`, and `pytest --cov`. Every push and
every PR has to pass all of it before merge.

## CLI

The package installs an `sqlguard` console script for validating SQL
files or stdin from a shell or CI pipeline:

```bash
# From a file
sqlguard verify query.sql --policy policy.yml --context '{"tenant_id": 42}'

# From stdin (pipe LLM output through validation)
echo 'SELECT id FROM orders WHERE 1=1' \
  | sqlguard verify --policy policy.yml --stdin

# JSON output for scripting / log ingestion
sqlguard verify query.sql --policy policy.yml --format json
```

Exit codes:

| Code | Meaning |
|---|---|
| `0` | Allowed |
| `1` | Denied (one or more violations) |
| `2` | Parse error |
| `3` | Usage error (bad arguments or invalid context JSON) |

## REST API and Docker image

If your app isn't in Python, run sql-guardrail as a sidecar. The HTTP
server is a thin wrapper around `verify()` — same rules, same response
shape as the CLI's JSON output. Install with the `[server]` extra or
use the published Docker image.

### Run with Docker

```bash
docker run --rm -p 8000:8000 \
  -v "$(pwd)/policy.yml:/etc/sqlguard/policy.yml:ro" \
  ghcr.io/nickusevich/sql-guardrail:latest
```

The image mounts your policy at `/etc/sqlguard/policy.yml` (the path
the server reads from `$SQLGUARD_POLICY_PATH`). For local hacking the
repo ships a `docker-compose.yml` that wires up `examples/policy.yml`:

```bash
docker compose up --build
```

### Run from Python

```bash
uv add "sql-guardrail[server]"
SQLGUARD_POLICY_PATH=policy.yml sqlguard-server
```

### Endpoints

- `POST /verify` — validate a SQL string.
- `GET /health` — liveness check (200 when policy is loaded, 503 otherwise).
- `GET /docs` — auto-generated OpenAPI UI.
- `GET /openapi.json` — machine-readable OpenAPI schema.

The `/verify` request body is `{"sql": "...", "context": {...}}`.
`context` carries the same per-request values you'd pass to
`verify(..., context=...)` in Python — typically `{"tenant_id": ...}`
sourced from the **authenticated session**, never the LLM prompt.

```bash
curl -s -X POST localhost:8000/verify \
  -H 'Content-Type: application/json' \
  -d '{"sql": "SELECT id FROM orders WHERE account_id=42",
       "context": {"tenant_id": 42}}'
```

```json
{
  "allowed": true,
  "statement_kind": "SELECT",
  "violations": []
}
```

On a denial, each violation carries the same `code` / `category` /
`message` / `suggestion` fields the library returns — feed `suggestion`
back to the LLM for a self-correction retry loop.

### Configuration

| Env var | Default | Purpose |
|---|---|---|
| `SQLGUARD_POLICY_PATH` | `/etc/sqlguard/policy.yml` (in image) | Path to the policy YAML. Required. |
| `SQLGUARD_HOST` | `0.0.0.0` | Bind address. |
| `SQLGUARD_PORT` | `8000` | Bind port. |
| `SQLGUARD_LOG_LEVEL` | `info` | uvicorn / app log level. |

`POST /verify` always returns HTTP 200; the `allowed` boolean lives in
the body. This matches the CLI's exit-code convention and means
callers branch on one field rather than mixing HTTP status with policy
outcome.

**The server does no authentication.** Put it behind a reverse proxy,
mTLS, or a K8s NetworkPolicy. Treat it as an internal service.

## Result API

```python
result.allowed         # bool: should I run this query?
result.violations      # tuple[Violation, ...]
result.statement_kind  # "SELECT" | "UPDATE" | ...
result.has_category(ViolationCategory.DENIED)
```

Each `Violation` has `.code` (one of ~20 specific codes), `.category`
(coarse grouping: `DENIED`, `INVALID`, `LIMIT`, `PARSE`, `POLICY`),
`.message`, and `.suggestion`.

Most integrations don't need to look at every code:

```python
# Simple: did anything fire?
if not result.allowed:
    log.warning("blocked SQL", violations=[v.code.value for v in result.violations])
    return 403

# Or: branch by what kind of problem
if result.has_category(ViolationCategory.DENIED):
    audit_security_event(...)
elif result.has_category(ViolationCategory.INVALID):
    return "Bad query, please rephrase"
elif result.has_category(ViolationCategory.LIMIT):
    return "Query too expensive, add LIMIT or narrow filters"
```

## Policy reference

See [`examples/policy.yml`](examples/policy.yml) for a fully-annotated
policy. Quick reference of every supported field:

**Top-level**

- `read_only: bool` (default `true`). Block writes, locks, SELECT
  INTO, data-modifying CTEs.
- `tables: [TablePolicy, ...]`. Per-table scoping. Without this the
  table/column allowlist is a no-op.
- `forbid.always_true_predicates: bool` (default `true`).
- `forbid.select_star: bool` (default `true`).
- `forbid.cartesian_join: bool` (default `true`).
- `forbid.recursive_cte: bool` (default `true`).
- `limits.max_sql_length: int` (default `20000`).
- `limits.max_ast_nodes: int | null` (default `5000`).
- `limits.max_limit_value: int | null` (default `10000`).
- `limits.max_offset_value: int | null` (default `100000`).
- `limits.max_joins: int | null` (default `10`).
- `limits.max_subquery_depth: int | null` (default `8`).
- `allowed_functions: [str, ...] | null` (default `null`).

**Per-table (`tables[*]`)**

- `name: str`. Required.
- `schema: str | null`. Optional schema qualifier. Two entries with
  the same `name` but different `schema` work fine side by side.
- `allow_columns: [str, ...] | null`. Column allowlist. `null` means
  any column on this table is allowed.
- `deny_columns: [str, ...]`. Column blacklist. Matched in any AST
  position.
- `require_predicate: RequiredPredicate | [RequiredPredicate, ...]`.
  Forces WHERE / INNER-JOIN-ON to include this predicate joined with
  AND.
- `large: bool` (default `false`). When true, every query referencing
  this table must have an effective LIMIT.

**`require_predicate`**: `{column, op, value}`. `op` is one of
`= != < <= > >= IN BETWEEN` (default `=`). `value` can contain
`${var}` placeholders resolved from the `context=` arg of `verify()`.
For `IN`, `value` is a list. For `BETWEEN`, `value` is `[low, high]`.

## SQL dialects

Parsing uses sqlglot's neutral parser, so any SQL it can tokenize
reaches the rule pipeline. Identifier folding is lowercase-unquoted
by default, which matches PostgreSQL, MySQL, SQLite, and DuckDB.
Snowflake and BigQuery folding rules differ and would need a dialect
plugin (not shipped yet). Anything sqlglot can't parse fails closed
as `PARSE_ERROR`, which is better than letting it through.

## See also

- [`examples/policy.yml`](examples/policy.yml). Fully-annotated policy.
- [`examples/backend_integration.py`](examples/backend_integration.py).
  End-to-end FastAPI-style example.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). File-by-file walk
  through `core/` and the pipeline.
- [`CHANGELOG.md`](CHANGELOG.md). Per-release notes.
- [`CONTRIBUTING.md`](CONTRIBUTING.md). Local checks, test layout,
  what belongs (and doesn't belong) as a new rule.
- [`SECURITY.md`](SECURITY.md). How to report a bypass privately.

## Versioning and stability

Currently `0.5.x`, following [SemVer](https://semver.org/). Patch
bumps fix bugs (including security bypasses) without changing the
public API. Minor bumps may add fields to `Policy` and `Violation`
but won't change the meaning of existing ones. A 1.0 release will
commit to the current public API: `verify`, `Policy`,
`VerificationResult`, `Violation`, `ViolationCode`,
`ViolationCategory`.

## License

MIT. See [`LICENSE`](LICENSE).
