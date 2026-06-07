# sql-guardrail

[![CI](https://github.com/nickusevich/sql-guardrail/actions/workflows/ci.yml/badge.svg)](https://github.com/nickusevich/sql-guardrail/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/sql-guardrail.svg)](https://pypi.org/project/sql-guardrail/)
[![Python versions](https://img.shields.io/pypi/pyversions/sql-guardrail.svg)](https://pypi.org/project/sql-guardrail/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**A safety check for SQL that an LLM wrote.**

If your app lets a language model write SQL, `sql-guardrail` reads each query
*before* it runs and blocks the dangerous ones — a write when only reads are
allowed, a `WHERE 1=1`, a missing tenant filter, a banned column, a runaway
scan — with a clear reason you can log or feed back to the model.

It never touches your database, never rewrites your SQL, and **never raises**.
You write a policy; you call `verify()`; you get back `allowed` plus a list of
reasons. If it says yes, you run the exact string you gave it.

```python
from sqlguard import Policy, verify

policy = Policy.from_yaml("policy.yml")          # load once at startup

sql = my_llm_app(question)                       # the query your model wrote
result = verify(sql, policy, context={"tenant_id": user.tenant_id})

if not result.allowed:
    raise PermissionError([v.message for v in result.violations])
conn.execute(sql)
```

> One guardrail, not the only one. Pair it with a read-only DB role, row-level
> security, and a statement timeout — see [Where it fits](#where-it-fits).

## Why this exists

SQL injection used to be solved: you wrote the query once with placeholders and
passed user input as values, so input could never change the *shape* of the
query. Text-to-SQL breaks that — the LLM writes the whole query as text every
time, so there's no fixed shape to protect and prepared statements can't help.
A read-only role and row-level security catch *permission* errors, but the
database will still run `SELECT password_hash ... WHERE 1=1` and fail silently,
telling you nothing. `sql-guardrail` is the fast first check that blocks the
obvious problems with a clear reason, before the query reaches the database.

## Install

```bash
uv add sql-guardrail        # or: pip install sql-guardrail
```

Python 3.10+. Runtime deps: `sqlglot`, `pydantic`, `PyYAML`, `click`.

## The policy

A policy lists which tables and columns the LLM may touch and the rules every
query must follow. A small one for a multi-tenant `orders` table:

```yaml
# policy.yml
read_only: true                   # only reads, no writes

tables:
  - name: orders
    allow_columns: [id, product_name, account_id, total]
    require_predicate:            # every query must filter by tenant
      column: account_id
      op: "="
      value: "${tenant_id}"       # filled per request from context=

forbid:
  select_star: true               # no `SELECT *`
  always_true_predicates: true    # no `WHERE 1=1`

limits:
  max_limit_value: 1000           # no `LIMIT 1000000`
```

`context` carries per-request values that fill in `${...}` placeholders. **The
`tenant_id` must come from the authenticated session, never the LLM prompt** —
if the LLM picks its own tenant id, every tenant rule collapses.

See [`examples/policy.yml`](examples/policy.yml) for a fully-annotated policy
and [`examples/backend_integration.py`](examples/backend_integration.py) for a
FastAPI-style request handler.

> Validate the string you actually run. If you strip comments or normalize the
> SQL after `verify()`, call `verify()` again on the final form.

## What it checks

- **Statement shape** — `SELECT` only (DML when `read_only=false`); no multi-statement, DDL/DCL, data-modifying CTEs, locks, or `SELECT INTO`.
- **Always-true filters** — `WHERE 1=1`, `id = id`, every constant-folded shape, across WHERE / JOIN ON / HAVING / QUALIFY / MERGE.
- **Tables & columns** — per-table/column allowlists, plus a denylist that blocks a column in *any* position (even `JOIN USING`); no `SELECT *`.
- **Tenant isolation** — `require_predicate` forces every alias of a table to carry your tenant filter in WHERE / INNER JOIN ON.
- **Function allowlist** (opt-in) — every function call must be approved; closes `pg_sleep`, `pg_read_file`, and unvetted helpers.
- **DoS caps** — joins, nesting depth, `LIMIT`, `OFFSET`, SQL length, AST size; blocks cartesian and recursive queries.

Full field reference and per-check semantics: [**`docs/POLICY.md`**](docs/POLICY.md).

## Where it fits

Safety is layers. Each catches different problems; no single one is enough.

```
┌──────────────────────────────────────────┐
│ 1. Prompt design + tool wrappers         │  Shape what the LLM tries.
├──────────────────────────────────────────┤
│ 2. sql-guardrail.verify()   ← THIS LIB   │  Check the SQL against a policy.
├──────────────────────────────────────────┤  (only if allowed)
│ 3. Least-privileged database user        │  Read-only, no catalog access.
├──────────────────────────────────────────┤
│ 4. Row-level security (RLS)              │  DB rule pinned to the user.
├──────────────────────────────────────────┤
│ 5. Statement timeout                     │  Slow queries get killed.
└──────────────────────────────────────────┘
                     ▼  Database
```

This library is layer 2: fast, in-process, no network calls. It blocks
obviously bad queries with a reason you can act on. Layers 3–5 are the hard
outer wall — even if a query slips past, a read-only user can't write, RLS
hides other tenants' rows, and the timeout kills runaways. **If this library
is all you have, you've improved things but you're not safe.** Set up the
database layers too.

## What it does NOT catch

- **Bare `INSERT ... VALUES` / `MERGE` tenant isolation** — no WHERE on the target row; use DB `CHECK` constraints or RLS write policies.
- **Column-arithmetic tautologies** (`id*0=0`) — safe by construction; lean on `require_predicate` + RLS.
- **Plan-time cost surprises** — only the planner knows; use `statement_timeout`.
- **Bugs in your auth** — if the tenant id comes from the LLM, not the session, the library can't know.

More in [`docs/POLICY.md`](docs/POLICY.md#what-this-does-not-catch).

## CLI & HTTP server

Beyond the Python API, `sqlguard verify` validates a file, stdin, or a CI step:

```bash
echo 'SELECT id FROM orders WHERE 1=1' | sqlguard verify --policy policy.yml --stdin
```

Or run the HTTP sidecar — same rules, same response shape — from the image:

```bash
docker run --rm -p 8000:8000 \
  -v "$(pwd)/policy.yml:/etc/sqlguard/policy.yml:ro" \
  ghcr.io/nickusevich/sql-guardrail:latest
```

`POST /verify` returns the verdict in the body; `GET /docs` is the OpenAPI UI.
**The server does no auth — keep it internal.** Exit codes, every endpoint, and
env config live in [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

## Docs

- [`docs/POLICY.md`](docs/POLICY.md) — every policy field and what each check
  does, the result object, and what the library doesn't catch.
- [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) — CLI flags and exit codes, HTTP
  endpoints, env-var config, Docker.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — the pipeline, module map,
  and the four structural defenses.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — local checks, test layout, how to add
  a rule.
- [`SECURITY.md`](SECURITY.md) — how to report a bypass privately.

The test suite is **500+ tests** organized by attack class, run on Python
3.10–3.13 across Ubuntu and macOS with `ruff`, `mypy --strict`, and coverage.
Every `tests/malicious/*.sql` must be denied and every `tests/benign/*.sql`
allowed.

## Versioning

`0.5.x`, [SemVer](https://semver.org/). Patch bumps fix bugs (including
security bypasses); minor bumps may add fields without changing existing
meaning. 1.0 will commit to the public API: `verify`, `Policy`,
`VerificationResult`, `Violation`, `ViolationCode`, `ViolationCategory`.

## License

MIT. See [`LICENSE`](LICENSE).
