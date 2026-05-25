# Security policy

## Reporting a vulnerability

If you find a bypass or other security issue, **please do not open a
public GitHub issue** — that would disclose the bypass to attackers
before users can upgrade.

Use GitHub's private vulnerability reporting instead:

1. Go to https://github.com/nickusevich/sql-guardrail/security/advisories/new
2. (Or click the **Security** tab on the repo → **Report a vulnerability**.)
3. Include:
   - A minimal reproducing SQL string and policy.
   - The library version (`sqlguard.__version__`).
   - The expected behavior (what should have been blocked) and the
     actual behavior (what was allowed).

The report stays private until a fix ships. We will acknowledge
receipt within 72 hours, coordinate a fix and a published advisory
(GHSA), and credit the reporter unless they prefer otherwise.

## Scope

In scope:

- The validator returns `allowed=True` for SQL that any of the
  documented defenses should reject (writes under `read_only=True`,
  denied tables/columns, tautological WHERE/JOIN-ON, missing
  `require_predicate`, multi-statement, data-modifying CTEs, lock
  clauses, SELECT INTO writes, etc.).
- `verify()` raises an unhandled exception (it should never raise — the
  invariant is "always return a `VerificationResult`, even on
  pathological input").

Out of scope:

- Bypasses that require the caller to violate the documented
  contract — e.g. passing `context["tenant_id"]` from a user-controlled
  source instead of the authenticated session.
- Attacks that the documented database-layer defenses (least-privilege
  role, RLS, `statement_timeout`) are supposed to backstop. The
  validator is one layer; see the "Deployment" section in
  [`README.md`](README.md).
- Adversarial parse-time CPU/memory exhaustion that the configured
  `max_sql_length` / `max_ast_nodes` / `max_subquery_depth` caps make
  finite. If you find an input that bypasses those caps, that IS in
  scope.

## Defense-in-depth reminder

sql-guardrail catches structural attacks cheaply before SQL reaches the
database. It is **not** a complete safety boundary. A production
deployment MUST also configure:

1. A least-privilege role with `default_transaction_read_only = on`
   (or your DB's equivalent).
2. Row-Level Security pinned to a session GUC set from the
   authenticated identity.
3. `SET LOCAL statement_timeout` and `SET LOCAL
   idle_in_transaction_session_timeout` to bound query cost.

If those layers are in place, the worst case of any single
sql-guardrail bypass is "the database rejects it" or "returns one
tenant's data only" or "is killed after N seconds."
