# sql-guardrail architecture

Brief tour of the codebase for contributors. Single-pipeline,
sqlglot-only static SQL safety validator.

## Pipeline overview

```
       sql, policy, context
              │
              ▼
    ┌─────────────────────┐
    │ sqlguard.verify()   │  __init__.py
    │  - length cap       │
    │  - try/except       │
    └─────────┬───────────┘
              │
              ▼
    ┌─────────────────────┐    sqlglot — multi-stmt rejection, kind allowlist,
    │ core.preflight      │    exp.Command default-deny, PARSE_ERROR on empty
    └─────────┬───────────┘
              │  if can_continue
              ▼
    ┌─────────────────────┐    sqlglot — Expression tree for the
    │ core.parser.load()  │    downstream rules
    └─────────┬───────────┘
              │
              ▼
    ┌─────────────────────────┐
    │ check_data_modifying_   │   reject WITH x AS (INSERT…) SELECT *
    │   cte() on parsed AST   │
    └─────────┬───────────────┘
              │
              ▼
    ┌─────────────────────┐
    │ AST-size cap        │   bound validator CPU cost
    └─────────┬───────────┘
              │
              ▼
    ┌─────────────────────┐
    │  Rule pipeline      │  rules/*.py — each is a pure function
    │   1. check_readonly │      expression × policy → list[Violation]
    │   2. check_allowlist│
    │   3. check_predicates│
    │   4. check_limits   │
    │   5. check_function_│
    │       allow         │
    └─────────┬───────────┘
              │
              ▼
       VerificationResult
```

## Module map

| Module | Purpose |
|---|---|
| `__init__.py` | Public API: `verify`, exports |
| `cli.py` | Click-based CLI (`sqlguard verify`) |
| `result.py` | `Violation`, `ViolationCode`, `ViolationCategory`, `VerificationResult` |
| `core/preflight.py` | sqlglot preflight + data-modifying-CTE check |
| `core/parser.py` | sqlglot single-expression parse → `LoadResult(expression, violations)` |
| `core/idents.py` | Identifier case folding (lowercase unquoted, preserve quoted) |
| `core/scope.py` | `iter_scopes()` + `DmlScope` (works around sqlglot's empty-scope-for-DML quirk) |
| `config/schema.py` | Pydantic policy schema, `from_yaml/from_dict`, `${var}` substitution, schema-aware `table_by_name` |
| `core/rules/readonly.py` | Writes (`exp.Insert/Update/...`) + row locks + SELECT INTO under `read_only=True` |
| `core/rules/allowlist.py` | Table/column allowlists + select-star + identifier-name catchall |
| `core/rules/predicates.py` | Always-true catchall + per-alias `require_predicate` matcher |
| `core/rules/limits.py` | Cartesian, recursive CTE, max_joins, max_subquery_depth, LIMIT/OFFSET caps, large-table LIMIT |
| `core/rules/function_allow.py` | Opt-in `policy.allowed_functions` walker |

Parsing uses sqlglot's neutral (dialect-agnostic) parser. There is no
dialect knob — anything sqlglot can tokenize reaches the rule pipeline,
and anything it can't parse fails closed as `PARSE_ERROR`. Dialect is
a parser concern, not a security rule, and exposing it as a config
field invites accidental misconfiguration without buying any safety.

## The four structural defenses

The library is organized around "default-deny on uncertainty." Four
structural rules close entire bypass classes by construction; the
specific rules layered on top exist for **helpful error messages**, not
for catching different things.

| # | Defense | Location | Closes |
|---|---|---|---|
| 1 | **Statement-kind allowlist** | `core/preflight.py::_SELECT_LIKE` / `_DML_LIKE` + `exp.Command` default-deny | multi-statement, DDL/DCL, vendor extensions, anything sqlglot can't classify |
| 2 | **Tautology catchall** | `core/rules/predicates.py::_check_always_true` | every WHERE/JOIN-ON leaf without a Column/Table ref (`1=1`, `abs(1)>0`, `'true'::boolean`, any constant-folded shape) |
| 3 | **Identifier-name catchall** | `core/rules/allowlist.py::_check_denied_identifier_names` | denied col in any AST position (`JOIN USING (denied)`, denied-name alias, identifier-in-weird-position) |
| 4 | **Function allowlist** (opt-in) | `core/rules/function_allow.py` + `policy.allowed_functions` | "we forgot to add X to the denylist" for any unknown function name |

When a new bypass is found, the right fix is usually to extend the
relevant catchall, not to add a per-shape denylist entry.

## Test layout

| File | Purpose |
|---|---|
| `tests/test_security.py` | Security regression — every bypass class, organized by attack |
| `tests/test_corpus.py` | E2E: every `.sql` in `tests/malicious/` denied, every `tests/benign/` allowed |
| `tests/unit/test_*.py` | Per-rule unit tests for development feedback |

Test organization principle: **by attack class, not history**.
When adding a regression test, put it in the section for the attack class
it covers.

When you're tempted to add a per-shape tautology test (`'1'::int = 1`,
`bool_and(true)`, etc.), DON'T — the catchall test in
`tests/test_security.py::TestTautologies::test_constant_leaf_rejected`
covers them all. Add the shape to that parametrized list instead.

## Adding a new rule

1. Write a function `check_<thing>(expression, policy) -> list[Violation]`
   in a new `src/sqlguard/core/rules/<thing>.py`.
2. Add violation codes to `result.py::ViolationCode` and their category
   to `result.py::_CATEGORY` (defaults to DENIED if you forget).
3. Wire the call into `__init__.py::_run_pipeline`.
4. Add a section to `tests/test_security.py` covering the attack class.

## Adding a new violation code

1. Add to `ViolationCode` in `result.py`.
2. Add to `_CATEGORY` (the test `test_category_mapping_covers_all_codes`
   will fail if you forget).

## Layers beyond this library

sql-guardrail is one layer of defense; the README has a deployment diagram
for the full stack (least-privileged role, RLS, statement_timeout). If you
find yourself trying to make the validator catch something that's better
caught by RLS or `default_transaction_read_only`, push back — the
validator is a tripwire, the database is the perimeter.
