# Changelog

Notable changes per release. See
[GitHub Releases](https://github.com/nickusevich/sql-guardrail/releases)
for full release notes.

## [0.5.0] — 2026-05-25

First public release. Static SQL safety validator for LLM-generated
queries: statement-kind allowlist, table/column allow/deny lists,
tautology catchall, identifier-name catchall, function allowlist,
per-tenant `require_predicate`, DoS caps (length / AST nodes /
joins / depth / LIMIT / OFFSET). Ships with a CLI and an optional
FastAPI server. 535 tests, 92% line coverage.

[0.5.0]: https://github.com/nickusevich/sql-guardrail/releases/tag/v0.5.0
