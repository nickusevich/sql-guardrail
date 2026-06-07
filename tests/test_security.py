"""Security regression tests — organized by ATTACK CLASS.

This is the single file that protects against every confirmed-bypass
class. Each section corresponds to one defense; if any test here flips,
an entire class of bypasses has regressed.

When adding a new test, put it in the section for the ATTACK it covers.

Test-organization rule of thumb:
  * The library has FOUR structural defenses (see README §"Default-deny on
    uncertainty"). Each defense is tested in its own section, and the
    sections deliberately overlap so the catchall and the specific rule
    both have to fire for a denial to be lost.
  * Per-shape / per-function enumeration is the kind of test the structural
    catchalls made redundant. Don't add per-fold tests — add ONE catchall
    test with an arbitrary function and trust the catchall.
"""
from __future__ import annotations

import sys
import warnings

import pytest
from pydantic import ValidationError

from sqlguard import (
    Policy,
    Violation,
    ViolationCategory,
    ViolationCode,
    verify,
)


def _policy(data: dict | None = None) -> Policy:
    """Thin wrapper around ``Policy.from_dict`` for terser fixtures."""
    return Policy.from_dict(data or {})


# ===========================================================================
# Shared fixtures
# ===========================================================================
@pytest.fixture
def policy() -> Policy:
    """The shared reference policy for these tests — tenant `orders` with
    `account_id` predicate, plus a `users` table with denied columns."""
    return _policy(
        {
            "read_only": True,
            "tables": [
                {
                    "name": "orders",
                    "allow_columns": ["id", "product_name", "account_id", "created_at", "total"],
                    "large": True,
                    "require_predicate": {
                        "column": "account_id",
                        "op": "=",
                        "value": "${tenant_id}",
                    },
                },
                {
                    "name": "users",
                    "allow_columns": ["id", "name"],
                    "deny_columns": ["password_hash", "ssn", "email"],
                },
            ],
            "forbid": {
                "always_true_predicates": True,
                "select_star": True,
                "recursive_cte": True,
                "cartesian_join": True,
            },
            "limits": {"max_sql_length": 100_000},
        }
    )


@pytest.fixture
def writable_policy() -> Policy:
    """Same as `policy` but with read_only=False, so DML rules are exercised."""
    return _policy(
        {
            "read_only": False,
            "tables": [
                {
                    "name": "orders",
                    "allow_columns": ["id", "product_name", "account_id", "total"],
                    "require_predicate": {
                        "column": "account_id",
                        "op": "=",
                        "value": "${tenant_id}",
                    },
                },
                {
                    "name": "users",
                    "allow_columns": ["id", "name"],
                    "deny_columns": ["password_hash", "ssn", "email"],
                },
            ],
            "forbid": {"select_star": True, "always_true_predicates": True},
        }
    )


@pytest.fixture
def ctx() -> dict:
    return {"tenant_id": 42}


# ===========================================================================
# Section 1 — ROBUSTNESS
# verify() must never raise, regardless of input. Library invariant.
# ===========================================================================
class TestRobustness:
    @pytest.mark.parametrize(
        "sql", ["", "   ", ";", "-- only", "/* only */"]
    )
    def test_empty_or_degenerate_fails_closed(
        self, policy: Policy, ctx: dict, sql: str
    ) -> None:
        r = verify(sql, policy, context=ctx)
        assert not r.allowed
        assert any(v.code == ViolationCode.PARSE_ERROR for v in r.violations)

    def test_nul_byte_input_does_not_crash(
        self, policy: Policy, ctx: dict
    ) -> None:
        """NUL bytes inside SQL must not crash verify(). sqlglot may or
        may not parse the string; either way the result is a Boolean."""
        r = verify("SELECT \x00 FROM users", policy, context=ctx)
        assert isinstance(r.allowed, bool)

    def test_deep_nesting_does_not_crash(self, policy: Policy, ctx: dict) -> None:
        sys.setrecursionlimit(2000)
        sql = "SELECT 1" + " FROM (SELECT 1" * 500 + ")" * 500
        r = verify(sql, policy, context=ctx)
        assert isinstance(r.allowed, bool)

    def test_large_or_chain_does_not_crash(self, policy: Policy, ctx: dict) -> None:
        sql = "SELECT 1 WHERE " + " OR ".join(["account_id = 42"] * 1000)
        r = verify(sql, policy, context=ctx)
        assert isinstance(r.allowed, bool)

    def test_oversized_input_rejected(self, policy: Policy, ctx: dict) -> None:
        sql = "SELECT 1 " + "/* spam */ " * 20_000
        r = verify(sql, policy, context=ctx)
        assert not r.allowed
        assert any(v.code == ViolationCode.PARSE_ERROR for v in r.violations)

    @pytest.mark.parametrize(
        "sql",
        [
            "garbage SQL that won't parse $%@#",
            "SELECT 1 WHERE " + "(" * 100 + "TRUE" + ")" * 100,
            "",  # empty
        ],
    )
    def test_verify_never_raises(self, policy: Policy, ctx: dict, sql: str) -> None:
        sys.setrecursionlimit(2000)
        try:
            r = verify(sql, policy, context=ctx)
        except Exception as e:  # noqa: BLE001
            pytest.fail(f"verify() raised {type(e).__name__}: {e}")
        assert isinstance(r.allowed, bool)


# ===========================================================================
# Section 2 — STATEMENT KIND ALLOWLIST  (Defense 1)
# Only SelectStmt (and DML if read_only=False) reaches the rule engine;
# everything else fails at preflight.
# ===========================================================================
class TestStatementKinds:
    @pytest.mark.parametrize(
        "sql",
        [
            # Picks one representative from each statement-kind category that
            # historically slipped through. The allowlist is at preflight;
            # if any of these regress, the allowlist itself broke.
            "CREATE POLICY pol ON orders FOR SELECT USING (true)",
            "ALTER SYSTEM SET log_statement='all'",
            "COMMENT ON TABLE orders IS 'pwned'",
            "CREATE RULE r AS ON SELECT TO orders DO INSTEAD SELECT 1",
            "CREATE EVENT TRIGGER t ON ddl_command_start EXECUTE FUNCTION f()",
            "CREATE PUBLICATION p FOR TABLE orders",
            "CREATE INDEX idx ON orders (id)",
            "DROP TABLE orders",
            "CREATE EXTENSION pg_stat_statements",
        ],
    )
    def test_non_select_statements_blocked(
        self, policy: Policy, ctx: dict, sql: str
    ) -> None:
        r = verify(sql, policy, context=ctx)
        assert not r.allowed
        # Either the parser bailed (PG-specific syntax sqlglot can't
        # classify in neutral mode) or the kind allowlist rejected it.
        # Both block the query before the rule walks run.
        assert any(
            v.code in {
                ViolationCode.STATEMENT_FORBIDDEN,
                ViolationCode.WRITE_FORBIDDEN,
                ViolationCode.PARSE_ERROR,
            }
            for v in r.violations
        )


# ===========================================================================
# Section 3 — CATEGORICAL BANS
# DO, COPY, multi-statement, data-modifying CTE, write statements,
# row locks. Each is a categorical ban regardless of policy mode.
# ===========================================================================
class TestCategoricalBans:
    def test_multi_statement_forbidden(self, policy: Policy, ctx: dict) -> None:
        r = verify("SELECT 1; DROP TABLE orders;", policy, context=ctx)
        assert not r.allowed
        assert any(v.code == ViolationCode.MULTI_STATEMENT for v in r.violations)

    def test_data_modifying_cte_forbidden(self, policy: Policy, ctx: dict) -> None:
        """CTE-disguised write: the DELETE runs even though the outer SELECT
        is what's "returned." The core data-modifying-CTE check walks every
        CTE body and rejects any DML node."""
        sql = "WITH x AS (DELETE FROM orders RETURNING id) SELECT id FROM x"
        r = verify(sql, policy, context=ctx)
        assert not r.allowed
        assert any(
            v.code == ViolationCode.DATA_MODIFYING_CTE for v in r.violations
        )

    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT id FROM orders WHERE account_id = 42 FOR UPDATE",
            "SELECT id FROM orders WHERE account_id = 42 FOR SHARE",
            "SELECT id FROM orders WHERE account_id = 42 FOR UPDATE NOWAIT",
        ],
    )
    def test_locks_forbidden(self, policy: Policy, ctx: dict, sql: str) -> None:
        r = verify(sql, policy, context=ctx)
        assert not r.allowed
        assert any(v.code == ViolationCode.LOCK_FORBIDDEN for v in r.violations)

    @pytest.mark.parametrize(
        "sql",
        [
            # Regression: SELECT ... INTO is a write disguised as a read —
            # equivalent to CREATE TABLE AS. sqlglot parses it as
            # exp.Select with an `into` arg; check_readonly's _check_select_into
            # branch catches it so the source-table read isn't the only thing
            # the downstream rules see.
            "SELECT id INTO orders_copy FROM orders WHERE account_id = 42 LIMIT 10",
            # `SELECT INTO TEMP` is the same attack against a session-private
            # schema where no table allowlist applies.
            "SELECT id INTO TEMP tmp FROM orders WHERE account_id = 42 LIMIT 10",
            "SELECT id INTO TEMPORARY tmp FROM orders WHERE account_id = 42 LIMIT 10",
            "SELECT id INTO UNLOGGED tmp FROM orders WHERE account_id = 42 LIMIT 10",
            # Schema-qualified target.
            "SELECT id INTO public.orders_copy FROM orders WHERE account_id = 42 LIMIT 10",
        ],
    )
    def test_select_into_forbidden(
        self, policy: Policy, ctx: dict, sql: str
    ) -> None:
        r = verify(sql, policy, context=ctx)
        assert not r.allowed, (
            f"SELECT INTO should be denied but wasn't: "
            f"{[v.code.value for v in r.violations]}"
        )

    def test_select_into_blocked_even_with_target_allowlisted(self) -> None:
        """The bypass: even when the target table happens to be in the
        allowlist, SELECT INTO must be rejected because it's a write
        (caught by check_readonly's SELECT-INTO branch — emits
        WRITE_FORBIDDEN regardless of target-table allowlisting)."""
        p = _policy(
            {
                "read_only": True,
                "tables": [
                    {
                        "name": "orders",
                        "allow_columns": ["id", "account_id"],
                        "require_predicate": {
                            "column": "account_id", "op": "=", "value": "${tenant_id}",
                        },
                    },
                    {"name": "orders_copy", "allow_columns": ["id"]},
                ],
            }
        )
        r = verify(
            "SELECT id INTO orders_copy FROM orders WHERE account_id = 42 LIMIT 10",
            p,
            context={"tenant_id": 42},
        )
        assert not r.allowed
        assert any(v.code == ViolationCode.WRITE_FORBIDDEN for v in r.violations)

    @pytest.mark.parametrize(
        "sql",
        [
            # sqlglot parses `(SELECT ...)` as exp.Subquery wrapping a
            # Select. The preflight kind allowlist used to reject Subquery
            # as STATEMENT_FORBIDDEN — a real false positive since LLMs
            # do emit parenthesized SELECT for set-op compositions.
            "(SELECT id FROM orders WHERE account_id = 42 LIMIT 1)",
            "((SELECT id FROM orders WHERE account_id = 42 LIMIT 1))",
        ],
    )
    def test_parenthesized_select_allowed(
        self, policy: Policy, ctx: dict, sql: str
    ) -> None:
        r = verify(sql, policy, context=ctx)
        assert r.allowed, (
            f"parenthesized-SELECT regression: {sql!r} should be allowed "
            f"but got {[v.code.value for v in r.violations]}"
        )

    @pytest.mark.parametrize(
        "sql",
        [
            # Even quoted-uppercase identifiers that match a denied
            # lowercase column should be blocked. Earlier behavior:
            # deny_columns comparison was case-sensitive, so quoted-uppercase
            # slipped past when no allow_columns was set.
            'SELECT "PASSWORD_HASH" FROM users LIMIT 1',
            'SELECT "Password_Hash" FROM users LIMIT 1',
            'SELECT u."PASSWORD_HASH" FROM users u LIMIT 1',
        ],
    )
    def test_quoted_uppercase_denied_column_blocked(self, sql: str) -> None:
        """Quoted-uppercase variant of a denied lowercase column must still
        be blocked. PG strictly treats `"PASSWORD_HASH"` as a different
        identifier from `password_hash`, but the validator's job is to fail
        closed — an attacker would only write the quoted form to evade."""
        # Policy with NO allow_columns — the bypass only occurred when
        # deny_columns was the only barrier (allow_columns enforcement was
        # masking the bug previously).
        p = _policy(
            {
                "tables": [
                    {"name": "users", "deny_columns": ["password_hash"]}
                ]
            }
        )
        r = verify(sql, p)
        assert not r.allowed, (
            f"deny_columns case regression: {sql!r} should be blocked but got "
            f"{[v.code.value for v in r.violations]}"
        )
        assert any(v.code == ViolationCode.COLUMN_DENIED for v in r.violations)


# ===========================================================================
# Section 4 — FUNCTION ALLOWLIST  (Defense 4 — opt-in default-deny)
# ``policy.allowed_functions`` is the only safety net for unknown function
# names; without it any function call passes through.
# ===========================================================================
class TestFunctionAllowlist:
    def test_common_functions_still_allowed(
        self, policy: Policy, ctx: dict
    ) -> None:
        """Sanity: routine LLM-output functions don't trip a check."""
        for sql in [
            "SELECT count(id) FROM orders WHERE account_id = 42 LIMIT 1",
            "SELECT coalesce(product_name, 'x') FROM orders WHERE account_id = 42 LIMIT 1",
            "SELECT upper(name) FROM users WHERE id = 1 LIMIT 1",
            "SELECT extract(year FROM created_at) FROM orders WHERE account_id = 42 LIMIT 1",
        ]:
            r = verify(sql, policy, context=ctx)
            assert r.allowed, [v.code.value for v in r.violations]

    def test_allowlist_unset_allows_unknown_function(self) -> None:
        """Without allowed_functions set, no function-allowlist check runs;
        any function call passes through."""
        p = _policy(
            {"tables": [{"name": "users", "allow_columns": ["id"]}]}
        )
        r = verify("SELECT some_unknown_fn(id) FROM users LIMIT 1", p)
        assert r.allowed, [v.code.value for v in r.violations]

    def test_allowlist_set_blocks_unknown_function(self) -> None:
        p = _policy(
            {
                "tables": [{"name": "users", "allow_columns": ["id"]}],
                "allowed_functions": ["count", "lower"],
            }
        )
        r = verify("SELECT some_unknown_fn(id) FROM users LIMIT 1", p)
        assert not r.allowed
        assert any(
            v.code == ViolationCode.FUNCTION_NOT_ALLOWED for v in r.violations
        )

    def test_allowlist_passes_listed_function(self) -> None:
        p = _policy(
            {
                "tables": [{"name": "users", "allow_columns": ["id"]}],
                "allowed_functions": ["count", "lower"],
            }
        )
        r = verify("SELECT count(id) FROM users LIMIT 1", p)
        assert r.allowed

    def test_allowlist_blocks_pg_specific_function_when_not_listed(self) -> None:
        """Under the function allowlist, PG-specific functions like
        ``pg_sleep`` are rejected just like any other unlisted function —
        there is no longer a per-name denylist, but the allowlist still
        closes the "any unknown function" class."""
        p = _policy(
            {
                "tables": [{"name": "users", "allow_columns": ["id"]}],
                "allowed_functions": ["count"],
            }
        )
        r = verify("SELECT pg_sleep(1) FROM users LIMIT 1", p)
        assert not r.allowed
        assert any(v.code == ViolationCode.FUNCTION_NOT_ALLOWED for v in r.violations)

    @pytest.mark.parametrize(
        "sql",
        [
            # sqlglot parses these into specific Func subclasses (NOT
            # exp.Anonymous): an earlier implementation only walked
            # Anonymous, so every concrete subclass passed for free. The
            # walker now covers the full exp.Func hierarchy.
            "SELECT lower(name) FROM users LIMIT 1",
            "SELECT upper(name) FROM users LIMIT 1",
            "SELECT length(name) FROM users LIMIT 1",
            "SELECT substring(name, 1, 3) FROM users LIMIT 1",
            "SELECT abs(id) FROM users LIMIT 1",
            "SELECT coalesce(name, 'x') FROM users LIMIT 1",
            "SELECT cast(id AS text) FROM users LIMIT 1",
            "SELECT id::text FROM users LIMIT 1",
            "SELECT current_user FROM users LIMIT 1",
            "SELECT current_database() FROM users LIMIT 1",
            "SELECT current_schema() FROM users LIMIT 1",
            "SELECT now() FROM users LIMIT 1",
            "SELECT extract(YEAR FROM now()) FROM users LIMIT 1",
            "SELECT array_agg(id) FROM users LIMIT 1",
            "SELECT max(id) FROM users LIMIT 1",
            "SELECT replace(name, 'a', 'b') FROM users LIMIT 1",
            "SELECT trim(name) FROM users LIMIT 1",
            "SELECT concat(name, '!') FROM users LIMIT 1",
        ],
    )
    def test_allowlist_blocks_typed_func_subclasses_when_not_listed(
        self, sql: str
    ) -> None:
        """Regression: the function-allowlist used to only walk
        ``exp.Anonymous``. With ``allowed_functions: ["count"]``, every
        function sqlglot models as a concrete Func subclass (Lower, Cast,
        CurrentUser, Coalesce, Substring, ArrayAgg, ...) silently passed.
        The walker now covers ``exp.Func`` itself, so the entire bypass
        class is closed."""
        p = _policy(
            {
                "tables": [{"name": "users", "allow_columns": ["id", "name"]}],
                "allowed_functions": ["count"],
            }
        )
        r = verify(sql, p)
        assert not r.allowed, (
            f"function-allowlist regressed: {sql!r} should be blocked "
            f"but got {[v.code.value for v in r.violations]}"
        )
        assert any(
            v.code == ViolationCode.FUNCTION_NOT_ALLOWED for v in r.violations
        )

    @pytest.mark.parametrize(
        "policy_name,query_name",
        [
            # sqlglot rewrites some PG / dialect-specific names to a canonical
            # class. Users typing the SQL name into policy.allowed_functions
            # should still get a match.
            ("date_trunc", "date_trunc('day', name)"),
            ("to_char", "to_char(id, '999')"),
            ("json_agg", "json_agg(id)"),
            ("string_agg", "string_agg(name, ',')"),
        ],
    )
    def test_canonical_aliases_allowlist_users_sql_name(
        self, policy_name: str, query_name: str
    ) -> None:
        """When sqlglot's class name diverges from the SQL the user wrote
        (date_trunc → TimestampTrunc, to_char → TimeToStr, json_agg →
        JSONArrayAgg, string_agg → GroupConcat), the allowlist still
        accepts the user-side SQL name via a small canonical-alias map."""
        p = _policy(
            {
                "tables": [{"name": "users", "allow_columns": ["id", "name"]}],
                "allowed_functions": [policy_name],
            }
        )
        sql = f"SELECT {query_name} FROM users LIMIT 1"
        r = verify(sql, p)
        assert r.allowed, (
            f"canonical alias regressed: {policy_name!r} should match "
            f"{query_name!r} but got {[v.code.value for v in r.violations]}"
        )

    @pytest.mark.parametrize(
        "sql",
        [
            # AND / OR / XOR — sqlglot models boolean connectives as
            # exp.And / exp.Or / exp.Xor, each an exp.Func subclass with
            # sql_names() of ['AND'] / ['OR'] / ['XOR']. Walking these as
            # functions would fail every multi-clause WHERE on a sane
            # policy ('and' / 'or' are not function names users list).
            "SELECT id FROM users WHERE id = 1 AND name = 'x' LIMIT 1",
            "SELECT id FROM users WHERE id = 1 OR name = 'x' LIMIT 1",
            "SELECT id FROM users WHERE id = 1 AND (name = 'x' OR name = 'y') LIMIT 1",
            # CASE — exp.Case with sql_names ['CASE']. A simple CASE may
            # also generate an inner exp.If during normalization (sql_names
            # ['IF', 'IIF']) — exempting both classes keeps multi-arm and
            # single-arm CASE expressions allowed.
            "SELECT CASE WHEN id = 1 THEN 'a' ELSE 'b' END FROM users LIMIT 1",
            "SELECT CASE WHEN id = 1 THEN 'a' WHEN id = 2 THEN 'b' ELSE 'c' END FROM users LIMIT 1",
            # EXISTS — exp.Exists with sql_names ['EXISTS']. EXISTS
            # subqueries are SQL syntax, not function calls.
            "SELECT id FROM users WHERE EXISTS (SELECT 1 FROM users WHERE id = 1) LIMIT 1",
            "SELECT id FROM users WHERE NOT EXISTS (SELECT 1 FROM users WHERE id = 1) LIMIT 1",
        ],
    )
    def test_allowlist_does_not_reject_operator_keywords(self, sql: str) -> None:
        """Regression: ``AND`` / ``OR`` / ``XOR`` / ``CASE`` / ``IF`` /
        ``EXISTS`` are SQL keywords sqlglot models as ``exp.Func`` subclasses
        for AST uniformity. Walking them as function calls would falsely
        reject every multi-clause WHERE / CASE expression / EXISTS subquery
        under any sane ``allowed_functions`` list — users never list these
        keywords because they are syntax, not callable functions.

        See ``core/rules/function_allow.py::_OPERATOR_KEYWORDS``.
        """
        p = _policy(
            {
                "tables": [{"name": "users", "allow_columns": ["id", "name"]}],
                # Deliberately a typical "small + safe" allowlist — exactly
                # what the README example policy ships with. None of these
                # are keywords; the exemption must come from the walker, not
                # from over-listing.
                "allowed_functions": ["count", "lower", "upper", "coalesce"],
            }
        )
        r = verify(sql, p)
        assert r.allowed, (
            f"operator-keyword exemption regressed: {sql!r} should be "
            f"allowed but got {[v.code.value for v in r.violations]}"
        )

    def test_allowlist_still_rejects_genuine_functions_inside_case(self) -> None:
        """The keyword exemption must NOT leak coverage of real function
        calls nested inside an exempted construct. ``pg_sleep`` inside a
        ``CASE WHEN ... THEN pg_sleep(1) ...`` is still a function call and
        must still be denied.
        """
        p = _policy(
            {
                "tables": [{"name": "users", "allow_columns": ["id"]}],
                "allowed_functions": ["count"],
            }
        )
        r = verify(
            "SELECT CASE WHEN id = 1 THEN pg_sleep(1) ELSE 0 END "
            "FROM users LIMIT 1",
            p,
        )
        assert not r.allowed
        assert any(
            v.code == ViolationCode.FUNCTION_NOT_ALLOWED for v in r.violations
        )


# ===========================================================================
# Section 5 — MULTI-STATEMENT is unconditionally rejected
# ===========================================================================
class TestMultiStatementEnforcement:
    """Multi-statement input is always rejected — LLMs should emit a single
    statement and chained statements (`SELECT 1; DROP TABLE x`) are the
    textbook injection vector."""

    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT 1; SELECT 2",
            "SELECT id FROM users; SELECT id FROM orders",
            "SELECT id FROM users; DROP TABLE users",
            "SELECT id FROM users; COPY users TO '/tmp/x.csv'",
            "SELECT id FROM users; LISTEN evil_channel",
        ],
    )
    def test_multi_statement_always_denied(
        self, policy: Policy, sql: str
    ) -> None:
        r = verify(sql, policy, context={"tenant_id": 42})
        assert not r.allowed
        assert any(v.code == ViolationCode.MULTI_STATEMENT for v in r.violations)


# ===========================================================================
# Section 6 — TAUTOLOGIES  (Defense 2 — structural catchall)
# Any WHERE/JOIN-ON leaf that doesn't reference a Column or Table is a
# constant predicate and must be rejected. This ONE structural rule
# replaces enumerating every per-function constant fold.
# ===========================================================================
class TestTautologies:
    """If you're tempted to add a per-shape test here (`'1'::int = 1`,
    `bool_and(true)`, etc.), DON'T — the catchall already covers them.
    Add it to the parametrized list below and trust the structural rule.
    """

    @pytest.fixture
    def deny_policy(self) -> Policy:
        return _policy(
            {
                "tables": [
                    {
                        "name": "users",
                        "allow_columns": ["id", "name"],
                        "deny_columns": ["password_hash", "ssn", "email"],
                    }
                ],
                "forbid": {"always_true_predicates": True, "select_star": True},
            }
        )

    @pytest.mark.parametrize(
        "constant_leaf",
        [
            # A grab-bag of constant leaves across every PG syntactic
            # category. ALL of them have no Column / Table reference, so the
            # catchall rejects them — without enumerating each PG function.
            "1 = 1",
            "true",
            "'true'::boolean",
            "1 + 1 = 2",
            "abs(-5) = 5",
            "round(1.5) = 2",
            "power(2, 3) = 8",
            "lower('AB') = 'ab'",
            "concat('a','b') = 'ab'",
            "substring('abc' from 1 for 1) = 'a'",
            "1 BETWEEN 0 AND 10",
            "1 IN (1, 2, 3)",
            "1 = ANY(ARRAY[1, 2, 3])",
            "EXISTS (SELECT 1)",
            "(SELECT 1) = 1",
            "NULLIF(NULL, 1) IS NULL",
            "CASE WHEN 1 = 1 THEN true END",
            "1 IS NOT DISTINCT FROM 1",
            "1 IS TRUE",
            "(1 & 1) = 1",
            "ARRAY[1] IS NOT NULL",
            "coalesce(false, true)",
            "'a' LIKE 'a'",
        ],
    )
    def test_constant_leaf_rejected(
        self, deny_policy: Policy, constant_leaf: str
    ) -> None:
        sql = f"SELECT id, name FROM users WHERE id = 1 OR ({constant_leaf}) LIMIT 10"
        r = verify(sql, deny_policy)
        assert not r.allowed, (
            f"catchall missed constant leaf `{constant_leaf}`: "
            f"{[v.code.value for v in r.violations]}"
        )
        assert any(
            v.code == ViolationCode.ALWAYS_TRUE_PREDICATE for v in r.violations
        )

    def test_column_self_equality_rejected(
        self, deny_policy: Policy
    ) -> None:
        """`id = id` references columns so the catchall misses it, but
        can't constrain rows. A second structural rule catches this shape."""
        r = verify(
            "SELECT id FROM users WHERE id = 1 OR id = id LIMIT 10",
            deny_policy,
        )
        assert not r.allowed
        assert any(
            v.code == ViolationCode.ALWAYS_TRUE_PREDICATE for v in r.violations
        )

    @pytest.mark.parametrize(
        "shape",
        [
            # _same_expression now unwraps Paren / Cast on both sides, so
            # these trivially-obfuscated self-equalities don't escape via
            # a different SQL rendering.
            "id = (id)",
            "(id) = id",
            "(id) = (id)",
            "id::int = id",
            "id = id::int",
            "id::text = id::text",
        ],
    )
    def test_self_equality_paren_cast_wrappers_caught(
        self, deny_policy: Policy, shape: str
    ) -> None:
        sql = f"SELECT id FROM users WHERE id = 1 OR ({shape}) LIMIT 10"
        r = verify(sql, deny_policy)
        assert not r.allowed, (
            f"self-equality regression: {shape!r} should be flagged but "
            f"got {[v.code.value for v in r.violations]}"
        )
        assert any(
            v.code == ViolationCode.ALWAYS_TRUE_PREDICATE for v in r.violations
        )

    @pytest.mark.parametrize(
        "shape",
        [
            "id IS NULL OR id IS NOT NULL",
            "id IS NOT NULL OR id IS NULL",
            "users.id IS NULL OR users.id IS NOT NULL",
            "(id) IS NULL OR id IS NOT NULL",  # paren-wrapped column
        ],
    )
    def test_null_complement_or_rejected(
        self, deny_policy: Policy, shape: str
    ) -> None:
        """`X IS NULL OR X IS NOT NULL` covers every value of X — the
        canonical blind-exfil pattern. Catchall doesn't fire (both leaves
        reference a column); a dedicated OR-pair check catches it."""
        sql = f"SELECT id FROM users WHERE id = 1 OR ({shape}) LIMIT 10"
        r = verify(sql, deny_policy)
        assert not r.allowed, (
            f"null-complement OR not caught: {shape!r} got "
            f"{[v.code.value for v in r.violations]}"
        )
        assert any(
            v.code == ViolationCode.ALWAYS_TRUE_PREDICATE for v in r.violations
        )

    def test_legit_null_check_not_flagged(self, deny_policy: Policy) -> None:
        """Just `IS NULL` (or just `IS NOT NULL`) on its own is a real
        filter; the null-complement detector must require BOTH sides."""
        for shape in ["id IS NULL", "id IS NOT NULL", "name IS NULL AND id = 1"]:
            sql = f"SELECT id FROM users WHERE {shape} LIMIT 10"
            r = verify(sql, deny_policy)
            assert not any(
                v.code == ViolationCode.ALWAYS_TRUE_PREDICATE for v in r.violations
            ), f"false-positive on legit null check: {shape!r}"

    @pytest.mark.parametrize(
        "shape",
        [
            # `col IN (col, ...)` — the column always matches itself
            # (modulo NULL); a faux-filter that returns every non-null row.
            "id IN (id)",
            "id IN (id, 1, 2)",
            "id IN (1, id)",
            "id IN (id, id)",
        ],
    )
    def test_self_in_membership_rejected(
        self, deny_policy: Policy, shape: str
    ) -> None:
        sql = f"SELECT id FROM users WHERE id = 1 OR ({shape}) LIMIT 10"
        r = verify(sql, deny_policy)
        assert not r.allowed, (
            f"self-IN not caught: {shape!r} got "
            f"{[v.code.value for v in r.violations]}"
        )
        assert any(
            v.code == ViolationCode.ALWAYS_TRUE_PREDICATE for v in r.violations
        )

    def test_legit_in_membership_not_flagged(
        self, deny_policy: Policy
    ) -> None:
        """A normal `col IN (1, 2, 3)` is a real filter and must not fire."""
        sql = "SELECT id FROM users WHERE id IN (1, 2, 3) LIMIT 10"
        r = verify(sql, deny_policy)
        assert not any(
            v.code == ViolationCode.ALWAYS_TRUE_PREDICATE for v in r.violations
        )

    def test_join_on_tautology_caught(
        self, deny_policy: Policy
    ) -> None:
        """JOIN ON 1=1 turns the join into a cartesian product but
        cartesian-detection passes (ON is non-null); always-true must
        catch it via the same rule that handles WHERE leaves."""
        sql = (
            "SELECT u1.id FROM users u1 JOIN users u2 ON 1 < 2 "
            "WHERE u1.id = 1 LIMIT 10"
        )
        r = verify(sql, deny_policy)
        assert not r.allowed
        assert any(
            v.code == ViolationCode.ALWAYS_TRUE_PREDICATE for v in r.violations
        )

    @pytest.mark.parametrize(
        "real_predicate",
        [
            # Same syntactic shapes as above, but referencing a column —
            # must NOT be flagged. False-positive insurance.
            "id = 1",
            "name LIKE 'A%'",
            "substring(name, 1, 3) = 'Bob'",
            "lower(name) = 'alice'",
            "concat(name, '!') = 'Bob!'",
            "id BETWEEN 1 AND 100",
            "id IN (SELECT id FROM users WHERE name = 'Alice')",
            "(id)::text = '1'",
            "EXISTS (SELECT 1 FROM users u2 WHERE u2.id = users.id)",
            "name = ANY(ARRAY['Alice', 'Bob'])",
            "id + 1 = 2",
            "abs(id) > 0",
            "NOT (id = 99)",
        ],
    )
    def test_real_data_predicate_not_flagged(
        self, deny_policy: Policy, real_predicate: str
    ) -> None:
        sql = f"SELECT id, name FROM users WHERE {real_predicate} LIMIT 10"
        r = verify(sql, deny_policy)
        assert not any(
            v.code == ViolationCode.ALWAYS_TRUE_PREDICATE for v in r.violations
        )

    def test_no_double_flag_on_paren_wrapped_leaf(
        self, deny_policy: Policy
    ) -> None:
        """`(1 = 1)` parses as Paren(EQ) — we must flag exactly once,
        not twice (Paren wrapper + inner EQ)."""
        r = verify(
            "SELECT id, name FROM users WHERE id = 1 OR (1 = 1) LIMIT 10",
            deny_policy,
        )
        codes = [v.code.value for v in r.violations]
        assert codes.count("ALWAYS_TRUE_PREDICATE") == 1, codes

    def test_merge_on_tautology_caught(self) -> None:
        """MERGE's `on` arg isn't a Join — was a separate code path that
        previously slipped through. Affects only read_only=False policies."""
        p = _policy(
            {
                "read_only": False,
                "tables": [
                    {"name": "orders", "allow_columns": ["id", "account_id", "status"]}
                ],
                "forbid": {"always_true_predicates": True},
            }
        )
        sql = (
            "MERGE INTO orders o USING (SELECT 1 AS x) s ON 1=1 "
            "WHEN MATCHED THEN UPDATE SET status = 'x'"
        )
        r = verify(sql, p)
        assert not r.allowed
        assert any(
            v.code == ViolationCode.ALWAYS_TRUE_PREDICATE for v in r.violations
        )

    # -------------------------------------------------------------------
    # Predicate-clause coverage: WHERE/JOIN ON/MERGE ON are not the only
    # clauses that carry a row filter — HAVING, QUALIFY, MERGE WHEN
    # [NOT ]MATCHED, START WITH / CONNECT BY do too. All of them must
    # go through _scan_predicate_leaves so the structural catchall
    # promise in the README holds.
    # -------------------------------------------------------------------
    @pytest.mark.parametrize(
        "tautology",
        ["1=1", "true", "'true'::boolean", "1+1=2"],
    )
    def test_having_constant_caught(
        self, deny_policy: Policy, tautology: str
    ) -> None:
        sql = f"SELECT id FROM users GROUP BY id HAVING {tautology} LIMIT 10"
        r = verify(sql, deny_policy)
        assert not r.allowed, [v.code.value for v in r.violations]
        assert any(
            v.code == ViolationCode.ALWAYS_TRUE_PREDICATE for v in r.violations
        )

    def test_having_null_complement_caught(
        self, deny_policy: Policy
    ) -> None:
        sql = (
            "SELECT id FROM users GROUP BY id "
            "HAVING id IS NULL OR id IS NOT NULL LIMIT 10"
        )
        r = verify(sql, deny_policy)
        assert not r.allowed
        assert any(
            v.code == ViolationCode.ALWAYS_TRUE_PREDICATE for v in r.violations
        )

    def test_legit_having_aggregate_not_flagged(
        self, deny_policy: Policy
    ) -> None:
        """`HAVING count(*) > 1` has no Column leaf but is data-dependent
        via the AggFunc — exempt from the catchall."""
        sql = (
            "SELECT id, count(*) AS c FROM users GROUP BY id "
            "HAVING count(*) > 1 LIMIT 10"
        )
        r = verify(sql, deny_policy)
        assert r.allowed, [v.message for v in r.violations]

    def test_qualify_constant_caught(self, deny_policy: Policy) -> None:
        sql = "SELECT id FROM users QUALIFY 1=1 LIMIT 10"
        r = verify(sql, deny_policy)
        assert not r.allowed
        assert any(
            v.code == ViolationCode.ALWAYS_TRUE_PREDICATE for v in r.violations
        )

    def test_legit_qualify_window_not_flagged(
        self, deny_policy: Policy
    ) -> None:
        """`QUALIFY row_number() OVER () = 1` has no Column leaf but
        is data-dependent via the Window — exempt from the catchall."""
        sql = (
            "SELECT id FROM users "
            "QUALIFY row_number() OVER () = 1 LIMIT 10"
        )
        r = verify(sql, deny_policy)
        assert r.allowed, [v.message for v in r.violations]

    @pytest.mark.parametrize(
        "when_clause",
        [
            "WHEN MATCHED AND 1=1 THEN UPDATE SET name = 'x'",
            "WHEN NOT MATCHED AND 1=1 THEN INSERT (id, name) VALUES (1, 'x')",
            (
                "WHEN MATCHED AND (u.id IS NULL OR u.id IS NOT NULL) "
                "THEN UPDATE SET name = 'x'"
            ),
        ],
    )
    def test_merge_when_clause_tautology_caught(self, when_clause: str) -> None:
        """The AND-condition on MERGE's WHEN branches is a separate
        predicate from MERGE ON. Without scanning When.condition, an
        attacker could pin a real ON predicate but tautologize the WHEN
        and update / insert every matched row."""
        p = _policy(
            {
                "read_only": False,
                "tables": [
                    {"name": "users", "allow_columns": ["id", "name"]},
                    {"name": "orders", "allow_columns": ["id", "account_id"]},
                ],
                "forbid": {"always_true_predicates": True},
            }
        )
        sql = (
            "MERGE INTO users u USING orders o "
            "ON u.id = o.account_id "
            f"{when_clause}"
        )
        r = verify(sql, p)
        assert not r.allowed, [v.code.value for v in r.violations]
        assert any(
            v.code == ViolationCode.ALWAYS_TRUE_PREDICATE for v in r.violations
        )

    def test_legit_merge_when_predicate_not_flagged(self) -> None:
        p = _policy(
            {
                "read_only": False,
                "tables": [
                    {"name": "users", "allow_columns": ["id", "name"]},
                    {"name": "orders", "allow_columns": ["id", "account_id"]},
                ],
                "forbid": {"always_true_predicates": True},
            }
        )
        sql = (
            "MERGE INTO users u USING orders o ON u.id = o.account_id "
            "WHEN MATCHED AND u.id > 0 THEN UPDATE SET name = 'x'"
        )
        r = verify(sql, p)
        assert r.allowed, [v.message for v in r.violations]

    @pytest.mark.parametrize(
        "tautology",
        ["START WITH 1=1 CONNECT BY id = id", "START WITH true CONNECT BY 2=2"],
    )
    def test_connect_by_tautology_caught(
        self, deny_policy: Policy, tautology: str
    ) -> None:
        """Oracle hierarchical query. START WITH / CONNECT BY carry
        predicates exactly like WHERE; without scanning them both, an
        LLM-emitted CONNECT BY 1=1 against a tree-shaped table can
        return every row."""
        sql = f"SELECT id FROM users {tautology} LIMIT 10"
        r = verify(sql, deny_policy)
        assert not r.allowed, [v.code.value for v in r.violations]
        assert any(
            v.code == ViolationCode.ALWAYS_TRUE_PREDICATE for v in r.violations
        )


# ===========================================================================
# Section 7 — TENANT ISOLATION  (require_predicate)
# The multi-tenant guarantee. Every alias of a policy-protected table
# must AND-include the required predicate.
# ===========================================================================
class TestTenantIsolation:
    def test_missing_predicate_rejected(self, policy: Policy, ctx: dict) -> None:
        r = verify("SELECT id FROM orders LIMIT 10", policy, context=ctx)
        assert not r.allowed
        assert any(
            v.code == ViolationCode.MISSING_REQUIRED_PREDICATE for v in r.violations
        )

    def test_wrong_tenant_value_rejected(self, policy: Policy, ctx: dict) -> None:
        """Context says 42, query uses 99 — must NOT satisfy the predicate."""
        r = verify(
            "SELECT id FROM orders WHERE account_id = 99 LIMIT 10",
            policy,
            context=ctx,
        )
        assert not r.allowed
        assert any(
            v.code == ViolationCode.MISSING_REQUIRED_PREDICATE for v in r.violations
        )

    def test_or_wrapped_predicate_does_not_satisfy(
        self, policy: Policy, ctx: dict
    ) -> None:
        """`account_id = 42 OR id = 5` — the OR side defeats isolation."""
        r = verify(
            "SELECT id FROM orders WHERE account_id = 42 OR id = 5 LIMIT 10",
            policy,
            context=ctx,
        )
        assert not r.allowed

    def test_in_single_literal_satisfies_equality(
        self, policy: Policy, ctx: dict
    ) -> None:
        """`account_id IN (42)` is semantically `account_id = 42`."""
        r = verify(
            "SELECT id FROM orders WHERE account_id IN (42) LIMIT 10",
            policy,
            context=ctx,
        )
        assert r.allowed, [v.code.value for v in r.violations]

    def test_flipped_equality_satisfies_predicate(
        self, policy: Policy, ctx: dict
    ) -> None:
        """`42 = account_id` is semantically identical to `account_id = 42`.
        An LLM that emits the literal-on-left shape (common for some
        prompting styles) should not be falsely flagged."""
        r = verify(
            "SELECT id, total FROM orders WHERE 42 = account_id LIMIT 10",
            policy,
            context=ctx,
        )
        assert r.allowed, [v.code.value for v in r.violations]

    def test_flipped_inequality_does_not_misapply_to_order_ops(self) -> None:
        """The commutativity fix must ONLY apply to `=`/`!=`. Order-
        sensitive operators (`<`, `<=`, `>`, `>=`) have different meaning
        when flipped — `100 < x` is NOT the same as `x < 100` — and must
        not be accepted as a satisfying match."""
        import sqlglot

        from sqlguard.core.rules.predicates import check_predicates

        p = Policy.from_dict(
            {
                "tables": [
                    {
                        "name": "items",
                        "allow_columns": ["id"],
                        "require_predicate": {"column": "x", "op": "<", "value": 100},
                    }
                ],
            }
        )
        e = sqlglot.parse_one("SELECT id FROM items WHERE 100 < x", dialect=None)
        codes = [v.code for v in check_predicates(e, p, {})]
        assert ViolationCode.MISSING_REQUIRED_PREDICATE in codes

    def test_in_multiple_literals_does_not_satisfy_equality(
        self, policy: Policy, ctx: dict
    ) -> None:
        """`account_id IN (42, 99)` could return tenant 99's data."""
        r = verify(
            "SELECT id FROM orders WHERE account_id IN (42, 99) LIMIT 10",
            policy,
            context=ctx,
        )
        assert not r.allowed

    def test_cast_around_column_accepted(
        self, policy: Policy, ctx: dict
    ) -> None:
        """`account_id::text` doesn't change the row set; accept."""
        r = verify(
            "SELECT id FROM orders WHERE account_id::text = '42' LIMIT 10",
            policy,
            context=ctx,
        )
        # cast on the COLUMN side is fine — only cast of an expression is
        # rejected. With ${tenant_id}=42, the literal '42' matches.
        assert r.allowed or not any(
            v.code == ViolationCode.MISSING_REQUIRED_PREDICATE for v in r.violations
        ), [v.code.value for v in r.violations]

    def test_self_join_requires_every_alias_filtered(
        self, policy: Policy, ctx: dict
    ) -> None:
        """THE classic bypass: filter one alias, leak via the other."""
        sql = (
            "SELECT o2.id FROM orders o1 JOIN orders o2 ON o1.id = o2.id "
            "WHERE o1.account_id = 42"
        )
        r = verify(sql, policy, context=ctx)
        assert not r.allowed
        assert any(
            v.code == ViolationCode.MISSING_REQUIRED_PREDICATE for v in r.violations
        )

    def test_self_join_both_aliases_filtered_passes(
        self, policy: Policy, ctx: dict
    ) -> None:
        sql = (
            "SELECT o2.id FROM orders o1 JOIN orders o2 ON o1.id = o2.id "
            "WHERE o1.account_id = 42 AND o2.account_id = 42 LIMIT 10"
        )
        r = verify(sql, policy, context=ctx)
        assert r.allowed, [v.code.value for v in r.violations]

    def test_inner_join_on_predicate_satisfies(
        self, policy: Policy, ctx: dict
    ) -> None:
        """For an INNER join, an ON-clause condition is semantically
        equivalent to a WHERE condition. LLMs commonly place tenant
        filters in the ON; the matcher must accept that."""
        sql = (
            "SELECT u.id FROM users u "
            "JOIN orders o ON u.id = o.id AND o.account_id = 42 LIMIT 10"
        )
        r = verify(sql, policy, context=ctx)
        assert r.allowed, [v.code.value for v in r.violations]

    def test_left_join_on_predicate_does_not_satisfy(
        self, policy: Policy, ctx: dict
    ) -> None:
        """For OUTER (LEFT/RIGHT/FULL) joins, a filter in the ON clause
        preserves left rows with NULL-padded right columns instead of
        filtering — NOT equivalent to WHERE. Must still require the
        predicate in WHERE."""
        sql = (
            "SELECT u.id FROM users u "
            "LEFT JOIN orders o ON u.id = o.id AND o.account_id = 42 LIMIT 10"
        )
        r = verify(sql, policy, context=ctx)
        assert not r.allowed
        assert any(
            v.code == ViolationCode.MISSING_REQUIRED_PREDICATE for v in r.violations
        )

    def test_self_join_both_aliases_filtered_via_on_clause(
        self, policy: Policy, ctx: dict
    ) -> None:
        """Per-alias enforcement still works when both filters live in
        the JOIN ON instead of WHERE."""
        sql = (
            "SELECT o2.id FROM orders o1 "
            "JOIN orders o2 "
            "ON o1.account_id = 42 AND o2.account_id = 42 AND o1.id = o2.id "
            "LIMIT 10"
        )
        r = verify(sql, policy, context=ctx)
        assert r.allowed, [v.code.value for v in r.violations]

    def test_cte_body_must_be_filtered(self, policy: Policy, ctx: dict) -> None:
        """`WITH x AS (SELECT FROM orders) SELECT FROM x WHERE account_id=42`
        — the predicate is on the wrong scope; CTE body is unfiltered."""
        sql = (
            "WITH x AS (SELECT id, account_id FROM orders) "
            "SELECT id FROM x WHERE account_id = 42 LIMIT 10"
        )
        r = verify(sql, policy, context=ctx)
        assert not r.allowed
        assert any(
            v.code == ViolationCode.MISSING_REQUIRED_PREDICATE for v in r.violations
        )

    def test_union_each_arm_independently_checked(
        self, policy: Policy, ctx: dict
    ) -> None:
        sql = (
            "SELECT id FROM orders WHERE account_id = 42 "
            "UNION SELECT id FROM orders"
        )
        r = verify(sql, policy, context=ctx)
        assert not r.allowed

    def test_missing_context_value_is_policy_error(
        self, policy: Policy
    ) -> None:
        """Forgetting to pass tenant_id must surface as POLICY_ERROR,
        not silently match the literal string '${tenant_id}'."""
        r = verify(
            "SELECT id FROM orders WHERE account_id = 42 LIMIT 10",
            policy,
            context={},
        )
        assert not r.allowed
        assert any(v.code == ViolationCode.POLICY_ERROR for v in r.violations)

    # --- DML enforcement (require_predicate on UPDATE/DELETE) ---

    @pytest.mark.parametrize(
        "sql",
        [
            "DELETE FROM orders WHERE id = 1",
            "UPDATE orders SET total = 0 WHERE id = 1",
            "DELETE FROM orders USING users WHERE orders.id = users.id",
            "UPDATE orders o SET total = 0 FROM users u WHERE o.id = u.id",
        ],
    )
    def test_dml_missing_tenant_predicate_blocked(
        self, writable_policy: Policy, ctx: dict, sql: str
    ) -> None:
        r = verify(sql, writable_policy, context=ctx)
        assert not r.allowed
        assert any(
            v.code == ViolationCode.MISSING_REQUIRED_PREDICATE for v in r.violations
        )

    @pytest.mark.parametrize(
        "sql",
        [
            "DELETE FROM orders WHERE account_id = 42 AND id = 1",
            "UPDATE orders SET total = 0 WHERE account_id = 42 AND id = 1",
        ],
    )
    def test_dml_with_tenant_predicate_allowed(
        self, writable_policy: Policy, ctx: dict, sql: str
    ) -> None:
        r = verify(sql, writable_policy, context=ctx)
        assert r.allowed, [v.code.value for v in r.violations]


# ===========================================================================
# Section 8 — IDENTIFIERS  (Defense 3 — column allowlist + name catchall)
# Column allowlists, deny_columns, qualified wildcards, HAVING, unresolved
# qualifiers, and the structural identifier-name catchall (USING bypass).
# ===========================================================================
class TestIdentifiers:
    # --- Column allow/deny lists ---

    def test_denied_column_blocked(self, policy: Policy, ctx: dict) -> None:
        r = verify(
            "SELECT password_hash FROM users LIMIT 10", policy, context=ctx
        )
        assert not r.allowed
        assert any(v.code == ViolationCode.COLUMN_DENIED for v in r.violations)

    def test_non_allowed_column_blocked(self, policy: Policy, ctx: dict) -> None:
        """A column outside allow_columns (and not in deny_columns)."""
        r = verify(
            "SELECT created_at, bogus_col FROM users WHERE id = 1 LIMIT 10",
            policy,
            context=ctx,
        )
        assert not r.allowed
        assert any(v.code == ViolationCode.COLUMN_DENIED for v in r.violations)

    def test_table_not_in_allowlist_blocked(
        self, policy: Policy, ctx: dict
    ) -> None:
        r = verify("SELECT * FROM other_table LIMIT 10", policy, context=ctx)
        assert not r.allowed
        assert any(v.code == ViolationCode.TABLE_DENIED for v in r.violations)

    # --- Quoted-identifier handling (H1) ---

    @pytest.mark.parametrize(
        "sql",
        [
            'SELECT id FROM "Orders" WHERE account_id = 42 LIMIT 10',
            'SELECT id FROM "ORDERS" WHERE account_id = 42 LIMIT 10',
        ],
    )
    def test_quoted_identifier_not_mistaken_for_policy_table(
        self, policy: Policy, ctx: dict, sql: str
    ) -> None:
        """PG-folding: `"Orders"` is a different table from `Orders` (which
        folds to `orders`). Policy applies only to the folded form."""
        r = verify(sql, policy, context=ctx)
        assert not r.allowed
        # The literal "Orders" should be TABLE_DENIED (not in allowlist) —
        # NOT MISSING_REQUIRED_PREDICATE (which would mean we applied
        # orders policy to a literally-different table).
        assert any(v.code == ViolationCode.TABLE_DENIED for v in r.violations)
        assert not any(
            v.code == ViolationCode.MISSING_REQUIRED_PREDICATE for v in r.violations
        )

    def test_unquoted_pg_folded_table_still_works(
        self, policy: Policy, ctx: dict
    ) -> None:
        r = verify(
            "SELECT id FROM ORDERS WHERE account_id = 42 LIMIT 10",
            policy, context=ctx,
        )
        assert r.allowed, [v.code.value for v in r.violations]

    # --- SELECT * / qualified wildcards ---

    def test_select_star_blocked(self, policy: Policy, ctx: dict) -> None:
        r = verify(
            "SELECT * FROM orders WHERE account_id = 42 LIMIT 10",
            policy, context=ctx,
        )
        assert not r.allowed
        assert any(v.code == ViolationCode.SELECT_STAR for v in r.violations)

    def test_count_star_still_allowed(self, policy: Policy, ctx: dict) -> None:
        r = verify(
            "SELECT count(*) FROM orders WHERE account_id = 42 LIMIT 10",
            policy, context=ctx,
        )
        assert r.allowed, [v.code.value for v in r.violations]

    def test_count_distinct_star_blocked(self, policy: Policy, ctx: dict) -> None:
        """`count(DISTINCT *)` row-expands the `*` (so every column counts
        toward distinctness, including denied ones) — different semantics
        from bare `count(*)`. Treat as SELECT_STAR."""
        r = verify(
            "SELECT count(DISTINCT *) FROM orders WHERE account_id = 42 LIMIT 10",
            policy, context=ctx,
        )
        assert not r.allowed
        assert any(v.code == ViolationCode.SELECT_STAR for v in r.violations)

    @pytest.mark.parametrize(
        "sql",
        [
            # alias.* inside a function expands to every column
            # of the aliased table — including denied ones.
            "SELECT to_jsonb(users.*) FROM users WHERE id = 1 LIMIT 10",
            "SELECT row_to_json(users.*) FROM users WHERE id = 1 LIMIT 10",
            "SELECT json_agg(u.*) FROM users u WHERE id = 1 LIMIT 10",
            "SELECT u.* FROM users u WHERE id = 1 LIMIT 10",
        ],
    )
    def test_qualified_wildcard_blocked(
        self, policy: Policy, ctx: dict, sql: str
    ) -> None:
        r = verify(sql, policy, context=ctx)
        assert not r.allowed

    # --- HAVING ---

    @pytest.mark.parametrize(
        "sql",
        [
            # sqlglot's scope.columns walks SELECT/WHERE/GROUP BY/ORDER BY
            # but NOT HAVING. Bypasses found here:
            "SELECT id FROM users GROUP BY id "
            "HAVING bool_or(substr(password_hash, 1, 1) = 'a')",
            "SELECT 1 FROM users HAVING max(password_hash) IS NOT NULL",
            "SELECT id FROM users GROUP BY id HAVING "
            "max(CASE WHEN substr(ssn,1,1) > '5' THEN 1 ELSE 0 END) = 1",
        ],
    )
    def test_denied_column_in_having_blocked(
        self, policy: Policy, ctx: dict, sql: str
    ) -> None:
        r = verify(sql, policy, context=ctx)
        assert not r.allowed
        assert any(v.code == ViolationCode.COLUMN_DENIED for v in r.violations)

    def test_legitimate_having_still_allowed(
        self, policy: Policy, ctx: dict
    ) -> None:
        r = verify(
            "SELECT account_id, count(*) FROM orders WHERE account_id = 42 "
            "GROUP BY account_id HAVING count(*) > 5 LIMIT 10",
            policy, context=ctx,
        )
        assert r.allowed, [v.code.value for v in r.violations]

    # --- Unresolved column qualifier ---

    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT public.password_hash FROM users WHERE id = 1 LIMIT 10",
            "SELECT bogus.password_hash FROM users WHERE id = 1 LIMIT 10",
            'SELECT "bogus".password_hash FROM users WHERE id = 1 LIMIT 10',
        ],
    )
    def test_unresolved_qualifier_fails_closed(
        self, policy: Policy, ctx: dict, sql: str
    ) -> None:
        r = verify(sql, policy, context=ctx)
        assert not r.allowed
        assert any(v.code == ViolationCode.COLUMN_DENIED for v in r.violations)

    # --- Schema-qualified policy entries ---

    def test_schema_qualified_policies_do_not_collide(self) -> None:
        """Regression: two TablePolicy entries with the same `name:` but
        different `schema:` must NOT silently collapse to the first one.
        Previously `table_by_name` matched on name only — `public.orders`
        and `analytics.orders` got the same policy applied."""
        p = _policy(
            {
                "tables": [
                    {"name": "orders", "schema": "analytics", "allow_columns": ["id"]},
                    {"name": "orders", "schema": "public", "allow_columns": ["name"]},
                ],
            }
        )
        # analytics.orders allows `id` — should pass.
        r = verify("SELECT id FROM analytics.orders LIMIT 1", p)
        assert r.allowed, [v.code.value for v in r.violations]

        # public.orders does NOT allow `id` (only `name`) — must deny.
        r = verify("SELECT id FROM public.orders LIMIT 1", p)
        assert not r.allowed
        assert any(v.code == ViolationCode.COLUMN_DENIED for v in r.violations)

        # public.orders allows `name` — should pass.
        r = verify("SELECT name FROM public.orders LIMIT 1", p)
        assert r.allowed, [v.code.value for v in r.violations]

    def test_unqualified_policy_matches_any_schema(self) -> None:
        """Backward compat: a TablePolicy with no `schema:` matches a
        schema-qualified query (the historical behavior — `schema:` is
        an optional filter, not a barrier for unqualified policies)."""
        p = _policy(
            {"tables": [{"name": "orders", "allow_columns": ["id"]}]}
        )
        r = verify("SELECT id FROM public.orders LIMIT 1", p)
        assert r.allowed, [v.code.value for v in r.violations]
        r = verify("SELECT id FROM analytics.orders LIMIT 1", p)
        assert r.allowed, [v.code.value for v in r.violations]

    def test_schema_qualified_policy_matches_unqualified_query(self) -> None:
        """A schema-qualified policy `{name: orders, schema: public}` also
        matches an unqualified query `SELECT FROM orders` — search_path is
        assumed to resolve to that schema at runtime."""
        p = _policy(
            {
                "tables": [
                    {"name": "orders", "schema": "public", "allow_columns": ["id"]}
                ],
            }
        )
        r = verify("SELECT id FROM orders LIMIT 1", p)
        assert r.allowed, [v.code.value for v in r.violations]

    def test_alias_collision_does_not_misattribute_denied_column(self) -> None:
        """Regression: `FROM public.users, analytics.users` (same alias)
        used to collapse both Tables under the bare alias `users`. If the
        surviving entry allowed a column that the lost entry denied, the
        denied column slipped through. Schema-qualified column references
        (`public.users.email`) must resolve against the right policy entry.
        """
        p = _policy(
            {
                "tables": [
                    {
                        "name": "users",
                        "schema": "public",
                        "deny_columns": ["email"],
                        "allow_columns": ["id", "email"],
                    },
                    {
                        "name": "users",
                        "schema": "analytics",
                        "allow_columns": ["id", "email"],
                    },
                ],
                "forbid": {"cartesian_join": False},
            }
        )
        # The DENIED column on public.users must be flagged.
        r = verify(
            "SELECT public.users.email FROM public.users, analytics.users LIMIT 10",
            p,
        )
        assert not r.allowed
        denied = [v for v in r.violations if v.code == ViolationCode.COLUMN_DENIED]
        assert any("public.users" in v.message for v in denied), [
            v.message for v in denied
        ]

        # The ALLOWED column on analytics.users must still be allowed.
        r = verify(
            "SELECT analytics.users.email FROM public.users, analytics.users LIMIT 10",
            p,
        )
        assert r.allowed, [v.message for v in r.violations]

    def test_bogus_schema_qualifier_fails_closed(self) -> None:
        """`SELECT bogus.users.email FROM public.users` — the schema
        qualifier doesn't match any in-scope Table. Fail closed."""
        p = _policy(
            {
                "tables": [
                    {
                        "name": "users",
                        "schema": "public",
                        "allow_columns": ["id", "email"],
                    },
                ],
            }
        )
        r = verify("SELECT bogus.users.email FROM public.users LIMIT 10", p)
        assert not r.allowed
        assert any(
            v.code == ViolationCode.COLUMN_DENIED
            and "bogus" in v.message
            for v in r.violations
        )

    def test_schema_qualified_require_predicate_enforced_per_schema(self) -> None:
        """`require_predicate` on `public.orders` does not apply to
        `analytics.orders` — each schema has its own policy entry."""
        p = _policy(
            {
                "tables": [
                    {
                        "name": "orders",
                        "schema": "public",
                        "allow_columns": ["id", "account_id"],
                        "require_predicate": {
                            "column": "account_id", "op": "=", "value": "${tenant_id}",
                        },
                    },
                    {
                        "name": "orders",
                        "schema": "analytics",
                        "allow_columns": ["id"],
                    },
                ],
            }
        )
        # public.orders without predicate → denied.
        r = verify("SELECT id FROM public.orders LIMIT 1", p, context={"tenant_id": 42})
        assert not r.allowed
        assert any(
            v.code == ViolationCode.MISSING_REQUIRED_PREDICATE for v in r.violations
        )
        # analytics.orders without predicate → allowed (no require_predicate).
        r = verify("SELECT id FROM analytics.orders LIMIT 1", p, context={"tenant_id": 42})
        assert r.allowed, [v.code.value for v in r.violations]

    def test_schema_qualified_large_does_not_force_limit_on_other_schema(self) -> None:
        """`large: true` on `public.orders` does not force a LIMIT on
        `analytics.orders`."""
        p = _policy(
            {
                "tables": [
                    {
                        "name": "orders",
                        "schema": "public",
                        "allow_columns": ["id"],
                        "large": True,
                    },
                    {
                        "name": "orders",
                        "schema": "analytics",
                        "allow_columns": ["id"],
                    },
                ],
            }
        )
        r = verify("SELECT id FROM analytics.orders", p)
        assert r.allowed, [v.code.value for v in r.violations]
        # And public.orders still requires LIMIT.
        r = verify("SELECT id FROM public.orders", p)
        assert not r.allowed
        assert any(v.code == ViolationCode.LIMIT_REQUIRED for v in r.violations)

    def test_real_alias_qualifier_still_allowed(
        self, policy: Policy, ctx: dict
    ) -> None:
        for sql in [
            "SELECT o.id, o.total FROM orders o WHERE o.account_id = 42 LIMIT 10",
            "SELECT users.id, users.name FROM users WHERE id = 1 LIMIT 10",
        ]:
            r = verify(sql, policy, context=ctx)
            assert r.allowed, [v.code.value for v in r.violations]

    def test_cte_and_subquery_qualifiers_still_allowed(
        self, policy: Policy, ctx: dict
    ) -> None:
        for sql in [
            "WITH t AS (SELECT id, name FROM users WHERE id = 1) "
            "SELECT t.id, t.name FROM t LIMIT 10",
            "SELECT s.id, s.name FROM "
            "(SELECT id, name FROM users WHERE id = 1) s LIMIT 10",
        ]:
            r = verify(sql, policy, context=ctx)
            assert r.allowed, [v.code.value for v in r.violations]

    # --- Identifier-name catchall (Defense 3) ---
    # Closes USING (denied), alias-as-denied-name, and the entire class
    # of "denied col appears as an Identifier not wrapped in a Column."

    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT u.id FROM users u JOIN users u2 USING (password_hash) LIMIT 1",
            "SELECT u.id FROM users u JOIN users u2 USING (ssn, password_hash) LIMIT 1",
            "SELECT id AS password_hash FROM users LIMIT 1",
            'SELECT u.id FROM users u JOIN users u2 USING ("password_hash") LIMIT 1',
            "WITH x AS (SELECT id FROM users u JOIN users u2 USING (password_hash)) "
            "SELECT id FROM x LIMIT 1",
        ],
    )
    def test_denied_identifier_in_any_position(
        self, policy: Policy, ctx: dict, sql: str
    ) -> None:
        r = verify(sql, policy, context=ctx)
        assert not r.allowed
        assert any(v.code == ViolationCode.COLUMN_DENIED for v in r.violations)

    def test_catchall_no_double_flag_on_direct_ref(
        self, policy: Policy, ctx: dict
    ) -> None:
        """A direct Column reference to a denied column → ONE violation,
        not two (main column walk + identifier catchall)."""
        r = verify("SELECT password_hash FROM users LIMIT 1", policy, context=ctx)
        codes = [v.code.value for v in r.violations]
        assert codes.count("COLUMN_DENIED") == 1, codes

    def test_catchall_no_double_flag_on_insert_target(self) -> None:
        """Regression: INSERT target columns are wrapped in exp.Schema,
        and the synthesized DmlScope.columns already covers them with the
        main allowlist walk. The identifier-name catchall must skip
        exp.Schema parents to avoid duplicating COLUMN_DENIED."""
        p = _policy(
            {
                "read_only": False,
                "tables": [
                    {
                        "name": "users",
                        "allow_columns": ["id", "name"],
                        "deny_columns": ["password_hash"],
                    }
                ],
            }
        )
        r = verify(
            "INSERT INTO users (id, password_hash) VALUES (1, 'pwn')",
            p,
        )
        codes = [v.code.value for v in r.violations]
        assert codes.count("COLUMN_DENIED") == 1, codes

    def test_catchall_no_false_positive_on_literal_value(
        self, policy: Policy, ctx: dict
    ) -> None:
        """A literal string containing a denied column name is not an
        Identifier — must not be flagged."""
        r = verify(
            "SELECT id FROM users WHERE name = 'password_hash' LIMIT 10",
            policy, context=ctx,
        )
        assert r.allowed, [v.code.value for v in r.violations]


# ===========================================================================
# Section 9 — DoS CAPS
# Joins, subquery depth, LIMIT/OFFSET, AST node count.
# ===========================================================================
class TestDosCaps:
    def test_cartesian_join_blocked(self, policy: Policy, ctx: dict) -> None:
        sql = "SELECT o.id FROM orders o, orders o2 WHERE o.account_id = 42"
        r = verify(sql, policy, context=ctx)
        assert not r.allowed
        assert any(v.code == ViolationCode.CARTESIAN_JOIN for v in r.violations)

    def test_recursive_cte_blocked(self, policy: Policy, ctx: dict) -> None:
        sql = "WITH RECURSIVE r AS (SELECT 1 AS n UNION SELECT n+1 FROM r) SELECT n FROM r LIMIT 10"
        r = verify(sql, policy, context=ctx)
        assert not r.allowed
        assert any(v.code == ViolationCode.RECURSIVE_CTE for v in r.violations)

    def test_large_table_requires_limit(
        self, policy: Policy, ctx: dict
    ) -> None:
        r = verify(
            "SELECT id FROM orders WHERE account_id = 42", policy, context=ctx
        )
        assert not r.allowed
        assert any(v.code == ViolationCode.LIMIT_REQUIRED for v in r.violations)

    def test_sibling_subquery_limit_does_not_satisfy(
        self, policy: Policy, ctx: dict
    ) -> None:
        """LIMIT inside a non-ancestor subquery doesn't bound the outer table."""
        sql = (
            "SELECT id, total FROM orders WHERE account_id = 42 "
            "AND id < (SELECT count(*) FROM users LIMIT 1)"
        )
        r = verify(sql, policy, context=ctx)
        assert not r.allowed
        assert any(v.code == ViolationCode.LIMIT_REQUIRED for v in r.violations)

    def test_inner_cte_limit_satisfies(
        self, policy: Policy, ctx: dict
    ) -> None:
        sql = (
            "WITH x AS (SELECT id, total FROM orders WHERE account_id = 42 LIMIT 1000) "
            "SELECT id FROM x"
        )
        r = verify(sql, policy, context=ctx)
        assert r.allowed, [v.code.value for v in r.violations]

    def test_limit_all_is_not_effective(
        self, policy: Policy, ctx: dict
    ) -> None:
        """`LIMIT ALL` is PG syntax for unlimited. Must NOT satisfy
        require_limit AND must NOT trip COLUMN_DENIED on the pseudo-col."""
        r = verify(
            "SELECT id, total FROM orders WHERE account_id = 42 LIMIT ALL",
            policy, context=ctx,
        )
        assert not r.allowed
        codes = [v.code for v in r.violations]
        assert ViolationCode.LIMIT_REQUIRED in codes
        assert ViolationCode.COLUMN_DENIED not in codes

    def test_limit_zero_does_not_satisfy(
        self, policy: Policy, ctx: dict
    ) -> None:
        r = verify(
            "SELECT id, total FROM orders WHERE account_id = 42 LIMIT 0",
            policy, context=ctx,
        )
        assert not r.allowed
        assert any(v.code == ViolationCode.LIMIT_REQUIRED for v in r.violations)

    @pytest.mark.parametrize(
        "fetch_clause",
        [
            "FETCH FIRST 10 ROWS ONLY",
            "FETCH NEXT 10 ROWS ONLY",
            "FETCH FIRST 1 ROW ONLY",
        ],
    )
    def test_fetch_first_satisfies_limit(
        self, policy: Policy, ctx: dict, fetch_clause: str
    ) -> None:
        """SQL:2008 standard syntax; sqlglot parses as exp.Fetch under
        the `limit` arg."""
        sql = f"SELECT id, total FROM orders WHERE account_id = 42 {fetch_clause}"
        r = verify(sql, policy, context=ctx)
        assert r.allowed, [v.code.value for v in r.violations]

    def test_excessive_offset_blocked(self, policy: Policy, ctx: dict) -> None:
        """OFFSET 99M forces PG to scan-and-skip 100M rows — DoS vector."""
        sql = "SELECT id, total FROM orders WHERE account_id = 42 LIMIT 10 OFFSET 99999999"
        r = verify(sql, policy, context=ctx)
        assert not r.allowed

    def test_reasonable_offset_allowed(self, policy: Policy, ctx: dict) -> None:
        sql = "SELECT id, total FROM orders WHERE account_id = 42 LIMIT 10 OFFSET 20"
        r = verify(sql, policy, context=ctx)
        assert r.allowed, [v.code.value for v in r.violations]

    @pytest.mark.parametrize("set_op", ["UNION", "UNION ALL", "INTERSECT", "EXCEPT"])
    def test_set_operation_top_level_limit_satisfies_large_table(
        self, policy: Policy, ctx: dict, set_op: str
    ) -> None:
        """PG accepts a top-level LIMIT on every set-op flavor. Regression:
        `_has_limit_in_lineage` previously only walked exp.Select and
        exp.Union, so an INTERSECT or EXCEPT root with LIMIT failed the
        large-table check."""
        sql = (
            f"SELECT id FROM orders WHERE account_id = 42 {set_op} "
            f"SELECT id FROM orders WHERE account_id = 42 LIMIT 5"
        )
        r = verify(sql, policy, context=ctx)
        assert r.allowed, [v.code.value for v in r.violations]

    def test_default_policy_has_safe_dos_caps(self) -> None:
        """A Policy() with no overrides must still impose meaningful caps."""
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            p = _policy({})
        assert p.limits.max_joins is not None and p.limits.max_joins > 0
        assert p.limits.max_subquery_depth is not None
        assert p.limits.max_ast_nodes is not None

    def test_cte_body_does_not_inflate_subquery_depth(self) -> None:
        """`WITH a AS (SELECT FROM x) SELECT FROM a` is depth 1, not 2.
        Without the fix, max_subquery_depth=1 rejects every CTE query."""
        p = _policy(
            {
                "limits": {"max_subquery_depth": 1},
                "tables": [{"name": "orders", "allow_columns": ["id"]}],
            }
        )
        r = verify("WITH a AS (SELECT id FROM orders) SELECT id FROM a", p)
        assert r.allowed, [v.message for v in r.violations]

    def test_nested_subquery_still_counts_as_depth(self) -> None:
        """Sanity: real nested subqueries (not via WITH) still count."""
        p = _policy(
            {
                "limits": {"max_subquery_depth": 1},
                "tables": [{"name": "orders", "allow_columns": ["id"]}],
            }
        )
        r = verify("SELECT id FROM (SELECT id FROM orders) sub", p)
        assert not r.allowed
        assert any(v.code == ViolationCode.MAX_SUBQUERY_DEPTH for v in r.violations)

    def test_cross_schema_large_tables_each_fire_limit_required(self) -> None:
        """Two same-named `large` tables in different schemas (`public.orders`,
        `analytics.orders`) must surface as TWO violations, not one. The
        dedupe key must key on (table, schema): keying on the bare table
        name alone would silently swallow the second — leaving the integrator unaware that one of
        the two tables in their query was still unbounded."""
        p = _policy(
            {
                "tables": [
                    {
                        "name": "orders",
                        "schema": "public",
                        "allow_columns": ["id"],
                        "large": True,
                    },
                    {
                        "name": "orders",
                        "schema": "analytics",
                        "allow_columns": ["id"],
                        "large": True,
                    },
                ],
                "forbid": {"cartesian_join": False},
            }
        )
        sql = (
            "SELECT public.orders.id, analytics.orders.id "
            "FROM public.orders, analytics.orders"
        )
        r = verify(sql, p)
        limit_required = [
            v for v in r.violations if v.code == ViolationCode.LIMIT_REQUIRED
        ]
        assert len(limit_required) == 2, [v.message for v in r.violations]
        messages = " ".join(v.message for v in limit_required)
        assert "public.orders" in messages
        assert "analytics.orders" in messages


# ===========================================================================
# Section 10 — POLICY HYGIENE (extra="forbid")
# Typos in policy YAML must raise ValidationError instead of silently
# dropping the misspelled rule. Representative tests only.
# ===========================================================================
class TestPolicyHygiene:
    @pytest.mark.parametrize(
        "bad_doc",
        [
            # Top-level typos
            {"tabls": []},
            {"readonly": True},
            {"limit": {}},
            # Nested typos
            {"tables": [{"name": "x", "allow_colums": ["id"]}]},
            {"forbid": {"select_starr": True}},
            {"limits": {"max_join": 5}},
            {"tables": [{"name": "x", "require_predicate": {"col": "id", "value": 1}}]},
        ],
    )
    def test_unknown_key_rejected(self, bad_doc: dict) -> None:
        with pytest.raises(ValidationError):
            _policy(bad_doc)

    def test_correct_keys_still_work(self) -> None:
        p = _policy(
            {
                "read_only": True,
                "tables": [
                    {
                        "name": "users",
                        "schema": "public",
                        "allow_columns": ["id"],
                        "deny_columns": ["password_hash"],
                        "require_predicate": {"column": "id", "op": "=", "value": 1},
                    }
                ],
                "forbid": {"select_star": True},
                "limits": {"max_joins": 3},
            }
        )
        assert p.tables[0].schema_name == "public"

    def test_empty_policy_warns(self) -> None:
        """Policy() with no allowlist must surface unsafe defaults."""
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            _policy({})
        assert any("no `tables` allowlist" in str(w.message) for w in caught)


# ===========================================================================
# Section 11 — PUBLIC API CONTRACT
# Violation.category mapping and has_category() shortcut. Not "security"
# per se but anchor the integration surface so a refactor can't silently
# break callers.
# ===========================================================================
class TestPublicApi:
    def test_category_mapping_covers_all_codes(self) -> None:
        """Every ViolationCode must have a category; new codes without a
        mapping default to DENIED (fail-closed) but should be explicit."""
        from sqlguard.result import _CATEGORY

        for code in ViolationCode:
            assert code in _CATEGORY, (
                f"{code.value} missing from _CATEGORY map in result.py"
            )

    def test_has_category_shortcut(self) -> None:
        """The one-liner for callers who don't want to enumerate codes."""
        p = _policy(
            {
                "tables": [
                    {
                        "name": "users",
                        "allow_columns": ["id"],
                        "deny_columns": ["password_hash"],
                    }
                ]
            }
        )
        r = verify("SELECT password_hash FROM users", p)
        assert r.has_category(ViolationCategory.DENIED)
        r = verify("SELECT id FROM users", p)
        assert not r.has_category(ViolationCategory.DENIED)

    def test_category_default_is_denied_for_unmapped(self) -> None:
        """If a future code is added without a category, it defaults to
        DENIED so the unhandled violation never becomes a non-deny."""
        from sqlguard.result import _CATEGORY

        v = Violation(code=ViolationCode.COLUMN_DENIED, message="x")
        saved = _CATEGORY.pop(ViolationCode.COLUMN_DENIED)
        try:
            assert v.category == ViolationCategory.DENIED
        finally:
            _CATEGORY[ViolationCode.COLUMN_DENIED] = saved


# ===========================================================================
# Section 12 — OUTER-SCOPE ALIAS RESOLUTION
# Correlated subqueries (EXISTS, scalar, IN-subquery) and LATERAL joins can
# legitimately reference an outer scope's table alias. A bug in earlier
# versions falsely flagged every such reference as COLUMN_DENIED ("column
# qualifier 'o' does not reference any table or CTE in scope"), blocking
# the most common LLM-emitted patterns. The fix walks ancestor scopes —
# and ancestor DML targets, since traverse_scope skips DML roots — before
# declaring a qualifier bogus.
# ===========================================================================
class TestOuterScopeAliasResolution:
    """Each pair: an ALLOW case (legit outer reference) and a DENY case
    (denied column or genuinely bogus qualifier) — defense-in-depth must
    still fire while the false-positive is gone."""

    @pytest.fixture
    def policy_correlated(self) -> Policy:
        return _policy(
            {
                "tables": [
                    {
                        "name": "orders",
                        "allow_columns": ["id", "account_id", "total"],
                        "require_predicate": {
                            "column": "account_id",
                            "op": "=",
                            "value": "${tenant_id}",
                        },
                    },
                    {
                        "name": "users",
                        "allow_columns": ["id", "name"],
                        "deny_columns": ["password_hash"],
                    },
                ]
            }
        )

    @pytest.mark.parametrize(
        "sql",
        [
            # Scalar correlated subquery with outer alias 'o'.
            "SELECT o.id, (SELECT count(*) FROM users u WHERE u.id = o.id) "
            "FROM orders o WHERE o.account_id = 42 LIMIT 10",
            # EXISTS correlated.
            "SELECT o.id FROM orders o WHERE o.account_id = 42 "
            "AND EXISTS (SELECT 1 FROM users u WHERE u.id = o.id) LIMIT 10",
            # NOT EXISTS correlated.
            "SELECT o.id FROM orders o WHERE o.account_id = 42 "
            "AND NOT EXISTS (SELECT 1 FROM users u WHERE u.id = o.id) LIMIT 10",
            # LATERAL with outer alias 'u'.
            "SELECT u.id, p.total FROM users u, "
            "LATERAL (SELECT total FROM orders WHERE account_id = 42 AND id = u.id) p",
        ],
    )
    def test_correlated_subquery_outer_alias_is_allowed(
        self, policy_correlated: Policy, sql: str
    ) -> None:
        """Regression: inner scopes can reference outer-scope table aliases
        without the validator falsely emitting a bogus-qualifier denial."""
        r = verify(sql, policy_correlated, context={"tenant_id": 42})
        assert r.allowed, (
            f"outer-alias resolution regressed: {sql!r} should be allowed "
            f"but got {[v.code.value for v in r.violations]}"
        )

    @pytest.mark.parametrize(
        "sql",
        [
            # Denied col via correlated subquery using outer alias —
            # still caught (defense-in-depth via the identifier-name catchall
            # plus the per-table check on the resolved outer table).
            "SELECT o.id FROM orders o WHERE o.account_id = 42 "
            "AND EXISTS (SELECT 1 FROM users u WHERE u.password_hash = 'x') LIMIT 10",
            # Denied col on outer alias inside LATERAL.
            "SELECT u.id, p.x FROM users u, LATERAL "
            "(SELECT u.password_hash AS x FROM orders WHERE account_id = 42 AND id = u.id) p",
            # Truly bogus qualifier — neither current scope nor any ancestor
            # has it. Must still emit COLUMN_DENIED.
            "SELECT bogus.id FROM orders WHERE account_id = 42 LIMIT 1",
        ],
    )
    def test_outer_alias_fix_does_not_weaken_denials(
        self, policy_correlated: Policy, sql: str
    ) -> None:
        r = verify(sql, policy_correlated, context={"tenant_id": 42})
        assert not r.allowed
        assert any(
            v.code == ViolationCode.COLUMN_DENIED for v in r.violations
        )

    def test_update_correlated_subquery_resolves_dml_target(self) -> None:
        """UPDATE ... WHERE ... = (SELECT ... FROM t o WHERE o.col = t.col):
        the inner subquery's reference to the outer UPDATE target ``t`` must
        resolve. ``traverse_scope`` skips DML roots, so the fix walks the
        AST upward to pick up enclosing Update/Delete/Insert/Merge targets.
        Without this, ``orders.account_id`` in the inner subquery hit the
        bogus-qualifier path."""
        p = _policy(
            {
                "read_only": False,
                "tables": [
                    {
                        "name": "orders",
                        "allow_columns": ["id", "account_id", "total"],
                        "require_predicate": {
                            "column": "account_id",
                            "op": "=",
                            "value": "${tenant_id}",
                        },
                    }
                ],
            }
        )
        sql = (
            "UPDATE orders SET total = total + 1 "
            "WHERE account_id = 42 AND id = "
            "(SELECT max(id) FROM orders o WHERE o.account_id = orders.account_id)"
        )
        r = verify(sql, p, context={"tenant_id": 42})
        # The bogus-qualifier denial on 'orders' must NOT fire — that was
        # the regression we fixed. The MISSING_REQUIRED_PREDICATE on the
        # inner alias 'o' (no literal tenant filter) is correct and
        # expected to still fire.
        bogus = [
            v for v in r.violations
            if v.code == ViolationCode.COLUMN_DENIED
            and "does not reference any table or CTE" in v.message
        ]
        assert not bogus, (
            f"bogus-qualifier regression on UPDATE-correlated: "
            f"{[(v.code.value, v.message) for v in r.violations]}"
        )


# ===========================================================================
# Section 13 — NATURAL JOIN
# NATURAL JOIN implicitly joins on every same-named column. Those columns
# never appear as Identifier nodes in the AST, so the column allowlist /
# identifier-name catchall can't see them. Always rejected.
# ===========================================================================
class TestNaturalJoin:
    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT a.id FROM a NATURAL JOIN b",
            "SELECT a.id FROM a NATURAL INNER JOIN b",
            "SELECT a.id FROM a NATURAL LEFT JOIN b",
            "SELECT a.id FROM a NATURAL FULL JOIN b",
        ],
    )
    def test_natural_join_is_always_denied(self, sql: str) -> None:
        """NATURAL JOIN bypasses the column allowlist because the implicit
        join columns never reach the AST as Identifier nodes — always
        rejected, no policy toggle needed (same class as multi-statement)."""
        r = verify(sql, _policy({"read_only": True}))
        assert not r.allowed
        assert any(
            v.code == ViolationCode.NATURAL_JOIN_FORBIDDEN
            for v in r.violations
        ), [v.code.value for v in r.violations]

    @pytest.mark.parametrize(
        "sql",
        [
            "SELECT a.id FROM a NATURAL JOIN b",
            "SELECT a.id FROM a NATURAL LEFT JOIN b",
        ],
    )
    def test_natural_join_not_misclassified_as_cartesian(self, sql: str) -> None:
        """Regression: NATURAL JOIN has no ON/USING, so the cartesian-join
        check used to false-flag it as ``CARTESIAN_JOIN``. The fix skips
        NATURAL joins in the cartesian check; the dedicated rule emits
        the clearer ``NATURAL_JOIN_FORBIDDEN`` code."""
        r = verify(sql, _policy({"read_only": True}))
        cartesian = [
            v for v in r.violations if v.code == ViolationCode.CARTESIAN_JOIN
        ]
        assert not cartesian, (
            f"NATURAL JOIN should not be flagged as CARTESIAN_JOIN: "
            f"{[v.code.value for v in r.violations]}"
        )

    def test_real_cartesian_still_denied(self) -> None:
        """Smoke: the cartesian rule still fires on actual CROSS JOIN /
        comma-join with no ON / no USING."""
        for sql in [
            "SELECT a.id FROM a CROSS JOIN b",
            "SELECT a.id FROM a, b",
        ]:
            r = verify(sql, _policy({"read_only": True}))
            assert any(
                v.code == ViolationCode.CARTESIAN_JOIN for v in r.violations
            ), f"cartesian regression on {sql!r}: {[v.code.value for v in r.violations]}"
