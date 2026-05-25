from __future__ import annotations

import pytest

from sqlguard.config.schema import Policy, RequiredPredicate


def test_policy_defaults() -> None:
    p = Policy.from_dict({})
    assert p.read_only is True


def test_predicate_resolves_scalar_placeholder() -> None:
    pred = RequiredPredicate(column="account_id", op="=", value="${tenant_id}")
    resolved = pred.resolve({"tenant_id": 42})
    assert resolved.value == 42


def test_predicate_resolves_list_placeholder() -> None:
    pred = RequiredPredicate(column="account_id", op="IN", value="${tenant_ids}")
    resolved = pred.resolve({"tenant_ids": [1, 2, 3]})
    assert resolved.value == [1, 2, 3]


def test_predicate_missing_placeholder_raises() -> None:
    pred = RequiredPredicate(column="account_id", op="=", value="${tenant_id}")
    with pytest.raises(KeyError):
        pred.resolve({})


def test_table_by_name_is_case_sensitive_after_folding() -> None:
    """Per PG semantics: `name: orders` matches unquoted `FROM Orders`
    (which PG folds to 'orders'); `name: Orders` matches only quoted
    `FROM "Orders"` (literally case-preserved). The lookup itself is
    case-sensitive — callers fold the SQL input before looking up.
    """
    p = Policy.from_dict({"tables": [{"name": "Orders"}]})
    # Caller is expected to fold the input — i.e. only quoted "Orders"
    # would yield the literal 'Orders' string here.
    assert p.table_by_name("Orders") is not None
    assert p.table_by_name("orders") is None  # would be the unquoted match
    assert p.table_by_name("ORDERS") is None  # quoted "ORDERS" — different table
    assert p.table_by_name("missing") is None


def test_table_by_name_lowercase_yaml() -> None:
    """The common case: YAML uses lowercase, SQL is unquoted (which gets
    folded to lowercase). After folding, the caller passes 'orders'."""
    p = Policy.from_dict({"tables": [{"name": "orders"}]})
    assert p.table_by_name("orders") is not None
    assert p.table_by_name("Orders") is None  # quoted "Orders" should NOT match


def test_require_predicate_accepts_single_dict_or_list() -> None:
    p1 = Policy.from_dict(
        {"tables": [{"name": "orders", "require_predicate": {"column": "x", "value": 1}}]}
    )
    p2 = Policy.from_dict(
        {"tables": [{"name": "orders", "require_predicate": [{"column": "x", "value": 1}]}]}
    )
    assert p1.tables[0].require_predicate == p2.tables[0].require_predicate


def test_removed_fields_are_rejected() -> None:
    """Fields cut in 0.3 (dialect, mode, max_statements, schemas,
    forbid.lock_clause, limits.require_limit_on_large_tables) must now
    raise ValidationError, so old policies surface a clear error instead
    of silently no-opping."""
    from pydantic import ValidationError

    for bad in [
        {"dialect": "postgres"},
        {"mode": "warn"},
        {"max_statements": 5},
        {"schemas": {"allow": ["public"]}},
        {"forbid": {"lock_clause": True}},
        {"limits": {"require_limit_on_large_tables": True}},
        {"forbid": {"pg_catalog_access": True}},
        {"forbid": {"time_based_functions": True}},
    ]:
        with pytest.raises(ValidationError):
            Policy.from_dict(bad)
