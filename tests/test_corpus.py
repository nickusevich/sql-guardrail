"""Run every file in tests/malicious/ and tests/benign/ through verify().

A startup integrity check fails collection if a file exists on disk
but isn't listed in ``tests/malicious/_manifest.json`` (or vice-versa),
so a new malicious fixture can't silently slip past unclassified.

A separate parametrized test (``test_readme_example_policy_*``) loads
the actual ``examples/policy.yml`` and runs a small set of representative
LLM-shaped queries through it. The intent is to catch regressions where
the README's recommended policy stops accepting realistic SQL — the
exact failure mode that the AND/OR/CASE/EXISTS keyword-as-function bug
exhibited.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from sqlguard import Policy, verify

_CORPUS = Path(__file__).parent
_MALICIOUS_DIR = _CORPUS / "malicious"
_BENIGN_FILES = sorted((_CORPUS / "benign").glob("*.sql"))
_EXAMPLE_POLICY_PATH = _CORPUS.parent / "examples" / "policy.yml"


def _load_manifest() -> list[str]:
    raw = json.loads((_MALICIOUS_DIR / "_manifest.json").read_text())
    # Strip leading "_comment" key (purely documentation).
    return list(raw["files"])


def _ensure_manifest_in_sync() -> None:
    listed = set(_load_manifest())
    on_disk = {p.name for p in _MALICIOUS_DIR.glob("*.sql")}
    missing = on_disk - listed
    extra = listed - on_disk
    if missing or extra:
        raise RuntimeError(
            "tests/malicious/_manifest.json is out of sync with tests/malicious/: "
            f"on disk but not in manifest={sorted(missing)!r}; "
            f"in manifest but not on disk={sorted(extra)!r}"
        )


_ensure_manifest_in_sync()
_MAL_PARAMS = _load_manifest()
_BEN_PARAMS = [p.name for p in _BENIGN_FILES]


@pytest.mark.parametrize("filename", _MAL_PARAMS, ids=_MAL_PARAMS)
def test_malicious_is_denied(
    filename: str,
    standard_policy: Policy,
    standard_context: dict,
) -> None:
    sql = (_MALICIOUS_DIR / filename).read_text()
    result = verify(sql, standard_policy, context=standard_context)
    assert not result.allowed, (
        f"{filename} should have been denied but wasn't. "
        f"violations={[v.code.value for v in result.violations]}"
    )


@pytest.mark.parametrize("filename", _BEN_PARAMS, ids=_BEN_PARAMS)
def test_benign_is_allowed(
    filename: str,
    standard_policy: Policy,
    standard_context: dict,
) -> None:
    sql = (_CORPUS / "benign" / filename).read_text()
    result = verify(sql, standard_policy, context=standard_context)
    assert result.allowed, (
        f"{filename} should have been allowed but wasn't. "
        f"violations={[(v.code.value, v.message) for v in result.violations]}"
    )


# Representative LLM-shaped queries that any production-ready policy
# (including the README's ``examples/policy.yml`` with ``allowed_functions``
# set) must accept. Hand-picked to exercise the SQL constructs that
# realistic LLM output emits most frequently and that have historically
# regressed when the validator drifts:
#
#   - multi-clause WHERE with ``AND`` / ``OR`` (operator-keyword Funcs)
#   - ``CASE WHEN ... END`` (Case / If subclasses)
#   - ``EXISTS (...)`` subqueries (Exists subclass)
#   - aggregates with HAVING, GROUP BY, ORDER BY
#   - schema-aware references against allowed columns
#   - functions from the example policy's ``allowed_functions`` list
#
# If any of these fail under the shipped example policy, the README's
# recommended setup is broken for users — same failure mode as the
# AND/OR keyword-as-function regression.
_README_POLICY_BENIGN: list[tuple[str, str]] = [
    (
        "multi_clause_where_and",
        "SELECT id, total FROM orders "
        "WHERE account_id = 42 AND total > 0 LIMIT 10",
    ),
    (
        "multi_clause_where_or",
        "SELECT id, total FROM orders "
        "WHERE account_id = 42 AND (total > 100 OR total < 10) LIMIT 10",
    ),
    (
        "case_expression",
        "SELECT id, CASE WHEN total > 100 THEN 'big' ELSE 'small' END "
        "FROM orders WHERE account_id = 42 LIMIT 10",
    ),
    (
        "case_multi_arm",
        "SELECT id, CASE "
        "WHEN total > 1000 THEN 'huge' "
        "WHEN total > 100 THEN 'big' "
        "ELSE 'small' END "
        "FROM orders WHERE account_id = 42 LIMIT 10",
    ),
    (
        "exists_subquery",
        "SELECT id, total FROM orders o "
        "WHERE o.account_id = 42 "
        "AND EXISTS (SELECT 1 FROM users u WHERE u.id = 1) LIMIT 10",
    ),
    (
        "aggregate_with_having",
        "SELECT account_id, count(id) FROM orders "
        "WHERE account_id = 42 "
        "GROUP BY account_id HAVING count(id) > 5 LIMIT 10",
    ),
    (
        "coalesce_and_cast",
        "SELECT id, coalesce(cast(total AS text), '0') FROM orders "
        "WHERE account_id = 42 LIMIT 10",
    ),
    (
        "extract_from_timestamp",
        "SELECT extract(year FROM created_at), count(id) FROM orders "
        "WHERE account_id = 42 "
        "GROUP BY extract(year FROM created_at) LIMIT 10",
    ),
]


@pytest.mark.parametrize(
    "label,sql",
    _README_POLICY_BENIGN,
    ids=[label for label, _ in _README_POLICY_BENIGN],
)
def test_readme_example_policy_accepts_realistic_sql(
    label: str, sql: str
) -> None:
    """The exact policy in ``examples/policy.yml`` (which the README points
    new users at) must accept realistic LLM-shaped SQL. Loaded from disk so
    a drift in the example file fails this test, not silently misleads
    users."""
    policy = Policy.from_yaml(_EXAMPLE_POLICY_PATH)
    result = verify(sql, policy, context={"tenant_id": 42})
    assert result.allowed, (
        f"examples/policy.yml rejected realistic SQL ({label!r}): "
        f"{[(v.code.value, v.message) for v in result.violations]}"
    )
