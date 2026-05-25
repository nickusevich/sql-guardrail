"""Smoke tests for the `sqlguard` CLI.

The CLI is the only user-facing path for non-Python callers. These tests
cover the four exit codes (allowed / denied / parse error / usage error)
plus the JSON output, stdin path, and bad-context handling.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from sqlguard.cli import (
    EXIT_ALLOWED,
    EXIT_PARSE_ERROR,
    EXIT_USAGE_ERROR,
    EXIT_VIOLATIONS,
    main,
)


@pytest.fixture
def policy_file(tmp_path: Path) -> Path:
    p = tmp_path / "policy.yml"
    p.write_text(
        """
read_only: true
tables:
  - name: users
    allow_columns: [id, name]
    deny_columns: [password_hash]
  - name: orders
    allow_columns: [id, account_id, total]
    require_predicate:
      column: account_id
      op: "="
      value: "${tenant_id}"
"""
    )
    return p


@pytest.fixture
def sql_file_allowed(tmp_path: Path) -> Path:
    p = tmp_path / "ok.sql"
    p.write_text("SELECT id, name FROM users WHERE id = 1 LIMIT 10")
    return p


@pytest.fixture
def sql_file_denied(tmp_path: Path) -> Path:
    p = tmp_path / "bad.sql"
    p.write_text("SELECT password_hash FROM users LIMIT 10")
    return p


def test_allowed_exits_zero(policy_file: Path, sql_file_allowed: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main, ["verify", str(sql_file_allowed), "--policy", str(policy_file)]
    )
    assert result.exit_code == EXIT_ALLOWED
    assert "ALLOWED" in result.output


def test_denied_exits_one(policy_file: Path, sql_file_denied: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main, ["verify", str(sql_file_denied), "--policy", str(policy_file)]
    )
    assert result.exit_code == EXIT_VIOLATIONS
    assert "DENIED" in result.output
    assert "COLUMN_DENIED" in result.output


def test_parse_error_exits_two(policy_file: Path, tmp_path: Path) -> None:
    bad = tmp_path / "bad.sql"
    bad.write_text("garbage that won't parse $%@#")
    runner = CliRunner()
    result = runner.invoke(
        main, ["verify", str(bad), "--policy", str(policy_file)]
    )
    assert result.exit_code == EXIT_PARSE_ERROR
    assert "PARSE_ERROR" in result.output


def test_bad_policy_exits_three(tmp_path: Path) -> None:
    bad_policy = tmp_path / "bad.yml"
    bad_policy.write_text("tables: not_a_list")
    sql = tmp_path / "ok.sql"
    sql.write_text("SELECT 1")
    runner = CliRunner()
    result = runner.invoke(
        main, ["verify", str(sql), "--policy", str(bad_policy)]
    )
    assert result.exit_code == EXIT_USAGE_ERROR
    assert "policy load error" in result.output


def test_bad_context_json_exits_three(
    policy_file: Path, sql_file_allowed: Path
) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "verify", str(sql_file_allowed),
            "--policy", str(policy_file),
            "--context", "{not valid json}",
        ],
    )
    assert result.exit_code == EXIT_USAGE_ERROR
    assert "valid JSON" in result.output


def test_non_dict_context_exits_three(
    policy_file: Path, sql_file_allowed: Path
) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "verify", str(sql_file_allowed),
            "--policy", str(policy_file),
            "--context", '["not", "a", "dict"]',
        ],
    )
    assert result.exit_code == EXIT_USAGE_ERROR


def test_stdin_input(policy_file: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["verify", "--policy", str(policy_file), "--stdin"],
        input="SELECT id FROM users WHERE id = 1 LIMIT 10",
    )
    assert result.exit_code == EXIT_ALLOWED
    assert "ALLOWED" in result.output


def test_stdin_and_file_mutually_exclusive(
    policy_file: Path, sql_file_allowed: Path
) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "verify", str(sql_file_allowed),
            "--policy", str(policy_file),
            "--stdin",
        ],
    )
    assert result.exit_code != EXIT_ALLOWED
    # click formats usage errors as "Usage:" / "Error:" — both go to stderr
    # combined output should mention the mutual exclusion.
    assert "mutually exclusive" in result.output or "mutually exclusive" in (
        result.stderr_bytes or b""
    ).decode()


def test_missing_sql_input_errors(policy_file: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["verify", "--policy", str(policy_file)])
    assert result.exit_code != EXIT_ALLOWED


def test_json_output_shape(policy_file: Path, sql_file_denied: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "verify", str(sql_file_denied),
            "--policy", str(policy_file),
            "--format", "json",
        ],
    )
    assert result.exit_code == EXIT_VIOLATIONS
    payload = json.loads(result.output)
    assert payload["allowed"] is False
    assert payload["statement_kind"] == "SELECT"
    assert any(v["code"] == "COLUMN_DENIED" for v in payload["violations"])
    # Each violation should carry the full structured fields.
    v = payload["violations"][0]
    for key in ("code", "category", "message"):
        assert key in v


def test_context_resolves_tenant_predicate(
    policy_file: Path, tmp_path: Path
) -> None:
    """The context JSON must resolve ${tenant_id} placeholders in policy."""
    sql = tmp_path / "tenant.sql"
    sql.write_text("SELECT id FROM orders WHERE account_id = 42 LIMIT 10")
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "verify", str(sql),
            "--policy", str(policy_file),
            "--context", '{"tenant_id": 42}',
        ],
    )
    assert result.exit_code == EXIT_ALLOWED

    # Wrong tenant — denied.
    result = runner.invoke(
        main,
        [
            "verify", str(sql),
            "--policy", str(policy_file),
            "--context", '{"tenant_id": 99}',
        ],
    )
    assert result.exit_code == EXIT_VIOLATIONS
    assert "MISSING_REQUIRED_PREDICATE" in result.output


def test_version_flag() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == EXIT_ALLOWED
