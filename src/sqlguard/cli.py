from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import click

from sqlguard import Policy, ViolationCode, __version__, verify

EXIT_ALLOWED = 0
EXIT_VIOLATIONS = 1
EXIT_PARSE_ERROR = 2
EXIT_USAGE_ERROR = 3


@click.group()
@click.version_option(version=__version__, prog_name="sqlguard")
def main() -> None:
    """sqlguard — validate LLM-generated SQL against a policy before execution."""


@main.command("verify")
@click.argument(
    "sql_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    required=False,
)
@click.option(
    "--policy", "policy_path",
    required=True,
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Path to the policy YAML file.",
)
@click.option(
    "--context", "context_json",
    default=None,
    help='JSON dict of per-request values, e.g. \'{"tenant_id": 42}\'.',
)
@click.option(
    "--format", "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format.",
)
@click.option(
    "--stdin", "from_stdin",
    is_flag=True,
    help="Read SQL from stdin instead of a file.",
)
def verify_cmd(
    sql_file: Path | None,
    policy_path: Path,
    context_json: str | None,
    output_format: str,
    from_stdin: bool,
) -> None:
    """Validate a SQL file (or stdin) against a policy.

    Exit codes:
      0 = allowed
      1 = violations
      2 = parse error
      3 = usage error (bad policy or context JSON)
    """
    if from_stdin and sql_file is not None:
        raise click.UsageError("--stdin and SQL_FILE are mutually exclusive.")
    if not from_stdin and sql_file is None:
        raise click.UsageError("provide SQL_FILE or pass --stdin.")

    sql = sys.stdin.read() if from_stdin else sql_file.read_text()  # type: ignore[union-attr]

    try:
        policy = Policy.from_yaml(policy_path)
    except Exception as e:
        click.echo(f"policy load error: {e}", err=True)
        sys.exit(EXIT_USAGE_ERROR)

    context: dict[str, Any] = {}
    if context_json:
        try:
            parsed: Any = json.loads(context_json)
        except json.JSONDecodeError as e:
            click.echo(f"--context must be valid JSON: {e}", err=True)
            sys.exit(EXIT_USAGE_ERROR)
        if not isinstance(parsed, dict):
            click.echo("--context JSON must be an object/dict.", err=True)
            sys.exit(EXIT_USAGE_ERROR)
        context = parsed

    result = verify(sql, policy, context=context)

    if output_format == "json":
        payload = {
            "allowed": result.allowed,
            "statement_kind": result.statement_kind,
            "violations": [
                {
                    "code": v.code.value,
                    "category": v.category.value,
                    "message": v.message,
                    "suggestion": v.suggestion,
                }
                for v in result.violations
            ],
        }
        click.echo(json.dumps(payload, indent=2))
    else:
        verdict = (
            click.style("ALLOWED", fg="green")
            if result.allowed
            else click.style("DENIED", fg="red")
        )
        click.echo(f"{verdict}  kind={result.statement_kind}")
        for v in result.violations:
            tag = click.style(f"[{v.code.value}]", fg="red")
            click.echo(f"  {tag} {v.message}")
            if v.suggestion:
                click.echo(f"    -> {v.suggestion}")

    if not result.allowed:
        has_parse = any(v.code == ViolationCode.PARSE_ERROR for v in result.violations)
        sys.exit(EXIT_PARSE_ERROR if has_parse else EXIT_VIOLATIONS)
    sys.exit(EXIT_ALLOWED)


if __name__ == "__main__":
    main()
