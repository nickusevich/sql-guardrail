# Contributing to sql-guardrail

Thanks for your interest. The project's surface is intentionally small;
contributions that extend the surface should match the existing design.

## Quick start

```bash
git clone https://github.com/nickusevich/sql-guardrail.git
cd sql-guardrail
uv sync --extra dev --extra server
uv run pre-commit install        # enable git hooks: lint on commit, mypy on push
uv run pytest
```

(If you prefer not to use [uv](https://docs.astral.sh/uv/): create a
venv yourself and run `pip install -e ".[dev,server]"` — same result,
slower.)

Everything should be green before you start changing things.

## Local checks (must pass before opening a PR)

```bash
ruff check src tests        # lint
mypy src                    # types (--strict in pyproject)
pytest                      # all tests should pass
pytest --cov=sqlguard       # coverage
```

With the git hooks installed (see Quick start), `ruff` and the file-hygiene
checks run on `git commit` and `mypy` runs on `git push`. To run every hook
against the whole tree on demand:

```bash
uv run pre-commit run --all-files
```

CI runs the same checks across Python 3.10 / 3.11 / 3.12 / 3.13 on
Ubuntu and macOS — match that locally and you should be fine.

## Where things live

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the file-by-file
map. The sections you'll touch most often:

- **A new rule** → `src/sqlguard/core/rules/<thing>.py`. Wire into
  `src/sqlguard/__init__.py::_run_pipeline`.
- **A new violation code** → add to `ViolationCode` (`result.py`)
  and `_CATEGORY`.
- **A policy field** → add to the relevant Pydantic model in
  `config/schema.py`. Pydantic's `extra="forbid"` means callers passing
  unknown keys get a `ValidationError` immediately.

## Adding tests

- **Security regressions** → `tests/test_security.py`, grouped by
  attack class. See the section headers — pick
  the matching one and add to the parametrized list.
- **Unit tests** → `tests/unit/test_<rule>.py` for development feedback
  on a single rule.
- **Corpus** → drop a `tests/malicious/*.sql` or `tests/benign/*.sql`
  and list it in `tests/malicious/_manifest.json` (a startup integrity
  check fails collection if you forget).

Per-shape enumeration is what the structural catchalls made redundant.
**Don't add per-fold tautology tests** — add the shape to
`TestTautologies::test_constant_leaf_rejected` and trust the catchall.

## Coding conventions

- Absolute imports only: `from sqlguard.x import Y`, not `from .x` or
  `from ..x`.
- Type hints on every public function. `mypy --strict` must stay clean.
- Comments are reserved for *why*, not *what*. Don't restate the code.
- New violations must have a clear, actionable `.message` and
  `.suggestion`.
- No new runtime dependencies without discussion. The runtime stack
  (sqlglot, pydantic, PyYAML, click) is the entire surface.

## Reporting security issues

See [`SECURITY.md`](SECURITY.md) for how to report bypasses.

## License

By contributing you agree your contributions are licensed under the
MIT License (see [`LICENSE`](LICENSE)).
