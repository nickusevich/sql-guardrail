# Running sql-guardrail

The library is the core; the CLI and HTTP server are thin wrappers around
`verify()` — same rules, same result shape. For the Python API see the
[README](../README.md); for policy options see [`POLICY.md`](POLICY.md).

## CLI

The package installs an `sqlguard` console script.

```bash
# From a file
sqlguard verify query.sql --policy policy.yml --context '{"tenant_id": 42}'

# From stdin (pipe LLM output straight through validation)
echo 'SELECT id FROM orders WHERE 1=1' | sqlguard verify --policy policy.yml --stdin

# JSON output for scripting / log ingestion
sqlguard verify query.sql --policy policy.yml --format json
```

| Exit code | Meaning |
|---|---|
| `0` | Allowed |
| `1` | Denied (one or more violations) |
| `2` | Parse error |
| `3` | Usage error (bad arguments or invalid context JSON) |

Run `sqlguard verify --help` for the full flag list.

## HTTP server

Not in Python? Run sql-guardrail as a sidecar. Install with the `[server]`
extra or use the published Docker image.

### Docker

```bash
docker run --rm -p 8000:8000 \
  -v "$(pwd)/policy.yml:/etc/sqlguard/policy.yml:ro" \
  ghcr.io/nickusevich/sql-guardrail:latest
```

The image reads its policy from `$SQLGUARD_POLICY_PATH`
(`/etc/sqlguard/policy.yml` by default). The repo also ships a
`docker-compose.yml` wired to `examples/policy.yml`:

```bash
docker compose up --build
```

### From Python

```bash
uv add "sql-guardrail[server]"
SQLGUARD_POLICY_PATH=policy.yml sqlguard-server
```

### Endpoints

- `POST /verify` — validate a SQL string. Body: `{"sql": "...", "context": {...}}`.
- `GET /health` — liveness (200 when the policy is loaded, 503 otherwise).
- `GET /docs` — OpenAPI UI. `GET /openapi.json` — the machine-readable schema.

```bash
curl -s localhost:8000/verify -H 'Content-Type: application/json' \
  -d '{"sql": "SELECT id FROM orders WHERE account_id=42", "context": {"tenant_id": 42}}'
```

```json
{"allowed": true, "statement_kind": "SELECT", "violations": []}
```

`POST /verify` always returns HTTP 200 — the `allowed` boolean is in the body,
matching the CLI's exit-code convention. On a denial each violation carries
`code` / `category` / `message` / `suggestion`; feed `suggestion` back to the
model for a self-correction retry.

### Configuration

| Env var | Default | Purpose |
|---|---|---|
| `SQLGUARD_POLICY_PATH` | `/etc/sqlguard/policy.yml` (in image) | Path to the policy YAML. Required. |
| `SQLGUARD_HOST` | `0.0.0.0` | Bind address. |
| `SQLGUARD_PORT` | `8000` | Bind port. |
| `SQLGUARD_LOG_LEVEL` | `info` | uvicorn / app log level. |

**The server does no authentication.** Put it behind a reverse proxy, mTLS, or
a NetworkPolicy and treat it as an internal service. `context` carries the same
per-request values as the Python API — typically `{"tenant_id": ...}` from the
**authenticated session**, never the LLM prompt.
