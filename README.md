# AuditTrail

AuditTrail is an automated code review and security scanner API built as a portfolio-grade reference implementation. It ingests GitHub pull request webhooks (or on-demand REST requests), runs multiple security scanners in isolated Docker containers, normalizes and deduplicates findings, optionally summarizes results with an LLM, and posts PR review comments plus a GitHub check run.

## Architecture

```mermaid
flowchart LR
  subgraph ingress [Ingress]
    GH[GitHub App Webhook]
    REST[REST API + API Keys]
  end

  subgraph core [AuditTrail]
    API[FastAPI API]
    Q[(Redis Queue)]
    W[Celery Worker]
    DB[(PostgreSQL)]
  end

  subgraph sandbox [Scanner Sandbox]
    D1[Semgrep]
    D2[Bandit]
    D3[Gitleaks]
    D4[Trivy]
  end

  GH -->|signed webhook| API
  REST -->|rate limited| API
  API -->|enqueue scan| Q
  Q --> W
  W -->|read-only mount| sandbox
  D1 & D2 & D3 & D4 --> W
  W -->|findings + report| DB
  W -->|check run + review| GH
  API --> DB
```

## Security model

| Control | Implementation |
|--------|----------------|
| Webhook authenticity | HMAC SHA-256 (`X-Hub-Signature-256`) |
| REST access | Hashed API keys (`X-API-Key` or `Authorization: Bearer`) |
| Abuse prevention | Redis sliding-window rate limits per API key |
| Scanner isolation | One ephemeral container per tool; read-only workspace mount; `network_disabled` by default; memory/CPU limits; container removed after run |
| Secrets | No secrets in repo; configure via environment (see `.env.example`) |
| LLM | Optional; deterministic summary fallback when provider/key unset |

## Tech choices

- **FastAPI** — async-friendly API, automatic OpenAPI at `/docs`.
- **Celery + Redis** — durable background scan jobs with retries.
- **PostgreSQL + SQLAlchemy + Alembic** — persistent scans, findings, reports, API keys.
- **Docker** — consistent scanner toolchain without polluting the API image.
- **Semgrep / Bandit / Gitleaks / Trivy** — complementary SAST, Python security, secret detection, and dependency scanning.

## Quickstart

### Prerequisites

- Docker and Docker Compose
- Python 3.11+ (for local development/tests)

### Run the stack

```bash
cp .env.example .env
make scanner-image
docker compose up --build
```

Services:

| Service | URL / port |
|---------|------------|
| API + OpenAPI | http://localhost:8000/docs |
| Postgres | `localhost:5432` |
| Redis | `localhost:6379` |

Create an API key (bootstrap endpoint — restrict in production):

```bash
curl -X POST "http://localhost:8000/v1/admin/api-keys?name=local-dev"
```

Scan the bundled vulnerable fixture via upload (zip the sample first):

```bash
cd fixtures/vulnerable-sample && zip -r /tmp/vuln.zip . && cd -
curl -X POST "http://localhost:8000/v1/scans/upload" \
  -H "X-API-Key: at_..." \
  -F "archive=@/tmp/vuln.zip"
```

Or scan a public repository:

```bash
curl -X POST "http://localhost:8000/v1/scans" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: at_..." \
  -d '{"repo_url":"https://github.com/octocat/Hello-World","ref":"master"}'
```

Poll scan status:

```bash
curl -H "X-API-Key: at_..." "http://localhost:8000/v1/scans/{scan_id}"
```

### Local tests

```bash
pip install -e ".[dev]"
# Postgres + Redis required (docker compose up postgres redis)
export TEST_DATABASE_URL=postgresql+psycopg://audittrail:audittrail@localhost:5432/audittrail_test
pytest -q
```

## GitHub App setup

1. Create a GitHub App (Settings → Developer settings → GitHub Apps).
2. **Webhook URL:** `https://<your-host>/webhooks/github`
3. **Webhook secret:** set `GITHUB_WEBHOOK_SECRET` to the same value.
4. **Permissions:**
   - Checks: Read & write
   - Pull requests: Read & write
   - Contents: Read-only
   - Metadata: Read-only
5. **Subscribe to events:** `Pull request`
6. Install the app on your target repository.
7. Set environment variables:
   - `GITHUB_APP_ID`
   - `GITHUB_APP_PRIVATE_KEY` (PEM; newlines as `\n` in env)
   - `GITHUB_WEBHOOK_SECRET`

When a PR is opened or updated, AuditTrail queues a scan, runs scanners, posts inline comments (up to 50 findings), and creates a check run named **AuditTrail Security Scan**.

### Self-review (dogfooding this repo)

After deploying AuditTrail and installing the GitHub App on this repository:

1. Open a PR from a feature branch (e.g. `feat/*`) into `main`.
2. Include changes under `fixtures/vulnerable-sample/` or application code to trigger findings.
3. The webhook hits `/webhooks/github`; the worker clones the PR head and scans changed context.
4. Verify the check run and review comments on the PR.

For local webhook testing, use [smee.io](https://smee.io/) or `ngrok` to forward to `http://localhost:8000/webhooks/github`.

## API reference

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET` | `/health` | None | Liveness |
| `POST` | `/webhooks/github` | HMAC signature | GitHub App PR events |
| `POST` | `/v1/scans` | API key | Queue scan of public Git URL |
| `POST` | `/v1/scans/upload` | API key | Queue scan of `.zip` / `.tar.gz` archive |
| `GET` | `/v1/scans/{id}` | API key | Scan status, findings, report |
| `POST` | `/v1/admin/api-keys` | None* | Issue API key |

\*Protect or remove in production deployments.

OpenAPI schema: `/openapi.json` and interactive UI at `/docs`.

## Finding schema (normalized)

All scanner output is mapped to:

```json
{
  "scanner": "semgrep | bandit | gitleaks | trivy",
  "severity": "critical | high | medium | low | info",
  "title": "string",
  "description": "string",
  "file_path": "string | null",
  "line_start": "integer | null",
  "line_end": "integer | null",
  "rule_id": "string | null",
  "cwe": "string | null",
  "suggestion": "string | null",
  "fingerprint": "sha256 for deduplication"
}
```

Findings are deduplicated by `(scanner, file_path, line_start, rule_id/title)` and sorted by severity.

**Pass/fail:** a scan fails the check run if any finding has severity `critical` or `high`.

## Project layout

```
audittrail/          Application package (API, services, scanners, tasks)
alembic/             Database migrations
fixtures/            Sample vulnerable repo for demos
tests/               Pytest suite (mocked scanners for pipeline tests)
docker-compose.yml   API, worker, Postgres, Redis
Dockerfile.*         API, worker, and scanner images
```

## Roadmap

- [ ] Diff-scoped scanning (only changed files on PRs)
- [ ] SARIF export and GitHub Advanced Security integration
- [ ] Policy engine (severity gates per repo/team)
- [ ] Multi-tenant organizations and audit log
- [ ] Web UI for scan history
- [ ] Scheduled scans and baseline comparisons

## License

MIT (add `LICENSE` file before public release if needed).

See [CONTRIBUTING.md](CONTRIBUTING.md) for branch naming and commit conventions.
