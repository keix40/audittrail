# Contributing to AuditTrail

Thank you for contributing. This project uses **trunk-based development** with short-lived feature branches merged into `main` via pull request.

## Branch naming

| Prefix | Use |
|--------|-----|
| `feat/` | New features |
| `fix/` | Bug fixes |
| `chore/` | Tooling, deps, CI |
| `docs/` | Documentation only |
| `test/` | Test-only changes |

Examples: `feat/github-status-checks`, `fix/webhook-signature-timing`.

Cloud agent branches may use the `cursor/` prefix when automated.

## Commit messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(api): add archive upload scans
fix(worker): clean up docker containers on failure
chore(ci): bump ruff to 0.8
docs(readme): document GitHub App permissions
test(normalize): cover gitleaks parser
```

Reference issues in the footer when applicable: `Refs #123`.

## Development workflow

1. Branch from `main`.
2. Install dev dependencies: `pip install -e ".[dev]"`.
3. Run `make lint`, `make typecheck`, and `make test` before pushing.
4. Open a PR into `main` with a clear description and testing notes.

## Code style

- **Ruff** for lint/format (`ruff check audittrail tests`).
- **Mypy** strict on `audittrail/`.
- Prefer small, focused PRs.

## Security

- Never commit secrets, tokens, or private keys.
- Use `.env` locally (from `.env.example`).
- Report security issues privately to the maintainers rather than opening public issues.
