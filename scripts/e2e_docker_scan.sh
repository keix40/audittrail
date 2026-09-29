#!/usr/bin/env bash
# End-to-end scan against a real docker compose stack (API, worker, scanners).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

API_BASE="${API_BASE:-http://127.0.0.1:8000}"
COMPOSE="${COMPOSE:-docker compose -f docker-compose.yml -f docker-compose.e2e.yml}"
POLL_SECONDS="${POLL_SECONDS:-300}"
POLL_INTERVAL="${POLL_INTERVAL:-5}"

echo "Building scanner image and starting stack..."
docker build -f Dockerfile.scanner -t audittrail-scanner:local .
$COMPOSE down -v --remove-orphans 2>/dev/null || true
$COMPOSE build api worker migrate
$COMPOSE up -d postgres redis

echo "Waiting for Postgres and Redis..."
deadline=$((SECONDS + 120))
until $COMPOSE exec -T postgres pg_isready -U audittrail -d audittrail >/dev/null 2>&1; do
  if (( SECONDS >= deadline )); then
    echo "Postgres did not become ready" >&2
    exit 1
  fi
  sleep 2
done
until $COMPOSE exec -T redis redis-cli ping 2>/dev/null | grep -q PONG; do
  if (( SECONDS >= deadline )); then
    echo "Redis did not become ready" >&2
    exit 1
  fi
  sleep 2
done

echo "Running database migrations..."
migrate_ok=false
for attempt in $(seq 1 15); do
  if $COMPOSE run --rm migrate alembic upgrade head; then
    migrate_ok=true
    break
  fi
  echo "Migrate attempt ${attempt} failed; retrying..."
  sleep 3
done
if [[ "$migrate_ok" != true ]]; then
  echo "Database migration failed after retries" >&2
  exit 1
fi

$COMPOSE up -d api worker

echo "Waiting for API health at ${API_BASE}/health ..."
deadline=$((SECONDS + 120))
until curl -sf "${API_BASE}/health" >/dev/null; do
  if (( SECONDS >= deadline )); then
    echo "API did not become healthy in time" >&2
    $COMPOSE logs api worker | tail -200 >&2 || true
    exit 1
  fi
  sleep 2
done

echo "Creating API key via CLI..."
key_output="$($COMPOSE exec -T api audittrail create-api-key --name e2e-docker 2>&1)"
echo "$key_output"
API_KEY="$(echo "$key_output" | sed -n 's/^api_key=//p')"
if [[ -z "$API_KEY" ]]; then
  echo "Failed to parse api_key from CLI output" >&2
  exit 1
fi

echo "Packaging vulnerable sample..."
sample_zip="/tmp/vulnerable-sample-$$.zip"
rm -f "$sample_zip"
(
  cd "$ROOT/fixtures"
  zip -qr "$sample_zip" vulnerable-sample
)

echo "Submitting archive upload scan..."
create_resp="$(curl -sf -X POST "${API_BASE}/v1/scans/upload" \
  -H "X-API-Key: ${API_KEY}" \
  -F "archive=@${sample_zip};filename=vulnerable-sample.zip")"
rm -f "$sample_zip"

SCAN_ID="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["scan_id"])' <<<"$create_resp")"
echo "Scan id: ${SCAN_ID}"

echo "Polling scan status (timeout ${POLL_SECONDS}s)..."
deadline=$((SECONDS + POLL_SECONDS))
detail=""
while (( SECONDS < deadline )); do
  detail="$(curl -sf -H "X-API-Key: ${API_KEY}" "${API_BASE}/v1/scans/${SCAN_ID}")"
  status="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])' <<<"$detail")"
  echo "  status=${status}"
  if [[ "$status" == "completed" || "$status" == "failed" ]]; then
    break
  fi
  sleep "$POLL_INTERVAL"
done

if [[ -z "$detail" ]]; then
  echo "No scan detail received" >&2
  exit 1
fi

python3 - "$detail" <<'PY'
import json
import sys

data = json.loads(sys.argv[1])
status = data.get("status")
if status != "completed":
    print(json.dumps(data, indent=2))
    raise SystemExit(f"Expected completed scan, got {status!r}")

report = data.get("report") or {}
findings = data.get("findings") or []
scanners = {f.get("scanner") for f in findings}

if not findings:
    raise SystemExit("Scan completed with zero findings (empty workspace or broken mount)")

for required in ("bandit", "semgrep", "gitleaks"):
    if required not in scanners:
        raise SystemExit(f"Missing findings from scanner {required!r}; got {sorted(scanners)}")

if report.get("passed") is True:
    raise SystemExit("Scan incorrectly passed with high-severity findings present")

print(
    f"E2E OK: {len(findings)} finding(s) from "
    f"{', '.join(sorted(scanners))}; report.passed={report.get('passed')}"
)
PY

echo "E2E docker scan succeeded."
