#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${RENDER_SMOKE_IMAGE:-audittrail-render-smoke:local}"
FIXTURE="${ROOT}/fixtures/vulnerable-sample"

echo "Building ${IMAGE} from Dockerfile.render..."
docker build -f "${ROOT}/Dockerfile.render" -t "${IMAGE}" "${ROOT}"

NET="audittrail-render-smoke"
docker network create "${NET}" >/dev/null 2>&1 || true
trap 'docker rm -f audittrail-render-pg >/dev/null 2>&1 || true; docker network rm "${NET}" >/dev/null 2>&1 || true' EXIT

echo "Starting Postgres for smoke test..."
docker run -d --name audittrail-render-pg --network "${NET}" \
  -e POSTGRES_USER=audittrail -e POSTGRES_PASSWORD=audittrail -e POSTGRES_DB=audittrail \
  postgres:16-alpine >/dev/null

for _ in $(seq 1 30); do
  if docker exec audittrail-render-pg pg_isready -U audittrail -d audittrail >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

DB_URL="postgresql+psycopg://audittrail:audittrail@audittrail-render-pg:5432/audittrail?sslmode=disable"

echo "Running inline subprocess scan against fixture..."
docker run --rm --network "${NET}" \
  -e DATABASE_URL="${DB_URL}" \
  -e API_KEY_PEPPER=smoke-pepper-value-1234567890 \
  -e BOOTSTRAP_ADMIN_TOKEN=smoke-bootstrap-token-1234567890 \
  -e DEBUG=true \
  -e SCAN_EXECUTION_MODE=inline \
  -e SCANNER_RUNNER=subprocess \
  -e SCANNER_ENABLE_TRIVY=false \
  -e REDIS_URL= \
  -e WORK_DIR=/var/audittrail/work \
  -v "${FIXTURE}:/scan-src:ro" \
  "${IMAGE}" \
  python - <<'PY'
import shutil
import uuid
from pathlib import Path

from audittrail.config import get_settings
from audittrail.db.session import SessionLocal
from audittrail.models.base import Base
from audittrail.models.scan import Scan, ScanSource, ScanStatus
from audittrail.services.pipeline import run_scan_pipeline
from audittrail.services.workspace import allocate_scan_workspace
from audittrail.scanners.subprocess_runner import SubprocessScannerRunner
from audittrail.db.session import engine

Base.metadata.create_all(bind=engine)
settings = get_settings()
scan_id = uuid.uuid4()
workspace = allocate_scan_workspace(scan_id)
shutil.copytree("/scan-src", workspace, dirs_exist_ok=True)
db = SessionLocal()
try:
    scan = Scan(id=scan_id, source=ScanSource.ARCHIVE_UPLOAD, status=ScanStatus.PENDING)
    db.add(scan)
    db.commit()
    run_scan_pipeline(db, scan_id, workspace, runner=SubprocessScannerRunner())
    db.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED, scan.error_message
    assert len(scan.findings) >= 1, "expected at least one finding from vulnerable fixture"
    print(f"OK: scan completed with {len(scan.findings)} findings")
finally:
    db.close()
PY

echo "Render inline smoke test passed."
