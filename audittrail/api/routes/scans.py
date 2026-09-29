import json
import uuid

from audittrail.api.deps import DbSession, rate_limit_api_key
from audittrail.models.api_key import ApiKey
from audittrail.models.scan import Scan, ScanSource, ScanStatus
from audittrail.schemas.finding import FindingOut
from audittrail.schemas.scan import (
    ReportOut,
    RepoScanRequest,
    ScanCreated,
    ScanDetail,
    ScanStatusOut,
)
from audittrail.services.archive_extract import UnsafeArchiveError, extract_upload
from audittrail.services.pipeline import parse_github_repo_url
from audittrail.services.repo_url_validation import InvalidRepoUrlError, validate_repo_url
from audittrail.services.workspace import allocate_scan_workspace
from audittrail.tasks.scan_tasks import run_scan_task
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile

router = APIRouter(prefix="/v1/scans", tags=["scans"])


@router.post("", response_model=ScanCreated, status_code=202)
def create_repo_scan(
    body: RepoScanRequest,
    db: DbSession,
    api_key: ApiKey = Depends(rate_limit_api_key),
) -> ScanCreated:
    try:
        validate_repo_url(str(body.repo_url))
    except InvalidRepoUrlError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    repo_path = parse_github_repo_url(str(body.repo_url))
    scan = Scan(
        source=ScanSource.REPO_URL,
        status=ScanStatus.PENDING,
        repo_full_name=repo_path,
        ref=body.ref,
        owner_api_key_id=api_key.id,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    allocate_scan_workspace(scan.id)
    run_scan_task.delay(str(scan.id), repo_url=str(body.repo_url), ref=body.ref)
    return ScanCreated(scan_id=scan.id, status=ScanStatusOut.pending)


@router.post("/upload", response_model=ScanCreated, status_code=202)
async def create_archive_scan(
    db: DbSession,
    api_key: ApiKey = Depends(rate_limit_api_key),
    archive: UploadFile = File(...),
) -> ScanCreated:
    if not archive.filename:
        raise HTTPException(status_code=400, detail="Missing filename")
    lower = archive.filename.lower()
    if not lower.endswith((".zip", ".tar.gz", ".tgz")):
        raise HTTPException(status_code=400, detail="Upload must be .zip or .tar.gz")
    if ".." in archive.filename or archive.filename.startswith("/"):
        raise HTTPException(status_code=400, detail="Invalid filename")

    content = await archive.read()
    scan = Scan(
        source=ScanSource.ARCHIVE_UPLOAD,
        status=ScanStatus.PENDING,
        metadata_json={"filename": archive.filename},
        owner_api_key_id=api_key.id,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    workspace = allocate_scan_workspace(scan.id)
    try:
        extract_upload(archive.filename, content, workspace)
    except UnsafeArchiveError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    run_scan_task.delay(str(scan.id))
    return ScanCreated(scan_id=scan.id, status=ScanStatusOut.pending)


@router.get("/{scan_id}", response_model=ScanDetail)
def get_scan(
    scan_id: uuid.UUID,
    db: DbSession,
    api_key: ApiKey = Depends(rate_limit_api_key),
) -> ScanDetail:
    scan = db.get(Scan, scan_id)
    if not scan or scan.owner_api_key_id != api_key.id:
        raise HTTPException(status_code=404, detail="Scan not found")

    report_out = None
    if scan.report:
        report_out = ReportOut(
            passed=scan.report.passed,
            summary=scan.report.summary,
            llm_generated=scan.report.llm_generated,
            finding_counts=json.loads(scan.report.finding_counts or "{}"),
        )

    findings_out = [
        FindingOut(
            id=str(f.id),
            scanner=f.scanner,
            severity=f.severity,
            title=f.title,
            description=f.description,
            file_path=f.file_path,
            line_start=f.line_start,
            line_end=f.line_end,
            rule_id=f.rule_id,
            cwe=f.cwe,
            suggestion=f.suggestion,
        )
        for f in scan.findings
    ]

    return ScanDetail(
        id=scan.id,
        source=scan.source.value,
        status=ScanStatusOut(scan.status.value),
        repo_full_name=scan.repo_full_name,
        ref=scan.ref,
        pr_number=scan.pr_number,
        commit_sha=scan.commit_sha,
        created_at=scan.created_at,
        findings=findings_out,
        report=report_out,
    )
