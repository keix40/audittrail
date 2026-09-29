from __future__ import annotations

import uuid
from pathlib import Path

from celery import Task

from audittrail.celery_app import celery_app
from audittrail.db.session import SessionLocal
from audittrail.models.scan import Scan, ScanSource
from audittrail.scanners.docker_runner import DockerScannerRunner
from audittrail.services.diff_scope import file_diffs_from_github_files
from audittrail.services.github_client import list_pull_request_files
from audittrail.services.pipeline import (
    fetch_pr_workspace,
    run_scan_pipeline,
    workspace_from_repo_url,
)


@celery_app.task(name="audittrail.run_scan", bind=True, max_retries=2)  # type: ignore[untyped-decorator]
def run_scan_task(
    _self: Task,
    scan_id: str,
    *,
    workspace_path: str | None = None,
    repo_url: str | None = None,
    ref: str = "main",
    post_github: bool = False,
) -> str:
    db = SessionLocal()
    try:
        sid = uuid.UUID(scan_id)
        workspace: Path
        if workspace_path:
            workspace = Path(workspace_path)
        elif repo_url:
            workspace = workspace_from_repo_url(repo_url, ref)
        else:
            scan = db.get(Scan, sid)
            if scan and scan.repo_full_name:
                workspace = Path(f"/tmp/pr-{scan_id}")
                fetch_pr_workspace(scan.repo_full_name, scan.ref, workspace)
            else:
                raise ValueError("No workspace or repo context for scan")

        scan = db.get(Scan, sid)
        diff_scope = None
        if (
            scan
            and scan.source == ScanSource.GITHUB_PR
            and scan.pr_number
            and scan.installation_id
            and scan.repo_full_name
        ):
            pr_files = list_pull_request_files(
                scan.repo_full_name,
                scan.pr_number,
                scan.installation_id,
            )
            diff_scope = file_diffs_from_github_files(pr_files)

        runner = DockerScannerRunner()
        run_scan_pipeline(
            db,
            sid,
            workspace,
            runner=runner,
            post_github=post_github,
            diff_scope=diff_scope,
        )
        return scan_id
    finally:
        db.close()
