"""Core scan job logic shared by Celery workers and inline execution."""

from __future__ import annotations

import uuid
from pathlib import Path

from audittrail.db.session import SessionLocal
from audittrail.models.scan import Scan, ScanSource
from audittrail.scanners.runner_factory import get_scanner_runner
from audittrail.services.diff_scope import file_diffs_from_github_files
from audittrail.services.github_client import list_pull_request_files
from audittrail.services.pipeline import (
    fetch_pr_workspace,
    prepare_repo_scan_workspace,
    run_scan_pipeline,
)
from audittrail.services.workspace import scan_workspace_path


def execute_scan(
    scan_id: str,
    *,
    repo_url: str | None = None,
    ref: str = "main",
    post_github: bool = False,
) -> str:
    db = SessionLocal()
    try:
        sid = uuid.UUID(scan_id)
        scan = db.get(Scan, sid)
        if scan is None:
            raise ValueError(f"Scan {scan_id} not found")

        workspace: Path = scan_workspace_path(sid)
        if scan.source == ScanSource.REPO_URL and repo_url:
            workspace = prepare_repo_scan_workspace(sid, repo_url, ref)
        elif scan.source == ScanSource.GITHUB_PR:
            if not scan.commit_sha or not scan.installation_id:
                raise ValueError("GitHub PR scan missing commit or installation")
            head_repo = scan.metadata_json.get("head_repo_full_name") or scan.repo_full_name
            if not head_repo:
                raise ValueError("GitHub PR scan missing head repository")
            workspace.mkdir(parents=True, exist_ok=True)
            fetch_pr_workspace(
                str(head_repo),
                scan.commit_sha,
                scan.installation_id,
                workspace,
            )
        elif not workspace.exists():
            raise ValueError(f"Workspace not prepared for scan {scan_id}")

        diff_scope = None
        if (
            scan.source == ScanSource.GITHUB_PR
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

        runner = get_scanner_runner()
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
