"""End-to-end scan pipeline (fetch → scan → normalize → report)."""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path
from urllib.parse import urlparse

from audittrail.models.finding import FindingRecord
from audittrail.models.report import Report
from audittrail.models.scan import Scan, ScanStatus
from audittrail.scanners.docker_runner import MockScannerRunner, ScannerRunner
from audittrail.schemas.finding import NormalizedFinding
from audittrail.services.diff_scope import FileDiff, filter_findings_to_diff
from audittrail.services.llm_summary import generate_summary
from audittrail.services.normalize import merge_scanner_results
from audittrail.services.report import compute_pass_fail, counts_json
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)


def clone_public_repo(repo_url: str, ref: str, dest: Path) -> None:
    subprocess.run(
        ["git", "clone", "--depth", "1", "--branch", ref, repo_url, str(dest)],
        check=True,
        capture_output=True,
        timeout=120,
    )


def fetch_pr_workspace(repo_full_name: str, ref: str | None, dest: Path) -> None:
    url = f"https://github.com/{repo_full_name}.git"
    clone_public_repo(url, ref or "main", dest)


def run_scan_pipeline(
    db: Session,
    scan_id: uuid.UUID,
    workspace: Path,
    runner: ScannerRunner | None = None,
    *,
    post_github: bool = False,
    diff_scope: tuple[FileDiff, ...] | None = None,
) -> None:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise ValueError(f"Scan {scan_id} not found")

    scan.status = ScanStatus.RUNNING
    db.commit()

    try:
        scanner_runner = runner or MockScannerRunner()
        raw_results = scanner_runner.run_all(workspace)
        findings = merge_scanner_results(raw_results)
        if diff_scope is not None:
            findings = filter_findings_to_diff(findings, diff_scope)
            scan.metadata_json = {
                **scan.metadata_json,
                "diff_scoped": True,
                "diff_file_count": len(diff_scope),
                "reported_finding_count": len(findings),
            }

        for f in findings:
            db.add(
                FindingRecord(
                    scan_id=scan.id,
                    fingerprint=f.fingerprint(),
                    scanner=f.scanner.value,
                    severity=f.severity.value,
                    title=f.title,
                    description=f.description,
                    file_path=f.file_path,
                    line_start=f.line_start,
                    line_end=f.line_end,
                    rule_id=f.rule_id,
                    cwe=f.cwe,
                    suggestion=f.suggestion,
                    raw_json=f.raw,
                )
            )

        summary, llm_used = generate_summary(findings)
        passed = compute_pass_fail(findings)
        db.add(
            Report(
                scan_id=scan.id,
                passed=passed,
                summary=summary,
                llm_generated=llm_used,
                finding_counts=counts_json(findings),
            )
        )
        scan.status = ScanStatus.COMPLETED
        db.commit()

        if post_github and scan.installation_id and scan.repo_full_name and scan.commit_sha:
            _post_to_github(scan, findings, summary, passed)
    except Exception as exc:
        logger.exception("Scan failed")
        scan.status = ScanStatus.FAILED
        scan.error_message = str(exc)
        db.commit()
        raise
    finally:
        if workspace.exists() and str(workspace).startswith("/tmp"):
            shutil.rmtree(workspace, ignore_errors=True)


def _post_to_github(
    scan: Scan, findings: list[NormalizedFinding], summary: str, passed: bool
) -> None:
    from audittrail.services.github_client import create_check_run, post_review_comments

    conclusion = "success" if passed else "failure"
    create_check_run(
        scan.repo_full_name or "",
        scan.commit_sha or "",
        scan.installation_id or 0,
        conclusion=conclusion,
        summary=summary,
    )
    if scan.pr_number:
        post_review_comments(
            scan.repo_full_name or "",
            scan.pr_number,
            scan.installation_id or 0,
            scan.commit_sha or "",
            findings,
            summary,
        )


def workspace_from_repo_url(repo_url: str, ref: str) -> Path:
    dest = Path(tempfile.mkdtemp(prefix="repo-scan-"))
    clone_public_repo(repo_url, ref, dest)
    return dest


def parse_github_repo_url(url: str) -> str:
    parsed = urlparse(url)
    path = parsed.path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    return path
