from __future__ import annotations

from celery import Task

from audittrail.celery_app import celery_app
from audittrail.services.scan_execution import execute_scan


@celery_app.task(name="audittrail.run_scan", bind=True, max_retries=2)  # type: ignore[untyped-decorator]
def run_scan_task(
    _self: Task,
    scan_id: str,
    *,
    repo_url: str | None = None,
    ref: str = "main",
    post_github: bool = False,
) -> str:
    return execute_scan(
        scan_id,
        repo_url=repo_url,
        ref=ref,
        post_github=post_github,
    )
