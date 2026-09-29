"""Enqueue scans via Celery or the inline executor."""

from __future__ import annotations

import logging
from typing import Any

from audittrail.config import get_settings
from audittrail.services.inline_executor import ScanQueueFullError, get_inline_executor
from audittrail.services.scan_execution import execute_scan

logger = logging.getLogger(__name__)


def dispatch_scan(
    scan_id: str,
    *,
    repo_url: str | None = None,
    ref: str = "main",
    post_github: bool = False,
) -> None:
    settings = get_settings()
    kwargs: dict[str, Any] = {
        "repo_url": repo_url,
        "ref": ref,
        "post_github": post_github,
    }
    if settings.scan_execution_mode == "inline":
        executor = get_inline_executor()
        try:
            executor.submit(execute_scan, scan_id, **kwargs)
        except ScanQueueFullError:
            raise
        return

    from audittrail.tasks.scan_tasks import run_scan_task

    run_scan_task.delay(scan_id, **kwargs)


def dispatch_scan_or_raise_queue_full(
    scan_id: str,
    *,
    repo_url: str | None = None,
    ref: str = "main",
    post_github: bool = False,
) -> None:
    try:
        dispatch_scan(scan_id, repo_url=repo_url, ref=ref, post_github=post_github)
    except ScanQueueFullError as exc:
        logger.warning("Inline scan queue full for scan %s: %s", scan_id, exc)
        raise


def mark_scan_queue_rejected(scan_id: str, message: str) -> None:
    import uuid

    from audittrail.db.session import SessionLocal
    from audittrail.models.scan import Scan, ScanStatus

    db = SessionLocal()
    try:
        scan = db.get(Scan, uuid.UUID(scan_id))
        if scan is None:
            return
        scan.status = ScanStatus.FAILED
        scan.error_message = message
        db.commit()
    finally:
        db.close()
