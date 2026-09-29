"""Recover scans interrupted by process restarts."""

from __future__ import annotations

import logging

from audittrail.config import get_settings
from audittrail.db.session import SessionLocal
from audittrail.models.scan import Scan, ScanSource, ScanStatus
from audittrail.services.scan_dispatch import dispatch_scan

logger = logging.getLogger(__name__)

_STUCK_STATUSES = (ScanStatus.PENDING, ScanStatus.RUNNING)


def _requeue_scan(scan: Scan) -> None:
    post_github = scan.source == ScanSource.GITHUB_PR
    if scan.source == ScanSource.REPO_URL and scan.repo_full_name:
        dispatch_scan(
            str(scan.id),
            repo_url=f"https://github.com/{scan.repo_full_name}.git",
            ref=scan.ref or "main",
            post_github=post_github,
        )
        return
    dispatch_scan(str(scan.id), post_github=post_github)


def recover_stuck_scans() -> None:
    settings = get_settings()
    db = SessionLocal()
    try:
        stuck = db.query(Scan).filter(Scan.status.in_(_STUCK_STATUSES)).all()
        if not stuck:
            return

        if settings.scan_execution_mode == "inline":
            for scan in stuck:
                if scan.status == ScanStatus.RUNNING:
                    scan.status = ScanStatus.PENDING
                    scan.error_message = None
                db.commit()
                logger.info("Requeueing scan %s after startup", scan.id)
                try:
                    _requeue_scan(scan)
                except Exception:
                    logger.exception("Failed to requeue scan %s", scan.id)
            return

        for scan in stuck:
            scan.status = ScanStatus.FAILED
            scan.error_message = "Scan interrupted by service restart (Celery worker required)"
            logger.warning("Failing stuck scan %s on API startup (celery mode)", scan.id)
        db.commit()
    finally:
        db.close()
