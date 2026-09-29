from audittrail.models.scan import Scan, ScanSource, ScanStatus
from audittrail.services.scan_recovery import recover_stuck_scans
from sqlalchemy.orm import sessionmaker


def test_recovery_fails_stuck_scans_in_celery_mode(engine, monkeypatch) -> None:
    monkeypatch.setenv("SCAN_EXECUTION_MODE", "celery")
    from audittrail.config import get_settings

    get_settings.cache_clear()
    Session = sessionmaker(bind=engine)
    monkeypatch.setattr("audittrail.services.scan_recovery.SessionLocal", Session)

    db = Session()
    scan = Scan(source=ScanSource.ARCHIVE_UPLOAD, status=ScanStatus.RUNNING)
    db.add(scan)
    db.commit()

    recover_stuck_scans()

    db.refresh(scan)
    assert scan.status == ScanStatus.FAILED
    assert "restart" in (scan.error_message or "").lower()
    db.close()


def test_recovery_requeues_in_inline_mode(engine, monkeypatch) -> None:
    monkeypatch.setenv("SCAN_EXECUTION_MODE", "inline")
    from audittrail.config import get_settings

    get_settings.cache_clear()
    Session = sessionmaker(bind=engine)
    monkeypatch.setattr("audittrail.services.scan_recovery.SessionLocal", Session)

    db = Session()
    scan = Scan(source=ScanSource.ARCHIVE_UPLOAD, status=ScanStatus.PENDING)
    db.add(scan)
    db.commit()

    dispatched: list[str] = []

    def _fake_dispatch(scan_id: str, **kwargs: object) -> None:
        dispatched.append(scan_id)

    monkeypatch.setattr("audittrail.services.scan_recovery.dispatch_scan", _fake_dispatch)
    recover_stuck_scans()

    assert dispatched == [str(scan.id)]
    db.close()
