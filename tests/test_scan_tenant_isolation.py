import uuid

import pytest
from audittrail.models.scan import Scan, ScanSource, ScanStatus
from audittrail.services.api_keys import generate_api_key
from fastapi.testclient import TestClient


@pytest.fixture
def api_client(db_session, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("DEBUG", "true")
    from audittrail.config import get_settings

    get_settings.cache_clear()
    from audittrail.db.session import get_db
    from audittrail.main import create_app

    app = create_app()

    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    return TestClient(app)


def test_scan_only_visible_to_owner(db_session, api_client: TestClient) -> None:
    raw_a, key_a = generate_api_key(db_session, "tenant-a")
    raw_b, _key_b = generate_api_key(db_session, "tenant-b")

    scan = Scan(
        source=ScanSource.ARCHIVE_UPLOAD,
        status=ScanStatus.COMPLETED,
        owner_api_key_id=key_a.id,
    )
    db_session.add(scan)
    db_session.commit()

    ok = api_client.get(f"/v1/scans/{scan.id}", headers={"X-API-Key": raw_a})
    assert ok.status_code == 200

    denied = api_client.get(f"/v1/scans/{scan.id}", headers={"X-API-Key": raw_b})
    assert denied.status_code == 404

    missing = api_client.get(f"/v1/scans/{uuid.uuid4()}", headers={"X-API-Key": raw_a})
    assert missing.status_code == 404
