from collections.abc import Generator

import pytest
from audittrail.config import get_settings
from audittrail.db.session import get_db
from audittrail.main import create_app
from audittrail.services.admin_auth import AdminAuthError, verify_bootstrap_admin_token
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session


@pytest.fixture
def admin_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEBUG", "true")
    monkeypatch.setenv("API_KEY_PEPPER", "test-pepper")
    monkeypatch.setenv("BOOTSTRAP_ADMIN_TOKEN", "test-bootstrap-admin-token")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.fixture
def client(admin_env: None, db_session: Session) -> Generator[TestClient, None, None]:
    app = create_app()

    def override_get_db() -> Generator[Session, None, None]:
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_verify_bootstrap_token_success(admin_env: None) -> None:
    verify_bootstrap_admin_token("test-bootstrap-admin-token")


def test_verify_bootstrap_token_rejects_invalid(admin_env: None) -> None:
    with pytest.raises(AdminAuthError, match="Invalid"):
        verify_bootstrap_admin_token("wrong-token")


def test_verify_bootstrap_token_requires_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("BOOTSTRAP_ADMIN_TOKEN", raising=False)
    get_settings.cache_clear()
    with pytest.raises(AdminAuthError, match="not configured"):
        verify_bootstrap_admin_token("anything")
    get_settings.cache_clear()


def test_admin_api_requires_token(client: TestClient, db_session: Session) -> None:
    response = client.post("/v1/admin/api-keys?name=ci")
    assert response.status_code == 401


def test_admin_api_rejects_bad_token(client: TestClient, db_session: Session) -> None:
    response = client.post(
        "/v1/admin/api-keys?name=ci",
        headers={"X-Admin-Token": "not-the-token"},
    )
    assert response.status_code == 401


def test_admin_api_creates_key_with_valid_token(client: TestClient, db_session: Session) -> None:
    response = client.post(
        "/v1/admin/api-keys?name=ci",
        headers={"X-Admin-Token": "test-bootstrap-admin-token"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["name"] == "ci"
    assert body["api_key"].startswith("at_")
