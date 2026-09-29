from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from audittrail import __version__
from audittrail.api.routes import admin, health, scans, webhooks
from audittrail.config import get_settings
from audittrail.services.scan_recovery import recover_stuck_scans
from audittrail.services.startup_validation import validate_production_secrets


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    validate_production_secrets(settings)
    recover_stuck_scans()
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version=__version__,
        description=(
            "Automated code review and security scanner API. "
            "Runs Semgrep, Bandit, Gitleaks, and Trivy in sandboxed containers."
        ),
        lifespan=lifespan,
    )
    app.include_router(health.router)
    app.include_router(webhooks.router)
    app.include_router(scans.router)
    app.include_router(admin.router)
    return app


app = create_app()
