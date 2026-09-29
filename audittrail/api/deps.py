from __future__ import annotations

from typing import Annotated

from audittrail.db.session import get_db
from audittrail.models.api_key import ApiKey
from audittrail.services.admin_auth import AdminAuthError, verify_bootstrap_admin_token
from audittrail.services.api_keys import verify_api_key
from audittrail.services.rate_limit import RateLimiter, RateLimitExceeded
from fastapi import Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

DbSession = Annotated[Session, Depends(get_db)]


def get_rate_limiter() -> RateLimiter:
    return RateLimiter()


def require_api_key(
    db: DbSession,
    x_api_key: Annotated[str | None, Header()] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> ApiKey:
    raw = x_api_key
    if not raw and authorization and authorization.lower().startswith("bearer "):
        raw = authorization[7:].strip()
    record = verify_api_key(db, raw)
    if not record:
        raise HTTPException(status_code=401, detail="Invalid or missing API key")
    return record


def require_bootstrap_admin(
    x_admin_token: Annotated[str | None, Header()] = None,
    authorization: Annotated[str | None, Header()] = None,
) -> None:
    token = x_admin_token
    if not token and authorization and authorization.lower().startswith("bearer "):
        token = authorization[7:].strip()
    try:
        verify_bootstrap_admin_token(token)
    except AdminAuthError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc


def rate_limit_api_key(
    request: Request,
    api_key: Annotated[ApiKey, Depends(require_api_key)],
    limiter: Annotated[RateLimiter, Depends(get_rate_limiter)],
) -> ApiKey:
    try:
        limiter.check(str(api_key.id))
    except RateLimitExceeded as exc:
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded",
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc
    return api_key
