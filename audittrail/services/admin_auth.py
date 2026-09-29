"""Bootstrap admin token verification."""

from __future__ import annotations

import secrets

from audittrail.config import get_settings


class AdminAuthError(Exception):
    pass


def verify_bootstrap_admin_token(provided: str | None) -> None:
    expected = get_settings().bootstrap_admin_token
    if not expected:
        raise AdminAuthError("Bootstrap admin token is not configured")
    if not provided:
        raise AdminAuthError("Missing admin token")
    if not secrets.compare_digest(provided, expected):
        raise AdminAuthError("Invalid admin token")
