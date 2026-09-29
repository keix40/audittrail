"""Validate security-sensitive configuration at startup."""

from __future__ import annotations

from audittrail.config import Settings

DEFAULT_PEPPER = "change-me-in-production"
DEV_BOOTSTRAP = "dev-bootstrap-admin-token"


class ConfigurationError(RuntimeError):
    pass


def validate_production_secrets(settings: Settings) -> None:
    if settings.debug:
        return
    if not settings.api_key_pepper or settings.api_key_pepper == DEFAULT_PEPPER:
        raise ConfigurationError(
            "API_KEY_PEPPER must be set to a non-default value when debug is disabled"
        )
    if not settings.bootstrap_admin_token or settings.bootstrap_admin_token == DEV_BOOTSTRAP:
        raise ConfigurationError(
            "BOOTSTRAP_ADMIN_TOKEN must be set to a non-default value when debug is disabled"
        )
