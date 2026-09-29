import pytest
from audittrail.config import Settings
from audittrail.services.startup_validation import ConfigurationError, validate_production_secrets


def test_production_requires_non_default_secrets() -> None:
    settings = Settings(
        debug=False,
        api_key_pepper="change-me-in-production",
        bootstrap_admin_token="",
    )
    with pytest.raises(ConfigurationError):
        validate_production_secrets(settings)


def test_debug_skips_validation() -> None:
    settings = Settings(debug=True, api_key_pepper="change-me-in-production")
    validate_production_secrets(settings)
