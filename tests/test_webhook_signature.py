import hashlib
import hmac
import json

import pytest
from audittrail.services.github_webhook import WebhookVerificationError, verify_github_signature


def sign(body: bytes, secret: str) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_verify_valid_signature() -> None:
    body = json.dumps({"action": "opened"}).encode()
    secret = "test-secret"
    verify_github_signature(body, sign(body, secret), secret)


def test_verify_invalid_signature() -> None:
    body = b"{}"
    with pytest.raises(WebhookVerificationError, match="Invalid"):
        verify_github_signature(body, "sha256=deadbeef", "secret")


def test_verify_missing_header() -> None:
    with pytest.raises(WebhookVerificationError, match="Missing"):
        verify_github_signature(b"{}", None, "secret")
