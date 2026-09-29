"""GitHub webhook signature verification and payload helpers."""

from __future__ import annotations

import hashlib
import hmac
from typing import Any


class WebhookVerificationError(Exception):
    pass


def verify_github_signature(payload_body: bytes, signature_header: str | None, secret: str) -> None:
    if not secret:
        raise WebhookVerificationError("Webhook secret is not configured")
    if not signature_header:
        raise WebhookVerificationError("Missing X-Hub-Signature-256 header")
    expected = "sha256=" + hmac.new(secret.encode(), payload_body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature_header):
        raise WebhookVerificationError("Invalid webhook signature")


def extract_pr_context(payload: dict[str, Any]) -> dict[str, Any]:
    pr = payload.get("pull_request") or {}
    repo = payload.get("repository") or {}
    installation = payload.get("installation") or {}
    return {
        "action": payload.get("action"),
        "repo_full_name": repo.get("full_name"),
        "pr_number": pr.get("number"),
        "head_sha": (pr.get("head") or {}).get("sha"),
        "head_repo_full_name": ((pr.get("head") or {}).get("repo") or {}).get("full_name"),
        "base_ref": (pr.get("base") or {}).get("ref"),
        "installation_id": installation.get("id"),
        "changed_files": pr.get("changed_files"),
    }
