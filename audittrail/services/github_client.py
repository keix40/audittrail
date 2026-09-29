"""Minimal GitHub App API client for check runs and review comments."""

from __future__ import annotations

import time
from typing import Any, cast

import httpx
import jwt
from audittrail.config import get_settings
from audittrail.schemas.finding import NormalizedFinding


def _app_jwt() -> str:
    settings = get_settings()
    if not settings.github_app_id or not settings.github_app_private_key:
        raise RuntimeError("GitHub App credentials not configured")
    key = settings.github_app_private_key.replace("\\n", "\n")
    now = int(time.time())
    payload = {"iat": now - 60, "exp": now + 600, "iss": settings.github_app_id}
    return jwt.encode(payload, key, algorithm="RS256")


def _installation_token(installation_id: int) -> str:
    settings = get_settings()
    headers = {
        "Authorization": f"Bearer {_app_jwt()}",
        "Accept": "application/vnd.github+json",
    }
    url = f"{settings.github_api_base}/app/installations/{installation_id}/access_tokens"
    resp = httpx.post(url, headers=headers, timeout=30.0)
    resp.raise_for_status()
    return cast(str, resp.json()["token"])


def create_check_run(
    repo_full_name: str,
    head_sha: str,
    installation_id: int,
    *,
    name: str = "AuditTrail Security Scan",
    status: str = "completed",
    conclusion: str = "success",
    summary: str,
) -> dict[str, Any]:
    token = _installation_token(installation_id)
    url = f"{get_settings().github_api_base}/repos/{repo_full_name}/check-runs"
    resp = httpx.post(
        url,
        headers={
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
        },
        json={
            "name": name,
            "head_sha": head_sha,
            "status": status,
            "conclusion": conclusion,
            "output": {"title": name, "summary": summary},
        },
        timeout=30.0,
    )
    resp.raise_for_status()
    return cast(dict[str, Any], resp.json())


def post_review_comments(
    repo_full_name: str,
    pr_number: int,
    installation_id: int,
    commit_sha: str,
    findings: list[NormalizedFinding],
    body_summary: str,
) -> dict[str, Any]:
    token = _installation_token(installation_id)
    url = f"{get_settings().github_api_base}/repos/{repo_full_name}/pulls/{pr_number}/reviews"
    comments = []
    for f in findings[:50]:
        if f.file_path and f.line_start:
            comments.append(
                {
                    "path": f.file_path,
                    "line": f.line_start,
                    "body": f"**[{f.severity.value}] {f.title}**\n\n{f.description}",
                }
            )
    resp = httpx.post(
        url,
        headers={
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
        },
        json={
            "commit_id": commit_sha,
            "body": body_summary,
            "event": "COMMENT",
            "comments": comments,
        },
        timeout=60.0,
    )
    resp.raise_for_status()
    return cast(dict[str, Any], resp.json())
