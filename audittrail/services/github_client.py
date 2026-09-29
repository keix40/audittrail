"""Minimal GitHub App API client for check runs and review comments."""

from __future__ import annotations

import subprocess
import time
from pathlib import Path
from typing import Any, cast

import httpx
import jwt
from audittrail.config import get_settings
from audittrail.schemas.finding import NormalizedFinding
from audittrail.services.diff_scope import FileDiff, finding_in_diff, normalize_repo_path


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


def clone_repository_at_sha(
    repo_full_name: str,
    commit_sha: str,
    installation_id: int,
    dest: Path,
) -> None:
    token = _installation_token(installation_id)
    dest.mkdir(parents=True, exist_ok=True)
    clone_url = f"https://x-access-token:{token}@github.com/{repo_full_name}.git"
    subprocess.run(
        ["git", "clone", "--no-checkout", clone_url, str(dest)],
        check=True,
        capture_output=True,
        timeout=180,
    )
    subprocess.run(
        ["git", "fetch", "--depth", "1", "origin", commit_sha],
        check=True,
        capture_output=True,
        timeout=120,
        cwd=dest,
    )
    subprocess.run(
        ["git", "checkout", "--detach", commit_sha],
        check=True,
        capture_output=True,
        timeout=60,
        cwd=dest,
    )


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


def list_pull_request_files(
    repo_full_name: str,
    pr_number: int,
    installation_id: int,
) -> list[dict[str, Any]]:
    token = _installation_token(installation_id)
    url = f"{get_settings().github_api_base}/repos/{repo_full_name}/pulls/{pr_number}/files"
    resp = httpx.get(
        url,
        headers={
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
        },
        timeout=30.0,
    )
    resp.raise_for_status()
    return cast(list[dict[str, Any]], resp.json())


def _strip_workspace_prefix(file_path: str | None) -> str | None:
    if not file_path:
        return None
    normalized = normalize_repo_path(file_path)
    for prefix in ("/workspace/", "workspace/"):
        if normalized.startswith(prefix):
            normalized = normalized[len(prefix) :]
    if normalized.startswith("/"):
        normalized = normalized.lstrip("/")
    return normalized or None


def _inline_comment_for_finding(
    finding: NormalizedFinding,
    diff_scope: tuple[FileDiff, ...] | None,
) -> dict[str, object] | None:
    path = _strip_workspace_prefix(finding.file_path)
    if not path or not finding.line_start:
        return None
    scoped = NormalizedFinding(
        scanner=finding.scanner,
        severity=finding.severity,
        title=finding.title,
        description=finding.description,
        file_path=path,
        line_start=finding.line_start,
        line_end=finding.line_end,
        rule_id=finding.rule_id,
        cwe=finding.cwe,
        suggestion=finding.suggestion,
        raw=finding.raw,
    )
    if diff_scope and not finding_in_diff(scoped, diff_scope):
        return None
    return {
        "path": path,
        "line": finding.line_start,
        "body": f"**[{finding.severity.value}] {finding.title}**\n\n{finding.description}",
    }


def post_review_comments(
    repo_full_name: str,
    pr_number: int,
    installation_id: int,
    commit_sha: str,
    findings: list[NormalizedFinding],
    body_summary: str,
    *,
    diff_scope: tuple[FileDiff, ...] | None = None,
) -> dict[str, Any]:
    token = _installation_token(installation_id)
    url = f"{get_settings().github_api_base}/repos/{repo_full_name}/pulls/{pr_number}/reviews"
    comments: list[dict[str, object]] = []
    overflow: list[str] = []
    for f in findings[:50]:
        comment = _inline_comment_for_finding(f, diff_scope)
        if comment:
            comments.append(comment)
        else:
            path = _strip_workspace_prefix(f.file_path) or "n/a"
            loc = f"{path}:{f.line_start}" if f.line_start else path
            overflow.append(f"- [{f.severity.value}] {f.title} ({loc})")

    body = body_summary
    if overflow:
        body = body_summary + "\n\n**Additional findings (outside diff):**\n" + "\n".join(
            overflow[:20]
        )

    resp = httpx.post(
        url,
        headers={
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
        },
        json={
            "commit_id": commit_sha,
            "body": body,
            "event": "COMMENT",
            "comments": comments,
        },
        timeout=60.0,
    )
    resp.raise_for_status()
    return cast(dict[str, Any], resp.json())
