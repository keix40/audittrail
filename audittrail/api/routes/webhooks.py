import json

from audittrail.api.deps import DbSession
from audittrail.config import get_settings
from audittrail.models.scan import Scan, ScanSource, ScanStatus
from audittrail.services.github_webhook import (
    WebhookVerificationError,
    extract_pr_context,
    verify_github_signature,
)
from audittrail.services.inline_executor import ScanQueueFullError
from audittrail.services.scan_dispatch import dispatch_scan, mark_scan_queue_rejected
from fastapi import APIRouter, BackgroundTasks, Header, HTTPException, Request

router = APIRouter(prefix="/webhooks", tags=["webhooks"])


def _enqueue_github_scan(scan_id: str) -> None:
    try:
        dispatch_scan(scan_id, post_github=True)
    except ScanQueueFullError:
        mark_scan_queue_rejected(scan_id, "Inline scan queue full; try again later")


@router.post("/github", status_code=202)
async def github_webhook(
    request: Request,
    db: DbSession,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: str | None = Header(default=None),
    x_github_event: str | None = Header(default=None),
) -> dict[str, str]:
    body = await request.body()
    settings = get_settings()
    try:
        verify_github_signature(body, x_hub_signature_256, settings.github_webhook_secret)
    except WebhookVerificationError as exc:
        raise HTTPException(status_code=401, detail=str(exc)) from exc

    payload = json.loads(body)
    if x_github_event != "pull_request":
        return {"status": "ignored", "reason": f"event {x_github_event}"}

    ctx = extract_pr_context(payload)
    if ctx["action"] not in ("opened", "synchronize", "reopened"):
        return {"status": "ignored", "reason": f"action {ctx['action']}"}

    scan = Scan(
        source=ScanSource.GITHUB_PR,
        status=ScanStatus.PENDING,
        repo_full_name=ctx["repo_full_name"],
        ref=(payload.get("pull_request") or {}).get("head", {}).get("ref"),
        pr_number=ctx["pr_number"],
        installation_id=ctx["installation_id"],
        commit_sha=ctx["head_sha"],
        metadata_json={
            "action": ctx["action"],
            "head_repo_full_name": ctx["head_repo_full_name"],
        },
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    background_tasks.add_task(_enqueue_github_scan, str(scan.id))
    return {"status": "queued", "scan_id": str(scan.id)}
