from datetime import datetime
from enum import StrEnum
from uuid import UUID

from audittrail.schemas.finding import FindingOut
from pydantic import BaseModel, Field, HttpUrl


class ScanStatusOut(StrEnum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class RepoScanRequest(BaseModel):
    repo_url: HttpUrl = Field(..., description="Public Git repository URL (https)")
    ref: str = Field(default="main", description="Branch, tag, or commit")


class ScanCreated(BaseModel):
    scan_id: UUID
    status: ScanStatusOut


class ReportOut(BaseModel):
    passed: bool
    summary: str
    llm_generated: bool
    finding_counts: dict[str, int]


class ScanDetail(BaseModel):
    id: UUID
    source: str
    status: ScanStatusOut
    repo_full_name: str | None
    ref: str | None
    pr_number: int | None
    commit_sha: str | None
    created_at: datetime
    findings: list[FindingOut] = Field(default_factory=list)
    report: ReportOut | None = None

    model_config = {"from_attributes": True}
