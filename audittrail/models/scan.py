import enum
import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Enum, String, Text, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from audittrail.models.base import Base


class ScanStatus(enum.StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanSource(enum.StrEnum):
    GITHUB_PR = "github_pr"
    REPO_URL = "repo_url"
    ARCHIVE_UPLOAD = "archive_upload"


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source: Mapped[ScanSource] = mapped_column(Enum(ScanSource), nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        Enum(ScanStatus), nullable=False, default=ScanStatus.PENDING
    )
    repo_full_name: Mapped[str | None] = mapped_column(String(512), nullable=True)
    ref: Mapped[str | None] = mapped_column(String(256), nullable=True)
    pr_number: Mapped[int | None] = mapped_column(nullable=True)
    installation_id: Mapped[int | None] = mapped_column(nullable=True)
    commit_sha: Mapped[str | None] = mapped_column(String(64), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    findings: Mapped[list["FindingRecord"]] = relationship(back_populates="scan")
    report: Mapped["Report | None"] = relationship(back_populates="scan", uselist=False)


from audittrail.models.finding import FindingRecord  # noqa: E402
from audittrail.models.report import Report  # noqa: E402
