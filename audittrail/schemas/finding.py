from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class ScannerName(StrEnum):
    SEMGREP = "semgrep"
    BANDIT = "bandit"
    GITLEAKS = "gitleaks"
    TRIVY = "trivy"


class NormalizedFinding(BaseModel):
    scanner: ScannerName
    severity: Severity
    title: str
    description: str
    file_path: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    rule_id: str | None = None
    cwe: str | None = None
    suggestion: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)

    def fingerprint(self) -> str:
        import hashlib

        parts = [
            self.scanner.value,
            self.file_path or "",
            str(self.line_start or ""),
            self.rule_id or self.title,
        ]
        return hashlib.sha256("|".join(parts).encode()).hexdigest()


class FindingOut(BaseModel):
    id: str
    scanner: str
    severity: str
    title: str
    description: str
    file_path: str | None
    line_start: int | None
    line_end: int | None
    rule_id: str | None
    cwe: str | None
    suggestion: str | None

    model_config = {"from_attributes": True}
