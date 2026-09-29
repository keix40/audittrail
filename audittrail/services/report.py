from __future__ import annotations

import json

from audittrail.schemas.finding import NormalizedFinding, Severity


def compute_pass_fail(findings: list[NormalizedFinding]) -> bool:
    """Pass if no critical or high severity findings."""
    return not any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)


def finding_counts(findings: list[NormalizedFinding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    return counts


def counts_json(findings: list[NormalizedFinding]) -> str:
    return json.dumps(finding_counts(findings))
