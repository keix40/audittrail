"""Normalize raw scanner output into NormalizedFinding and deduplicate."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, cast

from audittrail.schemas.finding import (
    SEVERITY_ORDER,
    NormalizedFinding,
    ScannerName,
    Severity,
)


def _map_severity(value: str) -> Severity:
    v = value.lower().strip()
    mapping = {
        "critical": Severity.CRITICAL,
        "error": Severity.HIGH,
        "high": Severity.HIGH,
        "warning": Severity.MEDIUM,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
        "note": Severity.INFO,
    }
    return mapping.get(v, Severity.MEDIUM)


def parse_semgrep(raw: dict[str, Any]) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for r in raw.get("results", []):
        extra = r.get("extra", {})
        sev = _map_severity(extra.get("severity", "medium"))
        path = r.get("path")
        start = r.get("start", {})
        end = r.get("end", {})
        findings.append(
            NormalizedFinding(
                scanner=ScannerName.SEMGREP,
                severity=sev,
                title=r.get("check_id", "Semgrep finding"),
                description=extra.get("message", r.get("check_id", "")),
                file_path=path,
                line_start=start.get("line"),
                line_end=end.get("line"),
                rule_id=r.get("check_id"),
                cwe=extra.get("metadata", {}).get("cwe"),
                raw=r,
            )
        )
    return findings


def parse_bandit(raw: dict[str, Any]) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for r in raw.get("results", []):
        sev_map = {"HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
        sev = sev_map.get(r.get("issue_severity", "MEDIUM"), Severity.MEDIUM)
        findings.append(
            NormalizedFinding(
                scanner=ScannerName.BANDIT,
                severity=sev,
                title=r.get("test_name", "Bandit finding"),
                description=r.get("issue_text", ""),
                file_path=r.get("filename"),
                line_start=r.get("line_number"),
                line_end=r.get("line_number"),
                rule_id=r.get("test_id"),
                cwe=None,
                raw=r,
            )
        )
    return findings


def parse_gitleaks(raw: list[Any] | dict[str, Any]) -> list[NormalizedFinding]:
    items = raw if isinstance(raw, list) else raw.get("findings", raw.get("results", []))
    findings: list[NormalizedFinding] = []
    for r in items:
        findings.append(
            NormalizedFinding(
                scanner=ScannerName.GITLEAKS,
                severity=Severity.HIGH,
                title=f"Secret detected: {r.get('RuleID', r.get('rule', 'secret'))}",
                description=r.get(
                    "Description", r.get("description", "Potential secret in repository")
                ),
                file_path=r.get("File", r.get("file")),
                line_start=r.get("StartLine", r.get("startLine")),
                line_end=r.get("EndLine", r.get("endLine")),
                rule_id=r.get("RuleID", r.get("rule")),
                raw=r if isinstance(r, dict) else {"value": r},
            )
        )
    return findings


def parse_trivy(raw: dict[str, Any]) -> list[NormalizedFinding]:
    findings: list[NormalizedFinding] = []
    for result in raw.get("Results", []):
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities") or []:
            sev = _map_severity(vuln.get("Severity", "medium"))
            findings.append(
                NormalizedFinding(
                    scanner=ScannerName.TRIVY,
                    severity=sev,
                    title=f"{vuln.get('VulnerabilityID', 'CVE')}: {vuln.get('Title', '')}".strip(),
                    description=vuln.get("Description", "")[:2000],
                    file_path=target,
                    rule_id=vuln.get("VulnerabilityID"),
                    cwe=None,
                    suggestion=vuln.get("FixedVersion") and f"Upgrade to {vuln['FixedVersion']}",
                    raw=vuln,
                )
            )
    return findings


PARSERS = {
    ScannerName.SEMGREP: parse_semgrep,
    ScannerName.BANDIT: parse_bandit,
    ScannerName.GITLEAKS: parse_gitleaks,
    ScannerName.TRIVY: parse_trivy,
}


def normalize_scanner_output(
    scanner: ScannerName, payload: str | dict[str, Any] | list[Any]
) -> list[NormalizedFinding]:
    if isinstance(payload, str):
        data: Any = json.loads(payload) if payload.strip() else {}
    else:
        data = payload
    if scanner == ScannerName.GITLEAKS:
        return parse_gitleaks(cast(list[Any] | dict[str, Any], data))
    if scanner == ScannerName.SEMGREP:
        return parse_semgrep(cast(dict[str, Any], data))
    if scanner == ScannerName.BANDIT:
        return parse_bandit(cast(dict[str, Any], data))
    return parse_trivy(cast(dict[str, Any], data))


def deduplicate_and_rank(findings: list[NormalizedFinding]) -> list[NormalizedFinding]:
    seen: dict[str, NormalizedFinding] = {}
    for f in findings:
        fp = f.fingerprint()
        existing = seen.get(fp)
        if existing is None or SEVERITY_ORDER[f.severity] < SEVERITY_ORDER[existing.severity]:
            seen[fp] = f
    ranked = sorted(seen.values(), key=lambda x: (SEVERITY_ORDER[x.severity], x.title))
    return ranked


def merge_scanner_results(
    results: Mapping[ScannerName, str | dict[str, Any] | list[Any]],
) -> list[NormalizedFinding]:
    all_findings: list[NormalizedFinding] = []
    for scanner, payload in results.items():
        all_findings.extend(normalize_scanner_output(scanner, payload))
    return deduplicate_and_rank(all_findings)
