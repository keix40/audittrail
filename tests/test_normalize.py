from audittrail.schemas.finding import ScannerName, Severity
from audittrail.services.normalize import (
    deduplicate_and_rank,
    merge_scanner_results,
    normalize_scanner_output,
)


def test_semgrep_normalization() -> None:
    raw = {
        "results": [
            {
                "check_id": "python.lang.security.audit.eval-detected",
                "path": "app.py",
                "start": {"line": 10},
                "end": {"line": 10},
                "extra": {"message": "eval used", "severity": "ERROR"},
            }
        ]
    }
    findings = normalize_scanner_output(ScannerName.SEMGREP, raw)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].file_path == "app.py"


def test_deduplicate_keeps_higher_severity() -> None:
    raw_semgrep = {
        "results": [
            {
                "check_id": "rule-a",
                "path": "app.py",
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {"message": "low", "severity": "INFO"},
            },
            {
                "check_id": "rule-a",
                "path": "app.py",
                "start": {"line": 1},
                "end": {"line": 1},
                "extra": {"message": "high", "severity": "ERROR"},
            },
        ]
    }
    merged = merge_scanner_results({ScannerName.SEMGREP: raw_semgrep})
    assert len(merged) == 1
    assert merged[0].severity == Severity.HIGH


def test_ranking_orders_by_severity() -> None:
    from audittrail.schemas.finding import NormalizedFinding

    findings = deduplicate_and_rank(
        [
            NormalizedFinding(
                scanner=ScannerName.BANDIT,
                severity=Severity.LOW,
                title="low",
                description="",
            ),
            NormalizedFinding(
                scanner=ScannerName.GITLEAKS,
                severity=Severity.CRITICAL,
                title="crit",
                description="",
            ),
        ]
    )
    assert findings[0].severity == Severity.CRITICAL


def test_gitleaks_and_bandit_merge() -> None:
    results = merge_scanner_results(
        {
            ScannerName.GITLEAKS: [
                {
                    "RuleID": "aws-access-token",
                    "File": "app.py",
                    "StartLine": 5,
                    "Description": "AWS key",
                }
            ],
            ScannerName.BANDIT: {
                "results": [
                    {
                        "test_name": "blacklist_calls",
                        "issue_text": "pickle",
                        "issue_severity": "HIGH",
                        "filename": "app.py",
                        "line_number": 14,
                        "test_id": "B301",
                    }
                ]
            },
        }
    )
    assert len(results) == 2
    scanners = {f.scanner for f in results}
    assert ScannerName.GITLEAKS in scanners
    assert ScannerName.BANDIT in scanners
