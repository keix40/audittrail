import uuid
from pathlib import Path

from audittrail.models.scan import Scan, ScanSource, ScanStatus
from audittrail.scanners.docker_runner import MockScannerRunner
from audittrail.schemas.finding import ScannerName
from audittrail.services.pipeline import run_scan_pipeline

FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "vulnerable-sample"

MOCK_OUTPUT = {
    ScannerName.SEMGREP: {
        "results": [
            {
                "check_id": "python.lang.security.audit.eval-detected",
                "path": "app.py",
                "start": {"line": 9},
                "end": {"line": 9},
                "extra": {"message": "Detected use of eval", "severity": "ERROR"},
            }
        ]
    },
    ScannerName.BANDIT: {
        "results": [
            {
                "test_name": "blacklist_calls",
                "issue_text": "Use of exec",
                "issue_severity": "HIGH",
                "filename": "app.py",
                "line_number": 9,
                "test_id": "B307",
            }
        ]
    },
    ScannerName.GITLEAKS: [
        {
            "RuleID": "generic-api-key",
            "File": "app.py",
            "StartLine": 5,
            "Description": "Hardcoded credential",
        }
    ],
    ScannerName.TRIVY: {
        "Results": [
            {
                "Target": "requirements.txt",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2021-1234",
                        "Severity": "HIGH",
                        "Title": "Example vuln",
                        "Description": "Outdated dependency",
                        "FixedVersion": "2.31.0",
                    }
                ],
            }
        ]
    },
}


def test_pipeline_persists_findings_and_report(db_session) -> None:
    scan = Scan(source=ScanSource.ARCHIVE_UPLOAD, status=ScanStatus.PENDING)
    db_session.add(scan)
    db_session.commit()

    runner = MockScannerRunner(MOCK_OUTPUT)
    run_scan_pipeline(db_session, scan.id, FIXTURE_ROOT, runner=runner)

    db_session.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED
    assert len(scan.findings) >= 3
    assert scan.report is not None
    assert scan.report.passed is False
    assert "issue" in scan.report.summary.lower() or "finding" in scan.report.summary.lower()


def test_pipeline_missing_scan_raises(db_session) -> None:
    runner = MockScannerRunner(MOCK_OUTPUT)
    try:
        run_scan_pipeline(db_session, uuid.uuid4(), FIXTURE_ROOT, runner=runner)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
