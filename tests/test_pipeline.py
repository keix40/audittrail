import uuid
from pathlib import Path

import pytest
from audittrail.models.scan import Scan, ScanSource, ScanStatus
from audittrail.scanners.docker_runner import MockScannerRunner, ScannerExecutionError, ScannerName
from audittrail.services.diff_scope import FileDiff, LineRange
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


def test_pipeline_diff_scope_limits_reported_findings(db_session) -> None:
    scan = Scan(source=ScanSource.GITHUB_PR, status=ScanStatus.PENDING, pr_number=1)
    db_session.add(scan)
    db_session.commit()

    runner = MockScannerRunner(MOCK_OUTPUT)
    scope = (FileDiff(filename="app.py", line_ranges=(LineRange(9, 9),)),)
    run_scan_pipeline(
        db_session,
        scan.id,
        FIXTURE_ROOT,
        runner=runner,
        diff_scope=scope,
    )

    db_session.refresh(scan)
    assert scan.status == ScanStatus.COMPLETED
    assert len(scan.findings) == 2
    assert all(f.line_start == 9 for f in scan.findings)
    assert all(f.file_path == "app.py" for f in scan.findings)
    assert scan.metadata_json.get("diff_scoped") is True


def test_pipeline_scanner_failure_marks_scan_failed(db_session, tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("WORK_DIR", str(tmp_path))
    from audittrail.config import get_settings

    get_settings.cache_clear()
    scan = Scan(source=ScanSource.ARCHIVE_UPLOAD, status=ScanStatus.PENDING)
    db_session.add(scan)
    db_session.commit()

    runner = MockScannerRunner(fail_scanner=ScannerName.SEMGREP)
    with pytest.raises(ScannerExecutionError):
        run_scan_pipeline(db_session, scan.id, FIXTURE_ROOT, runner=runner)

    db_session.refresh(scan)
    assert scan.status == ScanStatus.FAILED
    assert scan.error_message


def test_pipeline_missing_scan_raises(db_session) -> None:
    runner = MockScannerRunner(MOCK_OUTPUT)
    try:
        run_scan_pipeline(db_session, uuid.uuid4(), FIXTURE_ROOT, runner=runner)
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError")
