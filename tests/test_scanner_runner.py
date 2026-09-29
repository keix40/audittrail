import json
from pathlib import Path

import pytest
from audittrail.scanners.docker_runner import (
    MockScannerRunner,
    ScannerExecutionError,
)
from audittrail.schemas.finding import ScannerName

FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "vulnerable-sample"


def test_scanner_error_fails_scan() -> None:
    runner = MockScannerRunner(fail_scanner=ScannerName.SEMGREP)
    with pytest.raises(ScannerExecutionError):
        runner.run_all(FIXTURE_ROOT)


def test_invalid_json_fails_scan() -> None:
    runner = MockScannerRunner(invalid_json=ScannerName.BANDIT)
    with pytest.raises(ScannerExecutionError):
        runner.run_all(FIXTURE_ROOT)


def test_vulnerable_fixture_yields_findings_via_mock() -> None:
    mock_output = {
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
        ScannerName.SEMGREP: {"results": []},
        ScannerName.GITLEAKS: "[]",
        ScannerName.TRIVY: {"Results": []},
    }
    runner = MockScannerRunner(mock_output)
    results = runner.run_all(FIXTURE_ROOT)
    assert ScannerName.BANDIT in results
    payload = json.loads(results[ScannerName.BANDIT].stdout)
    assert payload["results"]
