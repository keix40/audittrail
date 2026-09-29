import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from audittrail.scanners.docker_runner import ScannerRunResult
from audittrail.scanners.subprocess_runner import SubprocessScannerRunner
from audittrail.schemas.finding import ScannerName

FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "vulnerable-sample"


def test_subprocess_runner_runs_enabled_scanners(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SCANNER_ENABLE_TRIVY", "false")
    from audittrail.config import get_settings

    get_settings.cache_clear()

    calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):  # type: ignore[no-untyped-def]
        calls.append(cmd)
        if cmd[0] == "semgrep" or cmd[0] == "bandit":
            payload = json.dumps({"results": []})
        elif cmd[0] == "gitleaks":
            payload = "[]"
        else:
            payload = "{}"
        return MagicMock(returncode=0, stdout=payload, stderr="")

    monkeypatch.setattr("audittrail.scanners.subprocess_runner.subprocess.run", fake_run)
    runner = SubprocessScannerRunner()
    results = runner.run_all(FIXTURE_ROOT)
    assert set(results.keys()) == {ScannerName.SEMGREP, ScannerName.BANDIT, ScannerName.GITLEAKS}
    assert len(calls) == 3
    assert all(isinstance(r, ScannerRunResult) for r in results.values())
