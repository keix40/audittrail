import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from audittrail.scanners.docker_runner import ScannerRunResult
from audittrail.scanners.subprocess_runner import SubprocessScannerRunner, _apply_rlimits
from audittrail.schemas.finding import ScannerName

FIXTURE_ROOT = Path(__file__).resolve().parents[1] / "fixtures" / "vulnerable-sample"


def test_apply_rlimits_caps_address_space_and_stack() -> None:
    probe = """
import resource
from audittrail.scanners.subprocess_runner import (
    _SCANNER_RLIMIT_AS_BYTES,
    _SCANNER_RLIMIT_STACK_HARD_BYTES,
    _SCANNER_RLIMIT_STACK_SOFT_BYTES,
    _apply_rlimits,
)

_apply_rlimits()
as_soft, as_hard = resource.getrlimit(resource.RLIMIT_AS)
stack_soft, stack_hard = resource.getrlimit(resource.RLIMIT_STACK)
assert as_soft == as_hard == _SCANNER_RLIMIT_AS_BYTES
assert stack_soft == _SCANNER_RLIMIT_STACK_SOFT_BYTES
assert stack_hard == _SCANNER_RLIMIT_STACK_HARD_BYTES
"""
    completed = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        preexec_fn=_apply_rlimits,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr or completed.stdout


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
