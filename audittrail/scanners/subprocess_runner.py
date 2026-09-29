"""Run scanners as local subprocesses (Render / single-container mode)."""

from __future__ import annotations

import logging
import os
import resource
import subprocess
from pathlib import Path

from audittrail.config import get_settings
from audittrail.scanners.docker_runner import (
    ScannerExecutionError,
    ScannerRunResult,
    validate_scanner_result,
)
from audittrail.scanners.scanner_commands import (
    enabled_scanners,
    subprocess_scanner_commands,
)
from audittrail.schemas.finding import ScannerName
from audittrail.services.workspace import validate_workspace_not_empty

logger = logging.getLogger(__name__)

_SCRUBBED_ENV_KEYS = frozenset(
    {
        "DATABASE_URL",
        "REDIS_URL",
        "CELERY_BROKER_URL",
        "CELERY_RESULT_BACKEND",
        "GITHUB_APP_PRIVATE_KEY",
        "GITHUB_WEBHOOK_SECRET",
        "API_KEY_PEPPER",
        "BOOTSTRAP_ADMIN_TOKEN",
        "LLM_API_KEY",
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
    }
)


def _scrubbed_env() -> dict[str, str]:
    base = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": "/tmp",
        "LANG": "C.UTF-8",
        "XDG_CACHE_HOME": "/tmp",
    }
    for key, value in os.environ.items():
        if key in _SCRUBBED_ENV_KEYS or key.startswith(("AWS_", "GITHUB_")):
            continue
        if key.isupper() and key.endswith(("_KEY", "_SECRET", "_TOKEN", "_PASSWORD")):
            continue
        base[key] = value
    return base


def _apply_rlimits() -> None:
    try:
        resource.setrlimit(resource.RLIMIT_AS, (768 * 1024 * 1024, 768 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_CPU, (600, 600))
        resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    except (ValueError, OSError):
        logger.debug("Could not apply subprocess rlimits", exc_info=True)


class SubprocessScannerRunner:
    def __init__(self) -> None:
        self._settings = get_settings()

    def _run_one(self, scanner: ScannerName, workspace: Path, cmd: list[str]) -> ScannerRunResult:
        timeout = self._settings.scanner_timeout_seconds
        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=_scrubbed_env(),
                cwd=str(workspace),
                preexec_fn=_apply_rlimits,
            )
        except subprocess.TimeoutExpired as exc:
            stderr = exc.stderr.decode("utf-8", errors="replace") if exc.stderr else "timeout"
            raise ScannerExecutionError(
                scanner,
                f"timed out after {timeout}s",
                stderr=stderr,
            ) from exc
        return ScannerRunResult(
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
            exit_code=int(completed.returncode),
        )

    def run_all(self, workspace: Path) -> dict[ScannerName, ScannerRunResult]:
        validate_workspace_not_empty(workspace)
        resolved = str(workspace.resolve())
        commands = subprocess_scanner_commands(resolved, self._settings)
        results: dict[ScannerName, ScannerRunResult] = {}
        for scanner in enabled_scanners(self._settings):
            cmd = commands[scanner]
            result = self._run_one(scanner, workspace, cmd)
            validate_scanner_result(scanner, result)
            results[scanner] = result
        return results
