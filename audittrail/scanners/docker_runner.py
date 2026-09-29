"""Run scanners inside ephemeral Docker containers."""

from __future__ import annotations

import json
import logging
import tempfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Protocol

import docker
from docker.models.containers import Container

from audittrail.config import get_settings
from audittrail.schemas.finding import ScannerName

logger = logging.getLogger(__name__)

SCANNER_COMMANDS: dict[ScannerName, list[str]] = {
    ScannerName.SEMGREP: [
        "semgrep",
        "scan",
        "--config=auto",
        "--json",
        "/workspace",
    ],
    ScannerName.BANDIT: [
        "bandit",
        "-r",
        "/workspace",
        "-f",
        "json",
        "-q",
    ],
    ScannerName.GITLEAKS: [
        "gitleaks",
        "detect",
        "--source=/workspace",
        "--report-format=json",
        "--report-path=/dev/stdout",
        "--no-git",
    ],
    ScannerName.TRIVY: [
        "trivy",
        "fs",
        "--scanners=vuln",
        "--format=json",
        "/workspace",
    ],
}


class ScannerRunner(Protocol):
    def run_all(self, workspace: Path) -> dict[ScannerName, str]: ...


class DockerScannerRunner:
    def __init__(self) -> None:
        self._settings = get_settings()
        self._client = docker.from_env()

    def _run_one(self, scanner: ScannerName, workspace: Path) -> str:
        cmd = SCANNER_COMMANDS[scanner]

        container: Container | None = None
        try:
            container = self._client.containers.run(
                self._settings.scanner_docker_image,
                command=cmd,
                volumes={str(workspace.resolve()): {"bind": "/workspace", "mode": "ro"}},
                network_disabled=self._settings.scanner_network_disabled,
                mem_limit=self._settings.scanner_memory_limit,
                cpu_quota=self._settings.scanner_cpu_quota,
                remove=False,
                detach=True,
                read_only=True,
                tmpfs={"/tmp": "size=64m"},
            )
            result = container.wait(timeout=self._settings.scanner_timeout_seconds)
            raw_logs = container.logs(stdout=True, stderr=True)
            if isinstance(raw_logs, bytes):
                logs = raw_logs.decode("utf-8", errors="replace")
            else:
                logs = str(raw_logs)
            exit_code = result.get("StatusCode", 1)
            if exit_code not in (0, 1) and not logs.strip():
                logger.warning("Scanner %s exited %s with no output", scanner, exit_code)
            return logs
        finally:
            if container is not None:
                try:
                    container.remove(force=True)
                except Exception:
                    logger.exception("Failed to remove scanner container")

    def run_all(self, workspace: Path) -> dict[ScannerName, str]:
        results: dict[ScannerName, str] = {}
        with ThreadPoolExecutor(max_workers=len(ScannerName)) as pool:
            futures = {
                pool.submit(self._run_one, scanner, workspace): scanner for scanner in ScannerName
            }
            for future in as_completed(futures):
                scanner = futures[future]
                results[scanner] = future.result()
        return results


class MockScannerRunner:
    """Used in tests and when Docker is unavailable."""

    def __init__(
        self, fixtures: dict[ScannerName, str | dict[str, Any]] | None = None
    ) -> None:
        self._fixtures = fixtures or {}

    def run_all(self, workspace: Path) -> dict[ScannerName, str]:
        out: dict[ScannerName, str] = {}
        for scanner in ScannerName:
            payload = self._fixtures.get(scanner, _empty_payload(scanner))
            out[scanner] = payload if isinstance(payload, str) else json.dumps(payload)
        return out


def _empty_payload(scanner: ScannerName) -> str | dict[str, Any]:
    if scanner == ScannerName.GITLEAKS:
        return "[]"
    if scanner == ScannerName.SEMGREP:
        return {"results": []}
    if scanner == ScannerName.BANDIT:
        return {"results": []}
    return {"Results": []}


def prepare_workspace(source_path: Path, dest: Path | None = None) -> Path:
    """Copy source into an isolated workspace directory."""
    import shutil

    settings = get_settings()
    base = Path(settings.work_dir)
    base.mkdir(parents=True, exist_ok=True)
    if dest is None:
        dest = Path(tempfile.mkdtemp(prefix="scan-", dir=base))
    else:
        dest.mkdir(parents=True, exist_ok=True)
    if source_path.is_dir():
        shutil.copytree(source_path, dest, dirs_exist_ok=True)
    else:
        shutil.copy2(source_path, dest)
    return dest
