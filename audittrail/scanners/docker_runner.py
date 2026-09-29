"""Run scanners inside ephemeral Docker containers."""

from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import docker
from docker.models.containers import Container

from audittrail.config import get_settings
from audittrail.schemas.finding import ScannerName
from audittrail.services.workspace import validate_workspace_not_empty

logger = logging.getLogger(__name__)

SCANNER_COMMANDS: dict[ScannerName, list[str]] = {
    ScannerName.SEMGREP: [
        "semgrep",
        "scan",
        "--config=p/python",
        "--json",
        "--error",
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
        "--skip-db-update",
        "--cache-dir=/trivy-cache",
        "/workspace",
    ],
}

# Exit codes that indicate findings (not tool failure).
FINDING_EXIT_CODES: dict[ScannerName, frozenset[int]] = {
    ScannerName.SEMGREP: frozenset({0, 1}),
    ScannerName.BANDIT: frozenset({0, 1}),
    ScannerName.GITLEAKS: frozenset({0, 1}),
    ScannerName.TRIVY: frozenset({0}),
}


@dataclass(frozen=True)
class ScannerRunResult:
    stdout: str
    stderr: str
    exit_code: int


class ScannerExecutionError(RuntimeError):
    def __init__(self, scanner: ScannerName, message: str, *, stderr: str = "") -> None:
        self.scanner = scanner
        self.stderr = stderr
        super().__init__(f"{scanner.value}: {message}")


class ScannerRunner(Protocol):
    def run_all(self, workspace: Path) -> dict[ScannerName, ScannerRunResult]: ...


def _parse_json_payload(scanner: ScannerName, stdout: str) -> None:
    text = stdout.strip()
    if not text:
        raise ScannerExecutionError(scanner, "empty stdout (expected JSON)")
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ScannerExecutionError(
            scanner, f"invalid JSON output: {exc}", stderr=text[:500]
        ) from exc
    if scanner == ScannerName.GITLEAKS and not isinstance(data, list):
        raise ScannerExecutionError(scanner, "gitleaks output must be a JSON array")
    if scanner != ScannerName.GITLEAKS and not isinstance(data, dict):
        raise ScannerExecutionError(scanner, "scanner output must be a JSON object")


def validate_scanner_result(scanner: ScannerName, result: ScannerRunResult) -> None:
    allowed = FINDING_EXIT_CODES[scanner]
    if result.exit_code not in allowed:
        detail = result.stderr.strip() or result.stdout.strip() or "unknown error"
        raise ScannerExecutionError(
            scanner,
            f"exited with code {result.exit_code}: {detail[:500]}",
            stderr=result.stderr,
        )
    _parse_json_payload(scanner, result.stdout)


class DockerScannerRunner:
    def __init__(self) -> None:
        self._settings = get_settings()
        self._client = docker.from_env()

    def _workspace_subpath(self, workspace: Path) -> str:
        work_root = Path(self._settings.work_dir).resolve()
        resolved = workspace.resolve()
        try:
            return str(resolved.relative_to(work_root))
        except ValueError as exc:
            raise ScannerExecutionError(
                ScannerName.SEMGREP,
                f"workspace {workspace} must live under {work_root}",
            ) from exc

    def _mounts_for_workspace(self, workspace: Path) -> list[dict[str, object]]:
        subpath = self._workspace_subpath(workspace)
        volume_name = self._settings.scanner_work_volume_name
        mount: dict[str, object] = {
            "target": "/workspace",
            "source": volume_name,
            "type": "volume",
            "read_only": True,
        }
        if subpath and subpath != ".":
            mount["volume_options"] = {"subpath": subpath}
        return [mount]

    def _run_one(self, scanner: ScannerName, workspace: Path) -> ScannerRunResult:
        cmd = SCANNER_COMMANDS[scanner]
        container: Container | None = None
        try:
            container = self._client.containers.run(
                self._settings.scanner_docker_image,
                command=cmd,
                mounts=self._mounts_for_workspace(workspace),
                network_disabled=self._settings.scanner_network_disabled,
                mem_limit=self._settings.scanner_memory_limit,
                cpu_quota=self._settings.scanner_cpu_quota,
                remove=False,
                detach=True,
                read_only=True,
                tmpfs={"/tmp": "size=64m"},
            )
            wait_result = container.wait(timeout=self._settings.scanner_timeout_seconds)
            exit_code = int(wait_result.get("StatusCode", 1))
            stdout_bytes = container.logs(stdout=True, stderr=False)
            stderr_bytes = container.logs(stdout=False, stderr=True)
            stdout = (
                stdout_bytes.decode("utf-8", errors="replace")
                if isinstance(stdout_bytes, bytes)
                else str(stdout_bytes)
            )
            stderr = (
                stderr_bytes.decode("utf-8", errors="replace")
                if isinstance(stderr_bytes, bytes)
                else str(stderr_bytes)
            )
            return ScannerRunResult(stdout=stdout, stderr=stderr, exit_code=exit_code)
        except Exception:
            raise
        finally:
            if container is not None:
                try:
                    container.remove(force=True)
                except Exception:
                    logger.exception("Failed to remove scanner container")

    def run_all(self, workspace: Path) -> dict[ScannerName, ScannerRunResult]:
        validate_workspace_not_empty(workspace)
        results: dict[ScannerName, ScannerRunResult] = {}
        with ThreadPoolExecutor(max_workers=len(ScannerName)) as pool:
            futures = {
                pool.submit(self._run_one, scanner, workspace): scanner for scanner in ScannerName
            }
            for future in as_completed(futures):
                scanner = futures[future]
                result = future.result()
                validate_scanner_result(scanner, result)
                results[scanner] = result
        return results


class MockScannerRunner:
    """Used in tests and when Docker is unavailable."""

    def __init__(
        self,
        fixtures: dict[ScannerName, str | dict[str, object]] | None = None,
        *,
        fail_scanner: ScannerName | None = None,
        invalid_json: ScannerName | None = None,
    ) -> None:
        self._fixtures = fixtures or {}
        self._fail_scanner = fail_scanner
        self._invalid_json = invalid_json

    def run_all(self, workspace: Path) -> dict[ScannerName, ScannerRunResult]:
        validate_workspace_not_empty(workspace)
        out: dict[ScannerName, ScannerRunResult] = {}
        for scanner in ScannerName:
            if self._fail_scanner == scanner:
                out[scanner] = ScannerRunResult(
                    stdout="",
                    stderr="scanner crashed",
                    exit_code=2,
                )
                validate_scanner_result(scanner, out[scanner])
            elif self._invalid_json == scanner:
                out[scanner] = ScannerRunResult(stdout="not-json", stderr="", exit_code=0)
                validate_scanner_result(scanner, out[scanner])
            else:
                payload = self._fixtures.get(scanner, _empty_payload(scanner))
                stdout = payload if isinstance(payload, str) else json.dumps(payload)
                out[scanner] = ScannerRunResult(stdout=stdout, stderr="", exit_code=0)
                validate_scanner_result(scanner, out[scanner])
        return out


def _empty_payload(scanner: ScannerName) -> str | dict[str, object]:
    if scanner == ScannerName.GITLEAKS:
        return "[]"
    if scanner == ScannerName.SEMGREP:
        return {"results": []}
    if scanner == ScannerName.BANDIT:
        return {"results": []}
    return {"Results": []}


def scanner_results_as_strings(
    results: dict[ScannerName, ScannerRunResult],
) -> dict[ScannerName, str]:
    return {scanner: result.stdout for scanner, result in results.items()}
