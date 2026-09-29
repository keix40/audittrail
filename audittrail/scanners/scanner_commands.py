"""Scanner CLI definitions shared by Docker and subprocess runners."""

from __future__ import annotations

from audittrail.config import Settings, get_settings
from audittrail.schemas.finding import ScannerName

FINDING_EXIT_CODES: dict[ScannerName, frozenset[int]] = {
    ScannerName.SEMGREP: frozenset({0, 1}),
    ScannerName.BANDIT: frozenset({0, 1}),
    ScannerName.GITLEAKS: frozenset({0, 1}),
    ScannerName.TRIVY: frozenset({0}),
}


def semgrep_config_path(settings: Settings | None = None) -> str:
    cfg = settings or get_settings()
    return cfg.semgrep_config_path


def docker_scanner_commands(settings: Settings | None = None) -> dict[ScannerName, list[str]]:
    semgrep_cfg = semgrep_config_path(settings)
    return {
        ScannerName.SEMGREP: [
            "semgrep",
            "scan",
            f"--config={semgrep_cfg}",
            "--json",
            "--error",
            "--metrics=off",
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


def subprocess_scanner_commands(
    workspace: str,
    settings: Settings | None = None,
) -> dict[ScannerName, list[str]]:
    semgrep_cfg = semgrep_config_path(settings)
    return {
        ScannerName.SEMGREP: [
            "semgrep",
            "scan",
            f"--config={semgrep_cfg}",
            "--json",
            "--error",
            "--metrics=off",
            workspace,
        ],
        ScannerName.BANDIT: [
            "bandit",
            "-r",
            workspace,
            "-f",
            "json",
            "-q",
        ],
        ScannerName.GITLEAKS: [
            "gitleaks",
            "detect",
            f"--source={workspace}",
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
            workspace,
        ],
    }


def enabled_scanners(settings: Settings | None = None) -> tuple[ScannerName, ...]:
    cfg = settings or get_settings()
    scanners: list[ScannerName] = [
        ScannerName.SEMGREP,
        ScannerName.BANDIT,
        ScannerName.GITLEAKS,
    ]
    if cfg.scanner_enable_trivy:
        scanners.append(ScannerName.TRIVY)
    return tuple(scanners)
