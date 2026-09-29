"""Select Docker vs subprocess scanner runner from configuration."""

from __future__ import annotations

from audittrail.config import get_settings
from audittrail.scanners.docker_runner import ScannerRunner


def get_scanner_runner() -> ScannerRunner:
    settings = get_settings()
    if settings.scanner_runner == "subprocess":
        from audittrail.scanners.subprocess_runner import SubprocessScannerRunner

        return SubprocessScannerRunner()
    from audittrail.scanners.docker_runner import DockerScannerRunner

    return DockerScannerRunner()
