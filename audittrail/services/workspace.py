"""Shared scan workspace paths (API, worker, and scanner containers)."""

from __future__ import annotations

import uuid
from pathlib import Path

from audittrail.config import get_settings


class EmptyWorkspaceError(ValueError):
    """Raised when a scan workspace has no files to analyze."""


def scan_workspace_path(scan_id: uuid.UUID) -> Path:
    settings = get_settings()
    return Path(settings.work_dir) / "scans" / str(scan_id)


def allocate_scan_workspace(scan_id: uuid.UUID) -> Path:
    workspace = scan_workspace_path(scan_id)
    workspace.mkdir(parents=True, exist_ok=True)
    return workspace


def validate_workspace_not_empty(workspace: Path) -> None:
    if not workspace.is_dir():
        raise EmptyWorkspaceError(f"Workspace does not exist: {workspace}")
    file_count = sum(1 for _ in workspace.rglob("*") if _.is_file())
    if file_count == 0:
        raise EmptyWorkspaceError(f"Workspace is empty: {workspace}")
