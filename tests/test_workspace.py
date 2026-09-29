import uuid

import pytest
from audittrail.services.workspace import (
    EmptyWorkspaceError,
    allocate_scan_workspace,
    validate_workspace_not_empty,
)


def test_empty_workspace_rejected(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WORK_DIR", str(tmp_path))
    from audittrail.config import get_settings

    get_settings.cache_clear()
    workspace = allocate_scan_workspace(uuid.uuid4())
    with pytest.raises(EmptyWorkspaceError):
        validate_workspace_not_empty(workspace)


def test_nonempty_workspace_accepted(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WORK_DIR", str(tmp_path))
    from audittrail.config import get_settings

    get_settings.cache_clear()
    scan_id = uuid.uuid4()
    workspace = allocate_scan_workspace(scan_id)
    (workspace / "app.py").write_text("print('hi')\n", encoding="utf-8")
    validate_workspace_not_empty(workspace)
    assert workspace == tmp_path / "scans" / str(scan_id)
