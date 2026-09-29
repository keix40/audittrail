from pathlib import Path
from unittest.mock import MagicMock

import pytest
from audittrail.scanners.docker_runner import DockerScannerRunner


def test_host_workspace_path_uses_volume_mountpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WORK_DIR", "/var/audittrail/work")
    from audittrail.config import get_settings

    get_settings.cache_clear()

    mount_root = tmp_path / "docker-vol"
    scan_dir = mount_root / "scans" / "abc-123"
    scan_dir.mkdir(parents=True)
    (scan_dir / "app.py").write_text("print('x')\n", encoding="utf-8")

    mock_volume = MagicMock()
    mock_volume.attrs = {"Mountpoint": str(mount_root)}

    mock_client = MagicMock()
    mock_client.volumes.get.return_value = mock_volume

    runner = DockerScannerRunner.__new__(DockerScannerRunner)
    runner._settings = get_settings()
    runner._client = mock_client

    host_path = runner._host_workspace_path(Path("/var/audittrail/work/scans/abc-123"))
    assert host_path == scan_dir

    mounts = runner._mounts_for_workspace(Path("/var/audittrail/work/scans/abc-123"))
    assert mounts == [
        {
            "type": "bind",
            "source": str(scan_dir),
            "target": "/workspace",
            "read_only": True,
        }
    ]
