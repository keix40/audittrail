from unittest.mock import MagicMock, patch

import pytest
from audittrail.services.inline_executor import ScanQueueFullError
from audittrail.services.scan_dispatch import dispatch_scan


def test_dispatch_inline_submits_executor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SCAN_EXECUTION_MODE", "inline")
    from audittrail.config import get_settings

    get_settings.cache_clear()
    mock_executor = MagicMock()
    with patch(
        "audittrail.services.scan_dispatch.get_inline_executor",
        return_value=mock_executor,
    ):
        dispatch_scan("00000000-0000-0000-0000-000000000001")
    mock_executor.submit.assert_called_once()


def test_dispatch_inline_propagates_queue_full(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SCAN_EXECUTION_MODE", "inline")
    from audittrail.config import get_settings

    get_settings.cache_clear()
    mock_executor = MagicMock()
    mock_executor.submit.side_effect = ScanQueueFullError("full")
    with patch(
        "audittrail.services.scan_dispatch.get_inline_executor",
        return_value=mock_executor,
    ), pytest.raises(ScanQueueFullError):
        dispatch_scan("00000000-0000-0000-0000-000000000001")


def test_dispatch_celery_uses_delay(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SCAN_EXECUTION_MODE", "celery")
    from audittrail.config import get_settings

    get_settings.cache_clear()
    with patch("audittrail.tasks.scan_tasks.run_scan_task") as mock_task:
        dispatch_scan("00000000-0000-0000-0000-000000000002", ref="main")
    mock_task.delay.assert_called_once()
