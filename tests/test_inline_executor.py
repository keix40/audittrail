import time

import pytest
from audittrail.services.inline_executor import InlineScanExecutor, ScanQueueFullError


def test_inline_executor_runs_job() -> None:
    executor = InlineScanExecutor(max_workers=1, max_pending=2)
    result = executor.submit(lambda: 42).result(timeout=5)
    assert result == 42


def test_inline_executor_queue_full() -> None:
    executor = InlineScanExecutor(max_workers=1, max_pending=1)
    started = executor.submit(lambda: time.sleep(0.5))
    with pytest.raises(ScanQueueFullError):
        executor.submit(lambda: None)
    started.result(timeout=5)
