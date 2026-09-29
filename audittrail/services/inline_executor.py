"""Bounded in-process executor for inline scan execution."""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from typing import ParamSpec, TypeVar

from audittrail.config import get_settings

logger = logging.getLogger(__name__)

P = ParamSpec("P")
R = TypeVar("R")


class ScanQueueFullError(Exception):
    """Raised when the inline scan queue cannot accept another job."""


class InlineScanExecutor:
    def __init__(self, max_workers: int, max_pending: int) -> None:
        self._max_pending = max_pending
        self._lock = threading.Lock()
        self._pending = 0
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="scan-inline")

    @property
    def pending_count(self) -> int:
        with self._lock:
            return self._pending

    def submit(self, fn: Callable[P, R], /, *args: P.args, **kwargs: P.kwargs) -> Future[R]:
        with self._lock:
            if self._pending >= self._max_pending:
                raise ScanQueueFullError(
                    f"inline scan queue full ({self._pending}/{self._max_pending})"
                )
            self._pending += 1

        def _run() -> R:
            try:
                return fn(*args, **kwargs)
            finally:
                with self._lock:
                    self._pending -= 1

        return self._pool.submit(_run)

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)


_executor: InlineScanExecutor | None = None
_executor_lock = threading.Lock()


def get_inline_executor() -> InlineScanExecutor:
    global _executor
    if _executor is not None:
        return _executor
    with _executor_lock:
        if _executor is None:
            settings = get_settings()
            _executor = InlineScanExecutor(
                max_workers=settings.inline_scan_max_workers,
                max_pending=settings.inline_scan_max_pending,
            )
        return _executor
