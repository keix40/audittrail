from unittest.mock import MagicMock

import pytest
from audittrail.services.rate_limit import RateLimiter, RateLimitExceeded, get_redis_client


def test_shared_redis_pool_reused() -> None:
    first = get_redis_client()
    second = get_redis_client()
    assert first.connection_pool is second.connection_pool


def test_rate_limit_allows_under_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    limiter = RateLimiter(limit_per_minute=5)
    mock_redis = MagicMock()
    pipe = MagicMock()
    pipe.execute.return_value = [None, None, 3, None]
    mock_redis.pipeline.return_value = pipe
    limiter._client = mock_redis
    limiter.check("user-1")


def test_rate_limit_blocks_over_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    limiter = RateLimiter(limit_per_minute=2)
    mock_redis = MagicMock()
    pipe = MagicMock()
    pipe.execute.return_value = [None, None, 3, None]
    mock_redis.pipeline.return_value = pipe
    mock_redis.zrange.return_value = [("1", 0.0)]
    limiter._client = mock_redis
    with pytest.raises(RateLimitExceeded) as exc:
        limiter.check("user-2")
    assert exc.value.retry_after >= 1
