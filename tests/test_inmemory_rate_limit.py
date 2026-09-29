import pytest
from audittrail.services.rate_limit import InMemoryRateLimiterBackend, RateLimitExceeded


def test_inmemory_rate_limit_blocks_over_limit() -> None:
    backend = InMemoryRateLimiterBackend()
    for _ in range(2):
        backend.check("key-a", limit=2)
    with pytest.raises(RateLimitExceeded):
        backend.check("key-a", limit=2)


def test_rate_limiter_uses_memory_when_redis_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    import audittrail.services.rate_limit as rate_limit_module
    from audittrail.config import get_settings
    from audittrail.services.rate_limit import InMemoryRateLimiterBackend, RateLimiter

    monkeypatch.setenv("REDIS_URL", "")
    get_settings.cache_clear()
    rate_limit_module._redis_pool = None
    limiter = RateLimiter(limit_per_minute=5)
    assert isinstance(limiter._backend, InMemoryRateLimiterBackend)
    limiter.check("user-1")
    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/0")
    get_settings.cache_clear()
    rate_limit_module._redis_pool = None
