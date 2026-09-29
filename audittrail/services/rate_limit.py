"""Rate limiting with Redis or in-process fallback."""

from __future__ import annotations

import threading
import time
from collections import defaultdict
from typing import Any, Protocol

import redis
from audittrail.config import get_settings

_redis_pool: redis.ConnectionPool | None = None


def redis_is_configured() -> bool:
    return bool(get_settings().redis_url.strip())


def get_redis_client() -> Any:
    global _redis_pool
    settings = get_settings()
    if _redis_pool is None:
        _redis_pool = redis.ConnectionPool.from_url(
            settings.redis_url,
            decode_responses=True,
        )
    return redis.Redis(connection_pool=_redis_pool)


class RateLimitExceeded(Exception):
    def __init__(self, retry_after: int) -> None:
        self.retry_after = retry_after
        super().__init__(f"Rate limit exceeded; retry after {retry_after}s")


class RateLimiterBackend(Protocol):
    def check(self, key: str, limit: int) -> None: ...


class RedisRateLimiterBackend:
    def __init__(self, redis_url: str | None = None) -> None:
        settings = get_settings()
        url = redis_url or settings.redis_url
        if redis_url and redis_url != settings.redis_url:
            self._client = redis.from_url(url, decode_responses=True)
        else:
            self._client = get_redis_client()

    def check(self, key: str, limit: int) -> None:
        now = time.time()
        window_start = now - 60
        redis_key = f"ratelimit:{key}"
        pipe = self._client.pipeline()
        pipe.zremrangebyscore(redis_key, 0, window_start)
        pipe.zadd(redis_key, {str(now): now})
        pipe.zcard(redis_key)
        pipe.expire(redis_key, 120)
        _, _, count, _ = pipe.execute()
        if count > limit:
            oldest = self._client.zrange(redis_key, 0, 0, withscores=True)
            retry_after = 60
            if oldest:
                retry_after = max(1, int(60 - (now - oldest[0][1])))
            raise RateLimitExceeded(retry_after)


class InMemoryRateLimiterBackend:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: dict[str, list[float]] = defaultdict(list)

    def check(self, key: str, limit: int) -> None:
        now = time.time()
        window_start = now - 60
        with self._lock:
            events = [t for t in self._events[key] if t > window_start]
            events.append(now)
            self._events[key] = events
            if len(events) > limit:
                retry_after = max(1, int(60 - (now - events[0])))
                raise RateLimitExceeded(retry_after)


class RateLimiter:
    def __init__(
        self,
        redis_url: str | None = None,
        limit_per_minute: int | None = None,
        *,
        backend: RateLimiterBackend | None = None,
    ) -> None:
        settings = get_settings()
        self._limit = limit_per_minute or settings.rate_limit_per_minute
        if backend is not None:
            self._backend = backend
        elif redis_url is not None or redis_is_configured():
            url = redis_url if redis_url is not None else settings.redis_url
            self._backend = RedisRateLimiterBackend(url)
        else:
            self._backend = InMemoryRateLimiterBackend()

    def check(self, key: str) -> None:
        self._backend.check(key, self._limit)
