"""Redis-backed sliding window rate limiting."""

from __future__ import annotations

import time
from typing import Any

import redis
from audittrail.config import get_settings

_redis_pool: redis.ConnectionPool | None = None


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


class RateLimiter:
    def __init__(self, redis_url: str | None = None, limit_per_minute: int | None = None) -> None:
        settings = get_settings()
        if redis_url and redis_url != settings.redis_url:
            self._client = redis.from_url(redis_url, decode_responses=True)
        else:
            self._client = get_redis_client()
        self._limit = limit_per_minute or settings.rate_limit_per_minute

    def check(self, key: str) -> None:
        now = time.time()
        window_start = now - 60
        redis_key = f"ratelimit:{key}"
        pipe = self._client.pipeline()
        pipe.zremrangebyscore(redis_key, 0, window_start)
        pipe.zadd(redis_key, {str(now): now})
        pipe.zcard(redis_key)
        pipe.expire(redis_key, 120)
        _, _, count, _ = pipe.execute()
        if count > self._limit:
            oldest = self._client.zrange(redis_key, 0, 0, withscores=True)
            retry_after = 60
            if oldest:
                retry_after = max(1, int(60 - (now - oldest[0][1])))
            raise RateLimitExceeded(retry_after)
