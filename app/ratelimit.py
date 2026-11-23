"""Fixed-window rate limiter.

In-memory by default; if REDIS_URL is set and the redis package is installed,
counters are kept in Redis so limits hold across instances.
"""
import os
import time


class RateLimiter:
    def __init__(self, limit: int = 100, window_seconds: int = 60):
        self.limit = limit
        self.window = window_seconds
        self._counts: dict[str, tuple[int, float]] = {}
        self._redis = None
        if os.getenv("REDIS_URL"):
            try:
                import redis  # type: ignore

                self._redis = redis.from_url(os.getenv("REDIS_URL"))
            except Exception:
                self._redis = None

    def allow(self, key: str) -> bool:
        if self._redis is not None:
            bucket = f"rl:{key}:{int(time.time() // self.window)}"
            count = self._redis.incr(bucket)
            if count == 1:
                self._redis.expire(bucket, self.window)
            return count <= self.limit
        now = time.time()
        count, start = self._counts.get(key, (0, now))
        if now - start >= self.window:
            count, start = 0, now
        count += 1
        self._counts[key] = (count, start)
        return count <= self.limit
