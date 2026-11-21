"""Bounded in-memory token-bucket rate limiting for the local HTTP API."""
from __future__ import annotations

import hashlib
import math
import threading
import time
from collections import OrderedDict
from typing import Callable


DEFAULT_BUCKET_LIMIT = 8192

# Policies are expressed as (burst capacity, refill period in seconds).
# Auth endpoints are keyed by the direct socket peer IP. Authenticated work
# endpoints are keyed by the local account ID.
DEFAULT_POLICIES: dict[str, tuple[int, int]] = {
    "auth.setup": (3, 300),
    "auth.login": (8, 60),
    "auth.mfa": (6, 300),
    "api.scan": (15, 60),
    "api.speedtest": (2, 300),
    "api.feature.execution": (30, 60),
    "api.site.audit": (5, 60),
    "api.capture.start": (4, 900),
    "api.report.enqueue": (20, 60),
    "api.webhook.enqueue": (20, 60),
}


class TokenBucketRateLimiter:
    """Thread-safe token buckets with bounded memory and no persisted identifiers."""

    def __init__(
        self,
        *,
        max_buckets: int = DEFAULT_BUCKET_LIMIT,
        clock: Callable[[], float] = time.monotonic,
        idle_ttl_seconds: int = 3600,
    ) -> None:
        if isinstance(max_buckets, bool) or not isinstance(max_buckets, int) or max_buckets < 1:
            raise ValueError("max_buckets must be a positive integer")
        if isinstance(idle_ttl_seconds, bool) or not isinstance(idle_ttl_seconds, int) or idle_ttl_seconds < 1:
            raise ValueError("idle_ttl_seconds must be a positive integer")
        self.max_buckets = max_buckets
        self.idle_ttl_seconds = idle_ttl_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()

    @staticmethod
    def _bucket_key(key: str) -> str:
        if not isinstance(key, str) or not key or len(key) > 512:
            raise ValueError("rate-limit key must be a non-empty string of at most 512 characters")
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    @staticmethod
    def _validate_policy(capacity: int, period_seconds: int) -> None:
        if isinstance(capacity, bool) or not isinstance(capacity, int) or not 1 <= capacity <= 100000:
            raise ValueError("capacity must be an integer between 1 and 100000")
        if isinstance(period_seconds, bool) or not isinstance(period_seconds, int) or not 1 <= period_seconds <= 86400:
            raise ValueError("period_seconds must be an integer between 1 and 86400")

    def _prune(self, now: float) -> None:
        stale_before = now - self.idle_ttl_seconds
        while self._buckets:
            oldest_key, (_, last_seen) = next(iter(self._buckets.items()))
            if last_seen >= stale_before:
                break
            self._buckets.pop(oldest_key, None)

    def consume(
        self,
        key: str,
        *,
        capacity: int,
        period_seconds: int,
        cost: float = 1.0,
        now: float | None = None,
    ) -> dict:
        """Consume tokens and return limit metadata. Explicit time supports deterministic tests."""
        self._validate_policy(capacity, period_seconds)
        if isinstance(cost, bool) or not isinstance(cost, (int, float)) or not math.isfinite(cost) or not 0 < cost <= capacity:
            raise ValueError("cost must be a finite number greater than 0 and no greater than capacity")
        moment = self._clock() if now is None else now
        if isinstance(moment, bool) or not isinstance(moment, (int, float)) or not math.isfinite(moment):
            raise ValueError("now must be a finite monotonic timestamp")
        bucket_key = self._bucket_key(key)
        refill_per_second = capacity / period_seconds

        with self._lock:
            self._prune(float(moment))
            state = self._buckets.get(bucket_key)
            if state is None:
                tokens = float(capacity)
                updated_at = float(moment)
            else:
                available, previous_update = state
                effective_now = max(float(moment), previous_update)
                elapsed = effective_now - previous_update
                tokens = min(float(capacity), available + elapsed * refill_per_second)
                updated_at = effective_now

            allowed = tokens >= cost
            if allowed:
                tokens -= cost
                retry_after = 0
            else:
                retry_after = max(1, math.ceil((cost - tokens) / refill_per_second))

            self._buckets[bucket_key] = (tokens, updated_at)
            self._buckets.move_to_end(bucket_key)
            while len(self._buckets) > self.max_buckets:
                self._buckets.popitem(last=False)

            reset_after = max(0, math.ceil((capacity - tokens) / refill_per_second))
            return {
                "allowed": allowed,
                "limit": capacity,
                "remaining": max(0, math.floor(tokens)),
                "retry_after_seconds": retry_after,
                "reset_after_seconds": reset_after,
            }

    @property
    def bucket_count(self) -> int:
        with self._lock:
            return len(self._buckets)


__all__ = ["TokenBucketRateLimiter", "DEFAULT_POLICIES", "DEFAULT_BUCKET_LIMIT"]
