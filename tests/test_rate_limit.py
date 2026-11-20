"""Tests for bounded, concurrency-safe API token-bucket rate limiting."""
from __future__ import annotations

import concurrent.futures
import threading
import unittest

from wifi_analyzer_backend.rate_limit import TokenBucketRateLimiter


class TokenBucketRateLimiterTests(unittest.TestCase):
    def test_burst_is_limited_and_tokens_refill_over_time(self):
        limiter = TokenBucketRateLimiter()
        self.assertTrue(limiter.consume("user-1", capacity=2, period_seconds=60, now=100)["allowed"])
        self.assertTrue(limiter.consume("user-1", capacity=2, period_seconds=60, now=100)["allowed"])
        blocked = limiter.consume("user-1", capacity=2, period_seconds=60, now=100)
        self.assertFalse(blocked["allowed"])
        self.assertEqual(blocked["remaining"], 0)
        self.assertEqual(blocked["retry_after_seconds"], 30)
        recovered = limiter.consume("user-1", capacity=2, period_seconds=60, now=130)
        self.assertTrue(recovered["allowed"])
        self.assertEqual(recovered["remaining"], 0)

    def test_buckets_are_isolated_and_identifiers_are_not_retained(self):
        limiter = TokenBucketRateLimiter()
        limiter.consume("user-secret-a", capacity=1, period_seconds=60, now=10)
        limiter.consume("user-secret-b", capacity=1, period_seconds=60, now=10)
        self.assertEqual(limiter.bucket_count, 2)
        self.assertNotIn("user-secret-a", repr(limiter._buckets))
        self.assertNotIn("user-secret-b", repr(limiter._buckets))
        self.assertTrue(limiter.consume("user-secret-b", capacity=1, period_seconds=60, now=10)["allowed"])
        self.assertFalse(limiter.consume("user-secret-a", capacity=1, period_seconds=60, now=10)["allowed"])

    def test_expired_entries_are_pruned_and_storage_stays_bounded(self):
        limiter = TokenBucketRateLimiter(max_buckets=3, idle_ttl_seconds=5)
        limiter.consume("a", capacity=1, period_seconds=10, now=0)
        limiter.consume("b", capacity=1, period_seconds=10, now=0)
        limiter.consume("c", capacity=1, period_seconds=10, now=0)
        limiter.consume("d", capacity=1, period_seconds=10, now=1)
        self.assertEqual(limiter.bucket_count, 3)
        limiter.consume("e", capacity=1, period_seconds=10, now=20)
        self.assertEqual(limiter.bucket_count, 1)

    def test_concurrent_requests_cannot_exceed_the_burst_capacity(self):
        limiter = TokenBucketRateLimiter()
        barrier = threading.Barrier(20)

        def acquire():
            barrier.wait(timeout=3)
            return limiter.consume("shared-principal", capacity=5, period_seconds=60, now=100)["allowed"]

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
            outcomes = list(pool.map(lambda _: acquire(), range(20)))
        self.assertEqual(sum(outcomes), 5)

    def test_invalid_inputs_fail_closed(self):
        limiter = TokenBucketRateLimiter()
        for capacity, period in ((True, 60), (0, 60), (2, 0), (2, 86401)):
            with self.assertRaises(ValueError):
                limiter.consume("user", capacity=capacity, period_seconds=period)
        for key in ("", "x" * 513):
            with self.assertRaises(ValueError):
                limiter.consume(key, capacity=1, period_seconds=60)
        with self.assertRaises(ValueError):
            limiter.consume("user", capacity=1, period_seconds=60, cost=2)


if __name__ == "__main__":
    unittest.main()
