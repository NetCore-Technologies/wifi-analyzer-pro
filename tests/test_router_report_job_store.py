"""Tests for the transactional scheduled-report job outbox and worker leases."""
from __future__ import annotations

import concurrent.futures
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from wifi_analyzer_backend.router_adapters.report_job_store import (
    ReportJobConflictError,
    ReportJobNotFoundError,
    RouterReportJobStore,
)
from wifi_analyzer_backend.feature_plugins.feature_182_router_audit_report_bundle_builder import run as build_report
from wifi_analyzer_backend.feature_plugins.feature_188_router_scheduled_report_job_intake import run as prepare_job


NOW = datetime(2026, 11, 20, 10, 0, tzinfo=timezone.utc)


def job(occurrence="a" * 64, observed=90, max_attempts=3):
    bundle = build_report({
        "report_id": "weekly-home",
        "title": "Weekly router report",
        "generated_at": NOW.isoformat(),
        "sources": [{
            "source_id": "home-health",
            "source_type": "router_fleet_health_audit",
            "result": {
                "status": "audited",
                "summary": {"router_count": 1, "warning_count": 1},
                "routers": [{
                    "router_id": "openwrt-home",
                    "site_id": "home",
                    "findings": [{
                        "code": "resource.cpu_high",
                        "severity": "warning",
                        "resource_type": "router",
                        "resource_id": "openwrt-home",
                        "observed": observed,
                        "threshold": 85,
                    }],
                }],
            },
        }],
    })
    return prepare_job({
        "schedule_id": "daily-home",
        "occurrence_id": occurrence,
        "scheduled_at": (NOW + timedelta(minutes=1)).isoformat(),
        "report_bundle": bundle,
        "max_attempts": max_attempts,
    })


class RouterReportJobStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "jobs.sqlite3"
        self.store = RouterReportJobStore(self.path)

    def tearDown(self):
        self.temp.cleanup()

    def test_enqueue_is_persistent_and_idempotent_for_same_occurrence_and_content(self):
        prepared = job()
        first = self.store.enqueue(prepared, now=NOW)
        self.assertTrue(first["created"])
        self.assertFalse(first["replayed"])
        reopened = RouterReportJobStore(self.path)
        second = reopened.enqueue(prepared, now=NOW)
        self.assertFalse(second["created"])
        self.assertTrue(second["replayed"])
        self.assertEqual(first["job"]["id"], second["job"]["id"])
        self.assertEqual(self.store.summary()["counts_by_status"]["pending"], 1)

    def test_reusing_occurrence_for_different_report_content_is_conflict(self):
        self.store.enqueue(job(observed=90), now=NOW)
        with self.assertRaises(ReportJobConflictError):
            self.store.enqueue(job(observed=96), now=NOW)

    def test_claim_returns_report_bundle_and_is_exclusive_across_workers(self):
        self.store.enqueue(job(), now=NOW)
        due = NOW + timedelta(minutes=1)
        first = self.store.claim_due("worker-a", now=due, lease_seconds=60)
        self.assertEqual(len(first["jobs"]), 1)
        claimed = first["jobs"][0]
        self.assertEqual(claimed["status"], "leased")
        self.assertEqual(claimed["attempts"], 1)
        self.assertEqual(claimed["lease_owner"], "worker-a")
        self.assertEqual(claimed["report_bundle"]["report_id"], "weekly-home")
        second = self.store.claim_due("worker-b", now=due, lease_seconds=60)
        self.assertEqual(second["jobs"], [])

    def test_claim_does_not_run_before_scheduled_time(self):
        self.store.enqueue(job(), now=NOW)
        early = self.store.claim_due("worker-a", now=NOW + timedelta(seconds=30))
        self.assertEqual(early["jobs"], [])
        due = self.store.claim_due("worker-a", now=NOW + timedelta(minutes=1))
        self.assertEqual(len(due["jobs"]), 1)

    def test_lease_renewal_and_completion_require_current_lease(self):
        self.store.enqueue(job(), now=NOW)
        claim = self.store.claim_due("worker-a", now=NOW + timedelta(minutes=1), lease_seconds=30)
        item = claim["jobs"][0]
        with self.assertRaises(ReportJobNotFoundError):
            self.store.complete(item["id"], "00000000-0000-4000-8000-000000000000", {})
        renewed = self.store.renew_lease(
            item["id"], item["lease_id"],
            now=NOW + timedelta(minutes=1, seconds=20), lease_seconds=90,
        )
        self.assertGreater(
            datetime.fromisoformat(renewed["lease_expires_at"]),
            datetime.fromisoformat(item["lease_expires_at"]),
        )
        completed = self.store.complete(item["id"], item["lease_id"], {
            "report_id": "weekly-home",
            "content_hash": item["report_bundle"]["content_hash"],
            "delivery_status": "prepared",
            "secret": "must-not-be-persisted",
        }, now=NOW + timedelta(minutes=1, seconds=21))
        self.assertEqual(completed["status"], "completed")
        self.assertEqual(completed["result"]["delivery_status"], "prepared")
        self.assertNotIn("secret", str(completed["result"]))
        self.assertIsNone(completed["lease_owner"])

    def test_get_leased_job_requires_matching_unexpired_lease(self):
        self.store.enqueue(job(), now=NOW)
        claimed = self.store.claim_due(
            "worker-a", now=NOW + timedelta(minutes=1), lease_seconds=60,
        )["jobs"][0]
        current = self.store.get_leased_job(
            claimed["id"], claimed["lease_id"],
            now=NOW + timedelta(minutes=1, seconds=1),
        )
        self.assertEqual(current["id"], claimed["id"])
        self.assertEqual(current["lease_id"], claimed["lease_id"])
        self.assertEqual(current["report_bundle"]["report_id"], "weekly-home")
        with self.assertRaises(ReportJobNotFoundError):
            self.store.get_leased_job(
                claimed["id"], "00000000-0000-4000-8000-000000000000",
                now=NOW + timedelta(minutes=1, seconds=1),
            )
        with self.assertRaises(ReportJobNotFoundError):
            self.store.get_leased_job(
                claimed["id"], claimed["lease_id"],
                now=NOW + timedelta(minutes=2, seconds=1),
            )

    def test_expired_lease_is_recovered_and_not_completed_by_stale_worker(self):
        self.store.enqueue(job(), now=NOW)
        first = self.store.claim_due("worker-a", now=NOW + timedelta(minutes=1), lease_seconds=15)["jobs"][0]
        expired_at = NOW + timedelta(minutes=1, seconds=16)
        with self.assertRaises(ReportJobNotFoundError):
            self.store.complete(first["id"], first["lease_id"], {}, now=expired_at)
        # Attempt 1 was consumed by the first claim. Expiry schedules a 30-second backoff.
        too_early = self.store.claim_due("worker-b", now=expired_at, lease_seconds=30)
        self.assertEqual(too_early["jobs"], [])
        recovered = self.store.claim_due(
            "worker-b", now=expired_at + timedelta(seconds=30), lease_seconds=30,
        )
        self.assertEqual(len(recovered["jobs"]), 1)
        self.assertEqual(recovered["jobs"][0]["attempts"], 2)
        self.assertNotEqual(recovered["jobs"][0]["lease_id"], first["lease_id"])

    def test_failure_uses_bounded_backoff_then_moves_to_dead_letter(self):
        self.store.enqueue(job(max_attempts=2), now=NOW)
        first = self.store.claim_due("worker-a", now=NOW + timedelta(minutes=1))["jobs"][0]
        failed = self.store.fail(
            first["id"], first["lease_id"], "delivery_timeout",
            now=NOW + timedelta(minutes=1, seconds=1),
        )
        self.assertEqual(failed["status"], "retry_wait")
        self.assertEqual(failed["retry_delay_seconds"], 30)
        second = self.store.claim_due(
            "worker-b", now=NOW + timedelta(minutes=1, seconds=31),
        )["jobs"][0]
        dead = self.store.fail(
            second["id"], second["lease_id"], "delivery_timeout",
            now=NOW + timedelta(minutes=1, seconds=32),
        )
        self.assertEqual(dead["status"], "dead_letter")
        self.assertEqual(dead["retry_delay_seconds"], 0)
        self.assertEqual(self.store.summary()["counts_by_status"]["dead_letter"], 1)

    def test_cancel_only_applies_to_pending_or_retry_wait_jobs(self):
        pending = self.store.enqueue(job(), now=NOW)["job"]
        cancelled = self.store.cancel(pending["id"], now=NOW)
        self.assertEqual(cancelled["status"], "cancelled")
        self.store.enqueue(job(occurrence="b" * 64), now=NOW)
        claimed = self.store.claim_due("worker-a", now=NOW + timedelta(minutes=1))["jobs"][0]
        with self.assertRaises(ReportJobNotFoundError):
            self.store.cancel(claimed["id"], now=NOW + timedelta(minutes=1))

    def test_concurrent_workers_never_claim_the_same_job(self):
        for index in range(10):
            self.store.enqueue(job(occurrence=f"{index:064x}"), now=NOW)
        barrier = threading.Barrier(2)

        def claim(worker):
            barrier.wait(timeout=2)
            return self.store.claim_due(worker, now=NOW + timedelta(minutes=1), limit=5)["jobs"]

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            left, right = (future.result(timeout=8) for future in (
                pool.submit(claim, "worker-a"), pool.submit(claim, "worker-b")
            ))
        ids = [item["id"] for item in left + right]
        self.assertEqual(len(ids), 10)
        self.assertEqual(len(set(ids)), 10)

    def test_lists_are_filtered_and_payload_is_not_returned_unless_claimed(self):
        self.store.enqueue(job(), now=NOW)
        item = self.store.list_jobs(schedule_id="daily-home")[0]
        self.assertNotIn("report_bundle", item)
        self.assertEqual(self.store.get(item["id"])["status"], "pending")
        self.assertEqual(self.store.list_jobs(status="completed"), [])

    def test_rejects_invalid_leases_results_and_limits(self):
        prepared = job()
        with self.assertRaisesRegex(ValueError, "job_key"):
            self.store.enqueue({**prepared, "job_key": "bad"}, now=NOW)
        self.store.enqueue(prepared, now=NOW)
        with self.assertRaisesRegex(ValueError, "lease_seconds"):
            self.store.claim_due("worker-a", now=NOW + timedelta(minutes=1), lease_seconds=1)
        with self.assertRaisesRegex(ValueError, "limit"):
            self.store.claim_due("worker-a", now=NOW + timedelta(minutes=1), limit=1000)
        with self.assertRaisesRegex(ValueError, "lowercase error identifier"):
            claimed = self.store.claim_due("worker-a", now=NOW + timedelta(minutes=1))["jobs"][0]
            self.store.fail(claimed["id"], claimed["lease_id"], "../error", now=NOW + timedelta(minutes=1))


if __name__ == "__main__":
    unittest.main()
