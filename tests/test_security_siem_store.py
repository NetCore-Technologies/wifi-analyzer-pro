"""Tests for the durable audit-to-SIEM outbox and source cursor."""
from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from wifi_analyzer_backend.audit_store import SecurityAuditStore
from wifi_analyzer_backend.security_siem_store import (
    SecuritySiemStore,
    SiemDeliveryNotFoundError,
    SiemQueueFullError,
)


OWNER = {"id": "a" * 32, "username": "admin", "role": "owner"}


class SecuritySiemStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.audit = SecurityAuditStore(root / "audit.sqlite3")
        self.path = root / "siem.sqlite3"
        self.store = SecuritySiemStore(self.path, retention_days=7, max_pending_events=10)
        self.now = datetime.now(timezone.utc).replace(microsecond=0)

    def events(self, count=3):
        result = []
        for index in range(count):
            result.append(self.audit.record(
                "user.created" if index % 2 == 0 else "auth.login.failed",
                actor=OWNER,
                outcome="failure" if index % 2 else "success",
                target_type="user",
                target_id=f"user-{index}",
                metadata={"username": f"user-{index}", "token": "must-not-be-exported"},
                occurred_at=self.now + timedelta(seconds=index),
            ))
        return result

    def test_ingest_advances_cursor_and_is_idempotent_across_restart(self):
        events = self.events(3)
        result = self.store.ingest(events, now=self.now)
        self.assertEqual(result["ingested_count"], 3)
        self.assertEqual(result["duplicate_count"], 0)
        self.assertEqual(result["source_cursor_id"], 3)
        self.assertEqual(self.store.summary()["pending_count"], 3)

        duplicate = self.store.ingest(events, now=self.now)
        self.assertEqual(duplicate["ingested_count"], 0)
        self.assertEqual(duplicate["duplicate_count"], 3)
        self.assertEqual(self.store.summary()["pending_count"], 3)

        reopened = SecuritySiemStore(self.path, retention_days=7, max_pending_events=10)
        self.assertEqual(reopened.cursor_id(), 3)
        self.assertEqual(reopened.summary()["pending_count"], 3)
        items = reopened.list_events(limit=10)
        self.assertEqual([item["source_id"] for item in reversed(items)], [1, 2, 3])
        self.assertNotIn("must-not-be-exported", json.dumps(items))

    def test_queue_capacity_failure_rolls_back_rows_and_source_cursor(self):
        events = self.events(2)
        small = SecuritySiemStore(
            Path(self.temp.name) / "small.sqlite3",
            retention_days=7,
            max_pending_events=1,
        )
        with self.assertRaises(SiemQueueFullError):
            small.ingest(events, now=self.now)
        self.assertEqual(small.cursor_id(), 0)
        self.assertEqual(small.summary()["pending_count"], 0)

        first = small.ingest(events[:1], now=self.now)
        self.assertEqual(first["source_cursor_id"], 1)
        self.assertEqual(small.summary()["pending_count"], 1)

    def test_claims_are_leased_and_expired_leases_can_be_reclaimed(self):
        self.store.ingest(self.events(1), now=self.now)
        claim = self.store.claim_due("siem-worker", now=self.now, lease_seconds=15, limit=1)
        self.assertEqual(claim["claimed_count"], 1)
        first = claim["jobs"][0]
        self.assertIsNotNone(self.store.get_leased(first["id"], first["lease_id"], now=self.now))

        self.assertEqual(
            self.store.claim_due(
                "another-worker",
                now=self.now + timedelta(seconds=14),
                lease_seconds=15,
                limit=1,
            )["claimed_count"],
            0,
        )
        second = self.store.claim_due(
            "another-worker",
            now=self.now + timedelta(seconds=16),
            lease_seconds=15,
            limit=1,
        )
        self.assertEqual(second["claimed_count"], 1)
        self.assertNotEqual(second["jobs"][0]["lease_id"], first["lease_id"])
        with self.assertRaises(SiemDeliveryNotFoundError):
            self.store.complete(
                first["id"], first["lease_id"],
                http_status=202,
                now=self.now + timedelta(seconds=16),
            )

    def test_successful_completion_requires_active_lease_and_records_status(self):
        self.store.ingest(self.events(1), now=self.now)
        job = self.store.claim_due("siem-worker", now=self.now, lease_seconds=30)["jobs"][0]
        completed = self.store.complete(
            job["id"], job["lease_id"], http_status=202,
            now=self.now + timedelta(seconds=2),
        )
        self.assertEqual(completed["status"], "delivered")
        self.assertEqual(completed["http_status"], 202)
        self.assertEqual(self.store.summary()["pending_count"], 0)
        self.assertEqual(self.store.summary()["status_counts"]["delivered"], 1)

    def test_failure_uses_backoff_and_dead_letters_after_max_attempts(self):
        self.store.ingest(self.events(1), now=self.now)
        job = self.store.claim_due("siem-worker", now=self.now, lease_seconds=30)["jobs"][0]
        failure = self.store.fail(
            job["id"], job["lease_id"], "delivery_timeout", now=self.now,
        )
        self.assertEqual(failure["status"], "retry_wait")
        self.assertEqual(
            datetime.fromisoformat(failure["available_at"]),
            self.now + timedelta(seconds=5),
        )
        with self.assertRaises(SiemDeliveryNotFoundError):
            self.store.fail(job["id"], job["lease_id"], "delivery_timeout", now=self.now)

        current_time = self.now + timedelta(seconds=5)
        for expected_attempt in range(2, 13):
            claim = self.store.claim_due(
                "siem-worker", now=current_time, lease_seconds=30,
            )
            self.assertEqual(claim["claimed_count"], 1)
            active = claim["jobs"][0]
            failed = self.store.fail(
                active["id"], active["lease_id"], "delivery_http_error",
                now=current_time,
            )
            if expected_attempt < 12:
                self.assertEqual(failed["status"], "retry_wait")
                current_time = datetime.fromisoformat(failed["available_at"])
            else:
                self.assertEqual(failed["status"], "dead_letter")
        self.assertEqual(self.store.summary()["status_counts"]["dead_letter"], 1)

    def test_validation_rejects_malformed_events_and_invalid_queue_options(self):
        with self.assertRaisesRegex(ValueError, "event_id"):
            self.store.ingest([{"id": 1, "event_id": "bad"}], now=self.now)
        for value in (-1, True, "1"):
            with self.assertRaises(ValueError):
                self.store.ingest(
                    [{"id": value, "event_id": "a" * 32}],
                    now=self.now,
                )
        with self.assertRaisesRegex(ValueError, "no more than"):
            self.store.ingest(self.events(201), now=self.now)
        with self.assertRaisesRegex(ValueError, "worker_id"):
            self.store.claim_due("../attacker", now=self.now)
        with self.assertRaisesRegex(ValueError, "limit"):
            self.store.claim_due("siem-worker", now=self.now, limit=6)

    def test_empty_ingest_does_not_change_cursor(self):
        self.assertEqual(self.store.ingest([], now=self.now)["source_cursor_id"], 0)
        self.assertEqual(self.store.cursor_id(), 0)


if __name__ == "__main__":
    unittest.main()
