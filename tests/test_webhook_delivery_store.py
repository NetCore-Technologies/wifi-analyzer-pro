"""Tests for the idempotent, site-aware SQLite webhook delivery outbox."""
from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from wifi_analyzer_backend.webhook_delivery_store import (
    WebhookDeliveryConflictError,
    WebhookDeliveryNotFoundError,
    WebhookDeliveryStore,
)

NOW = datetime(2026, 11, 21, 0, 0, tzinfo=timezone.utc)


def prepared(batch_id="a" * 64, subscription_id="office-alerts", site_ids=("office",)):
    events = [{
        "event_id": ("b" * 63) + str(index),
        "event_type": "router.health",
        "severity": "warning",
        "occurred_at": NOW.isoformat(),
        "site_id": site_id,
        "router_id": "router-" + site_id,
        "summary": "Router health warning",
        "attributes": {"finding_count": 1},
    } for index, site_id in enumerate(site_ids)]
    body = json.dumps({
        "schema_version": "1.0",
        "batch_id": batch_id,
        "key_id": "office-key-v1",
        "created_at": NOW.isoformat(),
        "events": events,
    }, sort_keys=True, separators=(",", ":"))
    return {
        "subscription_id": subscription_id,
        "batch_id": batch_id,
        "event_count": len(events),
        "status": "prepared",
        "endpoint": "https://hooks.example.net/router/events",
        "allowed_hosts": ["hooks.example.net"],
        "headers": {
            "Content-Type": "application/json",
            "X-WiFiAnalyzer-Key-Id": "office-key-v1",
            "X-WiFiAnalyzer-Timestamp": str(int(NOW.timestamp())),
            "X-WiFiAnalyzer-Signature": "v1=" + ("c" * 64),
            "Idempotency-Key": batch_id,
        },
        "body": body,
    }


class WebhookDeliveryStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = WebhookDeliveryStore(Path(self.temp.name) / "deliveries.sqlite3")

    def tearDown(self):
        self.temp.cleanup()

    def test_enqueue_is_idempotent_and_never_persists_signing_secrets(self):
        item = prepared()
        result = self.store.enqueue_many([item], now=NOW)
        self.assertEqual(result["created_count"], 1)
        self.assertEqual(result["duplicate_count"], 0)
        repeated = self.store.enqueue_many([item], now=NOW + timedelta(seconds=1))
        self.assertEqual(repeated["created_count"], 0)
        self.assertEqual(repeated["duplicate_count"], 1)
        self.assertEqual(repeated["deliveries"][0]["id"], result["deliveries"][0]["id"])
        self.assertEqual(repeated["deliveries"][0]["site_ids"], ["office"])
        self.assertNotIn("body", str(self.store.get(result["deliveries"][0]["id"])))
        self.assertNotIn("signing_secret", str(self.store.get(result["deliveries"][0]["id"])))

    def test_reusing_batch_id_with_different_content_is_a_conflict(self):
        self.store.enqueue_many([prepared()], now=NOW)
        changed = prepared()
        changed["body"] = changed["body"].replace("Router health warning", "Different event")
        with self.assertRaises(WebhookDeliveryConflictError):
            self.store.enqueue_many([changed], now=NOW)

    def test_enqueue_rejects_private_hosts_malformed_envelopes_and_unbounded_input(self):
        private = prepared()
        private["endpoint"] = "https://127.0.0.1/router/events"
        private["allowed_hosts"] = ["hooks.example.net"]
        with self.assertRaisesRegex(ValueError, "DNS hostname"):
            self.store.enqueue_many([private], now=NOW)

        mismatched = prepared()
        mismatched["headers"]["Idempotency-Key"] = "d" * 64
        with self.assertRaisesRegex(ValueError, "Idempotency-Key"):
            self.store.enqueue_many([mismatched], now=NOW)

        malformed = prepared()
        malformed["body"] = "not-json"
        with self.assertRaisesRegex(ValueError, "valid JSON"):
            self.store.enqueue_many([malformed], now=NOW)

        with self.assertRaisesRegex(ValueError, "prepared envelopes"):
            self.store.enqueue_many([], now=NOW)

    def test_restricted_site_scope_cannot_enqueue_unassigned_or_cross_site_events(self):
        with self.assertRaises(PermissionError):
            self.store.enqueue_many([prepared(site_ids=("branch",))], now=NOW, allowed_site_ids=["office"])
        with self.assertRaises(PermissionError):
            self.store.enqueue_many([prepared(site_ids=("office", "branch"))], now=NOW, allowed_site_ids=["office"])

        unscoped = prepared()
        body = json.loads(unscoped["body"])
        body["events"][0]["site_id"] = None
        unscoped["body"] = json.dumps(body, sort_keys=True, separators=(",", ":"))
        with self.assertRaises(PermissionError):
            self.store.enqueue_many([unscoped], now=NOW, allowed_site_ids=["office"])

        accepted = self.store.enqueue_many(
            [prepared()], now=NOW, allowed_site_ids=["office"],
        )
        self.assertEqual(accepted["created_count"], 1)

    def test_lists_and_summaries_filter_entire_deliveries_by_site_scope(self):
        office = self.store.enqueue_many([prepared()], now=NOW)["deliveries"][0]
        branch = self.store.enqueue_many([
            prepared(batch_id="d" * 64, site_ids=("branch",))
        ], now=NOW)["deliveries"][0]
        self.assertEqual([item["id"] for item in self.store.list_deliveries(site_ids=["office"])], [office["id"]])
        self.assertEqual(self.store.summary(site_ids=["office"])["delivery_count"], 1)
        self.assertEqual(self.store.list_deliveries(site_ids=[]) , [])
        self.assertNotEqual(office["id"], branch["id"])

    def test_claim_is_exclusive_and_expired_leases_are_recovered(self):
        self.store.enqueue_many([prepared()], now=NOW)
        first = self.store.claim_due("worker-one", now=NOW, lease_seconds=15, limit=1)
        self.assertEqual(first["claimed_count"], 1)
        self.assertEqual(first["jobs"][0]["status"], "sending")
        second = self.store.claim_due("worker-two", now=NOW + timedelta(seconds=5), lease_seconds=15, limit=1)
        self.assertEqual(second["claimed_count"], 0)
        recovered = self.store.claim_due("worker-two", now=NOW + timedelta(seconds=16), lease_seconds=15, limit=1)
        self.assertEqual(recovered["claimed_count"], 1)
        self.assertEqual(recovered["jobs"][0]["attempts"], 2)
        self.assertNotEqual(recovered["jobs"][0]["lease_id"], first["jobs"][0]["lease_id"])
        with self.assertRaises(WebhookDeliveryNotFoundError):
            self.store.complete(first["jobs"][0]["id"], first["jobs"][0]["lease_id"], http_status=202, now=NOW + timedelta(seconds=17))

    def test_retry_dead_letter_manual_retry_and_cancel_transitions(self):
        first = self.store.enqueue_many([prepared()], now=NOW, max_attempts=1)["deliveries"][0]
        lease = self.store.claim_due("worker-one", now=NOW, lease_seconds=30)["jobs"][0]
        failed = self.store.fail(lease["id"], lease["lease_id"], "delivery_http_error", now=NOW + timedelta(seconds=1))
        self.assertEqual(failed["status"], "dead_letter")
        retried = self.store.retry(first["id"], now=NOW + timedelta(seconds=2))
        self.assertEqual(retried["status"], "pending")
        self.assertEqual(retried["attempts"], 0)
        cancelled = self.store.cancel(first["id"], now=NOW + timedelta(seconds=3))
        self.assertEqual(cancelled["status"], "cancelled")
        with self.assertRaises(WebhookDeliveryNotFoundError):
            self.store.cancel(first["id"], now=NOW + timedelta(seconds=4))
        self.assertEqual(self.store.summary()["counts_by_status"]["cancelled"], 1)

    def test_retention_prunes_only_old_terminal_rows(self):
        retained_store = WebhookDeliveryStore(
            Path(self.temp.name) / "retention.sqlite3",
            retention_days=7,
        )
        old = NOW - timedelta(days=20)
        delivered = retained_store.enqueue_many([prepared(batch_id="a" * 64)], now=old)["deliveries"][0]
        delivered_lease = retained_store.claim_due("worker-one", now=old, lease_seconds=30)["jobs"][0]
        retained_store.complete(
            delivered["id"], delivered_lease["lease_id"], http_status=202,
            now=old + timedelta(seconds=1),
        )

        dead = retained_store.enqueue_many([prepared(batch_id="d" * 64)], now=old)["deliveries"][0]
        dead_lease = retained_store.claim_due("worker-two", now=old, lease_seconds=30)["jobs"][0]
        retained_store.fail(dead["id"], dead_lease["lease_id"], "delivery_http_error", now=old + timedelta(seconds=1))

        cancelled = retained_store.enqueue_many([prepared(batch_id="c" * 64)], now=old)["deliveries"][0]
        retained_store.cancel(cancelled["id"], now=old + timedelta(seconds=1))

        sending = retained_store.enqueue_many([prepared(batch_id="f" * 64)], now=old)["deliveries"][0]
        sending_lease = retained_store.claim_due("worker-three", now=old, lease_seconds=3600)["jobs"][0]
        pending = retained_store.enqueue_many([prepared(batch_id="e" * 64)], now=old)["deliveries"][0]

        result = retained_store.prune(now=NOW)
        self.assertEqual(result["deleted_count"], 3)
        self.assertEqual(result["deleted_by_status"]["delivered"], 1)
        self.assertEqual(result["deleted_by_status"]["dead_letter"], 1)
        self.assertEqual(result["deleted_by_status"]["cancelled"], 1)
        self.assertIsNone(retained_store.get(delivered["id"]))
        self.assertIsNone(retained_store.get(dead["id"]))
        self.assertIsNone(retained_store.get(cancelled["id"]))
        self.assertIsNotNone(retained_store.get(pending["id"]))
        self.assertIsNotNone(retained_store.get(sending["id"]))
        self.assertEqual(sending_lease["status"], "sending")

    def test_retention_configuration_is_bounded(self):
        for value in (True, 0, 6, 3651):
            with self.assertRaises(ValueError):
                WebhookDeliveryStore(Path(self.temp.name) / f"invalid-{value}.sqlite3", retention_days=value)

    def test_completion_requires_2xx_and_an_active_lease(self):
        queued = self.store.enqueue_many([prepared()], now=NOW)["deliveries"][0]
        lease = self.store.claim_due("worker-one", now=NOW, lease_seconds=30)["jobs"][0]
        with self.assertRaises(ValueError):
            self.store.complete(queued["id"], lease["lease_id"], http_status=302, now=NOW + timedelta(seconds=1))
        completed = self.store.complete(
            queued["id"], lease["lease_id"], http_status=202, now=NOW + timedelta(seconds=1),
        )
        self.assertEqual(completed["status"], "delivered")
        self.assertEqual(completed["response_status"], 202)
        self.assertEqual(self.store.summary()["counts_by_status"]["delivered"], 1)


if __name__ == "__main__":
    unittest.main()
