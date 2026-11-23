"""Tests for durable alert-transition notifications and signed webhook queuing."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from wifi_analyzer_backend.alert_rule_store import AlertRuleStore
from wifi_analyzer_backend.alert_webhook_worker import (
    AlertWebhookBridgeWorker,
    load_signing_keys,
)
from wifi_analyzer_backend.webhook_delivery_store import WebhookDeliveryStore
from wifi_analyzer_backend.webhook_subscription_store import WebhookSubscriptionStore


class AlertWebhookWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.alerts = AlertRuleStore(root / "alerts.sqlite3")
        self.subscriptions = WebhookSubscriptionStore(root / "subscriptions.sqlite3")
        self.deliveries = WebhookDeliveryStore(root / "deliveries.sqlite3")
        self.now = datetime.now(timezone.utc).replace(microsecond=0)
        self.secret = "s" * 48

    def rule(self):
        return {
            "name": "Weak Wi-Fi signal",
            "metric": "minimum_rssi_dbm",
            "operator": "lt",
            "threshold": -75,
            "recovery_threshold": -70,
            "severity": "warning",
            "enabled": True,
            "hold_for_seconds": 0,
            "dedupe_window_seconds": 900,
            "quiet_start": None,
            "quiet_end": None,
            "timezone": "UTC",
        }

    def create_incident(self):
        self.alerts.save_rule("office", self.rule())
        result = self.alerts.evaluate(
            "office",
            {"minimum_rssi_dbm": -82},
            observed_at=self.now.isoformat(),
        )
        return result["created_event_ids"][0]

    def create_subscription(self, **overrides):
        value = {
            "subscription_id": "office-alerts",
            "enabled": True,
            "event_types": [
                "site.alert.opened",
                "site.alert.acknowledged",
                "site.alert.resolved",
            ],
            "minimum_severity": "warning",
            "site_allowlist": ["office"],
            "endpoint": "https://hooks.example.com/wifi-alerts",
            "allowed_hosts": ["hooks.example.com"],
            "key_id": "office-alert-key",
            "maximum_events_per_batch": 10,
            "maximum_batches": 10,
        }
        value.update(overrides)
        return self.subscriptions.create(value)

    def worker(self, keys=None):
        return AlertWebhookBridgeWorker(
            self.alerts,
            self.subscriptions,
            self.deliveries,
            signing_keys=keys if keys is not None else {"office-alert-key": self.secret},
        )

    def test_incident_open_acknowledge_and_recovery_are_transactionally_queued_once(self):
        event_id = self.create_incident()
        self.alerts.evaluate(
            "office",
            {"minimum_rssi_dbm": -85},
            observed_at=(self.now + timedelta(minutes=1)).isoformat(),
        )
        pending = self.alerts.pending_notifications(now=(self.now + timedelta(minutes=2)).isoformat())
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["transition"], "opened")
        self.assertEqual(pending[0]["event"]["event_id"], event_id)

        acknowledged = self.alerts.acknowledge("office", event_id, "network-admin")
        self.assertEqual(acknowledged["status"], "acknowledged")
        recovered = self.alerts.evaluate(
            "office",
            {"minimum_rssi_dbm": -65},
            observed_at=(self.now + timedelta(minutes=3)).isoformat(),
        )
        self.assertEqual(recovered["resolved_event_ids"], [event_id])

        transitions = self.alerts.pending_notifications(now=(self.now + timedelta(minutes=4)).isoformat())
        self.assertEqual([item["transition"] for item in transitions], [
            "opened", "acknowledged", "resolved",
        ])
        self.assertTrue(all(item["event"]["event_id"] == event_id for item in transitions))
        self.assertEqual(self.alerts.list_events("office")[0]["delivery_status"], "pending")

    def test_rule_edit_and_delete_close_incidents_and_queue_resolution(self):
        saved = self.alerts.save_rule("office", self.rule())
        event_id = self.alerts.evaluate(
            "office", {"minimum_rssi_dbm": -82}, observed_at=self.now.isoformat(),
        )["created_event_ids"][0]
        self.alerts.save_rule("office", self.rule(threshold=-80), rule_id=saved["rule_id"])
        first = self.alerts.pending_notifications(now=(self.now + timedelta(minutes=1)).isoformat())
        self.assertEqual([item["transition"] for item in first], ["opened", "resolved"])
        self.assertEqual(first[-1]["event"]["event_id"], event_id)

        new_event = self.alerts.evaluate(
            "office", {"minimum_rssi_dbm": -90},
            observed_at=(self.now + timedelta(minutes=2)).isoformat(),
        )["created_event_ids"][0]
        self.assertTrue(self.alerts.delete_rule("office", saved["rule_id"]))
        all_events = self.alerts.pending_notifications(now=(self.now + timedelta(minutes=4)).isoformat())
        self.assertEqual([item["transition"] for item in all_events], [
            "opened", "resolved", "opened", "resolved",
        ])
        self.assertEqual(all_events[-1]["event"]["event_id"], new_event)

    def test_bridge_signs_and_enqueues_without_network_io_and_is_idempotent(self):
        self.create_incident()
        self.create_subscription()
        result = self.worker().run_once()
        self.assertEqual(result, {
            "processed_count": 1,
            "queued_count": 1,
            "not_configured_count": 0,
            "retry_count": 0,
        })

        pending = self.deliveries.list_deliveries(status="pending", limit=10)
        self.assertEqual(len(pending), 1)
        job = self.deliveries.get(pending[0]["id"], include_body=True)
        self.assertEqual(job["event_count"], 1)
        self.assertEqual(job["site_ids"], ["office"])
        self.assertEqual(job["endpoint"], "https://hooks.example.com/wifi-alerts")
        timestamp = job["headers"]["X-WiFiAnalyzer-Timestamp"]
        signature = job["headers"]["X-WiFiAnalyzer-Signature"]
        expected = hmac.new(
            self.secret.encode("utf-8"),
            timestamp.encode("ascii") + b"." + job["body"].encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        self.assertEqual(signature, f"v1={expected}")
        envelope = json.loads(job["body"])
        self.assertEqual(envelope["events"][0]["event_type"], "site.alert.opened")
        self.assertEqual(envelope["events"][0]["site_id"], "office")
        self.assertNotIn(self.secret, job["body"])
        self.assertEqual(self.alerts.list_events("office")[0]["delivery_status"], "queued")

        self.assertEqual(self.worker().run_once()["processed_count"], 0)
        self.assertEqual(len(self.deliveries.list_deliveries(status="pending", limit=10)), 1)

    def test_maximum_length_site_identifier_survives_routing_signing_and_queue_scope(self):
        site_id = "s" * 128
        self.alerts.save_rule(site_id, self.rule())
        self.alerts.evaluate(
            site_id,
            {"minimum_rssi_dbm": -82},
            observed_at=self.now.isoformat(),
        )
        self.create_subscription(site_allowlist=[site_id])
        result = self.worker().run_once()
        self.assertEqual(result["queued_count"], 1)
        pending = self.deliveries.list_deliveries(status="pending", limit=10)
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0]["site_ids"], [site_id])
        job = self.deliveries.get(pending[0]["id"], include_body=True)
        event = json.loads(job["body"])["events"][0]
        self.assertEqual(event["site_id"], site_id)

    def test_unmatched_notifications_are_marked_not_configured(self):
        self.create_incident()
        result = self.worker().run_once()
        self.assertEqual(result["not_configured_count"], 1)
        self.assertEqual(self.alerts.list_events("office")[0]["delivery_status"], "not_configured")
        self.assertEqual(self.deliveries.list_deliveries(limit=10), [])

    def test_missing_signing_key_retries_without_exposing_secret_data(self):
        self.create_incident()
        self.create_subscription()
        result = self.worker({"different-key": "x" * 48}).run_once()
        self.assertEqual(result["retry_count"], 1)
        retry = self.alerts.pending_notifications(
            now=(datetime.now(timezone.utc) + timedelta(seconds=10)).isoformat()
        )[0]
        self.assertEqual(retry["attempts"], 1)
        self.assertEqual(retry["last_error_code"], "signing_key_missing")
        self.assertNotIn("signing_secret", retry["event"])
        self.assertEqual(self.deliveries.list_deliveries(limit=10), [])

    @unittest.skipIf(os.name == "nt", "POSIX key-file permission assertions")
    def test_signing_key_file_requires_owner_only_permissions(self):
        path = Path(self.temp.name) / "webhook-keys.json"
        path.write_text(json.dumps({"office-alert-key": self.secret}), encoding="utf-8")
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        self.assertEqual(load_signing_keys(str(path))["office-alert-key"], self.secret)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP)
        with self.assertRaisesRegex(ValueError, "group or other"):
            load_signing_keys(str(path))

    def test_signing_key_loader_rejects_symlinks_and_invalid_documents(self):
        target = Path(self.temp.name) / "target.json"
        target.write_text("{}", encoding="utf-8")
        link = Path(self.temp.name) / "link.json"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symbolic links are unavailable")
        with self.assertRaisesRegex(ValueError, "opened safely"):
            load_signing_keys(str(link))


if __name__ == "__main__":
    unittest.main()
