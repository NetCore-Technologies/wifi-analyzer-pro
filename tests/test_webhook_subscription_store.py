"""Tests for persisted webhook subscription metadata and per-site access."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from wifi_analyzer_backend.webhook_subscription_store import (
    WebhookSubscriptionConflictError,
    WebhookSubscriptionNotFoundError,
    WebhookSubscriptionStore,
)


def subscription(subscription_id="office-alerts", sites=None, **changes):
    value = {
        "subscription_id": subscription_id,
        "endpoint": "https://hooks.example.net/router/events",
        "allowed_hosts": ["hooks.example.net"],
        "key_id": "office-key-v1",
        "event_types": ["router.health", "radio.down"],
        "minimum_severity": "warning",
        "site_allowlist": ["office"] if sites is None else sites,
        "maximum_events_per_batch": 100,
        "maximum_batches": 10,
        "enabled": True,
    }
    value.update(changes)
    return value


class WebhookSubscriptionStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = WebhookSubscriptionStore(Path(self.temp.name) / "subscriptions.sqlite3")

    def tearDown(self):
        self.temp.cleanup()

    def test_create_list_update_disable_and_delete_subscription_without_secret_storage(self):
        created = self.store.create(subscription(), now="2026-11-21T00:00:00Z")
        self.assertEqual(created["subscription_id"], "office-alerts")
        self.assertTrue(created["enabled"])
        self.assertEqual(created["site_allowlist"], ["office"])
        self.assertNotIn("signing_secret", json.dumps(created))
        with self.assertRaises(WebhookSubscriptionConflictError):
            self.store.create(subscription(), now="2026-11-21T00:01:00Z")

        updated = self.store.update(
            "office-alerts",
            subscription(enabled=False, minimum_severity="critical"),
            now="2026-11-21T00:02:00Z",
        )
        self.assertFalse(updated["enabled"])
        self.assertEqual(updated["minimum_severity"], "critical")
        self.assertEqual(self.store.list_subscriptions(include_disabled=False), [])
        deleted = self.store.delete("office-alerts")
        self.assertTrue(deleted["deleted"])
        self.assertIsNone(self.store.get("office-alerts"))

    def test_restricted_scopes_cannot_create_global_or_cross_site_subscriptions(self):
        with self.assertRaises(PermissionError):
            self.store.create(subscription(sites=[]), allowed_site_ids=["office"])
        with self.assertRaises(PermissionError):
            self.store.create(subscription(sites=["office", "branch"]), allowed_site_ids=["office"])
        accepted = self.store.create(
            subscription(), allowed_site_ids=["office"], now="2026-11-21T00:00:00Z",
        )
        self.assertEqual(accepted["site_allowlist"], ["office"])

    def test_restricted_list_get_update_and_delete_hide_other_sites(self):
        self.store.create(subscription("office-alerts", ["office"]), now="2026-11-21T00:00:00Z")
        self.store.create(subscription("branch-alerts", ["branch"]), now="2026-11-21T00:00:00Z")
        self.assertEqual(
            [item["subscription_id"] for item in self.store.list_subscriptions(site_ids=["office"])],
            ["office-alerts"],
        )
        self.assertIsNone(self.store.get("branch-alerts", site_ids=["office"]))
        with self.assertRaises(WebhookSubscriptionNotFoundError):
            self.store.update(
                "branch-alerts",
                subscription("branch-alerts", ["branch"], enabled=False),
                allowed_site_ids=["office"],
            )
        with self.assertRaises(WebhookSubscriptionNotFoundError):
            self.store.delete("branch-alerts", site_ids=["office"])

    def test_update_cannot_change_subscription_identity_or_expand_its_scope(self):
        self.store.create(subscription(), now="2026-11-21T00:00:00Z")
        with self.assertRaisesRegex(ValueError, "cannot be changed"):
            self.store.update(
                "office-alerts",
                subscription("different-id"),
                allowed_site_ids=["office"],
            )
        with self.assertRaises(PermissionError):
            self.store.update(
                "office-alerts",
                subscription(sites=["office", "branch"]),
                allowed_site_ids=["office"],
            )

    def test_restart_preserves_subscription_configuration(self):
        self.store.create(subscription(), now="2026-11-21T00:00:00Z")
        restarted = WebhookSubscriptionStore(self.store.path)
        item = restarted.get("office-alerts")
        self.assertEqual(item["endpoint"], "https://hooks.example.net/router/events")
        self.assertEqual(item["key_id"], "office-key-v1")
        self.assertEqual(item["event_types"], ["router.health", "radio.down"])


if __name__ == "__main__":
    unittest.main()
