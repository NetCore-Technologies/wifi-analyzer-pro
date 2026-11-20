"""Tests for deterministic webhook subscription routing and bounded event batching."""
from __future__ import annotations

import unittest

from wifi_analyzer_backend.feature_plugins.feature_190_router_webhook_subscription_router import run


NOW = "2026-11-20T10:00:00Z"


def event(event_id: str, event_type="router.health", severity="warning", site="home"):
    return {
        "event_id": event_id,
        "event_type": event_type,
        "severity": severity,
        "occurred_at": NOW,
        "site_id": site,
        "router_id": "openwrt-home",
        "summary": f"{event_type} event",
        "attributes": {
            "report_id": "weekly-home",
            "finding_count": 3,
            "password": "must-not-be-routed",
        },
        "api_token": "must-not-be-routed",
    }


def subscription(subscription_id="home-health", **changes):
    value = {
        "subscription_id": subscription_id,
        "endpoint": "https://hooks.example.net/router/events",
        "allowed_hosts": ["hooks.example.net"],
        "key_id": "webhook-key-01",
        "event_types": ["router.health"],
        "minimum_severity": "warning",
        "site_allowlist": ["home"],
        "maximum_events_per_batch": 100,
        "maximum_batches": 10,
    }
    value.update(changes)
    return value


class RouterWebhookSubscriptionRouterTests(unittest.TestCase):
    def test_routes_events_by_type_severity_and_site_scope(self):
        events = [
            event("a" * 64, "router.health", "critical", "home"),
            event("b" * 64, "router.health", "warning", "home"),
            event("c" * 64, "router.health", "info", "home"),
            event("d" * 64, "radio.down", "critical", "home"),
            event("e" * 64, "router.health", "critical", "branch"),
        ]
        result = run({
            "subscriptions": [subscription()],
            "events": events,
        })
        self.assertEqual(result["status"], "planned")
        self.assertEqual(result["summary"]["input_event_count"], 5)
        self.assertEqual(result["summary"]["matched_event_count"], 2)
        self.assertEqual(result["summary"]["unmatched_event_count"], 3)
        self.assertEqual(result["summary"]["batch_count"], 1)
        routed = result["batches"][0]["events"]
        self.assertEqual([item["event_id"] for item in routed], ["a" * 64, "b" * 64])
        self.assertEqual(result["batches"][0]["severity_counts"], {
            "critical": 1, "warning": 1, "info": 0,
        })

    def test_wildcard_and_severity_info_subscriptions_receive_all_sites(self):
        result = run({
            "subscriptions": [subscription(
                "all-events",
                event_types=["*"],
                minimum_severity="info",
                site_allowlist=[],
            )],
            "events": [
                event("a" * 64, "router.health", "critical", "home"),
                event("b" * 64, "radio.down", "warning", "branch"),
                event("c" * 64, "report.generated", "info", "office"),
            ],
        })
        self.assertEqual(result["summary"]["matched_event_count"], 3)
        self.assertEqual(result["batches"][0]["event_count"], 3)

    def test_disabled_subscriptions_are_not_given_batches(self):
        result = run({
            "subscriptions": [subscription("disabled", enabled=False)],
            "events": [event("a" * 64)],
        })
        self.assertEqual(result["summary"]["disabled_subscription_count"], 1)
        self.assertEqual(result["summary"]["batch_count"], 0)
        self.assertFalse(result["subscriptions"][0]["enabled"])

    def test_duplicate_identical_events_are_deduplicated_and_conflicts_rejected(self):
        same = event("a" * 64)
        result = run({
            "subscriptions": [subscription()],
            "events": [same, same],
        })
        self.assertEqual(result["summary"]["input_event_count"], 2)
        self.assertEqual(result["summary"]["unique_event_count"], 1)
        self.assertEqual(result["summary"]["matched_event_count"], 1)
        conflicting = event("a" * 64, severity="critical")
        with self.assertRaisesRegex(ValueError, "identical normalized event contents"):
            run({
                "subscriptions": [subscription()],
                "events": [same, conflicting],
            })

    def test_splits_batches_with_stable_idempotency_keys_and_order(self):
        events = [event(f"{index:064x}") for index in range(5)]
        payload = {
            "subscriptions": [subscription(maximum_events_per_batch=2)],
            "events": events,
        }
        first = run(payload)
        second = run(payload)
        self.assertEqual([item["event_count"] for item in first["batches"]], [2, 2, 1])
        self.assertEqual(
            [item["batch_id"] for item in first["batches"]],
            [item["batch_id"] for item in second["batches"]],
        )
        all_ids = [event_item["event_id"] for batch in first["batches"] for event_item in batch["events"]]
        self.assertEqual(all_ids, sorted(all_ids))
        self.assertEqual(len(set(item["batch_id"] for item in first["batches"])), 3)

    def test_maximum_batches_truncates_and_reports_dropped_events(self):
        events = [event(f"{index:064x}") for index in range(7)]
        result = run({
            "subscriptions": [subscription(maximum_events_per_batch=2, maximum_batches=2)],
            "events": events,
        })
        self.assertEqual(result["summary"]["batch_count"], 2)
        self.assertEqual(result["summary"]["truncated_event_count"], 3)
        self.assertEqual(result["subscriptions"][0]["truncated_event_count"], 3)
        self.assertEqual(sum(item["event_count"] for item in result["batches"]), 4)

    def test_multiple_subscriptions_route_same_event_independently(self):
        result = run({
            "subscriptions": [
                subscription("home-health"),
                subscription("all-severities", minimum_severity="info", site_allowlist=[]),
            ],
            "events": [event("a" * 64)],
        })
        self.assertEqual(result["summary"]["matched_event_count"], 1)
        self.assertEqual(result["summary"]["subscription_event_match_count"], 2)
        self.assertEqual(result["summary"]["batch_count"], 2)
        self.assertEqual({item["subscription_id"] for item in result["batches"]},
                         {"home-health", "all-severities"})

    def test_normalizes_idna_and_requires_exact_https_host_allowlist(self):
        result = run({
            "subscriptions": [subscription(
                endpoint="https://xn--bcher-kva.example/events",
                allowed_hosts=["bücher.example"],
            )],
            "events": [event("a" * 64)],
        })
        self.assertEqual(result["batches"][0]["endpoint"], "https://xn--bcher-kva.example/events")
        for endpoint, hosts, message in (
            ("https://hooks.example.net.attacker.test/events", ["hooks.example.net"], "exact host allowlist"),
            ("http://hooks.example.net/events", ["hooks.example.net"], "HTTPS"),
            ("https://user@hooks.example.net/events", ["hooks.example.net"], "embedded credentials"),
            ("https://hooks.example.net/events?token=x", ["hooks.example.net"], "query string"),
            ("https://127.0.0.1/events", ["127.0.0.1"], "DNS hostname"),
            ("https://hooks.example.net:8443/events", ["hooks.example.net"], "port 443"),
        ):
            with self.subTest(endpoint=endpoint), self.assertRaisesRegex(ValueError, message):
                run({
                    "subscriptions": [subscription(endpoint=endpoint, allowed_hosts=hosts)],
                    "events": [],
                })

    def test_validates_subscription_ids_modes_and_bounded_batch_settings(self):
        with self.assertRaisesRegex(ValueError, "unique"):
            run({"subscriptions": [subscription("same"), subscription("same")], "events": []})
        for changes, message in (
            ({"minimum_severity": ["critical"]}, "minimum_severity"),
            ({"event_types": ["Bad.Event"]}, "lowercase event types"),
            ({"maximum_events_per_batch": 501}, "maximum_events_per_batch"),
            ({"maximum_batches": 101}, "maximum_batches"),
        ):
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, message):
                run({"subscriptions": [subscription(**changes)], "events": []})

    def test_rejects_invalid_event_ids_times_attributes_and_input_bounds(self):
        with self.assertRaisesRegex(ValueError, "SHA-256 ID"):
            run({"subscriptions": [subscription()], "events": [event("not-an-id")]})
        naive = event("a" * 64)
        naive["occurred_at"] = "2026-11-20T10:00:00"
        with self.assertRaisesRegex(ValueError, "timezone offset"):
            run({"subscriptions": [subscription()], "events": [naive]})
        bad = event("b" * 64)
        bad["attributes"] = {"observed": float("nan")}
        with self.assertRaisesRegex(ValueError, "finite"):
            run({"subscriptions": [subscription()], "events": [bad]})
        with self.assertRaisesRegex(ValueError, "no more than 5000"):
            run({"subscriptions": [subscription()], "events": [event(f"{i:064x}") for i in range(5001)]})

    def test_never_routes_or_returns_untrusted_secrets_or_signing_material(self):
        secret = subscription()
        secret["signing_secret"] = "must-not-be-accepted-or-returned"
        raw_event = event("a" * 64)
        result = run({"subscriptions": [secret], "events": [raw_event]})
        rendered = str(result)
        for value in ("must-not-be-routed", "must-not-be-accepted-or-returned", "api_token", "password"):
            self.assertNotIn(value, rendered)
        self.assertNotIn("signing_secret", result["batches"][0])


if __name__ == "__main__":
    unittest.main()
