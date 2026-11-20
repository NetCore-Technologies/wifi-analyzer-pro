"""Tests for safe signed router webhook envelope generation."""
from __future__ import annotations

import hashlib
import hmac
import json
import unittest

from wifi_analyzer_backend.feature_plugins.feature_185_router_webhook_envelope_builder import run


NOW = "2026-11-20T10:00:00Z"
SECRET = "test-only-signing-secret-that-is-at-least-32-bytes"


class RouterWebhookEnvelopeBuilderTests(unittest.TestCase):
    def test_builds_canonical_hmac_signed_https_envelope(self):
        result = run({
            "now": NOW,
            "batch_id": "batch-home-001",
            "key_id": "router-webhook-v1",
            "signing_secret": SECRET,
            "endpoint": "https://hooks.example.net/router/events",
            "allowed_hosts": ["hooks.example.net"],
            "events": [{
                "event_id": "event-001",
                "event_type": "router.health.warning",
                "severity": "warning",
                "occurred_at": NOW,
                "site_id": "home",
                "router_id": "openwrt-home",
                "summary": "Router CPU pressure exceeded policy threshold",
                "attributes": {
                    "observed": 91,
                    "threshold": 85,
                    "resource_type": "router",
                    "resource_id": "openwrt-home",
                    "unknown_secret": "must-not-be-included",
                },
            }],
        })
        self.assertEqual(result["status"], "prepared")
        self.assertEqual(result["delivery"]["method"], "POST")
        self.assertEqual(result["delivery"]["endpoint"], "https://hooks.example.net/router/events")
        headers = result["delivery"]["headers"]
        body = result["delivery"]["body"]
        signature = hmac.new(
            SECRET.encode(),
            headers["X-WiFiAnalyzer-Timestamp"].encode() + b"." + body.encode(),
            hashlib.sha256,
        ).hexdigest()
        self.assertEqual(headers["X-WiFiAnalyzer-Signature"], f"v1={signature}")
        self.assertEqual(headers["Idempotency-Key"], "batch-home-001")
        parsed = json.loads(body)
        self.assertEqual(parsed["schema_version"], "1.0")
        self.assertEqual(parsed["events"][0]["attributes"], {
            "observed": 91, "threshold": 85,
            "resource_id": "openwrt-home", "resource_type": "router",
        })
        self.assertEqual(result["summary"]["event_count"], 1)

    def test_sorts_events_and_attribute_keys_for_deterministic_signatures(self):
        base = {
            "now": NOW, "batch_id": "batch-stable", "key_id": "key-stable",
            "signing_secret": SECRET,
            "endpoint": "https://hooks.example.net/events",
            "allowed_hosts": ["hooks.example.net"],
        }
        events = [
            {"event_id": "event-b", "event_type": "router.info", "severity": "info",
             "occurred_at": NOW, "summary": "Second event",
             "attributes": {"threshold": 2, "observed": 1}},
            {"event_id": "event-a", "event_type": "router.warning", "severity": "warning",
             "occurred_at": NOW, "summary": "First event",
             "attributes": {"observed": 3, "threshold": 2}},
        ]
        first = run({**base, "events": events})
        second = run({**base, "events": list(reversed(events))})
        self.assertEqual(first["delivery"]["body"], second["delivery"]["body"])
        self.assertEqual(
            first["delivery"]["headers"]["X-WiFiAnalyzer-Signature"],
            second["delivery"]["headers"]["X-WiFiAnalyzer-Signature"],
        )

    def test_only_exact_allowlisted_https_dns_hosts_are_accepted(self):
        base = {
            "now": NOW, "batch_id": "batch-host", "key_id": "key-host",
            "signing_secret": SECRET,
            "allowed_hosts": ["hooks.example.net"],
            "events": [{
                "event_id": "event-host", "event_type": "router.info", "severity": "info",
                "occurred_at": NOW, "summary": "Host test",
            }],
        }
        for endpoint, message in (
            ("http://hooks.example.net/events", "HTTPS"),
            ("https://other.example.net/events", "allowlist"),
            ("https://hooks.example.net.evil.test/events", "allowlist"),
            ("https://127.0.0.1/events", "DNS hostname"),
            ("https://hooks.example.net:8443/events", "port 443"),
            ("https://user@hooks.example.net/events", "embedded credentials"),
            ("https://hooks.example.net/events?token=x", "query string"),
            ("https://hooks.example.net/events#fragment", "fragment"),
        ):
            with self.subTest(endpoint=endpoint), self.assertRaisesRegex(ValueError, message):
                run({**base, "endpoint": endpoint})

    def test_rejects_duplicate_or_invalid_allowlist_hosts(self):
        base = {
            "now": NOW, "batch_id": "batch-list", "key_id": "key-list",
            "signing_secret": SECRET, "endpoint": "https://hooks.example.net/events",
            "events": [{
                "event_id": "event-list", "event_type": "router.info", "severity": "info",
                "occurred_at": NOW, "summary": "Allowlist test",
            }],
        }
        with self.assertRaisesRegex(ValueError, "unique"):
            run({**base, "allowed_hosts": ["hooks.example.net", "HOOKS.example.net"]})
        with self.assertRaisesRegex(ValueError, "fully-qualified"):
            run({**base, "allowed_hosts": ["localhost"]})
        with self.assertRaisesRegex(ValueError, "from 1 to 50"):
            run({**base, "allowed_hosts": []})

    def test_normalizes_idna_hosts_and_default_https_port(self):
        result = run({
            "now": NOW, "batch_id": "batch-idna", "key_id": "key-idna",
            "signing_secret": SECRET,
            "endpoint": "https://hooks.example.net:443/events",
            "allowed_hosts": ["HOOKS.EXAMPLE.NET."],
            "events": [{
                "event_id": "event-idna", "event_type": "router.info", "severity": "info",
                "occurred_at": NOW, "summary": "IDNA host test",
            }],
        })
        self.assertEqual(result["delivery"]["endpoint"], "https://hooks.example.net/events")

    def test_rejects_duplicate_event_ids_invalid_severity_and_far_future_events(self):
        base = {
            "now": NOW, "batch_id": "batch-events", "key_id": "key-events",
            "signing_secret": SECRET, "endpoint": "https://hooks.example.net/events",
            "allowed_hosts": ["hooks.example.net"],
        }
        event = {
            "event_id": "event-duplicate", "event_type": "router.info", "severity": "info",
            "occurred_at": NOW, "summary": "Event",
        }
        with self.assertRaisesRegex(ValueError, "unique"):
            run({**base, "events": [event, event]})
        with self.assertRaisesRegex(ValueError, "severity"):
            run({**base, "events": [{**event, "severity": "urgent"}]})
        with self.assertRaisesRegex(ValueError, "five minutes"):
            run({**base, "events": [{**event, "occurred_at": "2026-11-20T10:06:00Z"}]})

    def test_rejects_short_secret_naive_time_and_invalid_event_types(self):
        base = {
            "now": NOW, "batch_id": "batch-invalid", "key_id": "key-invalid",
            "signing_secret": SECRET, "endpoint": "https://hooks.example.net/events",
            "allowed_hosts": ["hooks.example.net"],
            "events": [{
                "event_id": "event-invalid", "event_type": "router.info", "severity": "info",
                "occurred_at": NOW, "summary": "Invalid event",
            }],
        }
        with self.assertRaisesRegex(ValueError, "32 to 4096"):
            run({**base, "signing_secret": "too-short"})
        with self.assertRaisesRegex(ValueError, "timezone offset"):
            run({**base, "now": "2026-11-20T10:00:00"})
        with self.assertRaisesRegex(ValueError, "lowercase event type"):
            run({**base, "events": [{**base["events"][0], "event_type": "Router.Warning"}]})

    def test_does_not_return_signing_secret_or_unallowlisted_event_attributes(self):
        result = run({
            "now": NOW, "batch_id": "batch-redact", "key_id": "key-redact",
            "signing_secret": SECRET, "endpoint": "https://hooks.example.net/events",
            "allowed_hosts": ["hooks.example.net"],
            "events": [{
                "event_id": "event-redact", "event_type": "router.warning", "severity": "warning",
                "occurred_at": NOW, "summary": "Router warning",
                "attributes": {
                    "observed": 5, "api_token": "token-secret",
                    "password": "password-secret", "private_key": "key-secret",
                },
                "api_token": "top-level-token",
            }],
        })
        rendered = str(result)
        for secret in (SECRET, "token-secret", "password-secret", "key-secret", "top-level-token"):
            self.assertNotIn(secret, rendered)
        self.assertNotIn("api_token", rendered)
        self.assertNotIn("password", rendered)

    def test_rejects_naive_event_time_non_finite_values_and_oversized_batches(self):
        base = {
            "now": NOW, "batch_id": "batch-bounds", "key_id": "key-bounds",
            "signing_secret": SECRET, "endpoint": "https://hooks.example.net/events",
            "allowed_hosts": ["hooks.example.net"],
        }
        event = {
            "event_id": "event-bounds", "event_type": "router.info", "severity": "info",
            "occurred_at": NOW, "summary": "Bounds test",
        }
        with self.assertRaisesRegex(ValueError, "timezone offset"):
            run({**base, "events": [{**event, "occurred_at": "2026-11-20T10:00:00"}]})
        with self.assertRaisesRegex(ValueError, "finite values"):
            run({**base, "events": [{**event, "attributes": {"observed": float("nan")}}]})
        with self.assertRaisesRegex(ValueError, "from 1 to 500"):
            run({**base, "events": []})
        with self.assertRaisesRegex(ValueError, "no more than 500"):
            run({**base, "events": [dict(event, event_id=f"event-{i}") for i in range(501)]})


if __name__ == "__main__":
    unittest.main()
