"""Regression tests for the F192 multi-subscription delivery orchestrator."""
from __future__ import annotations

import json
import unittest

from wifi_analyzer_backend.feature_plugins.feature_192_router_webhook_delivery_orchestrator import run


NOW = "2026-11-20T10:00:00Z"
HOME_SECRET = "home-webhook-signing-secret-at-least-32-bytes"
BRANCH_SECRET = "branch-webhook-signing-secret-at-least-32-bytes"


def subscription(subscription_id, site_id, hostname, key_id):
    return {
        "subscription_id": subscription_id,
        "endpoint": "https://" + hostname + "/router/events",
        "allowed_hosts": [hostname],
        "key_id": key_id,
        "event_types": ["router.health"],
        "minimum_severity": "warning",
        "site_allowlist": [site_id],
        "maximum_events_per_batch": 100,
        "maximum_batches": 10,
    }


def event(identifier, site_id):
    return {
        "event_id": identifier * 64,
        "event_type": "router.health",
        "severity": "warning",
        "occurred_at": "2026-11-20T09:59:00Z",
        "site_id": site_id,
        "router_id": "router-" + site_id,
        "summary": "Router health warning at " + site_id,
        "attributes": {"finding_count": 1, "threshold": 85, "password": "not-allowlisted"},
    }


def evidence(subscription_id, hostname, *, connected_at=NOW, resolution_at="2026-11-20T09:59:55Z"):
    endpoint = "https://" + hostname + "/router/events"
    return {
        "subscription_id": subscription_id,
        "endpoint": endpoint,
        "allowed_hosts": [hostname],
        "resolution_at": resolution_at,
        "connected_at": connected_at,
        "resolved_addresses": ["1.1.1.1"],
        "peer_ip": "1.1.1.1",
        "connected_port": 443,
        "tls_version": "TLSv1.3",
        "tls_verified": True,
        "hostname_verified": True,
        "redirect_location": None,
    }


def valid_payload():
    return {
        "now": NOW,
        "subscriptions": [
            subscription("home-alerts", "home", "home-hooks.example.net", "home-key"),
            subscription("branch-alerts", "branch", "branch-hooks.example.net", "branch-key"),
        ],
        "events": [event("a", "home"), event("b", "branch")],
        "signing_keys": {"home-key": HOME_SECRET, "branch-key": BRANCH_SECRET},
        "egress_evidence": [
            evidence("home-alerts", "home-hooks.example.net"),
            evidence("branch-alerts", "branch-hooks.example.net"),
        ],
    }


class RouterWebhookDeliveryOrchestratorTests(unittest.TestCase):
    def test_prepares_independent_signed_deliveries_for_each_subscription(self):
        result = run(valid_payload())
        self.assertEqual(result["status"], "prepared")
        self.assertEqual(result["summary"]["subscription_count"], 2)
        self.assertEqual(result["summary"]["planned_batch_count"], 2)
        self.assertEqual(result["summary"]["prepared_delivery_count"], 2)
        self.assertEqual(result["summary"]["blocked_delivery_count"], 0)
        self.assertEqual(
            [item["subscription_id"] for item in result["prepared_deliveries"]],
            ["branch-alerts", "home-alerts"],
        )
        first, second = result["prepared_deliveries"]
        self.assertNotEqual(first["batch_id"], second["batch_id"])
        self.assertNotEqual(
            first["headers"]["X-WiFiAnalyzer-Signature"],
            second["headers"]["X-WiFiAnalyzer-Signature"],
        )
        self.assertEqual(first["headers"]["Idempotency-Key"], first["batch_id"])
        self.assertTrue(first["egress"]["approved"])
        self.assertEqual(first["egress"]["connected_peer_ip"], "1.1.1.1")
        body = json.loads(first["body"])
        self.assertEqual(body["events"][0]["attributes"]["finding_count"], 1)
        self.assertNotIn("password", body["events"][0]["attributes"])
        rendered = json.dumps(result)
        self.assertNotIn(HOME_SECRET, rendered)
        self.assertNotIn(BRANCH_SECRET, rendered)
        self.assertNotIn("signing_secret", rendered)

    def test_missing_key_and_evidence_block_only_the_affected_subscription(self):
        payload = valid_payload()
        payload["signing_keys"] = {"home-key": HOME_SECRET}
        payload["egress_evidence"] = [evidence("home-alerts", "home-hooks.example.net")]
        result = run(payload)
        self.assertEqual(result["status"], "partially_prepared")
        self.assertEqual(result["summary"]["prepared_delivery_count"], 1)
        self.assertEqual(result["summary"]["blocked_delivery_count"], 1)
        blocked = result["blocked_deliveries"][0]
        self.assertEqual(blocked["subscription_id"], "branch-alerts")
        self.assertEqual(blocked["reasons"], ["egress_evidence_missing", "signing_key_missing"])

    def test_stale_evidence_and_endpoint_mismatch_are_blocked_without_envelopes(self):
        payload = valid_payload()
        payload["egress_evidence"] = [
            evidence("home-alerts", "home-hooks.example.net", connected_at="2026-11-20T09:58:00Z",
                     resolution_at="2026-11-20T09:57:55Z"),
            {
                **evidence("branch-alerts", "branch-hooks.example.net"),
                "endpoint": "https://attacker.example.net/router/events",
            },
        ]
        result = run(payload)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["summary"]["prepared_delivery_count"], 0)
        reasons = {item["subscription_id"]: item["reasons"] for item in result["blocked_deliveries"]}
        self.assertIn("egress_evidence_stale", reasons["home-alerts"])
        self.assertIn("egress_endpoint_mismatch", reasons["branch-alerts"])

    def test_same_input_produces_stable_batch_ids_and_signatures(self):
        payload = valid_payload()
        first = run(payload)
        second = run(payload)
        self.assertEqual(
            [item["batch_id"] for item in first["prepared_deliveries"]],
            [item["batch_id"] for item in second["prepared_deliveries"]],
        )
        self.assertEqual(
            [item["headers"]["X-WiFiAnalyzer-Signature"] for item in first["prepared_deliveries"]],
            [item["headers"]["X-WiFiAnalyzer-Signature"] for item in second["prepared_deliveries"]],
        )

    def test_rejects_duplicate_unknown_and_invalid_evidence_or_signing_metadata(self):
        payload = valid_payload()
        payload["egress_evidence"].append(dict(payload["egress_evidence"][0]))
        with self.assertRaisesRegex(ValueError, "no more than one record"):
            run(payload)
        payload = valid_payload()
        payload["egress_evidence"][0]["subscription_id"] = "unknown-site"
        with self.assertRaisesRegex(ValueError, "unknown subscription"):
            run(payload)
        payload = valid_payload()
        payload["signing_keys"]["home-key"] = "too-short"
        with self.assertRaisesRegex(ValueError, "32 to 4096"):
            run(payload)

    def test_rejects_oversized_subscription_collections_and_non_finite_payloads(self):
        payload = valid_payload()
        payload["subscriptions"] = [
            subscription("sub-" + str(index), "home", "hooks-" + str(index) + ".example.net", "key-" + str(index))
            for index in range(101)
        ]
        with self.assertRaisesRegex(ValueError, "from 1 to 100"):
            run(payload)
        with self.assertRaisesRegex(ValueError, "finite values"):
            run({**valid_payload(), "metadata": float("nan")})


if __name__ == "__main__":
    unittest.main()
