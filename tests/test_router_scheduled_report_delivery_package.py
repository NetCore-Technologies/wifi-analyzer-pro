"""Tests for leased scheduled-report delivery packaging and egress gating."""
from __future__ import annotations

import hashlib
import hmac
import json
import unittest

from wifi_analyzer_backend.feature_plugins.feature_182_router_audit_report_bundle_builder import run as build_report
from wifi_analyzer_backend.feature_plugins.feature_189_router_scheduled_report_delivery_package import run


NOW = "2026-11-20T10:00:00Z"
SECRET = "test-webhook-secret-with-at-least-32-bytes"
WEBHOOK = {
    "endpoint": "https://hooks.example.net/reports",
    "allowed_hosts": ["hooks.example.net"],
    "key_id": "test-key-01",
    "signing_secret": SECRET,
}
EGRESS = {
    "resolution_at": "2026-11-20T09:59:55Z",
    "connected_at": NOW,
    "resolved_addresses": ["1.1.1.1", "2606:4700:4700::1111"],
    "peer_ip": "1.1.1.1",
    "connected_port": 443,
    "tls_version": "TLSv1.3",
    "tls_verified": True,
    "hostname_verified": True,
    "redirect_location": None,
}


def report_bundle(findings=None):
    source_findings = findings if findings is not None else [{
        "code": "resource.cpu_high",
        "severity": "warning",
        "resource_type": "router",
        "resource_id": "openwrt-home",
        "observed": 91,
        "threshold": 85,
    }]
    critical = sum(item["severity"] == "critical" for item in source_findings)
    warning = sum(item["severity"] == "warning" for item in source_findings)
    info = sum(item["severity"] == "info" for item in source_findings)
    return build_report({
        "report_id": "weekly-home",
        "title": "Weekly home router report",
        "generated_at": "2026-11-20T09:59:00Z",
        "sources": [{
            "source_id": "home-health",
            "source_type": "router_fleet_health_audit",
            "result": {
                "status": "audited",
                "summary": {
                    "router_count": 1,
                    "finding_count": len(source_findings),
                    "critical_count": critical,
                    "warning_count": warning,
                    "info_count": info,
                },
                "routers": [{
                    "router_id": "openwrt-home",
                    "site_id": "home",
                    "findings": source_findings,
                }],
            },
        }],
    })


def claimed_job(bundle=None):
    bundle = bundle or report_bundle()
    schedule_id = "daily-home"
    occurrence_id = "a" * 64
    report_id = bundle["report_id"]
    job_key = hashlib.sha256(
        json.dumps([schedule_id, occurrence_id, report_id], separators=(",", ":")).encode()
    ).hexdigest()
    payload_hash = hashlib.sha256(
        json.dumps(bundle, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()
    return {
        "id": 5,
        "schedule_id": schedule_id,
        "occurrence_id": occurrence_id,
        "report_id": report_id,
        "job_key": job_key,
        "payload_hash": payload_hash,
        "status": "leased",
        "lease_id": "00000000-0000-4000-8000-000000000005",
        "lease_owner": "report-worker",
        "lease_expires_at": "2026-11-20T10:02:00Z",
        "report_bundle": bundle,
    }


def payload(bundle=None, **changes):
    return {
        "now": NOW,
        "claimed_job": claimed_job(bundle),
        "webhook": WEBHOOK,
        "egress_evidence": EGRESS,
        **changes,
    }


class RouterScheduledReportDeliveryPackageTests(unittest.TestCase):
    def test_prepares_hmac_signed_delivery_only_for_valid_lease_and_public_verified_egress(self):
        result = run(payload())
        self.assertEqual(result["status"], "ready")
        self.assertTrue(result["egress"]["approved"])
        self.assertEqual(result["egress"]["connected_peer_ip"], "1.1.1.1")
        self.assertEqual(result["delivery"]["method"], "POST")
        self.assertEqual(result["delivery"]["endpoint"], WEBHOOK["endpoint"])
        self.assertEqual(result["summary"]["event_count"], 1)
        self.assertNotIn(SECRET, str(result))
        body = result["delivery"]["body"]
        headers = result["delivery"]["headers"]
        expected = hmac.new(
            SECRET.encode(),
            headers["X-WiFiAnalyzer-Timestamp"].encode("ascii") + b"." + body.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        self.assertEqual(headers["X-WiFiAnalyzer-Signature"], f"v1={expected}")
        decoded = json.loads(body)
        self.assertEqual(decoded["batch_id"], claimed_job()["job_key"])
        self.assertEqual(decoded["events"][0]["event_type"], "report.generated")
        self.assertEqual(decoded["events"][0]["attributes"]["content_hash"],
                         claimed_job()["report_bundle"]["content_hash"])

    def test_blocks_private_peer_and_never_creates_signed_delivery(self):
        blocked_evidence = {
            **EGRESS,
            "resolved_addresses": ["192.168.1.1"],
            "peer_ip": "192.168.1.1",
        }
        result = run(payload(egress_evidence=blocked_evidence))
        self.assertEqual(result["status"], "blocked")
        self.assertFalse(result["egress"]["approved"])
        self.assertIsNone(result["delivery"])
        self.assertIn("connected_peer_is_not_public", result["egress"]["reasons"])
        self.assertNotIn(SECRET, str(result))

    def test_adds_bounded_allowlisted_finding_events_with_stable_unique_event_ids(self):
        bundle = report_bundle([
            {
                "code": "resource.cpu_high", "severity": "warning",
                "site_id": "home", "router_id": "openwrt-home",
                "resource_type": "router", "resource_id": "openwrt-home",
                "details": {"observed": 91, "threshold": 85},
            },
            {
                "code": "radio.down", "severity": "critical",
                "site_id": "home", "router_id": "openwrt-home",
                "resource_type": "radio", "resource_id": "phy0",
                "details": {},
            },
        ])
        result = run(payload(bundle, event_mode="summary_and_findings", maximum_finding_events=2))
        self.assertEqual(result["status"], "ready")
        self.assertEqual(result["summary"]["event_count"], 3)
        self.assertEqual(result["summary"]["finding_event_count"], 2)
        events = json.loads(result["delivery"]["body"])["events"]
        finding_events = [item for item in events if item["event_type"] == "report.finding"]
        self.assertEqual(len(finding_events), 2)
        self.assertEqual(len({item["event_id"] for item in events}), 3)
        self.assertIn("observed", finding_events[0]["attributes"])

    def test_duplicate_upstream_finding_ids_still_produce_unique_batch_event_ids(self):
        duplicated = {
            "finding_id": "abcdefabcdefabcdefabcdef",
            "source_id": "home-health",
            "source_type": "router_fleet_health_audit",
            "category": "Router fleet health",
            "code": "radio.down",
            "severity": "warning",
            "site_id": "home",
            "router_id": "openwrt-home",
            "resource_type": "radio",
            "resource_id": "phy0",
            "details": {},
        }
        bundle = report_bundle([duplicated, duplicated])
        result = run(payload(bundle, event_mode="summary_and_findings", maximum_finding_events=5))
        events = json.loads(result["delivery"]["body"])["events"]
        self.assertEqual(len(events), 3)
        self.assertEqual(len({item["event_id"] for item in events}), 3)

    def test_rejects_expired_or_unleased_jobs_and_payload_identity_mismatches(self):
        expired = claimed_job()
        expired["lease_expires_at"] = "2026-11-20T09:59:59Z"
        with self.assertRaisesRegex(ValueError, "lease has expired"):
            run(payload(claimed_job=expired))
        pending = claimed_job()
        pending["status"] = "pending"
        with self.assertRaisesRegex(ValueError, "leased state"):
            run(payload(claimed_job=pending))
        wrong_hash = claimed_job()
        wrong_hash["payload_hash"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "payload_hash"):
            run(payload(claimed_job=wrong_hash))
        bad_bundle = claimed_job()
        bad_bundle["report_bundle"] = {**bad_bundle["report_bundle"], "title": "altered"}
        with self.assertRaisesRegex(ValueError, "content hash is invalid"):
            run(payload(claimed_job=bad_bundle))

    def test_rejects_unverified_dns_tls_and_invalid_signing_configuration(self):
        for evidence, expected in (
            ({**EGRESS, "tls_verified": False}, "tls_certificate_verification_failed"),
            ({**EGRESS, "hostname_verified": False}, "tls_hostname_verification_failed"),
            ({**EGRESS, "redirect_location": "https://evil.example.net/"}, "redirect_refused"),
            ({**EGRESS, "resolution_at": "2026-11-20T09:58:00Z"}, "dns_resolution_too_old"),
        ):
            with self.subTest(expected=expected):
                result = run(payload(egress_evidence=evidence))
                self.assertEqual(result["status"], "blocked")
                self.assertIn(expected, result["egress"]["reasons"])
                self.assertIsNone(result["delivery"])
        with self.assertRaisesRegex(ValueError, "signing_secret"):
            run(payload(webhook={**WEBHOOK, "signing_secret": "short"}))

    def test_rejects_invalid_event_mode_and_expired_hmac_batch_limits(self):
        with self.assertRaisesRegex(ValueError, "event_mode"):
            run(payload(event_mode=["summary"]))
        with self.assertRaisesRegex(ValueError, "maximum_finding_events"):
            run(payload(event_mode="summary_and_findings", maximum_finding_events=500))

    def test_does_not_echo_untrusted_or_secret_fields(self):
        raw = payload()
        raw["claimed_job"]["password"] = "job-password-secret"
        raw["webhook"]["private_key"] = "private-key-secret"
        raw["egress_evidence"]["api_token"] = "egress-token-secret"
        result = run(raw)
        rendered = str(result)
        for secret in ("job-password-secret", "private-key-secret", "egress-token-secret", SECRET):
            self.assertNotIn(secret, rendered)
        self.assertNotIn("api_token", rendered)
        self.assertNotIn("private_key", rendered)


if __name__ == "__main__":
    unittest.main()
