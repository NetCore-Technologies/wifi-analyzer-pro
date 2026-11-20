"""Tests for scheduled report job intake and payload identity."""
from __future__ import annotations

import hashlib
import json
import unittest

from wifi_analyzer_backend.feature_plugins.feature_182_router_audit_report_bundle_builder import run as build_report
from wifi_analyzer_backend.feature_plugins.feature_188_router_scheduled_report_job_intake import run


NOW = "2026-11-20T10:00:00Z"


def valid_payload():
    bundle = build_report({
        "report_id": "weekly-home",
        "title": "Weekly home audit",
        "generated_at": NOW,
        "sources": [{
            "source_id": "health-home",
            "source_type": "router_fleet_health_audit",
            "result": {"status": "audited", "summary": {"router_count": 1}, "routers": []},
        }],
    })
    return {
        "schedule_id": "daily-home",
        "occurrence_id": "a" * 64,
        "scheduled_at": "2026-11-20T10:05:00Z",
        "report_bundle": bundle,
        "max_attempts": 4,
    }


class RouterScheduledReportJobIntakeTests(unittest.TestCase):
    def test_prepares_stable_job_and_payload_hashes(self):
        payload = valid_payload()
        first = run(payload)
        second = run(payload)
        self.assertEqual(first["status"], "prepared")
        self.assertEqual(first["job_key"], second["job_key"])
        self.assertEqual(first["payload_hash"], second["payload_hash"])
        self.assertEqual(first["report_id"], "weekly-home")
        self.assertEqual(first["max_attempts"], 4)

    def test_same_occurrence_and_report_has_same_key_but_distinct_schedule_does_not(self):
        payload = valid_payload()
        first = run(payload)
        changed = run({**payload, "schedule_id": "weekly-home"})
        self.assertNotEqual(first["job_key"], changed["job_key"])

    def test_rejects_modified_bundle_hash_or_unsupported_secret_fields(self):
        payload = valid_payload()
        tampered = {**payload, "report_bundle": {**payload["report_bundle"], "title": "Tampered"}}
        with self.assertRaisesRegex(ValueError, "does not match"):
            run(tampered)
        secret = {**payload, "report_bundle": {**payload["report_bundle"], "signing_secret": "secret"}}
        with self.assertRaisesRegex(ValueError, "unsupported fields"):
            run(secret)

    def test_strips_untrusted_nested_source_fields_before_job_persistence(self):
        payload = valid_payload()
        bundle = dict(payload["report_bundle"])
        bundle["note"] = "private-source-message-secret"
        bundle["sections"] = [{
            **bundle["sections"][0],
            "api_token": "section-token-secret",
        }]
        body = {key: value for key, value in bundle.items() if key != "content_hash"}
        canonical = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        bundle["content_hash"] = hashlib.sha256(canonical.encode()).hexdigest()
        result = run({**payload, "report_bundle": bundle})
        rendered = str(result["report_bundle"])
        self.assertNotIn("private-source-message-secret", rendered)
        self.assertNotIn("section-token-secret", rendered)
        self.assertNotIn("api_token", rendered)
        self.assertIn("Raw snapshots, credentials", result["report_bundle"]["note"])

    def test_rejects_invalid_occurrence_timestamp_and_attempt_limits(self):
        payload = valid_payload()
        with self.assertRaisesRegex(ValueError, "64-character SHA-256"):
            run({**payload, "occurrence_id": "invalid"})
        with self.assertRaisesRegex(ValueError, "timezone offset"):
            run({**payload, "scheduled_at": "2026-11-20T10:05:00"})
        with self.assertRaisesRegex(ValueError, "from 1 to 10"):
            run({**payload, "max_attempts": 11})

    def test_rejects_non_finite_or_oversized_report_bundle(self):
        payload = valid_payload()
        bad = {**payload["report_bundle"], "summary": {"load": float("nan")}}
        with self.assertRaisesRegex(ValueError, "JSON-compatible finite values"):
            run({**payload, "report_bundle": bad})
        huge = {**payload["report_bundle"], "note": "x" * (512 * 1024)}
        body = {key: value for key, value in huge.items() if key != "content_hash"}
        canonical = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        huge["content_hash"] = hashlib.sha256(canonical.encode()).hexdigest()
        with self.assertRaisesRegex(ValueError, "storage limit"):
            run({**payload, "report_bundle": huge})


if __name__ == "__main__":
    unittest.main()
