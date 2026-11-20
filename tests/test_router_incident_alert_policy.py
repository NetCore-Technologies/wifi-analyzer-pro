"""Tests for local router incident alert policy evaluation."""
from __future__ import annotations

import unittest

from wifi_analyzer_backend.feature_plugins.feature_181_router_incident_alert_policy_evaluator import run


NOW = "2026-11-20T10:00:00Z"
FINDINGS = [
    {
        "site_id": "home", "router_id": "openwrt-home", "adapter_id": "openwrt",
        "code": "resource.cpu_high", "severity": "warning", "resource_type": "router",
        "resource_id": "openwrt-home", "observed": 91, "threshold": 85,
        "message": "raw secret text is omitted",
    },
    {
        "site_id": "home", "router_id": "openwrt-home", "adapter_id": "openwrt",
        "code": "interface.down", "severity": "warning", "resource_type": "interface",
        "resource_id": "wan",
    },
    {
        "site_id": "branch", "router_id": "mikrotik-branch", "adapter_id": "mikrotik",
        "code": "resource.cpu_critical", "severity": "critical", "resource_type": "router",
        "resource_id": "mikrotik-branch", "observed": 99, "threshold": 95,
    },
]


class RouterIncidentAlertPolicyTests(unittest.TestCase):
    def test_deduplicates_and_creates_policy_scoped_alerts(self):
        result = run({
            "generated_at": NOW,
            "policies": [{
                "policy_id": "router-health", "match_codes": ["resource.cpu_high", "resource.cpu_critical"],
                "minimum_severity": "warning", "group_by": "router",
            }],
            "findings": FINDINGS,
        })
        self.assertEqual(result["summary"]["new_alert_count"], 2)
        self.assertEqual(result["summary"]["critical_alert_count"], 1)
        by_router = {item["router_id"]: item for item in result["alerts"]}
        self.assertEqual(by_router["openwrt-home"]["source_codes"], ["resource.cpu_high"])
        self.assertEqual(by_router["mikrotik-branch"]["severity"], "critical")
        self.assertEqual(len(by_router["openwrt-home"]["alert_key"]), 64)

    def test_groups_by_site_or_resource(self):
        site = run({
            "generated_at": NOW,
            "policies": [{"policy_id": "site", "match_codes": ["*"], "group_by": "site"}],
            "findings": FINDINGS,
        })
        self.assertEqual(len(site["alerts"]), 2)
        home = next(item for item in site["alerts"] if item["site_id"] == "home")
        self.assertIsNone(home["router_id"])
        self.assertEqual(home["current_occurrence_count"], 2)
        resource = run({
            "generated_at": NOW,
            "policies": [{"policy_id": "resource", "match_codes": ["*"], "group_by": "resource"}],
            "findings": FINDINGS,
        })
        self.assertEqual(len(resource["alerts"]), 3)

    def test_severity_override_and_site_adapter_scopes(self):
        result = run({
            "generated_at": NOW,
            "policies": [{
                "policy_id": "branch-critical", "match_codes": ["*"], "minimum_severity": "critical",
                "severity_override": "warning", "site_allowlist": ["branch"],
                "adapter_allowlist": ["mikrotik"], "group_by": "router",
            }],
            "findings": FINDINGS,
        })
        self.assertEqual(len(result["alerts"]), 1)
        self.assertEqual(result["alerts"][0]["severity"], "warning")
        self.assertEqual(result["alerts"][0]["router_id"], "mikrotik-branch")

    def test_occurrence_threshold_deduplicates_identical_events(self):
        result = run({
            "generated_at": NOW,
            "policies": [{
                "policy_id": "repeat", "match_codes": ["resource.cpu_high"],
                "minimum_occurrences": 2, "group_by": "router",
            }],
            "findings": [FINDINGS[0], FINDINGS[0]],
        })
        self.assertEqual(result["summary"]["new_alert_count"], 0)
        self.assertEqual(result["suppressed"][0]["observed_occurrences"], 1)

    def test_existing_alert_becomes_ongoing_and_preserves_acknowledgement(self):
        policy = {"policy_id": "cpu", "match_codes": ["resource.cpu_high"], "group_by": "router"}
        first = run({"generated_at": "2026-11-20T09:00:00Z", "policies": [policy], "findings": [FINDINGS[0]]})
        prior = {**first["alerts"][0], "status": "acknowledged"}
        second = run({"generated_at": NOW, "policies": [policy], "findings": [FINDINGS[0]], "previous_alerts": [prior]})
        self.assertEqual(second["alerts"][0]["status"], "acknowledged")
        self.assertEqual(second["alerts"][0]["first_seen_at"], "2026-11-20T09:00:00+00:00")
        self.assertEqual(second["alerts"][0]["occurrence_count"], 2)

    def test_disappearing_alert_and_disabled_policy_resolve(self):
        policy = {"policy_id": "interface-down", "match_codes": ["interface.down"], "group_by": "resource"}
        first = run({"generated_at": "2026-11-20T09:00:00Z", "policies": [policy], "findings": [FINDINGS[1]]})
        second = run({"generated_at": NOW, "policies": [policy], "findings": [], "previous_alerts": first["alerts"]})
        self.assertEqual(second["resolved_alerts"][0]["status"], "resolved")
        disabled = run({
            "generated_at": NOW,
            "policies": [{**policy, "enabled": False}],
            "findings": [FINDINGS[1]],
            "previous_alerts": first["alerts"],
        })
        self.assertEqual(disabled["summary"]["enabled_policy_count"], 0)
        self.assertEqual(disabled["summary"]["resolved_alert_count"], 1)

    def test_rejects_invalid_policy_severity_group_code_and_duplicate_id(self):
        with self.assertRaisesRegex(ValueError, "policy_id values must be unique"):
            run({"generated_at": NOW, "policies": [
                {"policy_id": "same", "match_codes": ["a.event"]},
                {"policy_id": "same", "match_codes": ["b.event"]},
            ]})
        for value, message in (
            ({"minimum_severity": "urgent"}, "minimum_severity"),
            ({"group_by": "network"}, "group_by"),
            ({"match_codes": ["Bad.Code"]}, "valid lowercase finding codes"),
        ):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, message):
                run({"generated_at": NOW, "policies": [{
                    "policy_id": "invalid", "match_codes": ["*"], **value,
                }]})

    def test_rejects_invalid_finding_adapter_time_and_duplicate_previous_keys(self):
        with self.assertRaisesRegex(ValueError, "timezone offset"):
            run({"generated_at": "2026-11-20T10:00:00", "policies": [{
                "policy_id": "cpu", "match_codes": ["*"],
            }]})
        with self.assertRaisesRegex(ValueError, "adapter_id"):
            run({"generated_at": NOW, "policies": [{"policy_id": "cpu", "match_codes": ["*"]}],
                 "findings": [{"site_id": "home", "code": "a.event", "severity": "warning", "adapter_id": ["openwrt"]}]})
        previous = run({"generated_at": NOW, "policies": [{"policy_id": "cpu", "match_codes": ["resource.cpu_high"]}],
                        "findings": [FINDINGS[0]]})["alerts"]
        with self.assertRaisesRegex(ValueError, "duplicate alert keys"):
            run({"generated_at": NOW, "policies": [{"policy_id": "cpu", "match_codes": ["*"]}],
                 "previous_alerts": previous * 2})

    def test_redacts_raw_finding_messages_and_unknown_credential_fields(self):
        result = run({
            "generated_at": NOW,
            "policies": [{"policy_id": "secret-check", "match_codes": ["router.secret_test"]}],
            "findings": [{
                "site_id": "home", "router_id": "router-home", "adapter_id": "openwrt",
                "code": "router.secret_test", "severity": "warning",
                "message": "controller-password-secret", "api_token": "token-secret",
            }],
        })
        rendered = str(result)
        self.assertNotIn("controller-password-secret", rendered)
        self.assertNotIn("token-secret", rendered)
        self.assertNotIn("api_token", rendered)
        self.assertNotIn("message", result["alerts"][0]["sample_evidence"][0])

    def test_enforces_policy_and_finding_caps(self):
        with self.assertRaisesRegex(ValueError, "from 1 to 100"):
            run({"generated_at": NOW, "policies": [
                {"policy_id": f"p{i}", "match_codes": ["*"]} for i in range(101)
            ]})
        with self.assertRaisesRegex(ValueError, "no more than 20000"):
            run({"generated_at": NOW, "policies": [{"policy_id": "p", "match_codes": ["*"]}],
                 "findings": [{}] * 20001})


if __name__ == "__main__":
    unittest.main()
