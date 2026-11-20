"""Tests for building deterministic, bounded router audit report bundles."""
from __future__ import annotations

import unittest

from wifi_analyzer_backend.feature_plugins.feature_182_router_audit_report_bundle_builder import run


NOW = "2026-11-20T10:00:00Z"


def sources():
    return [
        {
            "source_id": "fleet-health-1",
            "source_type": "router_fleet_health_audit",
            "result": {
                "status": "audited",
                "summary": {
                    "router_count": 2, "site_count": 2, "critical_count": 1,
                    "warning_count": 1, "info_count": 0,
                },
                "routers": [
                    {
                        "router_id": "openwrt-home", "site_id": "home",
                        "findings": [{
                            "code": "resource.cpu_high", "severity": "warning",
                            "resource_type": "router", "resource_id": "openwrt-home",
                            "observed": 91, "threshold": 85,
                            "message": "untrusted raw message with controller-password",
                        }],
                    },
                    {
                        "router_id": "mikrotik-branch", "site_id": "branch",
                        "findings": [{
                            "code": "resource.cpu_critical", "severity": "critical",
                            "resource_type": "router", "resource_id": "mikrotik-branch",
                            "observed": 99, "threshold": 95,
                        }],
                    },
                ],
            },
        },
        {
            "source_id": "subnets-home",
            "source_type": "router_subnet_overlap_audit",
            "result": {
                "status": "audited",
                "summary": {"router_count": 2, "subnet_count": 2, "overlap_count": 1},
                "overlaps": [{
                    "site_id": "home", "code": "subnet.overlap",
                    "left": {"router_id": "openwrt-home", "cidr": "192.0.2.0/24"},
                    "right": {"router_id": "unifi-home", "cidr": "192.0.2.128/25"},
                    "overlap_type": "overlap",
                }],
            },
        },
        {
            "source_id": "incidents-1",
            "source_type": "router_incident_alert_policy_evaluator",
            "result": {
                "status": "evaluated",
                "summary": {"new_alert_count": 1, "ongoing_alert_count": 0},
                "alerts": [{
                    "site_id": "home", "router_id": "openwrt-home",
                    "severity": "warning", "policy_id": "cpu-policy",
                    "resource_type": "router", "resource_id": "openwrt-home",
                }],
                "resolved_alerts": [],
            },
        },
    ]


class RouterAuditReportBundleTests(unittest.TestCase):
    def test_builds_versioned_report_with_aggregated_severity_and_site_summaries(self):
        result = run({
            "report_id": "weekly-home",
            "title": "Weekly router health",
            "generated_at": NOW,
            "period_start": "2026-11-19T00:00:00Z",
            "period_end": NOW,
            "sources": sources(),
        })
        self.assertEqual(result["schema_version"], "1.0")
        self.assertEqual(result["report_id"], "weekly-home")
        self.assertEqual(result["summary"]["source_count"], 3)
        self.assertEqual(result["summary"]["finding_count"], 4)
        self.assertEqual(result["summary"]["critical_count"], 1)
        self.assertEqual(result["summary"]["warning_count"], 3)
        self.assertEqual(result["summary"]["site_count"], 2)
        self.assertEqual({item["site_id"] for item in result["sites"]}, {"home", "branch"})
        self.assertEqual(len(result["content_hash"]), 64)
        self.assertEqual(len(result["sections"]), 3)

    def test_report_hash_is_deterministic_for_same_inputs_and_changes_when_content_changes(self):
        payload = {
            "report_id": "daily-home",
            "generated_at": NOW,
            "sources": sources(),
        }
        first = run(payload)
        second = run(payload)
        self.assertEqual(first["content_hash"], second["content_hash"])
        changed = {**payload, "title": "Renamed report"}
        third = run(changed)
        self.assertNotEqual(first["content_hash"], third["content_hash"])

    def test_site_allowlist_filters_findings_and_site_summaries(self):
        result = run({
            "report_id": "home-only",
            "generated_at": NOW,
            "site_allowlist": ["home"],
            "sources": sources(),
        })
        self.assertEqual(result["summary"]["site_count"], 1)
        self.assertEqual({item["site_id"] for item in result["sites"]}, {"home"})
        self.assertTrue(all(item["site_id"] == "home" for item in result["findings"]))
        self.assertEqual(result["filters"]["site_allowlist"], ["home"])

    def test_detail_limit_truncates_returned_details_but_preserves_full_counts(self):
        large = {
            "source_id": "many-overlaps",
            "source_type": "router_subnet_overlap_audit",
            "result": {
                "status": "audited",
                "summary": {"overlap_count": 3},
                "overlaps": [
                    {"site_id": "home", "code": "subnet.overlap", "overlap_type": "overlap"}
                    for _ in range(3)
                ],
            },
        }
        result = run({
            "report_id": "limited",
            "generated_at": NOW,
            "maximum_findings": 2,
            "sources": [large],
        })
        self.assertEqual(result["summary"]["finding_count"], 3)
        self.assertEqual(result["summary"]["detail_count"], 2)
        self.assertEqual(len(result["findings"]), 2)
        self.assertTrue(result["summary"]["details_truncated"])

    def test_summary_only_mode_does_not_return_finding_records(self):
        result = run({
            "report_id": "summary-only",
            "generated_at": NOW,
            "include_details": False,
            "sources": sources(),
        })
        self.assertEqual(result["summary"]["finding_count"], 4)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["summary"]["detail_count"], 0)

    def test_supports_each_of_the_eight_router_audit_source_types(self):
        supported = [
            "router_snapshot_drift_report",
            "router_fleet_health_audit",
            "router_subnet_overlap_audit",
            "router_client_roaming_audit",
            "router_route_table_audit",
            "router_vlan_segmentation_audit",
            "router_gateway_redundancy_audit",
            "router_incident_alert_policy_evaluator",
        ]
        result = run({
            "report_id": "all-sources",
            "generated_at": NOW,
            "sources": [{
                "source_id": f"source-{index}",
                "source_type": source_type,
                "result": {"status": "audited", "summary": {}},
            } for index, source_type in enumerate(supported)],
        })
        self.assertEqual(result["summary"]["source_count"], 8)
        self.assertEqual({item["source_type"] for item in result["sections"]}, set(supported))

    def test_does_not_copy_raw_messages_snapshots_or_credential_fields(self):
        result = run({
            "report_id": "redaction",
            "generated_at": NOW,
            "sources": [{
                "source_id": "fleet",
                "source_type": "router_fleet_health_audit",
                "result": {
                    "status": "audited",
                    "summary": {"router_count": 1},
                    "routers": [{
                        "site_id": "home", "router_id": "openwrt-home",
                        "password": "router-password",
                        "findings": [{
                            "code": "interface.down", "severity": "warning",
                            "resource_type": "interface", "resource_id": "wan",
                            "message": "controller-secret", "api_token": "token-secret",
                        }],
                        "raw_snapshot": {"private_key": "key-secret"},
                    }],
                    "api_token": "outer-token",
                },
            }],
        })
        rendered = str(result)
        for secret in (
            "router-password", "controller-secret", "token-secret",
            "key-secret", "outer-token", "api_token", "raw_snapshot",
        ):
            self.assertNotIn(secret, rendered)
        self.assertNotIn("message", result["findings"][0])

    def test_rejects_invalid_ids_sources_periods_sites_and_limits(self):
        base = {"generated_at": NOW, "sources": sources()}
        with self.assertRaisesRegex(ValueError, "report_id"):
            run({**base, "report_id": "../secret"})
        with self.assertRaisesRegex(ValueError, "source_type"):
            run({"report_id": "bad-source", "generated_at": NOW, "sources": [{
                "source_id": "x", "source_type": ["router_fleet_health_audit"], "result": {},
            }]})
        with self.assertRaisesRegex(ValueError, "source_id values must be unique"):
            run({"report_id": "duplicate", "generated_at": NOW, "sources": [
                sources()[0], sources()[0],
            ]})
        with self.assertRaisesRegex(ValueError, "period_start must not be after"):
            run({**base, "report_id": "bad-period",
                 "period_start": "2026-11-21T00:00:00Z", "period_end": NOW})
        with self.assertRaisesRegex(ValueError, "no more than 128"):
            run({**base, "report_id": "bad-sites", "site_allowlist": [f"site-{i}" for i in range(129)]})
        with self.assertRaisesRegex(ValueError, "from 1 to 64"):
            run({"report_id": "too-many-sources", "generated_at": NOW,
                 "sources": sources() * 22})

    def test_rejects_naive_time_non_finite_values_and_oversized_input(self):
        with self.assertRaisesRegex(ValueError, "timezone offset"):
            run({"report_id": "naive", "generated_at": "2026-11-20T10:00:00", "sources": sources()})
        with self.assertRaisesRegex(ValueError, "finite values"):
            run({
                "report_id": "nan",
                "generated_at": NOW,
                "sources": [{
                    "source_id": "bad",
                    "source_type": "router_fleet_health_audit",
                    "result": {"summary": {"load": float("nan")}},
                }],
            })
        with self.assertRaisesRegex(ValueError, "byte input limit"):
            run({
                "report_id": "large",
                "generated_at": NOW,
                "sources": [{
                    "source_id": "large",
                    "source_type": "router_fleet_health_audit",
                    "result": {"summary": {"metadata": "x" * (4 * 1024 * 1024)}},
                }],
            })


if __name__ == "__main__":
    unittest.main()
