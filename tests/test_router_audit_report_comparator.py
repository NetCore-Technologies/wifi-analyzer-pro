"""Tests for hash-validated report bundle comparison."""
from __future__ import annotations

import unittest

from wifi_analyzer_backend.feature_plugins.feature_182_router_audit_report_bundle_builder import run as build_report
from wifi_analyzer_backend.feature_plugins.feature_183_router_audit_report_comparator import run


NOW = "2026-11-20T10:00:00Z"


def _health_findings(cpu: int, extra: list[dict] | None = None) -> list[dict]:
    values = [
        {
            "code": "resource.cpu_high", "severity": "warning",
            "resource_type": "router", "resource_id": "openwrt-home",
            "observed": cpu, "threshold": 85,
        },
        {
            "code": "interface.down", "severity": "warning",
            "resource_type": "interface", "resource_id": "lan",
        },
    ]
    return values + (extra or [])


def _bundle(report_id: str, generated_at: str, cpu: int, extra: list[dict] | None = None,
            include_subnet: bool = True) -> dict:
    sources = [{
        "source_id": "health-home",
        "source_type": "router_fleet_health_audit",
        "result": {
            "status": "audited",
            "summary": {
                "router_count": 1,
                "site_count": 1,
                "critical_count": 0,
                "warning_count": len(_health_findings(cpu, extra)),
                "info_count": 0,
            },
            "routers": [{
                "router_id": "openwrt-home",
                "site_id": "home",
                "findings": _health_findings(cpu, extra),
            }],
        },
    }]
    if include_subnet:
        sources.append({
            "source_id": "subnets-home",
            "source_type": "router_subnet_overlap_audit",
            "result": {
                "status": "audited",
                "summary": {"overlap_count": 1},
                "overlaps": [{
                    "site_id": "home", "code": "subnet.overlap",
                    "overlap_type": "overlap",
                    "left": {"router_id": "openwrt-home", "ip_version": 4},
                    "right": {"router_id": "unifi-home", "ip_version": 4},
                }],
            },
        })
    return build_report({
        "report_id": report_id,
        "title": "Router audit",
        "generated_at": generated_at,
        "sources": sources,
    })


class RouterAuditReportComparatorTests(unittest.TestCase):
    def test_classifies_unchanged_changed_added_and_removed_findings(self):
        previous = _bundle(
            "previous", "2026-11-20T09:00:00Z", 90,
        )
        current = _bundle(
            "current", NOW, 95,
            extra=[{
                "code": "radio.down", "severity": "warning",
                "resource_type": "radio", "resource_id": "phy0",
            }],
            include_subnet=False,
        )
        result = run({"previous": previous, "current": current})
        summary = result["summary"]
        self.assertEqual(result["status"], "compared")
        self.assertEqual(summary["previous_finding_count"], 3)
        self.assertEqual(summary["current_finding_count"], 3)
        self.assertEqual(summary["unchanged_count"], 1)
        self.assertEqual(summary["changed_count"], 1)
        self.assertEqual(summary["added_count"], 1)
        self.assertEqual(summary["removed_count"], 1)
        self.assertEqual(summary["critical_delta"], 0)
        changed = result["findings"]["changed"][0]
        self.assertEqual(changed["code"], "resource.cpu_high")
        self.assertEqual(changed["previous"]["details"]["observed"], 90)
        self.assertEqual(changed["current"]["details"]["observed"], 95)
        self.assertEqual(result["findings"]["added"][0]["code"], "radio.down")
        self.assertEqual(result["findings"]["removed"][0]["code"], "subnet.overlap")
        self.assertEqual(result["summary"]["section_removed_count"], 1)

    def test_identical_bundles_have_no_finding_or_site_deltas(self):
        bundle = _bundle("same", "2026-11-20T09:00:00Z", 90)
        result = run({"previous": bundle, "current": bundle})
        self.assertEqual(result["summary"]["unchanged_count"], 3)
        self.assertEqual(result["summary"]["changed_count"], 0)
        self.assertEqual(result["summary"]["added_count"], 0)
        self.assertEqual(result["summary"]["removed_count"], 0)
        self.assertEqual(result["site_changes"], [])
        self.assertEqual(result["sections"]["changed"], [])

    def test_detects_section_status_and_summary_changes(self):
        previous = _bundle("previous", "2026-11-20T09:00:00Z", 90)
        current = _bundle("current", NOW, 92, extra=[{
            "code": "radio.down", "severity": "warning",
            "resource_type": "radio", "resource_id": "phy0",
        }])
        result = run({"previous": previous, "current": current})
        changed_sections = {
            item["source_id"]: item for item in result["sections"]["changed"]
        }
        health = changed_sections["health-home"]
        self.assertFalse(health["status_changed"])
        self.assertIn("warning_count", health["summary_changes"])
        self.assertEqual(result["site_changes"][0]["status"], "changed")
        self.assertTrue(result["site_changes"][0]["source_types_changed"])

    def test_source_allowlist_limits_the_comparison_scope(self):
        previous = _bundle("previous", "2026-11-20T09:00:00Z", 90)
        current = _bundle("current", NOW, 95, include_subnet=False)
        result = run({
            "previous": previous,
            "current": current,
            "source_allowlist": ["health-home"],
        })
        self.assertEqual(result["summary"]["previous_finding_count"], 2)
        self.assertEqual(result["summary"]["current_finding_count"], 2)
        self.assertEqual(result["summary"]["removed_count"], 0)
        self.assertEqual(result["filters"]["source_allowlist"], ["health-home"])

    def test_summary_only_mode_reports_zero_detail_count(self):
        previous = _bundle("previous", "2026-11-20T09:00:00Z", 90)
        current = _bundle("current", NOW, 95, include_subnet=False)
        result = run({
            "previous": previous,
            "current": current,
            "include_details": False,
        })
        self.assertGreater(result["summary"]["changed_count"], 0)
        self.assertEqual(result["summary"]["details_count"], 0)
        self.assertEqual(result["findings"], {"changed": [], "added": [], "removed": []})

    def test_maximum_details_is_a_global_cap_across_all_change_categories(self):
        previous = _bundle("previous", "2026-11-20T09:00:00Z", 90)
        current = _bundle(
            "current", NOW, 95,
            extra=[
                {"code": "radio.down", "severity": "warning", "resource_type": "radio", "resource_id": "phy0"},
                {"code": "client.signal_weak", "severity": "warning", "resource_type": "client", "resource_id": "aa:bb"},
            ],
            include_subnet=False,
        )
        result = run({"previous": previous, "current": current, "maximum_details": 2})
        returned = sum(len(values) for values in result["findings"].values())
        self.assertEqual(returned, 2)
        self.assertEqual(result["summary"]["details_count"], 2)
        self.assertTrue(result["summary"]["details_truncated"])

    def test_accepts_duplicate_source_finding_ids_as_distinct_observations(self):
        previous = _bundle(
            "previous", "2026-11-20T09:00:00Z", 90,
            extra=[{
                "code": "radio.down", "severity": "warning",
                "resource_type": "radio", "resource_id": "phy0",
            }],
            include_subnet=False,
        )
        # The report builder can legitimately issue equal IDs for indistinguishable
        # repeated observations; the comparator handles them as a multiset.
        current = _bundle(
            "current", NOW, 90,
            extra=[
                {"code": "radio.down", "severity": "warning", "resource_type": "radio", "resource_id": "phy0"},
                {"code": "radio.down", "severity": "warning", "resource_type": "radio", "resource_id": "phy0"},
            ],
            include_subnet=False,
        )
        result = run({"previous": previous, "current": current})
        self.assertEqual(result["summary"]["added_count"], 1)
        self.assertEqual(result["summary"]["unchanged_count"], 2)

    def test_rejects_tampered_hash_unknown_schema_and_wrong_report_order(self):
        previous = _bundle("previous", "2026-11-20T09:00:00Z", 90)
        current = _bundle("current", NOW, 95)
        tampered = {**previous, "title": "Tampered"}
        with self.assertRaisesRegex(ValueError, "does not match"):
            run({"previous": tampered, "current": current})
        unknown_schema = {**previous, "schema_version": "2.0"}
        # Recompute the digest so the schema validator, not the hash guard, is exercised.
        import hashlib
        body = {key: value for key, value in unknown_schema.items() if key != "content_hash"}
        canonical = __import__("json").dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        unknown_schema["content_hash"] = hashlib.sha256(canonical.encode()).hexdigest()
        with self.assertRaisesRegex(ValueError, "schema_version"):
            run({"previous": unknown_schema, "current": current})
        future = _bundle("future", "2026-11-20T11:00:00Z", 95)
        with self.assertRaisesRegex(ValueError, "must not be after"):
            run({"previous": future, "current": previous})

    def test_rejects_invalid_finding_fields_and_detail_limits(self):
        previous = _bundle("previous", "2026-11-20T09:00:00Z", 90)
        current = _bundle("current", NOW, 95)
        import hashlib
        import json
        invalid = json.loads(json.dumps(previous))
        invalid["findings"][0]["severity"] = ["critical"]
        body = {key: value for key, value in invalid.items() if key != "content_hash"}
        invalid["content_hash"] = hashlib.sha256(
            json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        with self.assertRaisesRegex(ValueError, "severity"):
            run({"previous": invalid, "current": current})
        with self.assertRaisesRegex(ValueError, "from 1 to 4000"):
            run({"previous": previous, "current": current, "maximum_details": 0})

    def test_redacts_unknown_fields_by_revalidating_only_allowlisted_bundle_data(self):
        previous = _bundle("previous", "2026-11-20T09:00:00Z", 90)
        current = _bundle("current", NOW, 95)
        # Add an untrusted field and re-hash the bundle; it is ignored by the comparator.
        previous = dict(previous)
        previous["private_key"] = "must-not-appear"
        import hashlib
        import json
        body = {key: value for key, value in previous.items() if key != "content_hash"}
        previous["content_hash"] = hashlib.sha256(
            json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        result = run({"previous": previous, "current": current})
        self.assertNotIn("must-not-appear", str(result))
        self.assertNotIn("private_key", str(result))


if __name__ == "__main__":
    unittest.main()
