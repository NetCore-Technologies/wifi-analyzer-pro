"""Tests for site-scoped UniFi/MikroTik VLAN segmentation consistency."""
from __future__ import annotations

import unittest

from wifi_analyzer_backend.feature_plugins.feature_179_router_vlan_segmentation_audit import run


NOW = "2026-11-20T10:00:00Z"


class RouterVlanSegmentationAuditTests(unittest.TestCase):
    def test_detects_same_vlan_id_with_different_subnets_across_vendors(self):
        result = run({"snapshots": [
            {
                "router_id": "unifi-controller",
                "site_id": "office",
                "snapshot": {
                    "adapter_id": "unifi",
                    "captured_at": NOW,
                    "controller": {"hostname": "unifi.office.local"},
                    "networks": [{
                        "id": "office", "name": "Office", "vlan_enabled": True,
                        "vlan_id": 20, "ip_subnet": "192.0.2.0/24",
                    }],
                },
            },
            {
                "router_id": "mikrotik-switch",
                "site_id": "office",
                "snapshot": {
                    "adapter_id": "mikrotik",
                    "captured_at": NOW,
                    "interfaces": [{"name": "bridge", "type": "bridge"}],
                    "vlans": [{
                        "name": "vlan20", "interface": "bridge", "interface_known": True,
                        "vlan_id": 20, "running": True,
                    }],
                    "addresses": [{
                        "interface": "vlan20", "network": "192.0.3.0/24",
                    }],
                },
            },
        ]})
        self.assertEqual(result["status"], "audited")
        self.assertEqual(result["summary"]["router_count"], 2)
        self.assertEqual(result["summary"]["segment_count"], 2)
        finding = next(item for item in result["findings"] if item["code"] == "vlan.subnet_mismatch")
        self.assertEqual(finding["vlan_id"], 20)
        self.assertEqual(finding["subnets"], ["192.0.2.0/24", "192.0.3.0/24"])

    def test_matching_vlan_and_subnet_across_vendors_has_no_mismatch(self):
        result = run({"snapshots": [
            {
                "router_id": "unifi-controller", "site_id": "home",
                "snapshot": {
                    "adapter_id": "unifi", "captured_at": NOW,
                    "controller": {"hostname": "unifi.home.local"},
                    "networks": [{
                        "id": "iot", "name": "IoT", "vlan_enabled": True,
                        "vlan_id": 30, "ip_subnet": "10.30.0.0/24",
                    }],
                },
            },
            {
                "router_id": "mikrotik-router", "site_id": "home",
                "snapshot": {
                    "adapter_id": "mikrotik", "captured_at": NOW,
                    "vlans": [{
                        "name": "iot", "interface": "bridge", "interface_known": True,
                        "vlan_id": 30, "running": True,
                    }],
                    "addresses": [{"interface": "iot", "network": "10.30.0.0/24"}],
                },
            },
        ]})
        self.assertEqual(result["summary"]["finding_count"], 0)
        self.assertEqual(result["sites"][0]["vlan_id_count"], 1)

    def test_duplicate_vlan_id_on_one_router_is_reported(self):
        result = run({"snapshots": [{
            "router_id": "mikrotik-core",
            "site_id": "home",
            "snapshot": {
                "adapter_id": "mikrotik",
                "captured_at": NOW,
                "vlans": [
                    {"name": "vlan20-a", "interface": "bridge-a", "interface_known": True, "vlan_id": 20},
                    {"name": "vlan20-b", "interface": "bridge-b", "interface_known": True, "vlan_id": 20},
                ],
            },
        }]})
        duplicates = [item for item in result["findings"] if item["code"] == "vlan.duplicate_id_on_router"]
        self.assertEqual(len(duplicates), 1)
        self.assertEqual(duplicates[0]["segment_count"], 2)

    def test_flags_missing_parent_and_down_vlan_interfaces(self):
        result = run({"snapshots": [{
            "router_id": "mikrotik-access",
            "site_id": "home",
            "snapshot": {
                "adapter_id": "mikrotik",
                "captured_at": NOW,
                "vlans": [{
                    "name": "vlan70", "interface": "missing-bridge",
                    "interface_known": False, "vlan_id": 70, "running": False,
                }],
            },
        }]})
        codes = {item["code"] for item in result["findings"]}
        self.assertIn("vlan.parent_interface_unknown", codes)
        self.assertIn("vlan.interface_down", codes)

    def test_reports_inconsistent_unifi_tagging_flags_and_duplicate_profiles(self):
        result = run({"snapshots": [{
            "router_id": "unifi-controller",
            "site_id": "home",
            "snapshot": {
                "adapter_id": "unifi",
                "captured_at": NOW,
                "controller": {"hostname": "unifi.home.local"},
                "networks": [
                    {"id": "office-a", "name": "Office A", "vlan_enabled": False, "vlan_id": 20},
                    {"id": "office-b", "name": "Office B", "vlan_enabled": True, "vlan_id": 20},
                    {"id": "guest", "name": "Guest", "vlan_enabled": True, "vlan_id": None},
                ],
            },
        }]})
        codes = [item["code"] for item in result["findings"]]
        self.assertIn("vlan.disabled_with_id", codes)
        self.assertIn("vlan.enabled_without_id", codes)
        self.assertIn("vlan.duplicate_id_on_router", codes)

    def test_same_vlan_id_in_different_sites_is_not_compared(self):
        result = run({"snapshots": [
            {
                "router_id": "unifi-home", "site_id": "home",
                "snapshot": {
                    "adapter_id": "unifi", "captured_at": NOW,
                    "controller": {"hostname": "unifi.home.local"},
                    "networks": [{"id": "office", "name": "Office", "vlan_id": 20, "ip_subnet": "192.0.2.0/24"}],
                },
            },
            {
                "router_id": "unifi-branch", "site_id": "branch",
                "snapshot": {
                    "adapter_id": "unifi", "captured_at": NOW,
                    "controller": {"hostname": "unifi.branch.local"},
                    "networks": [{"id": "office", "name": "Office", "vlan_id": 20, "ip_subnet": "198.51.100.0/24"}],
                },
            },
        ]})
        self.assertEqual(result["summary"]["site_count"], 2)
        self.assertNotIn("vlan.subnet_mismatch", [item["code"] for item in result["findings"]])

    def test_rejects_invalid_adapters_vlan_ids_subnets_and_duplicate_router_ids(self):
        with self.assertRaisesRegex(ValueError, "UniFi or MikroTik"):
            run({"snapshots": [{
                "router_id": "openwrt-router",
                "snapshot": {"adapter_id": "openwrt", "captured_at": NOW},
            }]})
        with self.assertRaisesRegex(ValueError, "1 to 4094"):
            run({"snapshots": [{
                "router_id": "mikrotik-bad-vlan",
                "snapshot": {
                    "adapter_id": "mikrotik", "captured_at": NOW,
                    "vlans": [{"name": "bad", "interface": "bridge", "vlan_id": 4095}],
                },
            }]})
        with self.assertRaisesRegex(ValueError, "valid CIDR"):
            run({"snapshots": [{
                "router_id": "unifi-bad-subnet",
                "snapshot": {
                    "adapter_id": "unifi", "captured_at": NOW,
                    "networks": [{"id": "bad", "name": "Bad", "vlan_id": 3, "ip_subnet": "192.0.2.1/99"}],
                },
            }]})
        snapshot = {"adapter_id": "unifi", "captured_at": NOW}
        with self.assertRaisesRegex(ValueError, "unique"):
            run({"snapshots": [
                {"router_id": "same", "site_id": "home", "snapshot": snapshot},
                {"router_id": "same", "site_id": "home", "snapshot": snapshot},
            ]})

    def test_missing_vlan_evidence_is_reported_without_inventing_segments(self):
        result = run({"snapshots": [{
            "router_id": "mikrotik-empty",
            "site_id": "home",
            "snapshot": {"adapter_id": "mikrotik", "captured_at": NOW, "vlans": []},
        }]})
        self.assertEqual(result["status"], "no_vlan_evidence")
        self.assertEqual(result["summary"]["segment_count"], 0)
        self.assertEqual(result["findings"], [])

    def test_does_not_echo_unknown_configuration_or_secret_fields(self):
        result = run({"snapshots": [{
            "router_id": "unifi-secret",
            "site_id": "home",
            "snapshot": {
                "adapter_id": "unifi", "captured_at": NOW,
                "controller": {"hostname": "unifi.local", "password": "controller-secret"},
                "networks": [{
                    "id": "office", "name": "Office", "vlan_id": 20,
                    "ip_subnet": "192.0.2.0/24", "wifi_password": "wifi-secret",
                    "radius_secret": "radius-secret",
                }],
                "api_token": "token-secret",
            },
        }]})
        rendered = str(result)
        for secret in ("controller-secret", "wifi-secret", "radius-secret", "token-secret",
                       "password", "wifi_password", "radius_secret", "api_token"):
            self.assertNotIn(secret, rendered)

    def test_rejects_non_finite_and_oversized_input(self):
        with self.assertRaisesRegex(ValueError, "finite values"):
            run({"snapshots": [{
                "router_id": "mikrotik-nan",
                "snapshot": {
                    "adapter_id": "mikrotik", "captured_at": NOW,
                    "vlans": [{"name": "vlan20", "interface": "bridge", "vlan_id": 20, "unknown": float("nan")}],
                },
            }]})
        with self.assertRaisesRegex(ValueError, "byte input limit"):
            run({"snapshots": [{
                "router_id": "unifi-large",
                "snapshot": {
                    "adapter_id": "unifi", "captured_at": NOW,
                    "controller": {"hostname": "u.local", "large": "x" * (2 * 1024 * 1024)},
                },
            }]})


if __name__ == "__main__":
    unittest.main()
