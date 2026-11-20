"""Tests for site-scoped, multi-vendor IP subnet overlap auditing."""
from __future__ import annotations

import unittest

from wifi_analyzer_backend.feature_plugins.feature_176_router_subnet_overlap_audit import run


NOW = "2026-11-20T10:00:00Z"


class RouterSubnetOverlapAuditTests(unittest.TestCase):
    def test_finds_duplicate_and_partial_overlaps_across_vendor_schemas(self):
        result = run({
            "snapshots": [
                {
                    "router_id": "openwrt-gateway",
                    "site_id": "home",
                    "snapshot": {
                        "adapter_id": "openwrt",
                        "captured_at": NOW,
                        "interfaces": [{
                            "interface": "lan",
                            "ipv4_addresses": ["10.10.0.1/24"],
                            "ipv6_addresses": ["2001:db8:1::1/64"],
                        }],
                    },
                },
                {
                    "router_id": "unifi-controller",
                    "site_id": "home",
                    "snapshot": {
                        "adapter_id": "unifi",
                        "captured_at": NOW,
                        "controller": {"hostname": "unifi.home.local"},
                        "networks": [
                            {"id": "office", "name": "Office", "vlan_id": 10,
                             "ip_subnet": "10.10.0.0/24"},
                            {"id": "iot", "name": "IoT", "vlan_id": 20,
                             "ip_subnet": "2001:db8:1::/64"},
                        ],
                    },
                },
                {
                    "router_id": "mikrotik-edge",
                    "site_id": "home",
                    "snapshot": {
                        "adapter_id": "mikrotik",
                        "captured_at": NOW,
                        "addresses": [
                            {"interface": "vlan30", "address": "10.10.0.129",
                             "prefix_length": 25, "network": "10.10.0.128/25"},
                        ],
                    },
                },
            ],
        })
        self.assertEqual(result["status"], "audited")
        self.assertEqual(result["summary"]["router_count"], 3)
        self.assertEqual(result["summary"]["site_count"], 1)
        self.assertEqual(result["summary"]["subnet_count"], 4)
        self.assertEqual(result["summary"]["overlap_count"], 4)
        self.assertEqual(result["summary"]["duplicate_subnet_count"], 2)
        self.assertEqual(result["summary"]["overlapping_subnet_count"], 2)
        self.assertEqual(result["sites"][0]["overlap_count"], 4)
        self.assertTrue(all(item["severity"] == "warning" for item in result["overlaps"]))
        self.assertIn("2001:db8:1::/64", {item["cidr"] for item in result["subnets"]})

    def test_does_not_compare_different_sites(self):
        result = run({
            "snapshots": [
                {
                    "router_id": "router-home",
                    "site_id": "home",
                    "snapshot": {
                        "adapter_id": "openwrt", "captured_at": NOW,
                        "interfaces": [{"interface": "lan", "ipv4_addresses": ["192.168.1.1/24"]}],
                    },
                },
                {
                    "router_id": "router-branch",
                    "site_id": "branch",
                    "snapshot": {
                        "adapter_id": "mikrotik", "captured_at": NOW,
                        "addresses": [{"interface": "bridge", "network": "192.168.1.0/24"}],
                    },
                },
            ],
        })
        self.assertEqual(result["summary"]["subnet_count"], 2)
        self.assertEqual(result["summary"]["overlap_count"], 0)
        self.assertEqual([site["site_id"] for site in result["sites"]], ["branch", "home"])

    def test_deduplicates_same_router_bridge_and_member_interface_ranges(self):
        result = run({
            "snapshots": [{
                "router_id": "router-home",
                "site_id": "home",
                "snapshot": {
                    "adapter_id": "openwrt",
                    "captured_at": NOW,
                    "interfaces": [
                        {"interface": "br-lan", "ipv4_addresses": ["192.0.2.1/24"]},
                        {"interface": "lan1", "ipv4_addresses": ["192.0.2.2/24"]},
                    ],
                },
            }],
        })
        self.assertEqual(result["summary"]["subnet_count"], 1)
        self.assertEqual(result["summary"]["overlap_count"], 0)

    def test_unifi_networks_without_a_subnet_are_skipped_not_failed(self):
        result = run({
            "snapshots": [{
                "router_id": "unifi-router",
                "site_id": "home",
                "snapshot": {
                    "adapter_id": "unifi",
                    "captured_at": NOW,
                    "controller": {"hostname": "unifi.home.local"},
                    "networks": [
                        {"id": "lan", "name": "LAN", "ip_subnet": "192.0.2.0/24"},
                        {"id": "layer2", "name": "Layer 2 only", "ip_subnet": None},
                    ],
                },
            }],
        })
        self.assertEqual(result["summary"]["subnet_count"], 1)
        self.assertEqual(result["subnets"][0]["cidr"], "192.0.2.0/24")

    def test_returns_no_subnets_status_when_snapshots_have_no_address_evidence(self):
        result = run({
            "snapshots": [{
                "router_id": "unifi-router",
                "snapshot": {
                    "adapter_id": "unifi",
                    "captured_at": NOW,
                    "controller": {"hostname": "unifi.home.local"},
                    "networks": [{"id": "default", "name": "Default", "ip_subnet": None}],
                },
            }],
        })
        self.assertEqual(result["status"], "no_subnets")
        self.assertEqual(result["summary"]["overlap_count"], 0)

    def test_rejects_invalid_cidrs_timestamps_adapters_and_duplicate_router_identity(self):
        with self.assertRaisesRegex(ValueError, "valid CIDR"):
            run({"snapshots": [{
                "router_id": "openwrt-bad",
                "snapshot": {
                    "adapter_id": "openwrt", "captured_at": NOW,
                    "interfaces": [{"interface": "lan", "ipv4_addresses": ["192.0.2.1/99"]}],
                },
            }]})
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            run({"snapshots": [{
                "router_id": "router-naive",
                "snapshot": {"adapter_id": "openwrt", "captured_at": "2026-11-20T10:00:00"},
            }]})
        with self.assertRaisesRegex(ValueError, "normalised"):
            run({"snapshots": [{
                "router_id": "router-unknown",
                "snapshot": {"adapter_id": "routeros-v99", "captured_at": NOW},
            }]})
        with self.assertRaisesRegex(ValueError, "unique"):
            run({"snapshots": [
                {"router_id": "same", "snapshot": {"adapter_id": "unifi", "captured_at": NOW}},
                {"router_id": "same", "snapshot": {"adapter_id": "mikrotik", "captured_at": NOW}},
            ]})

    def test_rejects_bounded_input_and_invalid_vlan_values(self):
        with self.assertRaisesRegex(ValueError, "no more than 64"):
            run({"snapshots": [
                {"router_id": f"router-{index}", "snapshot": {
                    "adapter_id": "openwrt", "captured_at": NOW,
                }} for index in range(65)
            ]})
        with self.assertRaisesRegex(ValueError, "vlan_id"):
            run({"snapshots": [{
                "router_id": "unifi-router",
                "snapshot": {
                    "adapter_id": "unifi",
                    "captured_at": NOW,
                    "networks": [{"id": "office", "ip_subnet": "192.0.2.0/24", "vlan_id": 4095}],
                },
            }]})

    def test_does_not_leak_unknown_fields_or_credentials_into_findings(self):
        result = run({
            "snapshots": [
                {
                    "router_id": "router-a",
                    "site_id": "home",
                    "snapshot": {
                        "adapter_id": "unifi", "captured_at": NOW,
                        "controller": {"hostname": "unifi.home", "password": "controller-secret"},
                        "networks": [{
                            "id": "office", "name": "Office",
                            "ip_subnet": "10.0.0.0/24",
                            "wifi_password": "wifi-secret",
                        }],
                        "api_token": "token-secret",
                    },
                },
                {
                    "router_id": "router-b",
                    "site_id": "home",
                    "snapshot": {
                        "adapter_id": "mikrotik", "captured_at": NOW,
                        "addresses": [{"interface": "bridge", "network": "10.0.0.0/24",
                                       "radius_secret": "radius-secret"}],
                    },
                },
            ],
        })
        rendered = str(result)
        for secret in ("controller-secret", "wifi-secret", "token-secret", "radius-secret",
                       "password", "api_token", "radius_secret"):
            self.assertNotIn(secret, rendered)

    def test_rejects_non_finite_json_and_oversized_payload(self):
        with self.assertRaisesRegex(ValueError, "finite values"):
            run({"snapshots": [{
                "router_id": "unifi-nan",
                "snapshot": {
                    "adapter_id": "unifi", "captured_at": NOW,
                    "networks": [{"id": "office", "ip_subnet": "192.0.2.0/24", "unknown": float("nan")}],
                },
            }]})
        with self.assertRaisesRegex(ValueError, "byte input limit"):
            run({"snapshots": [{
                "router_id": "unifi-large",
                "snapshot": {
                    "adapter_id": "unifi", "captured_at": NOW,
                    "controller": {"hostname": "u.local", "metadata": "x" * (4 * 1024 * 1024)},
                },
            }]})

    def test_unknown_nested_configuration_is_not_echoed(self):
        result = run({"snapshots": [{
            "router_id": "mikrotik-router",
            "snapshot": {
                "adapter_id": "mikrotik",
                "captured_at": NOW,
                "addresses": [{
                    "interface": "bridge",
                    "network": "198.51.100.0/24",
                    "raw_export": {"password": "not-returned"},
                }],
            },
        }]})
        self.assertNotIn("raw_export", str(result))
        self.assertNotIn("not-returned", str(result))


if __name__ == "__main__":
    unittest.main()
