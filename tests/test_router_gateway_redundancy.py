"""Tests for site-level default-gateway redundancy across router snapshots."""
from __future__ import annotations

import unittest

from wifi_analyzer_backend.feature_plugins.feature_180_router_gateway_redundancy_audit import run


NOW = "2026-11-20T10:00:00Z"


class RouterGatewayRedundancyAuditTests(unittest.TestCase):
    def test_reports_multiple_configured_gateways_without_claiming_failover_verified(self):
        result = run({"snapshots": [
            {
                "router_id": "openwrt-edge",
                "site_id": "office",
                "snapshot": {
                    "adapter_id": "openwrt",
                    "captured_at": NOW,
                    "routes": [{
                        "target": "0.0.0.0/0", "gateway": "192.0.2.1",
                        "device": "wan", "metric": 10,
                    }],
                },
            },
            {
                "router_id": "mikrotik-edge",
                "site_id": "office",
                "snapshot": {
                    "adapter_id": "mikrotik",
                    "captured_at": NOW,
                    "routes": [{
                        "target": "0.0.0.0/0", "gateway": "198.51.100.1",
                        "gateway_interface": "ether1", "routing_table": "main",
                        "distance": 1, "active": True,
                    }],
                },
            },
        ]})
        self.assertEqual(result["status"], "audited")
        self.assertEqual(result["summary"]["router_count"], 2)
        self.assertEqual(result["summary"]["configured_default_route_count"], 2)
        group = result["groups"][0]
        self.assertEqual(group["status"], "multiple_configured_paths_unverified")
        self.assertEqual(group["eligible_router_count"], 2)
        self.assertEqual(group["distinct_gateway_count"], 2)
        self.assertIn("gateway.multiple_configured_paths", [item["code"] for item in group["findings"]])
        self.assertIn("gateway.activation_unknown", [item["code"] for item in group["findings"]])
        self.assertIn("not been tested", result["note"])

    def test_reports_shared_upstream_next_hop_across_multiple_routers(self):
        result = run({"snapshots": [
            {
                "router_id": "openwrt-a", "site_id": "home",
                "snapshot": {
                    "adapter_id": "openwrt", "captured_at": NOW,
                    "routes": [{"target": "0.0.0.0/0", "gateway": "192.0.2.1", "device": "wan"}],
                },
            },
            {
                "router_id": "mikrotik-b", "site_id": "home",
                "snapshot": {
                    "adapter_id": "mikrotik", "captured_at": NOW,
                    "routes": [{
                        "target": "0.0.0.0/0", "gateway": "192.0.2.1",
                        "gateway_interface": "ether1", "routing_table": "main", "active": True,
                    }],
                },
            },
        ]})
        group = result["groups"][0]
        self.assertEqual(group["status"], "shared_next_hop")
        self.assertEqual(group["distinct_gateway_count"], 1)
        self.assertIn("gateway.shared_next_hop", [item["code"] for item in group["findings"]])

    def test_one_router_with_two_default_routes_is_still_a_single_router_path(self):
        result = run({"snapshots": [{
            "router_id": "mikrotik-dual-wan",
            "site_id": "home",
            "snapshot": {
                "adapter_id": "mikrotik", "captured_at": NOW,
                "routes": [
                    {"target": "0.0.0.0/0", "gateway": "192.0.2.1", "routing_table": "main", "distance": 1, "active": True},
                    {"target": "0.0.0.0/0", "gateway": "198.51.100.1", "routing_table": "main", "distance": 2, "active": False},
                ],
            },
        }]})
        group = result["groups"][0]
        self.assertEqual(group["default_route_count"], 2)
        self.assertEqual(group["eligible_router_count"], 1)
        self.assertEqual(group["status"], "single_router_candidate")
        self.assertIn("gateway.single_router_candidate", [item["code"] for item in group["findings"]])

    def test_separates_ipv4_ipv6_and_routing_tables(self):
        result = run({"snapshots": [{
            "router_id": "mikrotik-multi-table",
            "site_id": "branch",
            "snapshot": {
                "adapter_id": "mikrotik", "captured_at": NOW,
                "routes": [
                    {"target": "0.0.0.0/0", "gateway": "192.0.2.1", "routing_table": "main"},
                    {"target": "::/0", "gateway": "fe80::1", "gateway_interface": "wan1", "routing_table": "main"},
                    {"target": "0.0.0.0/0", "gateway": "198.51.100.1", "routing_table": "backup"},
                ],
            },
        }]})
        keys = {(item["ip_version"], item["routing_table"]) for item in result["groups"]}
        self.assertEqual(keys, {(4, "main"), (6, "main"), (4, "backup")})

    def test_ipv6_link_local_next_hops_use_the_interface_as_part_of_identity(self):
        result = run({"snapshots": [
            {
                "router_id": "mikrotik-a", "site_id": "home",
                "snapshot": {
                    "adapter_id": "mikrotik", "captured_at": NOW,
                    "routes": [{
                        "target": "::/0", "gateway": "fe80::1",
                        "gateway_interface": "wan1", "routing_table": "main",
                    }],
                },
            },
            {
                "router_id": "mikrotik-b", "site_id": "home",
                "snapshot": {
                    "adapter_id": "mikrotik", "captured_at": NOW,
                    "routes": [{
                        "target": "::/0", "gateway": "fe80::1",
                        "gateway_interface": "wan2", "routing_table": "main",
                    }],
                },
            },
        ]})
        group = result["groups"][0]
        self.assertEqual(group["distinct_gateway_count"], 2)
        self.assertEqual(group["status"], "multiple_configured_paths_unverified")

    def test_reports_disabled_only_routes_and_routers_without_default_routes(self):
        result = run({"snapshots": [
            {
                "router_id": "mikrotik-disabled", "site_id": "home",
                "snapshot": {
                    "adapter_id": "mikrotik", "captured_at": NOW,
                    "routes": [{
                        "target": "0.0.0.0/0", "gateway": "192.0.2.1",
                        "routing_table": "main", "disabled": True,
                    }],
                },
            },
            {
                "router_id": "openwrt-isolated", "site_id": "home",
                "snapshot": {
                    "adapter_id": "openwrt", "captured_at": NOW,
                    "routes": [{"target": "10.0.0.0/8", "gateway": None, "device": "lan", "metric": 0}],
                },
            },
        ]})
        self.assertEqual(result["summary"]["router_without_default_route_count"], 1)
        self.assertEqual(result["groups"][0]["status"], "no_forwarding_candidates")
        self.assertIn("gateway.no_eligible_default", [item["code"] for item in result["findings"]])
        self.assertEqual(result["sites"][0]["router_without_default_route_count"], 1)

    def test_marks_gateway_unknown_when_multiple_routers_have_no_next_hop_address(self):
        result = run({"snapshots": [
            {
                "router_id": "openwrt-a", "site_id": "home",
                "snapshot": {
                    "adapter_id": "openwrt", "captured_at": NOW,
                    "routes": [{"target": "0.0.0.0/0", "device": "wan"}],
                },
            },
            {
                "router_id": "mikrotik-b", "site_id": "home",
                "snapshot": {
                    "adapter_id": "mikrotik", "captured_at": NOW,
                    "routes": [{"target": "0.0.0.0/0", "routing_table": "main"}],
                },
            },
        ]})
        group = result["groups"][0]
        self.assertEqual(group["status"], "multiple_router_candidates_gateway_unknown")
        self.assertIn("gateway.next_hop_unknown", [item["code"] for item in group["findings"]])

    def test_rejects_unknown_adapters_duplicate_routers_and_invalid_gateways(self):
        with self.assertRaisesRegex(ValueError, "OpenWrt or MikroTik"):
            run({"snapshots": [{
                "router_id": "unifi-controller",
                "snapshot": {"adapter_id": "unifi", "captured_at": NOW},
            }]})
        snapshot = {"adapter_id": "openwrt", "captured_at": NOW}
        with self.assertRaisesRegex(ValueError, "unique"):
            run({"snapshots": [
                {"router_id": "same", "site_id": "home", "snapshot": snapshot},
                {"router_id": "same", "site_id": "home", "snapshot": snapshot},
            ]})
        with self.assertRaisesRegex(ValueError, "valid IP address"):
            run({"snapshots": [{
                "router_id": "openwrt-invalid",
                "snapshot": {
                    "adapter_id": "openwrt", "captured_at": NOW,
                    "routes": [{"target": "0.0.0.0/0", "gateway": "not-an-ip"}],
                },
            }]})

    def test_rejects_non_finite_and_oversized_inputs(self):
        with self.assertRaisesRegex(ValueError, "finite values"):
            run({"snapshots": [{
                "router_id": "mikrotik-nan",
                "snapshot": {
                    "adapter_id": "mikrotik", "captured_at": NOW,
                    "routes": [{"target": "0.0.0.0/0", "unknown": float("nan")}],
                },
            }]})
        with self.assertRaisesRegex(ValueError, "byte input limit"):
            run({"snapshots": [{
                "router_id": "openwrt-large",
                "snapshot": {
                    "adapter_id": "openwrt", "captured_at": NOW,
                    "raw": "x" * (2 * 1024 * 1024),
                },
            }]})

    def test_does_not_echo_secret_fields(self):
        result = run({"snapshots": [{
            "router_id": "mikrotik-secret",
            "snapshot": {
                "adapter_id": "mikrotik", "captured_at": NOW,
                "routes": [{
                    "target": "0.0.0.0/0", "gateway": "192.0.2.1",
                    "routing_table": "main", "password": "route-secret",
                    "private_key": "key-secret",
                }],
                "api_token": "token-secret",
            },
        }]})
        rendered = str(result)
        for secret in ("route-secret", "key-secret", "token-secret", "password", "private_key", "api_token"):
            self.assertNotIn(secret, rendered)


if __name__ == "__main__":
    unittest.main()
