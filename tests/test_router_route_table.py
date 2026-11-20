"""Tests for the OpenWrt and MikroTik route-table audit."""
from __future__ import annotations

import unittest

from wifi_analyzer_backend.feature_plugins.feature_178_router_route_table_audit import run


NOW = "2026-11-20T10:00:00Z"


class RouterRouteTableAuditTests(unittest.TestCase):
    def test_audits_openwrt_default_routes_duplicates_and_connected_gateway_evidence(self):
        result = run({"snapshots": [{
            "router_id": "openwrt-home",
            "site_id": "home",
            "snapshot": {
                "adapter_id": "openwrt",
                "captured_at": NOW,
                "interfaces": [{
                    "interface": "lan",
                    "ipv4_addresses": ["192.0.2.2/24"],
                    "ipv6_addresses": ["2001:db8:1::2/64"],
                }],
                "routes": [
                    {"target": "0.0.0.0/0", "gateway": "192.0.2.1", "device": "wan", "metric": 10},
                    {"target": "0.0.0.0/0", "gateway": "192.0.2.1", "device": "wan", "metric": 10},
                    {"target": "10.0.0.0/8", "gateway": "198.51.100.1", "device": "tun0", "metric": 20},
                    {"target": "::/0", "gateway": "2001:db8:1::1", "device": "wan6", "metric": 5},
                ],
            },
        }]})
        self.assertEqual(result["status"], "audited")
        self.assertEqual(result["summary"]["router_count"], 1)
        self.assertEqual(result["summary"]["route_count"], 4)
        self.assertEqual(result["summary"]["default_route_count"], 2)
        router = result["routers"][0]
        codes = [finding["code"] for finding in router["findings"]]
        self.assertIn("route.duplicate", codes)
        self.assertIn("route.gateway_not_directly_connected", codes)
        self.assertEqual(router["connected_network_count"], 2)
        self.assertEqual(router["active_default_route_count"], 0)

    def test_audits_mikrotik_default_routes_failover_tables_and_gateway_flags(self):
        result = run({"snapshots": [{
            "router_id": "mikrotik-branch",
            "site_id": "branch",
            "snapshot": {
                "adapter_id": "mikrotik",
                "captured_at": NOW,
                "addresses": [
                    {"interface": "wan1", "network": "192.0.2.0/24"},
                    {"interface": "wan2", "address": "198.51.100.2", "prefix_length": 24},
                ],
                "routes": [
                    {
                        "target": "0.0.0.0/0", "gateway": "192.0.2.1",
                        "routing_table": "main", "distance": 1, "active": True,
                    },
                    {
                        "target": "0.0.0.0/0", "gateway": "198.51.100.1",
                        "routing_table": "main", "distance": 2, "active": False,
                    },
                    {
                        "target": "0.0.0.0/0", "gateway": "203.0.113.1",
                        "routing_table": "vpn", "distance": 1, "disabled": True,
                    },
                    {
                        "target": "::/0", "gateway": None,
                        "routing_table": "blackhole", "distance": 1,
                        "active": True, "blackhole": True,
                    },
                ],
            },
        }]})
        router = result["routers"][0]
        self.assertEqual(router["default_route_count"], 4)
        self.assertEqual(router["active_default_route_count"], 1)
        codes = [finding["code"] for finding in router["findings"]]
        self.assertIn("route.multiple_default_candidates", codes)
        self.assertIn("route.default_inactive", codes)
        self.assertIn("route.default_disabled", codes)
        self.assertIn("route.default_blackhole", codes)
        self.assertIn("route.gateway_not_directly_connected", codes)

    def test_does_not_mark_recursive_gateway_as_unreachable(self):
        result = run({"snapshots": [{
            "router_id": "openwrt-vpn",
            "site_id": "home",
            "snapshot": {
                "adapter_id": "openwrt",
                "captured_at": NOW,
                "interfaces": [{"interface": "lan", "ipv4_addresses": ["192.0.2.1/24"]}],
                "routes": [{
                    "target": "10.0.0.0/8",
                    "gateway": "198.51.100.254",
                    "device": "wg0",
                    "metric": 5,
                }],
            },
        }]})
        finding = result["routers"][0]["findings"][0]
        self.assertEqual(finding["code"], "route.gateway_not_directly_connected")
        self.assertEqual(finding["severity"], "info")
        self.assertIn("Recursive, point-to-point and tunnel routes", finding["message"])
        self.assertNotIn("unreachable", finding["message"].lower())

    def test_route_tables_are_kept_separate_and_multiple_defaults_are_review_only(self):
        result = run({"snapshots": [{
            "router_id": "mikrotik-dual-table",
            "snapshot": {
                "adapter_id": "mikrotik",
                "captured_at": NOW,
                "routes": [
                    {"target": "0.0.0.0/0", "gateway": "192.0.2.1", "table": "main", "distance": 1},
                    {"target": "0.0.0.0/0", "gateway": "192.0.2.2", "table": "main", "distance": 1},
                    {"target": "0.0.0.0/0", "gateway": "198.51.100.1", "table": "backup", "distance": 1},
                ],
            },
        }]})
        router = result["routers"][0]
        self.assertEqual(router["routing_tables"], ["backup", "main"])
        multiple = [item for item in router["findings"] if item["code"] == "route.multiple_default_candidates"]
        self.assertEqual(len(multiple), 1)
        self.assertEqual(multiple[0]["routing_table"], "main")
        self.assertEqual(multiple[0]["candidate_count"], 2)
        self.assertEqual(multiple[0]["severity"], "info")

    def test_reports_no_forwarding_default_when_only_disabled_default_exists(self):
        result = run({"snapshots": [{
            "router_id": "mikrotik-disabled-default",
            "snapshot": {
                "adapter_id": "mikrotik",
                "captured_at": NOW,
                "routes": [{
                    "target": "0.0.0.0/0", "gateway": "192.0.2.1",
                    "table": "main", "disabled": True,
                }],
            },
        }]})
        self.assertIn("route.no_forwarding_default", [
            item["code"] for item in result["routers"][0]["findings"]
        ])

    def test_rejects_mixed_invalid_adapter_and_duplicate_router_identity(self):
        with self.assertRaisesRegex(ValueError, "OpenWrt or MikroTik"):
            run({"snapshots": [{
                "router_id": "unifi-controller",
                "snapshot": {"adapter_id": "unifi", "captured_at": NOW},
            }]})
        with self.assertRaisesRegex(ValueError, "unique"):
            run({"snapshots": [
                {"router_id": "same", "snapshot": {"adapter_id": "openwrt", "captured_at": NOW}},
                {"router_id": "same", "snapshot": {"adapter_id": "mikrotik", "captured_at": NOW}},
            ]})

    def test_rejects_malformed_route_targets_gateways_metrics_and_flags(self):
        base = {
            "router_id": "mikrotik-invalid",
            "snapshot": {"adapter_id": "mikrotik", "captured_at": NOW},
        }
        for route, message in (
            ({"target": "192.0.2.1/99"}, "valid IP network"),
            ({"target": "0.0.0.0/0", "gateway": "not-an-ip"}, "valid IP address"),
            ({"target": "0.0.0.0/0", "gateway": "::1"}, "IP version"),
            ({"target": "0.0.0.0/0", "distance": 0}, "distance"),
            ({"target": "0.0.0.0/0", "active": "yes"}, "active must be a boolean"),
        ):
            with self.subTest(route=route), self.assertRaisesRegex(ValueError, message):
                run({ "snapshots": [{
                    **base,
                    "snapshot": {**base["snapshot"], "routes": [route]},
                }]})

    def test_rejects_bad_connected_network_and_route_collection_bounds(self):
        with self.assertRaisesRegex(ValueError, "valid IP interface address"):
            run({"snapshots": [{
                "router_id": "openwrt-bad-address",
                "snapshot": {
                    "adapter_id": "openwrt",
                    "captured_at": NOW,
                    "interfaces": [{"interface": "lan", "ipv4_addresses": ["192.0.2.1/99"]}],
                },
            }]})
        with self.assertRaisesRegex(ValueError, "no more than 2048"):
            run({"snapshots": [{
                "router_id": "mikrotik-many-routes",
                "snapshot": {
                    "adapter_id": "mikrotik",
                    "captured_at": NOW,
                    "routes": [{"target": "0.0.0.0/0", "table": f"table-{i}"} for i in range(2049)],
                },
            }]})

    def test_rejects_naive_timestamps_and_non_finite_or_oversized_inputs(self):
        with self.assertRaisesRegex(ValueError, "timezone offset"):
            run({"snapshots": [{
                "router_id": "router-naive",
                "snapshot": {"adapter_id": "openwrt", "captured_at": "2026-11-20T10:00:00"},
            }]})
        with self.assertRaisesRegex(ValueError, "finite values"):
            run({"snapshots": [{
                "router_id": "router-nan",
                "snapshot": {
                    "adapter_id": "mikrotik", "captured_at": NOW,
                    "routes": [{"target": "0.0.0.0/0", "unknown": float("nan")}],
                },
            }]})
        with self.assertRaisesRegex(ValueError, "byte input limit"):
            run({"snapshots": [{
                "router_id": "router-large",
                "snapshot": {
                    "adapter_id": "mikrotik", "captured_at": NOW,
                    "raw": "x" * (2 * 1024 * 1024),
                },
            }]})

    def test_omits_unknown_configuration_and_credential_fields(self):
        result = run({"snapshots": [{
            "router_id": "mikrotik-secrets",
            "snapshot": {
                "adapter_id": "mikrotik",
                "captured_at": NOW,
                "routes": [{
                    "target": "0.0.0.0/0",
                    "gateway": "203.0.113.1",
                    "routing_table": "main",
                    "password": "route-secret",
                    "private_key": "private-secret",
                }],
                "api_token": "token-secret",
            },
        }]})
        rendered = str(result)
        for secret in ("route-secret", "private-secret", "token-secret", "password", "private_key", "api_token"):
            self.assertNotIn(secret, rendered)


if __name__ == "__main__":
    unittest.main()
