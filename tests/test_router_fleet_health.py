"""Tests for the multi-vendor router fleet health audit."""
from __future__ import annotations

import unittest

from wifi_analyzer_backend.feature_plugins.feature_175_router_fleet_health_audit import run


NOW = "2026-11-20T10:00:00Z"


class RouterFleetHealthAuditTests(unittest.TestCase):
    def test_audits_openwrt_unifi_and_mikrotik_with_per_router_evidence(self):
        result = run({
            "now": NOW,
            "max_age_seconds": 900,
            "snapshots": [
                {
                    "router_id": "openwrt-home",
                    "site_id": "home",
                    "snapshot": {
                        "adapter_id": "openwrt",
                        "captured_at": "2026-11-20T09:58:00Z",
                        "system_health": {
                            "uptime_seconds": 10000,
                            "load_average": {"1m": 0.2, "5m": 0.3, "15m": 0.4},
                            "memory_bytes": {"total": 1024, "free": 10, "available": 20},
                            "swap_bytes": {"total": 0, "free": 0},
                        },
                        "interfaces": [{"interface": "lan", "up": False}],
                        "wireless_radios": [{"interface": "phy0-ap0", "up": False}],
                        "associations": [{
                            "client_mac": "AA:BB:CC:DD:EE:01", "signal_dbm": -90,
                        }],
                    },
                },
                {
                    "router_id": "unifi-office",
                    "site_id": "office",
                    "snapshot": {
                        "adapter_id": "unifi",
                        "captured_at": "2026-11-20T09:59:00Z",
                        "controller": {"hostname": "unifi.local"},
                        "access_points": [{
                            "mac": "00:11:22:33:44:55", "status": "offline",
                        }],
                        "wireless_radios": [{
                            "ap_mac": "00:11:22:33:44:55", "radio": "na", "up": False,
                        }],
                        "associations": [{
                            "client_mac": "AA:BB:CC:DD:EE:02", "signal_dbm": -78,
                        }],
                    },
                },
                {
                    "router_id": "mikrotik-branch",
                    "site_id": "branch",
                    "snapshot": {
                        "adapter_id": "mikrotik",
                        "captured_at": "2026-11-20T09:59:30Z",
                        "resource": {
                            "cpu_load_pct": 90,
                            "free_memory_bytes": 50,
                            "total_memory_bytes": 1000,
                        },
                        "interfaces": [{"name": "ether1", "state": "down"}],
                        "wireless_radios": [{"interface": "wifi1", "state": "up"}],
                        "associations": [{
                            "client_mac": "AA:BB:CC:DD:EE:03", "signal_dbm": -80,
                        }],
                    },
                },
            ],
        })
        self.assertEqual(result["status"], "audited")
        self.assertEqual(result["summary"]["router_count"], 3)
        self.assertEqual(result["summary"]["site_count"], 3)
        self.assertEqual(result["summary"]["critical_count"], 3)
        self.assertEqual([item["router_id"] for item in result["routers"]],
                         ["mikrotik-branch", "openwrt-home", "unifi-office"])
        by_id = {item["router_id"]: item for item in result["routers"]}
        self.assertEqual(by_id["openwrt-home"]["resource_metrics"]["memory_used_pct"], 98.05)
        self.assertIn("interface.down", [item["code"] for item in by_id["openwrt-home"]["findings"]])
        self.assertIn("access_point.offline", [item["code"] for item in by_id["unifi-office"]["findings"]])
        self.assertIn("resource.cpu_high", [item["code"] for item in by_id["mikrotik-branch"]["findings"]])
        self.assertIn("resource.memory_critical", [item["code"] for item in by_id["mikrotik-branch"]["findings"]])

    def test_missing_telemetry_is_unknown_not_healthy(self):
        result = run({
            "now": NOW,
            "snapshots": [{
                "router_id": "unifi-empty",
                "snapshot": {
                    "adapter_id": "unifi",
                    "captured_at": NOW,
                    "controller": {"hostname": "unifi.local"},
                    "access_points": [{}],
                    "wireless_radios": [{}],
                    "associations": [],
                },
            }],
        })
        router = result["routers"][0]
        self.assertEqual(router["health_status"], "unknown")
        self.assertEqual(router["health_score"], 100)
        self.assertEqual(router["evidence"], [])
        self.assertEqual(result["summary"]["unknown_count"], 1)

    def test_stale_snapshots_are_degraded_and_future_snapshots_are_rejected(self):
        result = run({
            "now": NOW,
            "max_age_seconds": 600,
            "snapshots": [{
                "router_id": "old-router",
                "snapshot": {
                    "adapter_id": "mikrotik",
                    "captured_at": "2026-11-20T09:00:00Z",
                    "interfaces": [],
                    "wireless_radios": [],
                    "associations": [],
                },
            }],
        })
        self.assertEqual(result["routers"][0]["health_status"], "degraded")
        self.assertIn("snapshot.stale", [item["code"] for item in result["routers"][0]["findings"]])
        with self.assertRaisesRegex(ValueError, "five minutes in the future"):
            run({
                "now": NOW,
                "snapshots": [{
                    "router_id": "future-router",
                    "snapshot": {
                        "adapter_id": "mikrotik",
                        "captured_at": "2026-11-20T10:10:00Z",
                    },
                }],
            })

    def test_applies_configurable_signal_and_freshness_thresholds(self):
        base = {
            "now": NOW,
            "max_age_seconds": 60,
            "weak_signal_dbm": -70,
            "critical_signal_dbm": -82,
            "snapshots": [{
                "router_id": "openwrt-lab",
                "snapshot": {
                    "adapter_id": "openwrt",
                    "captured_at": "2026-11-20T09:59:30Z",
                    "interfaces": [{"interface": "lan", "up": True}],
                    "wireless_radios": [{"interface": "phy0-ap0", "up": True}],
                    "associations": [
                        {"client_mac": "AA:BB:CC:DD:EE:01", "signal_dbm": -75},
                        {"client_mac": "AA:BB:CC:DD:EE:02", "signal_dbm": -85},
                    ],
                },
            }],
        }
        result = run(base)
        codes = [item["code"] for item in result["routers"][0]["findings"]]
        self.assertIn("client.signal_weak", codes)
        self.assertIn("client.signal_critical", codes)
        self.assertEqual(result["routers"][0]["summary"]["critical_count"], 1)
        self.assertEqual(result["routers"][0]["summary"]["warning_count"], 1)

    def test_does_not_leak_credentials_unknown_fields_or_raw_snapshots(self):
        result = run({
            "now": NOW,
            "snapshots": [{
                "router_id": "mikrotik-secret-test",
                "site_id": "lab",
                "snapshot": {
                    "adapter_id": "mikrotik",
                    "captured_at": "2026-11-20T09:59:00Z",
                    "router": {"serial_number": "SERIAL-001"},
                    "resource": {
                        "cpu_load_pct": 99,
                        "free_memory_bytes": 5,
                        "total_memory_bytes": 100,
                        "password": "router-password",
                    },
                    "interfaces": [{"name": "ether1", "state": "down", "private_key": "key-secret"}],
                    "api_token": "token-secret",
                },
            }],
        })
        rendered = str(result)
        for secret in ("router-password", "key-secret", "token-secret", "api_token", "private_key"):
            self.assertNotIn(secret, rendered)
        self.assertEqual(result["routers"][0]["findings"][0]["resource_type"], "router")

    def test_rejects_duplicate_router_ids_unknown_adapters_and_invalid_thresholds(self):
        snapshot = {
            "adapter_id": "unifi",
            "captured_at": NOW,
            "controller": {"hostname": "unifi.local"},
        }
        with self.assertRaisesRegex(ValueError, "unique"):
            run({"now": NOW, "snapshots": [
                {"router_id": "same", "snapshot": snapshot},
                {"router_id": "same", "snapshot": snapshot},
            ]})
        with self.assertRaisesRegex(ValueError, "normalised"):
            run({"now": NOW, "snapshots": [{
                "router_id": "unknown-router",
                "snapshot": {"adapter_id": "unknown", "captured_at": NOW},
            }]})
        with self.assertRaisesRegex(ValueError, "between 60 and 86400"):
            run({"now": NOW, "max_age_seconds": 30, "snapshots": [{
                "router_id": "r1", "snapshot": snapshot,
            }]})
        with self.assertRaisesRegex(ValueError, "lower than weak_signal_dbm"):
            run({"now": NOW, "weak_signal_dbm": -70, "critical_signal_dbm": -65,
                 "snapshots": [{"router_id": "r1", "snapshot": snapshot}]})

    def test_rejects_invalid_memory_values_and_bounded_collections(self):
        with self.assertRaisesRegex(ValueError, "cannot exceed total"):
            run({"now": NOW, "snapshots": [{
                "router_id": "openwrt-bad-memory",
                "snapshot": {
                    "adapter_id": "openwrt",
                    "captured_at": NOW,
                    "system_health": {
                        "memory_bytes": {"total": 100, "available": 200},
                    },
                },
            }]})
        with self.assertRaisesRegex(ValueError, "no more than"):
            run({"now": NOW, "snapshots": [{
                "router_id": "mikrotik-many",
                "snapshot": {
                    "adapter_id": "mikrotik",
                    "captured_at": NOW,
                    "interfaces": [{"name": f"e{i}"} for i in range(513)],
                },
            }]})

    def test_requires_timezone_aware_now_and_capture_times(self):
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            run({"now": "2026-11-20T10:00:00", "snapshots": [{
                "router_id": "r1",
                "snapshot": {"adapter_id": "unifi", "captured_at": NOW},
            }]})
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            run({"now": NOW, "snapshots": [{
                "router_id": "r1",
                "snapshot": {"adapter_id": "unifi", "captured_at": "2026-11-20T10:00:00"},
            }]})

    def test_rejects_non_finite_json_and_oversized_input(self):
        with self.assertRaisesRegex(ValueError, "finite values"):
            run({"now": NOW, "snapshots": [{
                "router_id": "mikrotik-nan",
                "snapshot": {
                    "adapter_id": "mikrotik", "captured_at": NOW,
                    "resource": {"cpu_load_pct": float("nan")},
                },
            }]})
        with self.assertRaisesRegex(ValueError, "byte input limit"):
            run({"now": NOW, "snapshots": [{
                "router_id": "unifi-large",
                "snapshot": {
                    "adapter_id": "unifi", "captured_at": NOW,
                    "controller": {"hostname": "u.local", "metadata": "x" * (4 * 1024 * 1024)},
                },
            }]})

    def test_fleet_summary_includes_sites_and_meaningful_status_counts(self):
        result = run({
            "now": NOW,
            "snapshots": [
                {
                    "router_id": "r-healthy",
                    "site_id": "home",
                    "snapshot": {
                        "adapter_id": "mikrotik", "captured_at": NOW,
                        "resource": {"cpu_load_pct": 20, "free_memory_bytes": 800, "total_memory_bytes": 1000},
                        "interfaces": [{"name": "bridge", "state": "up"}],
                        "wireless_radios": [{"interface": "wifi1", "state": "up"}],
                    },
                },
                {
                    "router_id": "r-unknown",
                    "site_id": "branch",
                    "snapshot": {
                        "adapter_id": "unifi", "captured_at": NOW,
                        "controller": {"hostname": "u-branch.local"},
                    },
                },
            ],
        })
        self.assertEqual(result["summary"]["healthy_count"], 1)
        self.assertEqual(result["summary"]["unknown_count"], 1)
        self.assertEqual(result["sites"][0]["site_id"], "branch")
        self.assertEqual(result["sites"][1]["average_health_score"], 100.0)


if __name__ == "__main__":
    unittest.main()
