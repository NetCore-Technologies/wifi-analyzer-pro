"""Tests for the schema-aware multi-vendor router snapshot drift report."""
from __future__ import annotations

import unittest

from wifi_analyzer_backend.feature_plugins.feature_174_router_snapshot_drift_report import run


UNIFI_PREVIOUS = {
    "adapter_id": "unifi",
    "captured_at": "2026-11-20T09:00:00Z",
    "controller": {"model": "Cloud Gateway", "version": "9.0.1", "api_token": "controller-secret"},
    "access_points": [{
        "id": "ap-1",
        "mac": "00:11:22:33:44:55",
        "name": "Lobby AP",
        "model": "U7 Pro",
        "ip_address": "192.0.2.10",
        "status": "online",
        "adopted": True,
        "radio_count": 1,
        "associated_client_count": 1,
        "password": "never-copy-this",
    }],
    "wireless_radios": [{
        "ap_mac": "00:11:22:33:44:55",
        "radio": "ng",
        "band": "2.4GHz",
        "channel": 1,
        "channel_width_mhz": 20,
        "frequency_mhz": 2412,
    }],
    "associations": [{
        "client_mac": "AA:BB:CC:DD:EE:01",
        "ap_mac": "00:11:22:33:44:55",
        "ap_known": True,
        "ssid": "Office",
        "signal_dbm": -72,
        "is_wired": False,
    }],
    "networks": [{
        "id": "office",
        "name": "Office",
        "vlan_id": 10,
        "vlan_enabled": True,
        "ip_subnet": "192.0.2.0/24",
    }],
}

UNIFI_CURRENT = {
    "adapter_id": "unifi",
    "captured_at": "2026-11-20T10:00:00Z",
    "controller": {"model": "Cloud Gateway", "version": "9.0.2", "password": "second-secret"},
    "access_points": [{
        "id": "ap-1",
        "mac": "00:11:22:33:44:55",
        "name": "Lobby AP",
        "model": "U7 Pro",
        "ip_address": "192.0.2.11",
        "status": "online",
        "adopted": True,
        "radio_count": 1,
        "associated_client_count": 2,
        "secret": "third-secret",
    }],
    "wireless_radios": [{
        "ap_mac": "00:11:22:33:44:55",
        "radio": "ng",
        "band": "2.4GHz",
        "channel": 6,
        "channel_width_mhz": 20,
        "frequency_mhz": 2437,
    }],
    "associations": [
        {
            "client_mac": "AA:BB:CC:DD:EE:01",
            "ap_mac": "00:11:22:33:44:55",
            "ap_known": True,
            "ssid": "Office",
            "signal_dbm": -60,
            "is_wired": False,
        },
        {
            "client_mac": "AA:BB:CC:DD:EE:02",
            "ap_mac": "00:11:22:33:44:55",
            "ap_known": True,
            "ssid": "Office",
            "signal_dbm": -55,
            "is_wired": False,
        },
    ],
    "networks": [{
        "id": "office",
        "name": "Office",
        "vlan_id": 20,
        "vlan_enabled": True,
        "ip_subnet": "192.0.2.0/24",
    }],
}


class RouterSnapshotDriftTests(unittest.TestCase):
    def test_unifi_drift_reports_ap_radio_client_and_vlan_changes(self):
        result = run({"previous": {"id": 10, "snapshot": UNIFI_PREVIOUS},
                      "current": {"id": 11, "snapshot": UNIFI_CURRENT}})
        self.assertEqual(result["status"], "compared")
        self.assertEqual(result["adapter_id"], "unifi")
        self.assertEqual(result["previous_snapshot_id"], 10)
        self.assertEqual(result["current_snapshot_id"], 11)
        self.assertEqual(result["summary"]["access_points_changed"], 1)
        self.assertEqual(result["summary"]["wireless_radios_changed"], 1)
        self.assertEqual(result["summary"]["associations_added"], 1)
        self.assertEqual(result["summary"]["associations_changed"], 1)
        self.assertEqual(result["summary"]["networks_changed"], 1)
        self.assertEqual(result["changes"]["wireless_radios"]["changed"][0]["identity"], {
            "ap_mac": "00:11:22:33:44:55",
            "radio": "ng",
        })
        self.assertTrue(any(item["field"] == "version" for item in result["metadata_changes"]["controller"]))
        rendered = str(result)
        for secret in ("controller-secret", "never-copy-this", "second-secret", "third-secret"):
            self.assertNotIn(secret, rendered)
        for field in ("api_token", "password", "secret"):
            self.assertNotIn(field, rendered)

    def test_mikrotik_drift_reports_interface_vlan_address_and_lease_changes(self):
        previous = {
            "adapter_id": "mikrotik",
            "captured_at": "2026-11-20T09:00:00Z",
            "router": {"board_name": "hAP ax3", "version": "7.17.2"},
            "resource": {"cpu_load_pct": 10, "free_memory_bytes": 1000},
            "interfaces": [{"name": "bridge", "state": "up", "mtu": 1500}],
            "wireless_radios": [{"interface": "wifi1", "band": "5GHz", "channel": 36, "ssid": "Office"}],
            "associations": [{"client_mac": "AA:BB:CC:DD:EE:01", "interface": "wifi1", "signal_dbm": -70}],
            "addresses": [{"interface": "bridge", "address": "192.0.2.1", "prefix_length": 24}],
            "vlans": [{"name": "vlan10", "interface": "bridge", "vlan_id": 10}],
            "dhcp_leases": [{
                "mac_address": "AA:BB:CC:DD:EE:01",
                "address": "192.0.2.25",
                "host_name": "tablet",
                "status": "bound",
            }],
        }
        current = {
            **previous,
            "captured_at": "2026-11-20T10:00:00Z",
            "resource": {"cpu_load_pct": 35, "free_memory_bytes": 700},
            "interfaces": [{"name": "bridge", "state": "down", "mtu": 1500}],
            "wireless_radios": [{"interface": "wifi1", "band": "5GHz", "channel": 40, "ssid": "Office"}],
            "addresses": [{"interface": "bridge", "address": "192.0.2.1", "prefix_length": 24},
                          {"interface": "bridge", "address": "2001:db8::1", "prefix_length": 64}],
            "vlans": [{"name": "vlan10", "interface": "bridge", "vlan_id": 10},
                      {"name": "vlan20", "interface": "bridge", "vlan_id": 20}],
            "dhcp_leases": [],
        }
        result = run({"previous": previous, "current": current})
        self.assertEqual(result["summary"]["interfaces_changed"], 1)
        self.assertEqual(result["summary"]["wireless_radios_changed"], 1)
        self.assertEqual(result["summary"]["addresses_added"], 1)
        self.assertEqual(result["summary"]["vlans_added"], 1)
        self.assertEqual(result["summary"]["dhcp_leases_removed"], 1)
        self.assertEqual(result["metadata_changes"]["resource"][0]["field"], "cpu_load_pct")

    def test_openwrt_health_metadata_is_flattened_and_compared(self):
        previous = {
            "adapter_id": "openwrt",
            "captured_at": "2026-11-20T09:00:00Z",
            "board": {"distribution": "OpenWrt", "version": "24.10.0", "secret": "dont-show"},
            "system_health": {
                "uptime_seconds": 1000,
                "load_average": {"1m": 0.5, "5m": 0.4, "15m": 0.3},
                "memory_bytes": {"total": 1024, "free": 512, "available": 600},
                "swap_bytes": {"total": 0, "free": 0},
            },
            "interfaces": [{"interface": "lan", "up": True, "device": "br-lan"}],
            "wireless_radios": [{"interface": "phy0-ap0", "ssid": "Office", "channel": 36}],
            "associations": [{"interface": "phy0-ap0", "client_mac": "AA:BB:CC:DD:EE:01"}],
            "routes": [{"target": "0.0.0.0/0", "device": "eth0", "metric": 10, "gateway": "192.0.2.1"}],
        }
        current = {
            **previous,
            "captured_at": "2026-11-20T10:00:00Z",
            "system_health": {
                **previous["system_health"],
                "uptime_seconds": 4600,
                "load_average": {"1m": 1.2, "5m": 0.4, "15m": 0.3},
            },
            "interfaces": [{"interface": "lan", "up": False, "device": "br-lan"}],
            "wireless_radios": [{"interface": "phy0-ap0", "ssid": "Office", "channel": 40}],
            "associations": [],
            "routes": [{"target": "0.0.0.0/0", "device": "eth0", "metric": 10, "gateway": "192.0.2.254"}],
        }
        result = run({"previous": previous, "current": current})
        self.assertEqual(result["summary"]["interfaces_changed"], 1)
        self.assertEqual(result["summary"]["wireless_radios_changed"], 1)
        self.assertEqual(result["summary"]["associations_removed"], 1)
        self.assertEqual(result["summary"]["routes_changed"], 1)
        self.assertEqual(result["summary"]["metadata_changed_field_count"], 2)
        self.assertEqual(result["metadata_changes"]["system_health"][0]["field"], "load_average_1m")
        self.assertNotIn("dont-show", str(result))

    def test_initial_baseline_has_counts_but_no_claimed_changes(self):
        result = run({"current": UNIFI_CURRENT})
        self.assertEqual(result["status"], "initial_snapshot")
        self.assertEqual(result["summary"]["total_changes"], 0)
        self.assertEqual(result["changes"]["access_points"]["baseline_count"], 1)
        self.assertEqual(result["changes"]["associations"]["baseline_count"], 2)

    def test_network_identity_falls_back_to_name_when_export_has_no_id(self):
        previous = {
            "adapter_id": "unifi", "captured_at": "2026-11-20T09:00:00Z",
            "networks": [{"name": "Office", "vlan_id": 10}],
        }
        current = {
            "adapter_id": "unifi", "captured_at": "2026-11-20T10:00:00Z",
            "networks": [{"name": "Office", "vlan_id": 20}],
        }
        result = run({"previous": previous, "current": current})
        self.assertEqual(result["summary"]["networks_changed"], 1)
        self.assertEqual(result["changes"]["networks"]["changed"][0]["identity"], {"name": "Office"})

    def test_rejects_mixed_adapters_unsupported_adapters_and_non_increasing_times(self):
        with self.assertRaisesRegex(ValueError, "same adapter"):
            run({"previous": UNIFI_PREVIOUS, "current": {
                **UNIFI_CURRENT, "adapter_id": "mikrotik",
            }})
        with self.assertRaisesRegex(ValueError, "supported normalised adapter"):
            run({"current": {"adapter_id": "unknown", "captured_at": "2026-11-20T10:00:00Z"}})
        with self.assertRaisesRegex(ValueError, "strictly increasing"):
            run({"previous": UNIFI_PREVIOUS, "current": {
                **UNIFI_CURRENT, "captured_at": "2026-11-20T09:00:00Z",
            }})

    def test_rejects_naive_timestamps_duplicate_and_missing_identities(self):
        with self.assertRaisesRegex(ValueError, "timezone offset"):
            run({"current": {**UNIFI_CURRENT, "captured_at": "2026-11-20T10:00:00"}})
        with self.assertRaisesRegex(ValueError, "duplicate identities"):
            run({"current": {
                **UNIFI_CURRENT,
                "access_points": [UNIFI_CURRENT["access_points"][0]] * 2,
            }})
        with self.assertRaisesRegex(ValueError, "stable identity"):
            run({"current": {
                "adapter_id": "mikrotik",
                "captured_at": "2026-11-20T10:00:00Z",
                "interfaces": [{"type": "ether"}],
            }})

    def test_rejects_invalid_collection_types_and_oversized_records(self):
        with self.assertRaisesRegex(ValueError, "must be a list"):
            run({"current": {
                "adapter_id": "unifi",
                "captured_at": "2026-11-20T10:00:00Z",
                "access_points": {},
            }})
        with self.assertRaisesRegex(ValueError, "no more than 1024"):
            run({"current": {
                "adapter_id": "unifi",
                "captured_at": "2026-11-20T10:00:00Z",
                "access_points": [{"mac": f"00:11:22:33:{i // 256:02X}:{i % 256:02X}"} for i in range(1025)],
            }})

    def test_drops_unknown_fields_and_rejects_non_finite_json(self):
        payload = {
            "adapter_id": "unifi",
            "captured_at": "2026-11-20T10:00:00Z",
            "controller": {"model": "Cloud Gateway", "password": "hidden-secret"},
            "networks": [{"id": "office", "name": "Office", "wifi_password": "wifi-secret"}],
        }
        rendered = str(run({"current": payload}))
        self.assertNotIn("hidden-secret", rendered)
        self.assertNotIn("wifi-secret", rendered)
        self.assertNotIn("password", rendered)
        with self.assertRaisesRegex(ValueError, "finite values"):
            run({"current": {
                "adapter_id": "unifi",
                "captured_at": "2026-11-20T10:00:00Z",
                "controller": {"version": float("nan")},
            }})

    def test_truncates_detail_lists_without_losing_aggregate_counts(self):
        previous = {
            "adapter_id": "unifi",
            "captured_at": "2026-11-20T09:00:00Z",
            "access_points": [],
        }
        current = {
            "adapter_id": "unifi",
            "captured_at": "2026-11-20T10:00:00Z",
            "access_points": [{
                "mac": f"02:00:{(i >> 24) & 255:02X}:{(i >> 16) & 255:02X}:{(i >> 8) & 255:02X}:{i & 255:02X}",
                "name": f"AP-{i}",
            } for i in range(205)],
        }
        result = run({"previous": previous, "current": current})
        self.assertEqual(result["summary"]["access_points_added"], 205)
        self.assertEqual(len(result["changes"]["access_points"]["added"]), 200)
        self.assertTrue(result["changes"]["access_points"]["details_truncated"])


if __name__ == "__main__":
    unittest.main()
