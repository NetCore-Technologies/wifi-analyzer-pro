"""Regression tests for the offline MikroTik RouterOS export adapter."""
from __future__ import annotations

import unittest

from wifi_analyzer_backend.router_adapters.registry import list_manifests, negotiate
from wifi_analyzer_backend.router_adapters.mikrotik import normalize_snapshot


SAMPLE = {
    "captured_at": "2026-11-20T17:00:00+11:00",
    "router": {
        "board_name": "MikroTik hAP ax3",
        "model_name": "C53UiG+5HPaxD2HPaxD",
        "version": "7.17.2",
        "architecture_name": "arm64",
        "serial_number": "A1B2C3D4",
    },
    "resource": {
        "uptime": "2d03:12:00",
        "cpu_load": "12",
        "free_memory": "268435456",
        "total_memory": "536870912",
    },
    "interfaces": [
        {
            "name": "bridge",
            "type": "bridge",
            "mac_address": "00:11:22:33:44:55",
            "mtu": "1500",
            "actual_mtu": "1500",
            "running": True,
            "disabled": False,
        },
        {"name": "ether1", "type": "ether", "running": "yes", "disabled": "no"},
    ],
    "wireless": [
        {
            "name": "wifi1",
            "configuration": {"ssid": "Lab", "band": "5ghz-ax", "passphrase": "must-not-leak"},
            "channel": "36",
            "frequency": "5180",
            "channel_width": "80mhz",
            "tx_power": "20",
            "mac_address": "00:11:22:33:44:66",
            "running": True,
        },
        {
            "name": "wifi2",
            "ssid": "Legacy",
            "band": "2ghz-n",
            "channel": 6,
            "channel_width": "20/40mhz",
            "running": False,
        },
    ],
    "registrations": [
        {
            "mac_address": "aa:bb:cc:dd:ee:01",
            "interface": "wifi1",
            "signal_strength": "-61",
            "tx_rate": "1200Mbps-80MHz/2S",
            "rx_rate": "866Mbps-80MHz/2S",
            "uptime": "00:12:00",
            "private_key": "never-export-this",
        }
    ],
    "addresses": [
        {"address": "192.0.2.1/24", "interface": "bridge"},
        {"address": "2001:db8::1/64", "interface": "bridge"},
    ],
    "vlans": [
        {"name": "guest-vlan", "interface": "bridge", "vlan_id": "20", "running": True}
    ],
    "dhcp_leases": [
        {
            "address": "192.0.2.25",
            "mac_address": "aa:bb:cc:dd:ee:01",
            "host_name": "tablet",
            "status": "bound",
            "expires_after": "01:30:00",
            "radius_password": "must-never-leave",
        }
    ],
}


class MikroTikSnapshotTests(unittest.TestCase):
    def test_normalises_router_interfaces_radios_registrations_and_network_services(self):
        result = normalize_snapshot(SAMPLE)
        self.assertEqual(result["adapter_id"], "mikrotik")
        self.assertEqual(result["captured_at"], "2026-11-20T06:00:00+00:00")
        self.assertEqual(result["router"]["board_name"], "MikroTik hAP ax3")
        self.assertEqual(result["resource"]["cpu_load_pct"], 12)
        self.assertEqual(result["resource"]["free_memory_bytes"], 268435456)
        self.assertEqual(result["interfaces"][0]["state"], "up")
        self.assertEqual(result["interfaces"][1]["state"], "up")
        self.assertEqual(result["wireless_radios"][0]["band"], "5GHz")
        self.assertEqual(result["wireless_radios"][0]["channel_width_mhz"], 80)
        self.assertIsNone(result["wireless_radios"][1]["channel_width_mhz"])
        self.assertEqual(result["wireless_radios"][1]["channel_width_setting"], "20/40mhz")
        self.assertTrue(result["associations"][0]["interface_known"])
        self.assertEqual(result["associations"][0]["signal_dbm"], -61)
        self.assertEqual(result["addresses"][0]["network"], "192.0.2.0/24")
        self.assertEqual(result["addresses"][1]["version"], 6)
        self.assertEqual(result["vlans"][0]["vlan_id"], 20)
        self.assertEqual(result["dhcp_leases"][0]["status"], "bound")
        self.assertEqual(result["summary"]["interface_count"], 2)
        self.assertEqual(result["summary"]["wireless_radio_count"], 2)
        self.assertEqual(result["summary"]["association_count"], 1)
        self.assertEqual(result["summary"]["dhcp_lease_count"], 1)
        self.assertEqual(result["summary"]["route_count"], 0)
        self.assertEqual(result["routes"], [])


    def test_normalises_routeros_routes_and_gateway_interfaces(self):
        result = normalize_snapshot({
            "captured_at": "2026-11-20T10:00:00Z",
            "routes": [
                {
                    "dst-address": "0.0.0.0/0",
                    "gateway": "192.0.2.1%ether1",
                    "routing-table": "main",
                    "distance": "1",
                    "active": "yes",
                    "disabled": "no",
                },
                {
                    "dst_address": "::/0",
                    "gateway": "fe80::1",
                    "table": "backup",
                    "distance": 2,
                    "active": False,
                    "blackhole": False,
                },
            ],
        })
        self.assertEqual(result["summary"]["route_count"], 2)
        self.assertEqual(result["summary"]["active_route_count"], 1)
        self.assertEqual(result["summary"]["default_route_count"], 2)
        self.assertEqual(result["routes"][0]["target"], "0.0.0.0/0")
        self.assertEqual(result["routes"][0]["gateway"], "192.0.2.1")
        self.assertEqual(result["routes"][0]["gateway_interface"], "ether1")
        self.assertEqual(result["routes"][0]["routing_table"], "main")
        self.assertTrue(result["routes"][0]["active"])
        self.assertFalse(result["routes"][0]["disabled"])
        self.assertEqual(result["routes"][1]["target"], "::/0")
        self.assertEqual(result["routes"][1]["routing_table"], "backup")
        self.assertFalse(result["routes"][1]["active"])

    def test_rejects_invalid_routeros_route_target_distance_and_flags(self):
        base = {"captured_at": "2026-11-20T10:00:00Z"}
        for route, message in (
            ({"dst-address": "192.0.2.1/99"}, "valid IP network"),
            ({"dst-address": "0.0.0.0/0", "distance": 0}, "distance"),
            ({"dst-address": "0.0.0.0/0", "active": "maybe"}, "active must be a boolean"),
            ({"dst-address": "0.0.0.0/0", "gateway": "192.0.2.1%"}, "required"),
        ):
            with self.subTest(route=route), self.assertRaisesRegex(ValueError, message):
                normalize_snapshot({**base, "routes": [route]})

    def test_unknown_and_credential_like_fields_never_leave_import_boundary(self):
        payload = {
            **SAMPLE,
            "router": {**SAMPLE["router"], "api_token": "controller-secret", "password": "router-secret"},
            "resource": {**SAMPLE["resource"], "secret": "resource-secret"},
            "wireless": [{
                **SAMPLE["wireless"][0],
                "psk": "wifi-passphrase",
                "private_key": "private-key-secret",
            }],
            "registrations": [{
                **SAMPLE["registrations"][0],
                "radius_password": "radius-secret",
            }],
            "dhcp_leases": [{
                **SAMPLE["dhcp_leases"][0],
                "comment": "contains private metadata",
            }],
        }
        rendered = str(normalize_snapshot(payload))
        for secret in (
            "controller-secret", "router-secret", "resource-secret", "wifi-passphrase",
            "private-key-secret", "radius-secret", "contains private metadata",
            "must-not-leak", "must-never-leave",
        ):
            self.assertNotIn(secret, rendered)
        for field in ("api_token", "password", "psk", "private_key", "radius_password"):
            self.assertNotIn(field, rendered)

    def test_accepts_routeros_field_aliases_and_string_booleans(self):
        payload = {
            "captured_at": "2026-11-20T06:00:00Z",
            "router": {"model": "RouterOS sample", "routeros_version": "7.16.1"},
            "resource": {"cpu-load": "1", "free-memory": "100", "total-memory": "200"},
            "interfaces": [{
                "name": "ether1",
                "mac-address": "00-11-22-33-44-55",
                "actual-mtu": "1500",
                "running": "yes",
                "disabled": "no",
            }],
            "wireless": [{"name": "wlan1", "band": "2.4GHz", "channel": "11", "running": "false"}],
            "registration_table": [],
        }
        result = normalize_snapshot(payload)
        self.assertEqual(result["router"]["version"], "7.16.1")
        self.assertEqual(result["resource"]["cpu_load_pct"], 1)
        self.assertEqual(result["interfaces"][0]["mac_address"], "00:11:22:33:44:55")
        self.assertEqual(result["wireless_radios"][0]["band"], "2.4GHz")
        self.assertEqual(result["wireless_radios"][0]["state"], "down")

    def test_rejects_invalid_timestamps_mac_addresses_ip_prefixes_and_channels(self):
        with self.assertRaisesRegex(ValueError, "timezone offset"):
            normalize_snapshot({"captured_at": "2026-11-20T10:00:00"})
        with self.assertRaisesRegex(ValueError, "valid MAC"):
            normalize_snapshot({
                "captured_at": "2026-11-20T10:00:00Z",
                "interfaces": [{"name": "ether1", "mac-address": "not-a-mac"}],
            })
        with self.assertRaisesRegex(ValueError, "valid IP address and prefix"):
            normalize_snapshot({
                "captured_at": "2026-11-20T10:00:00Z",
                "addresses": [{"interface": "bridge", "address": "192.0.2.1/99"}],
            })
        with self.assertRaisesRegex(ValueError, "channel"):
            normalize_snapshot({
                "captured_at": "2026-11-20T10:00:00Z",
                "wireless": [{"name": "wifi1", "band": "5ghz-ax", "channel": "0"}],
            })
        with self.assertRaisesRegex(ValueError, "identify"):
            normalize_snapshot({
                "captured_at": "2026-11-20T10:00:00Z",
                "wireless": [{"name": "wifi1", "band": "unknown"}],
            })

    def test_supports_spaced_interface_names_and_enforces_band_channel_limits(self):
        result = normalize_snapshot({
            "captured_at": "2026-11-20T10:00:00Z",
            "interfaces": [{"name": "Office Bridge", "running": True}],
            "wireless": [
                {"name": "wifi24", "band": "2ghz-n", "channel": 14},
                {"name": "wifi5", "band": "5ghz-ax", "channel": 196},
                {"name": "wifi6", "band": "6ghz-ax", "channel": 233},
            ],
            "addresses": [{"interface": "Office Bridge", "address": "192.0.2.1/24"}],
        })
        self.assertEqual(result["interfaces"][0]["name"], "Office Bridge")
        self.assertTrue(result["addresses"][0]["interface_known"])
        self.assertEqual(
            [radio["channel"] for radio in result["wireless_radios"]],
            [14, 196, 233],
        )
        for band, channel in (("2ghz-n", 15), ("5ghz-ax", 197), ("6ghz-ax", 234)):
            with self.subTest(band=band, channel=channel), self.assertRaisesRegex(ValueError, "channel"):
                normalize_snapshot({
                    "captured_at": "2026-11-20T10:00:00Z",
                    "wireless": [{"name": "wifi1", "band": band, "channel": channel}],
                })

    def test_rejects_invalid_resource_vlan_mtu_and_registration_values(self):
        base = {"captured_at": "2026-11-20T10:00:00Z"}
        with self.assertRaisesRegex(ValueError, "cpu_load"):
            normalize_snapshot({**base, "resource": {"cpu_load": 101}})
        with self.assertRaisesRegex(ValueError, "free_memory cannot exceed"):
            normalize_snapshot({**base, "resource": {"free_memory": 101, "total_memory": 100}})
        with self.assertRaisesRegex(ValueError, "mtu"):
            normalize_snapshot({**base, "interfaces": [{"name": "ether1", "mtu": 100}]})
        with self.assertRaisesRegex(ValueError, "vlan_id"):
            normalize_snapshot({**base, "vlans": [{"name": "vlan4095", "interface": "bridge", "vlan_id": 4095}]})
        with self.assertRaisesRegex(ValueError, "signal_dbm"):
            normalize_snapshot({
                **base,
                "registrations": [{
                    "mac-address": "AA:BB:CC:DD:EE:FF",
                    "signal-strength": "-200",
                }],
            })

    def test_rejects_duplicate_identity_records_and_malformed_collections(self):
        base = {"captured_at": "2026-11-20T10:00:00Z"}
        interface = {"name": "ether1"}
        with self.assertRaisesRegex(ValueError, "interface names"):
            normalize_snapshot({**base, "interfaces": [interface, interface]})
        wireless = {"name": "wifi1"}
        with self.assertRaisesRegex(ValueError, "wireless interface names"):
            normalize_snapshot({**base, "wireless": [wireless, wireless]})
        registration = {"mac-address": "AA:BB:CC:DD:EE:FF", "interface": "wifi1"}
        with self.assertRaisesRegex(ValueError, "registration identities"):
            normalize_snapshot({**base, "registrations": [registration, registration]})
        address = {"interface": "bridge", "address": "192.0.2.1/24"}
        with self.assertRaisesRegex(ValueError, "address identities"):
            normalize_snapshot({**base, "addresses": [address, address]})
        with self.assertRaisesRegex(ValueError, "no more than"):
            normalize_snapshot({**base, "interfaces": [{"name": f"e{i}"} for i in range(513)]})

    def test_enforces_json_serialisation_and_total_payload_limits(self):
        with self.assertRaisesRegex(ValueError, "finite values"):
            normalize_snapshot({"captured_at": "2026-11-20T10:00:00Z", "resource": {"cpu_load": float("nan")}})
        with self.assertRaisesRegex(ValueError, "byte input limit"):
            normalize_snapshot({
                "captured_at": "2026-11-20T10:00:00Z",
                "router": {"model": "x" * (1024 * 1024)},
            })


class MikroTikAdapterManifestTests(unittest.TestCase):
    def test_mikrotik_manifest_is_read_only_export_only_and_scoped(self):
        manifests = {item["adapter_id"]: item for item in list_manifests()}
        self.assertIn("mikrotik", manifests)
        manifest = manifests["mikrotik"]
        self.assertTrue(manifest["read_only"])
        self.assertEqual(manifest["transport"], "controller_export")
        self.assertEqual(manifest["supported_permissions"], ["read"])
        result = negotiate({
            "adapter_id": "mikrotik",
            "agent_version": "1.0.0",
            "advertised_capabilities": [
                "system.board", "network.interfaces", "wireless.radios",
                "network.config.write",
            ],
            "requested_capabilities": [
                "system.board", "wireless.radios", "network.config.write",
            ],
            "requested_permissions": ["read"],
        })
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["negotiated_capabilities"], ["system.board", "wireless.radios"])
        self.assertEqual(result["rejected_capabilities"], [{
            "capability": "network.config.write",
            "reason": "not_supported_by_adapter",
        }])


if __name__ == "__main__":
    unittest.main()
