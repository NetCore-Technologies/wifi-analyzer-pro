"""Contract tests for offline router/controller export adapters."""
from __future__ import annotations

import unittest

from wifi_analyzer_backend.router_adapters.registry import list_manifests, negotiate
from wifi_analyzer_backend.router_adapters.unifi import normalize_snapshot


SAMPLE = {
    "captured_at": "2026-11-20T10:00:00+11:00",
    "controller": {"model": "Cloud Gateway", "version": "9.0.1", "hostname": "unifi.local"},
    "devices": [{
        "_id": "ap-office",
        "mac": "00:11:22:33:44:55",
        "name": "Office AP",
        "model": "U7 Pro",
        "ip": "192.0.2.10",
        "state": 1,
        "adopted": True,
        "radio_table": [
            {"radio": "ng", "channel": 6, "ht": "HT20", "tx_power": 17},
            {"radio": "na", "channel": 36, "ht": "VHT80", "tx_power": 21},
            {"radio": "6e", "channel": 5, "ht": "HE160", "tx_power": 18},
        ],
    }],
    "clients": [
        {
            "mac": "aa:bb:cc:dd:ee:01",
            "ap_mac": "00:11:22:33:44:55",
            "hostname": "laptop",
            "ip": "192.0.2.25",
            "essid": "Office",
            "signal": -57,
            "channel": 36,
            "tx_bytes": 1000,
            "rx_bytes": 2000,
        },
        {"mac": "aa:bb:cc:dd:ee:02", "is_wired": True, "ip": "192.0.2.26"},
    ],
    "networks": [{
        "_id": "network-office",
        "name": "Office",
        "purpose": "corporate",
        "enabled": True,
        "vlan_enabled": True,
        "vlan": 20,
        "ip_subnet": "192.0.2.0/24",
    }],
}


class UniFiSnapshotTests(unittest.TestCase):
    def test_normalises_access_points_radios_clients_and_networks(self):
        result = normalize_snapshot(SAMPLE)
        self.assertEqual(result["captured_at"], "2026-11-19T23:00:00+00:00")
        self.assertEqual(result["adapter_id"], "unifi")
        self.assertEqual(result["access_points"][0]["status"], "online")
        self.assertEqual(result["access_points"][0]["associated_client_count"], 1)
        self.assertEqual(
            [radio["band"] for radio in result["wireless_radios"]],
            ["2.4GHz", "5GHz", "6GHz"],
        )
        self.assertEqual(
            [radio["channel_width_mhz"] for radio in result["wireless_radios"]],
            [20, 80, 160],
        )
        self.assertTrue(result["associations"][0]["ap_known"])
        self.assertEqual(result["networks"][0]["ip_subnet"], "192.0.2.0/24")
        self.assertEqual(result["networks"][0]["vlan_id"], 20)
        self.assertEqual(result["summary"]["wireless_client_count"], 1)
        self.assertEqual(result["summary"]["wired_client_count"], 1)

    def test_drops_passphrases_tokens_and_unrecognised_controller_fields(self):
        payload = {
            **SAMPLE,
            "controller": {
                **SAMPLE["controller"],
                "password": "controller-secret",
                "api_token": "never-export-this",
            },
            "devices": [{
                **SAMPLE["devices"][0],
                "x_passphrase": "wifi-secret",
                "radio_table": [{
                    **SAMPLE["devices"][0]["radio_table"][0],
                    "key": "wifi-secret",
                }],
            }],
            "networks": [{
                **SAMPLE["networks"][0],
                "x_passphrase": "network-secret",
                "radius_secret": "radius-secret",
            }],
        }
        rendered = str(normalize_snapshot(payload))
        for secret in (
            "controller-secret", "never-export-this", "wifi-secret",
            "network-secret", "radius-secret",
        ):
            self.assertNotIn(secret, rendered)
        self.assertNotIn("api_token", rendered)
        self.assertNotIn("password", rendered)

    def test_accepts_access_points_alias_and_unknown_radio_status(self):
        payload = {
            "captured_at": "2026-11-20T10:00:00Z",
            "access_points": [{
                "mac": "00-11-22-33-44-66",
                "status": "adopting",
                "radios": [{"band": "5GHz", "channel": 44, "channel_width": 80}],
            }],
        }
        result = normalize_snapshot(payload)
        self.assertEqual(result["access_points"][0]["mac"], "00:11:22:33:44:66")
        self.assertEqual(result["access_points"][0]["status"], "unknown")
        self.assertEqual(result["wireless_radios"][0]["band"], "5GHz")

    def test_rejects_naive_timestamps_invalid_macs_ips_and_subnets(self):
        with self.assertRaisesRegex(ValueError, "timezone offset"):
            normalize_snapshot({"captured_at": "2026-11-20T10:00:00"})
        with self.assertRaisesRegex(ValueError, "valid MAC"):
            normalize_snapshot({
                "captured_at": "2026-11-20T10:00:00Z",
                "devices": [{"mac": "not-a-mac"}],
            })
        with self.assertRaisesRegex(ValueError, "valid IP"):
            normalize_snapshot({
                "captured_at": "2026-11-20T10:00:00Z",
                "devices": [{"mac": "00:11:22:33:44:55", "ip": "999.1.1.1"}],
            })
        with self.assertRaisesRegex(ValueError, "valid CIDR"):
            normalize_snapshot({
                "captured_at": "2026-11-20T10:00:00Z",
                "networks": [{"ip_subnet": "192.0.2.1/99"}],
            })

    def test_rejects_invalid_band_channel_width_and_vlan(self):
        base = {"captured_at": "2026-11-20T10:00:00Z"}
        for radio, message in (
            ({"radio": "unknown", "channel": 36}, "supported band"),
            ({"radio": "na", "channel": 0}, "channel must be an integer"),
            ({"radio": "na", "channel": 36, "ht": "VHT999"}, "supported channel width"),
        ):
            with self.subTest(radio=radio), self.assertRaisesRegex(ValueError, message):
                normalize_snapshot({
                    **base,
                    "devices": [{"mac": "00:11:22:33:44:55", "radio_table": [radio]}],
                })
        with self.assertRaisesRegex(ValueError, "vlan"):
            normalize_snapshot({**base, "networks": [{"vlan": 4095}]})

    def test_untagged_networks_allow_vlan_zero_without_inventing_a_vlan_id(self):
        result = normalize_snapshot({
            "captured_at": "2026-11-20T10:00:00Z",
            "networks": [{"name": "Default", "vlan_enabled": False, "vlan": 0}],
        })
        self.assertFalse(result["networks"][0]["vlan_enabled"])
        self.assertIsNone(result["networks"][0]["vlan_id"])
        with self.assertRaisesRegex(ValueError, "vlan"):
            normalize_snapshot({
                "captured_at": "2026-11-20T10:00:00Z",
                "networks": [{"vlan_enabled": True, "vlan": 0}],
            })

    def test_rejects_duplicate_ap_client_and_network_identities(self):
        base = {"captured_at": "2026-11-20T10:00:00Z"}
        ap = {"mac": "00:11:22:33:44:55"}
        with self.assertRaisesRegex(ValueError, "access-point MAC"):
            normalize_snapshot({**base, "devices": [ap, ap]})
        with self.assertRaisesRegex(ValueError, "client MAC"):
            normalize_snapshot({
                **base,
                "clients": [
                    {"mac": "AA:BB:CC:DD:EE:FF"},
                    {"mac": "AA:BB:CC:DD:EE:FF"},
                ],
            })
        network = {"_id": "same", "name": "Network"}
        with self.assertRaisesRegex(ValueError, "network identifiers"):
            normalize_snapshot({**base, "networks": [network, network]})

    def test_enforces_collection_and_payload_size_limits(self):
        with self.assertRaisesRegex(ValueError, "no more than"):
            normalize_snapshot({
                "captured_at": "2026-11-20T10:00:00Z",
                "devices": [{}] * 1025,
            })
        with self.assertRaisesRegex(ValueError, "byte input limit"):
            normalize_snapshot({
                "captured_at": "2026-11-20T10:00:00Z",
                "controller": {"model": "x" * (1024 * 1024)},
            })


class UniFiAdapterManifestTests(unittest.TestCase):
    def test_unifi_manifest_is_read_only_and_negotiates_only_intersecting_scopes(self):
        manifests = {item["adapter_id"]: item for item in list_manifests()}
        self.assertIn("unifi", manifests)
        self.assertTrue(manifests["unifi"]["read_only"])
        self.assertEqual(manifests["unifi"]["transport"], "controller_export")
        result = negotiate({
            "adapter_id": "unifi",
            "agent_version": "1.0.0",
            "advertised_capabilities": [
                "controller.devices",
                "controller.networks",
                "wireless.radios",
                "wireless.config.write",
            ],
            "requested_capabilities": [
                "controller.devices",
                "controller.networks",
                "wireless.config.write",
            ],
            "requested_permissions": ["read"],
        })
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["negotiated_permissions"], ["read"])
        self.assertEqual(
            result["negotiated_capabilities"],
            ["controller.devices", "controller.networks"],
        )
        self.assertEqual(result["rejected_capabilities"], [{
            "capability": "wireless.config.write",
            "reason": "not_supported_by_adapter",
        }])


if __name__ == "__main__":
    unittest.main()
