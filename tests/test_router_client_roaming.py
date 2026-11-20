"""Tests for normalized cross-vendor client roaming and association timelines."""
from __future__ import annotations

import unittest

from wifi_analyzer_backend.feature_plugins.feature_177_router_client_roaming_audit import run


class RouterClientRoamingAuditTests(unittest.TestCase):
    def test_tracks_openwrt_to_mikrotik_handoff_and_unifi_multi_ap_window(self):
        client = "AA:BB:CC:DD:EE:01"
        snapshots = [
            {
                "router_id": "openwrt-ap1",
                "site_id": "home",
                "snapshot": {
                    "adapter_id": "openwrt",
                    "captured_at": "2026-11-20T09:00:00Z",
                    "wireless_radios": [{
                        "interface": "phy0-ap0", "bssid": "00:11:22:33:44:01",
                        "ssid": "Office", "channel": 36,
                    }],
                    "associations": [{
                        "interface": "phy0-ap0", "client_mac": client, "signal_dbm": -88,
                    }],
                },
            },
            {
                "router_id": "openwrt-ap1",
                "site_id": "home",
                "snapshot": {
                    "adapter_id": "openwrt",
                    "captured_at": "2026-11-20T09:00:45Z",
                    "wireless_radios": [{
                        "interface": "phy0-ap0", "bssid": "00:11:22:33:44:01",
                        "ssid": "Office", "channel": 36,
                    }],
                    "associations": [{
                        "interface": "phy0-ap0", "client_mac": client, "signal_dbm": -80,
                    }],
                },
            },
            {
                "router_id": "mikrotik-ap2",
                "site_id": "home",
                "snapshot": {
                    "adapter_id": "mikrotik",
                    "captured_at": "2026-11-20T09:05:00Z",
                    "wireless_radios": [{
                        "interface": "wifi1", "bssid": "00:11:22:33:44:02",
                        "ssid": "Office", "channel": 40,
                    }],
                    "associations": [{
                        "interface": "wifi1", "client_mac": client, "signal_dbm": -70,
                    }],
                },
            },
            {
                "router_id": "unifi-controller",
                "site_id": "home",
                "snapshot": {
                    "adapter_id": "unifi",
                    "captured_at": "2026-11-20T09:05:10Z",
                    "controller": {"hostname": "unifi.home.local"},
                    "associations": [{
                        "ap_mac": "00:11:22:33:44:03",
                        "client_mac": client,
                        "ssid": "Office",
                        "signal_dbm": -60,
                        "is_wired": False,
                    }],
                },
            },
        ]
        result = run({"snapshots": snapshots})
        self.assertEqual(result["status"], "audited")
        self.assertEqual(result["summary"]["snapshot_count"], 4)
        self.assertEqual(result["summary"]["client_count"], 1)
        self.assertEqual(result["summary"]["observation_count"], 4)
        self.assertEqual(result["summary"]["handoff_count"], 1)
        self.assertEqual(result["summary"]["multi_ap_window_count"], 1)
        self.assertEqual(result["summary"]["critical_signal_count"], 1)
        self.assertEqual(result["summary"]["warning_signal_count"], 1)
        handoff = result["handoffs"][0]
        self.assertEqual(handoff["from_ap_id"], "00:11:22:33:44:01")
        self.assertEqual(handoff["to_ap_id"], "00:11:22:33:44:02")
        self.assertEqual(handoff["elapsed_seconds"], 255)
        self.assertEqual(result["multi_ap_windows"][0]["ap_ids"],
                         ["00:11:22:33:44:02", "00:11:22:33:44:03"])

    def test_falls_back_to_router_interface_identity_when_bssid_is_missing(self):
        result = run({"snapshots": [{
            "router_id": "mikrotik-router",
            "site_id": "home",
            "snapshot": {
                "adapter_id": "mikrotik",
                "captured_at": "2026-11-20T10:00:00Z",
                "wireless_radios": [{"interface": "wifi1", "ssid": "Office"}],
                "associations": [{
                    "interface": "wifi1",
                    "client_mac": "AA:BB:CC:DD:EE:02",
                    "signal_dbm": -55,
                }],
            },
        }]})
        self.assertEqual(result["summary"]["observation_count"], 1)
        self.assertEqual(result["summary"]["handoff_count"], 0)
        self.assertEqual(result["weak_signal_observations"], [])
        # A stable router/interface identity is used instead of inventing a BSSID.
        self.assertEqual(result["sites"][0]["observation_count"], 1)

    def test_skips_wired_and_unmapped_client_rows_with_explicit_counts(self):
        result = run({"snapshots": [
            {
                "router_id": "unifi-controller",
                "site_id": "home",
                "snapshot": {
                    "adapter_id": "unifi",
                    "captured_at": "2026-11-20T10:00:00Z",
                    "associations": [
                        {"client_mac": "AA:BB:CC:DD:EE:03", "is_wired": True},
                        {"client_mac": "AA:BB:CC:DD:EE:04", "is_wired": False, "ap_mac": None},
                    ],
                },
            },
            {
                "router_id": "openwrt-router",
                "site_id": "home",
                "snapshot": {
                    "adapter_id": "openwrt",
                    "captured_at": "2026-11-20T10:00:00Z",
                    "associations": [{
                        "client_mac": "AA:BB:CC:DD:EE:05",
                        "interface": None,
                        "signal_dbm": -55,
                    }],
                },
            },
        ]})
        self.assertEqual(result["summary"]["observation_count"], 0)
        self.assertEqual(result["summary"]["wired_client_rows_skipped"], 1)
        self.assertEqual(result["summary"]["unmapped_client_rows_skipped"], 2)
        self.assertEqual(result["status"], "no_wireless_associations")

    def test_does_not_correlate_the_same_client_across_different_sites(self):
        client = "AA:BB:CC:DD:EE:06"
        result = run({"snapshots": [
            {
                "router_id": "ap-home", "site_id": "home",
                "snapshot": {
                    "adapter_id": "unifi", "captured_at": "2026-11-20T10:00:00Z",
                    "associations": [{
                        "client_mac": client, "ap_mac": "00:11:22:33:44:11", "signal_dbm": -60,
                    }],
                },
            },
            {
                "router_id": "ap-branch", "site_id": "branch",
                "snapshot": {
                    "adapter_id": "unifi", "captured_at": "2026-11-20T10:00:10Z",
                    "associations": [{
                        "client_mac": client, "ap_mac": "00:11:22:33:44:22", "signal_dbm": -60,
                    }],
                },
            },
        ]})
        self.assertEqual(result["summary"]["client_count"], 2)
        self.assertEqual(result["summary"]["handoff_count"], 0)
        self.assertEqual(result["summary"]["multi_ap_window_count"], 0)

    def test_rejects_invalid_snapshot_times_macs_and_duplicate_capture_identities(self):
        with self.assertRaisesRegex(ValueError, "timezone offset"):
            run({"snapshots": [{
                "router_id": "router-naive",
                "snapshot": {"adapter_id": "unifi", "captured_at": "2026-11-20T10:00:00"},
            }]})
        with self.assertRaisesRegex(ValueError, "valid client MAC"):
            run({"snapshots": [{
                "router_id": "router-bad-mac",
                "snapshot": {
                    "adapter_id": "unifi", "captured_at": "2026-11-20T10:00:00Z",
                    "associations": [{"client_mac": "invalid", "ap_mac": "00:11:22:33:44:55"}],
                },
            }]})
        snapshot = {
            "adapter_id": "unifi",
            "captured_at": "2026-11-20T10:00:00Z",
            "associations": [],
        }
        with self.assertRaisesRegex(ValueError, "snapshot identities"):
            run({"snapshots": [
                {"router_id": "same-router", "site_id": "home", "snapshot": snapshot},
                {"router_id": "same-router", "site_id": "home", "snapshot": snapshot},
            ]})

    def test_validates_timing_and_signal_thresholds(self):
        snapshot = {
            "adapter_id": "unifi", "captured_at": "2026-11-20T10:00:00Z",
            "associations": [],
        }
        with self.assertRaisesRegex(ValueError, "between 1 and 300"):
            run({"concurrent_window_seconds": 0, "snapshots": [{"router_id": "r1", "snapshot": snapshot}]})
        with self.assertRaisesRegex(ValueError, "exceed the concurrent window"):
            run({
                "concurrent_window_seconds": 60, "max_roam_interval_seconds": 60,
                "snapshots": [{"router_id": "r1", "snapshot": snapshot}],
            })
        with self.assertRaisesRegex(ValueError, "lower than weak_signal_dbm"):
            run({
                "weak_signal_dbm": -70, "critical_signal_dbm": -65,
                "snapshots": [{"router_id": "r1", "snapshot": snapshot}],
            })

    def test_rejects_invalid_collection_types_and_signal_ranges(self):
        with self.assertRaisesRegex(ValueError, "must be a list"):
            run({"snapshots": [{
                "router_id": "router-invalid",
                "snapshot": {
                    "adapter_id": "mikrotik",
                    "captured_at": "2026-11-20T10:00:00Z",
                    "associations": {},
                },
            }]})
        with self.assertRaisesRegex(ValueError, "RSSI range"):
            run({"snapshots": [{
                "router_id": "router-signal",
                "snapshot": {
                    "adapter_id": "unifi", "captured_at": "2026-11-20T10:00:00Z",
                    "associations": [{
                        "client_mac": "AA:BB:CC:DD:EE:07",
                        "ap_mac": "00:11:22:33:44:55",
                        "signal_dbm": -200,
                    }],
                },
            }]})

    def test_omits_unknown_fields_and_credential_like_data(self):
        client = "AA:BB:CC:DD:EE:08"
        result = run({"snapshots": [
            {
                "router_id": "ap-a", "site_id": "home",
                "snapshot": {
                    "adapter_id": "unifi", "captured_at": "2026-11-20T09:00:00Z",
                    "controller": {"hostname": "unifi.local", "password": "controller-secret"},
                    "associations": [{
                        "client_mac": client, "ap_mac": "00:11:22:33:44:55",
                        "signal_dbm": -88, "wifi_password": "wifi-secret",
                    }],
                    "api_token": "token-secret",
                },
            },
            {
                "router_id": "ap-b", "site_id": "home",
                "snapshot": {
                    "adapter_id": "unifi", "captured_at": "2026-11-20T09:05:00Z",
                    "associations": [{
                        "client_mac": client, "ap_mac": "00:11:22:33:44:66",
                        "signal_dbm": -60,
                    }],
                },
            },
        ]})
        rendered = str(result)
        for secret in ("controller-secret", "wifi-secret", "token-secret", "api_token", "wifi_password"):
            self.assertNotIn(secret, rendered)

    def test_rejects_non_finite_and_oversized_inputs(self):
        with self.assertRaisesRegex(ValueError, "finite values"):
            run({"snapshots": [{
                "router_id": "router-nan",
                "snapshot": {
                    "adapter_id": "unifi",
                    "captured_at": "2026-11-20T10:00:00Z",
                    "metadata": {"value": float("nan")},
                },
            }]})
        with self.assertRaisesRegex(ValueError, "byte input limit"):
            run({"snapshots": [{
                "router_id": "router-large",
                "snapshot": {
                    "adapter_id": "unifi",
                    "captured_at": "2026-11-20T10:00:00Z",
                    "controller": {"hostname": "unifi.local", "metadata": "x" * (4 * 1024 * 1024)},
                },
            }]})

    def test_caps_snapshot_count(self):
        with self.assertRaisesRegex(ValueError, "from 1 to 64"):
            run({"snapshots": [
                {"router_id": f"router-{index}",
                 "snapshot": {"adapter_id": "unifi", "captured_at": "2026-11-20T10:00:00Z"}}
                for index in range(65)
            ]})


if __name__ == "__main__":
    unittest.main()
