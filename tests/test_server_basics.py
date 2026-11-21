"""Regression tests for measured Wi-Fi data and platform-independent helpers."""
import unittest
import json
from unittest.mock import patch

from wifi_analyzer_backend import server


class FrequencyMappingTests(unittest.TestCase):
    def test_24_ghz_frequency_mapping(self):
        self.assertEqual(server.freq_to_ch(2412), 1)
        self.assertEqual(server.freq_to_ch(2437), 6)
        self.assertEqual(server.freq_to_ch(2484), 14)

    def test_5_ghz_frequency_mapping(self):
        self.assertEqual(server.freq_to_ch(5180), 36)
        self.assertEqual(server.freq_to_ch(5500), 100)

    def test_6_ghz_frequency_mapping(self):
        self.assertEqual(server.freq_to_ch(5955), 1)
        self.assertEqual(server.freq_to_ch(5975), 5)
        self.assertEqual(server.frequency_band(6115), "6GHz")

    def test_channel_frequency_mapping(self):
        self.assertEqual(server.ch_to_freq(1), 2412)
        self.assertEqual(server.ch_to_freq(6), 2437)
        self.assertEqual(server.ch_to_freq(36), 5180)


class SignalQualityTests(unittest.TestCase):
    def test_rssi_quality_is_bounded(self):
        self.assertEqual(server.rssi_quality(-50), 100)
        self.assertEqual(server.rssi_quality(-75), 50)
        self.assertEqual(server.rssi_quality(-100), 0)
        self.assertEqual(server.rssi_quality(-120), 0)
        self.assertEqual(server.rssi_quality(-20), 100)

    def test_snr_is_not_invented_when_noise_is_unavailable(self):
        observation = {"rssi": -57}
        server.enrich(observation)
        self.assertNotIn("noise", observation)
        self.assertNotIn("snr", observation)

    def test_snr_uses_measured_noise(self):
        observation = {"rssi": -57, "noise": -96}
        server.enrich(observation)
        self.assertEqual(observation["snr"], 39)


class ScanParserTests(unittest.TestCase):
    def test_iw_parser_extracts_access_point_fields(self):
        output = """BSS aa:bb:cc:dd:ee:01(on wlan0)
        freq: 5180
        signal: -55.00 dBm
        SSID: Test-Network
        RSN: WPA2
        """
        networks = server.parse_iw(output)
        self.assertEqual(len(networks), 1)
        self.assertEqual(networks[0]["ssid"], "Test-Network")
        self.assertEqual(networks[0]["bssid"], "AA:BB:CC:DD:EE:01")
        self.assertEqual(networks[0]["channel"], 36)
        self.assertEqual(networks[0]["band"], "5GHz")
        self.assertEqual(networks[0]["rssi"], -55)

    def test_iw_parser_preserves_hidden_ssid(self):
        output = """BSS aa:bb:cc:dd:ee:02(on wlan0)
        freq: 2412
        signal: -72.00 dBm
        """
        networks = server.parse_iw(output)
        self.assertEqual(len(networks), 1)
        self.assertEqual(networks[0]["ssid"], "")
        self.assertEqual(networks[0]["channel"], 1)

    def test_iw_parser_detects_6_ghz_and_wpa3(self):
        output = """BSS aa:bb:cc:dd:ee:03(on wlan0)
        freq: 5975
        signal: -51.00 dBm
        SSID: Modern-Network
        RSN:
            * Authentication suites: SAE
        """
        networks = server.parse_iw(output)
        self.assertEqual(networks[0]["channel"], 5)
        self.assertEqual(networks[0]["band"], "6GHz")
        self.assertEqual(networks[0]["security"], "WPA3")


    def test_iw_parser_keeps_missing_measurements_unknown(self):
        output = """BSS aa:bb:cc:dd:ee:04(on wlan0)
        SSID: Partial-Scan
        """
        network = server.parse_iw(output)[0]
        self.assertEqual(network["ssid"], "Partial-Scan")
        self.assertIsNone(network["frequency"])
        self.assertIsNone(network["channel"])
        self.assertIsNone(network["band"])
        self.assertIsNone(network["rssi"])
        self.assertIsNone(network["quality"])
        self.assertIsNone(network["snr"])

    def test_iwlist_parser_derives_channel_only_from_reported_frequency(self):
        output = """Cell 01 - Address: AA:BB:CC:DD:EE:05
        ESSID:"Measured-Frequency"
        Frequency:5.180 GHz
        """
        network = server.parse_iwlist(output)[0]
        self.assertEqual(network["frequency"], 5.18)
        self.assertEqual(network["channel"], 36)
        self.assertEqual(network["band"], "5GHz")
        self.assertIsNone(network["rssi"])
        self.assertIsNone(network["quality"])

    def test_netsh_signal_percentage_is_not_relabelled_as_measured_rssi(self):
        output = """SSID 1 : Windows-Network
            BSSID 1 : aa:bb:cc:dd:ee:06
            Signal : 80%
            Channel : 36
            Authentication : WPA2-Personal
        """
        network = server.parse_netsh(output)[0]
        self.assertEqual(network["signal_pct"], 80)
        self.assertIsNone(network["rssi"])
        self.assertIsNone(network["quality"])
        self.assertEqual(network["channel"], 36)
        self.assertIsNone(network["band"])
        self.assertIsNone(network["frequency"])

    def test_system_profiler_does_not_invent_signal_channel_or_band(self):
        output = json.dumps({
            "SPAirPortDataType": [{
                "spairport_airport_other_local_wireless_networks": [{
                    "_name": "Partial-Mac-Scan",
                    "spairport_network_bssid": "AA:BB:CC:DD:EE:07",
                }],
            }],
        })
        network = server.parse_system_profiler(output)[0]
        self.assertIsNone(network["rssi"])
        self.assertIsNone(network["quality"])
        self.assertIsNone(network["channel"])
        self.assertIsNone(network["frequency"])
        self.assertIsNone(network["band"])

    def test_system_profiler_parses_explicit_band_and_signal_noise_pair(self):
        output = json.dumps({
            "SPAirPortDataType": [{
                "spairport_airport_other_local_wireless_networks": [{
                    "_name": "Measured-Mac-Scan",
                    "spairport_network_bssid": "AA:BB:CC:DD:EE:08",
                    "spairport_network_channel": "36 (5GHz, 80MHz)",
                    "spairport_signal_noise": "-58 dBm / -95 dBm",
                    "spairport_security_mode": "WPA2 Personal",
                }],
            }],
        })
        network = server.parse_system_profiler(output)[0]
        self.assertEqual(network["band"], "5GHz")
        self.assertEqual(network["channel"], 36)
        self.assertEqual(network["frequency"], 5.18)
        self.assertEqual(network["rssi"], -58)
        self.assertEqual(network["noise"], -95)
        self.assertEqual(network["snr"], 37)

class ScanModeTests(unittest.TestCase):
    def test_missing_linux_adapter_returns_no_live_networks(self):
        with patch.object(server, "DEMO_MODE", False), patch.object(server, "OS", "Linux"), patch.object(server, "get_wifi_iface", return_value=None):
            self.assertEqual(server.scan(), [])

    def test_demo_networks_require_explicit_demo_mode(self):
        with patch.object(server, "DEMO_MODE", True):
            networks = server.scan()
        self.assertTrue(networks)
        self.assertTrue(all("bssid" in network for network in networks))


class ChannelCongestionTests(unittest.TestCase):
    def test_ignores_malformed_channel_and_unknown_band_records(self):
        networks = [
            {"band": "2.4GHz", "channel": 6},
            {"band": "2.4GHz", "channel": "not-a-channel"},
            {"band": "2.4GHz", "channel": True},
            {"band": "2.4GHz", "channel": 234},
            {"band": None, "channel": 36},
            {"band": "5GHz", "channel": 36},
        ]
        result = server.channel_congestion(networks)
        self.assertEqual(result["2.4GHz"], {4: 1, 5: 1, 6: 1, 7: 1, 8: 1})
        self.assertEqual(result["5GHz"], {36: 1})
        self.assertEqual(result["6GHz"], {})


    def test_counts_channels_separately_by_band(self):
        networks = [
            {"band": "2.4GHz", "channel": 1},
            {"band": "2.4GHz", "channel": 6},
            {"band": "5GHz", "channel": 36},
            {"band": "5GHz", "channel": 36},
            {"band": "6GHz", "channel": 5},
        ]
        result = server.channel_congestion(networks)
        self.assertEqual(result["2.4GHz"][1], 1)
        self.assertEqual(result["2.4GHz"][6], 1)
        self.assertEqual(result["5GHz"][36], 2)
        self.assertEqual(result["6GHz"][5], 1)


if __name__ == "__main__":
    unittest.main()
