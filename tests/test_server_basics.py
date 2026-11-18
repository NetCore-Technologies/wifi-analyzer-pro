"""Regression tests for measured Wi-Fi data and platform-independent helpers."""
import unittest
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
