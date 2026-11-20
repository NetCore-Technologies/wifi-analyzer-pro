"""Regression tests for the independently registered feature tools."""
import unittest

from wifi_analyzer_backend.feature_plugins import catalog, run, count
from wifi_analyzer_backend.feature_plugins.registry import FEATURE_MODULES

SAMPLE = [
    {"ssid": "Lab", "bssid": "02:11:22:33:44:55", "band": "2.4GHz", "channel": 6, "rssi": -52, "security": "WPA3"},
    {"ssid": "Lab", "bssid": "00:11:22:33:44:66", "band": "5GHz", "channel": 36, "rssi": -72, "security": "WPA2"},
    {"ssid": "Guest", "bssid": "00:11:22:33:44:77", "band": "6GHz", "channel": 5, "rssi": -88, "security": "Open"},
]

PAYLOADS = {
    "interface_inventory": {},
    "wireless_interface_inventory": {},
    "wifi_scan": {"networks": SAMPLE, "source": "test"},
    "normalise_bssid": {"bssid": "aa-bb-cc-dd-ee-ff"},
    "normalise_ssid": {"ssid": "Office\nWiFi"},
    "classify_frequency_band": {"frequency_mhz": 5975},
    "frequency_to_channel": {"frequency_mhz": 5975},
    "channel_to_frequency": {"channel": 5, "band": "6GHz"},
    "signal_quality": {"rssi": -65},
    "classify_signal": {"rssi": -65},
    "measured_snr": {"rssi": -60, "noise": -95},
    "sort_networks_by_signal": {"networks": SAMPLE},
    "filter_networks_by_band": {"networks": SAMPLE, "band": "6GHz"},
    "filter_networks_by_security": {"networks": SAMPLE, "security": "WPA3"},
    "open_access_points": {"networks": SAMPLE},
    "wpa3_access_points": {"networks": SAMPLE},
    "hidden_networks": {"networks": SAMPLE + [{"ssid": "", "bssid": "00:11:22:33:44:88"}]},
    "deduplicate_scan": {"networks": SAMPLE},
    "scan_delta": {"current": SAMPLE, "previous": SAMPLE[:2]},
    "scan_summary": {"networks": SAMPLE},
    "strongest_networks": {"networks": SAMPLE},
    "weakest_networks": {"networks": SAMPLE},
    "group_by_ssid": {"networks": SAMPLE},
    "strongest_per_ssid": {"networks": SAMPLE},
    "oui_vendor_lookup": {"bssid": "DC:A6:32:00:00:01"},
    "locally_administered_mac": {"mac": "02:11:22:33:44:55"},
    "randomized_mac_detect": {"mac": "02:11:22:33:44:55"},
    "channel_congestion": {"networks": SAMPLE},
    "overlap_24ghz": {"networks": SAMPLE},
    "recommend_24ghz_channel": {"networks": SAMPLE},
    "recommend_5ghz_channel": {"networks": SAMPLE},
    "recommend_6ghz_channel": {"networks": SAMPLE},
    "channel_quality": {"networks": SAMPLE, "band": "2.4GHz", "channel": 6},
    "dfs_channel_detect": {"channel": 100},
    "six_ghz_psc_detect": {"channel": 5},
    "recommend_channel_width": {"networks": SAMPLE, "band": "5GHz"},
    "band_distribution": {"networks": SAMPLE},
    "security_distribution": {"networks": SAMPLE},
    "vendor_distribution": {"networks": SAMPLE},
    "parse_iw_scan": {"text": "BSS aa:bb:cc:dd:ee:ff(on wlan0)\n freq: 5975\n signal: -55.00 dBm\n SSID: Test\n RSN:\n * Authentication suites: SAE\n"},
    "parse_iwlist_scan": {"text": 'Cell 01 - Address: AA:BB:CC:DD:EE:FF\n ESSID:"Test"\n Frequency:5.975 GHz (Channel 5)\n Quality=50/70 Signal level=-55 dBm\n'} ,
    "parse_netsh_scan": {"text": "SSID 1 : Test\n    BSSID 1 : aa:bb:cc:dd:ee:ff\n         Signal : 80%\n         Channel : 36\n         Authentication : WPA2-Personal\n"},
    "parse_airport_scan": {"text": "SSID BSSID             RSSI CHANNEL HT CC SECURITY\nTest AA:BB:CC:DD:EE:FF -55 36,Y  Y  WPA2\n"},
    "parse_system_profiler": {"text": '{"SPAirPortDataType": []}'},
    "parse_station_dump": {"text": "signal: -55 dBm\ntx bitrate: 300.0 MBit/s\ntx retries: 4\n"},
    "parse_iw_link": {"text": "Connected to aa:bb:cc:dd:ee:ff\nSSID: Test\nfreq: 5975\nsignal: -55 dBm\n"},
    "parse_ethtool": {"text": "Speed: 1000Mb/s\nDuplex: Full\nLink detected: yes\n"},
    "parse_route_table": {"text": "default via 192.168.1.1 dev wlan0 proto dhcp\n"},
    "parse_arp_linux": {"text": "? (192.168.1.2) at aa:bb:cc:dd:ee:ff [ether] on wlan0"},
    "parse_arp_windows": {"text": "  192.168.1.2          aa-bb-cc-dd-ee-ff     dynamic"},
    "parse_resolv_conf": {"text": "nameserver 1.1.1.1\nnameserver 2606:4700:4700::1111\n"},
    "parse_ping_output": {"text": "10 packets transmitted, 9 received, 10% packet loss\nrtt min/avg/max/mdev = 2.0/3.0/5.0/0.8 ms"},
    "parse_traceroute": {"text": " 1  gateway (192.168.1.1)  1.23 ms  1.45 ms\n 2  * * *"},
    "validate_network_record": {"network": SAMPLE[0]},
    "validate_scan": {"networks": SAMPLE},
    "subnet_summary": {"cidr": "192.168.1.50/24"},
    "ip_in_subnet": {"ip": "192.168.1.4", "subnet": "192.168.1.0/24"},
    "default_gateway_from_route": {"text": "default via 192.168.1.1 dev wlan0"},
    "dns_servers_from_config": {"text": "nameserver 1.1.1.1"},
    "reverse_dns_lookup": {"ip": "127.0.0.1"},
    "dns_lookup_timing": {"host": "localhost"},
    "latency_summary": {"samples_ms": [3, 5, 7, 9]},
    "packet_loss_calculator": {"sent": 10, "received": 9},
    "jitter_calculator": {"samples_ms": [1, 4, 2, 3]},
    "interface_counter_delta": {"before": {"rx_bytes": 100}, "after": {"rx_bytes": 150}},
    "interface_throughput": {"before": {"rx_bytes": 100}, "after": {"rx_bytes": 200}, "interval_seconds": 2},
    "packet_error_rate": {"stats": {"rx_packets": 100, "tx_packets": 100, "rx_errors": 1}},
    "inspect_url": {"url": "https://example.com/path"},
    "tls_certificate_expiry": {"host": "localhost", "port": 1},
    "security_rank": {"security": "WPA3"},
    "security_warnings": {"networks": SAMPLE},
    "rogue_ap_candidates": {"networks": SAMPLE, "trusted_bssids": [SAMPLE[0]["bssid"]], "trusted_networks": [{"ssid":"Guest"}]},
    "evil_twin_candidates": {"networks": SAMPLE},
    "duplicate_bssid_check": {"networks": SAMPLE + [SAMPLE[0]]},
    "weak_signal_alerts": {"networks": SAMPLE, "threshold_dbm": -70},
    "open_wifi_alerts": {"networks": SAMPLE},
    "transition_mode_detect": {"networks": [{"ssid":"x", "security":"WPA2/WPA3"}]},
    "redact_mac": {"mac": "AA:BB:CC:DD:EE:FF"},
    "redact_ssid": {"networks": SAMPLE},
    "anonymise_scan": {"networks": SAMPLE},
    "ssid_hash": {"ssid": "Test"},
    "scan_fingerprint": {"networks": SAMPLE},
    "alert_severity": {"type": "evil_twin"},
    "deduplicate_alerts": {"alerts": [{"type":"x"},{"type":"x"}]},
    "alert_threshold": {"value": 90, "warning": 70, "critical": 85},
    "export_json": {"networks": SAMPLE},
    "export_csv": {"networks": SAMPLE},
    "export_html": {"networks": SAMPLE},
    "prometheus_metrics": {"networks": SAMPLE},
    "network_report": {"networks": SAMPLE},
    "history_window": {"history": list(range(20)), "limit": 5},
    "signal_trend": {"samples_dbm": [-80, -78, -75, -70]},
    "signal_percentiles": {"samples_dbm": [-80, -70, -60]},
    "channel_rank": {"networks": SAMPLE, "band": "5GHz"},
    "format_bytes": {"bytes": 1024},
    "format_duration": {"seconds": 3661},
    "safe_filename": {"name": "Wi-Fi scan/report 2026"},
    "validate_settings": {"refresh_interval_seconds": 10, "scan_timeout_seconds": 20, "max_history": 500},
    "health_report": {"networks": SAMPLE},
    "wifi_generation_classify": {"capabilities": {"he": True}, "band": "6GHz"},
    "same_ssid_band_presence": {"networks":[{"ssid":"Lab","bssid":"00:11:22:33:44:55","band":"2.4GHz"},{"ssid":"Lab","bssid":"00:11:22:33:44:66","band":"5GHz"}]},
    "band_steering_evidence": {"networks":[{"ssid":"Lab","band":"2.4GHz","rssi":-55},{"ssid":"Lab","band":"5GHz","rssi":-62}]},
    "roaming_candidate_ranking": {"networks":[{"ssid":"Lab","bssid":"00:11:22:33:44:55","rssi":-75},{"ssid":"Lab","bssid":"00:11:22:33:44:66","rssi":-60}],"current_bssid":"00:11:22:33:44:55","min_improvement_db":8},
    "association_roam_events": {"previous":[{"client_mac":"AA:BB:CC:DD:EE:01","ssid":"Lab","bssid":"00:11:22:33:44:55"}],"current":[{"client_mac":"AA:BB:CC:DD:EE:01","ssid":"Lab","bssid":"00:11:22:33:44:66"}]},
    "roaming_timeline_summary": {"events":[{"client_mac":"AA:BB:CC:DD:EE:01","event":"roamed"},{"client_mac":"AA:BB:CC:DD:EE:01","event":"roamed"}]},
    "sticky_client_candidates": {"clients":[{"client_mac":"AA:BB:CC:DD:EE:01","ssid":"Lab","connected_bssid":"00:11:22:33:44:55","connected_rssi_dbm":-80,"alternatives":[{"bssid":"00:11:22:33:44:66","rssi_dbm":-55}]}]},
    "association_dwell_summary": {"sessions":[{"client_mac":"AA:BB:CC:DD:EE:01","bssid":"00:11:22:33:44:55","connected_at":"2026-11-20T10:00:00Z","disconnected_at":"2026-11-20T10:05:00Z"}]},
    "roam_latency_summary": {"samples":[{"before_ms":55,"after_ms":35},{"before_ms":50,"after_ms":30}]},
    "roaming_stability_score": {"events":[{"client_mac":"AA:BB:CC:DD:EE:01","event":"roamed"},{"client_mac":"AA:BB:CC:DD:EE:01","event":"roamed"}],"window_hours":24},
    "band_occupancy_delta": {"previous":[{"band":"2.4GHz"}],"current":[{"band":"5GHz"},{"band":"5GHz"}]},
    "channel_width_frequency_range": {"center_frequency_mhz":5975,"width_mhz":80},
    "frequency_overlap_score": {"a":{"center_frequency_mhz":5975,"width_mhz":80},"b":{"center_frequency_mhz":6015,"width_mhz":80}},
    "channel_separation_rank": {"candidates":[{"id":"c1","center_frequency_mhz":5180,"width_mhz":20},{"id":"c2","center_frequency_mhz":5500,"width_mhz":20}],"observed":[{"center_frequency_mhz":5180,"width_mhz":20}]},
    "channel_overlap_pairs": {"channels":[{"id":"a","center_frequency_mhz":5180,"width_mhz":80},{"id":"b","center_frequency_mhz":5220,"width_mhz":80},{"id":"c","center_frequency_mhz":5500,"width_mhz":20}]},
    "dfs_frequency_intersection": {"center_frequency_mhz":5500,"width_mhz":80},
    "six_ghz_psc_plan": {"observed_channels":[5,21]},
    "wifi7_eht_summary": {"capabilities":{"eht":True,"mlo":True,"320mhz":True}},
    "multi_link_operation_summary": {"links":[{"link_id":0,"band":"5GHz","channel":36,"active":True,"rssi_dbm":-55},{"link_id":1,"band":"6GHz","channel":5,"active":True,"rssi_dbm":-60}]},
    "pmf_security_audit": {"networks":[{"ssid":"Lab","bssid":"00:11:22:33:44:55","pmf":"required"},{"ssid":"Guest","pmf":"unknown"}]},
    "regulatory_channel_allowlist_check": {"band":"2.4GHz","allowed_channels":[1,6,11],"networks":[{"ssid":"Lab","band":"2.4GHz","channel":1},{"ssid":"Lab","band":"2.4GHz","channel":14}]},
    "client_association_inventory": {"clients":[{"client_mac":"AA:BB:CC:DD:EE:01","bssid":"00:11:22:33:44:55","ssid":"Lab"}],"access_points":[{"bssid":"00:11:22:33:44:55","ssid":"Lab","band":"5GHz","name":"AP-1"}]},
    "stale_client_detector": {"now":"2026-11-20T10:00:00Z","stale_after_seconds":300,"clients":[{"client_mac":"AA:BB:CC:DD:EE:01","last_seen":"2026-11-20T09:00:00Z"},{"client_mac":"AA:BB:CC:DD:EE:02","last_seen":"2026-11-20T09:59:00Z"}]},
    "airtime_fairness_summary": {"clients":[{"client_mac":"AA:BB:CC:DD:EE:01","tx_airtime_ms":40,"rx_airtime_ms":60},{"client_mac":"AA:BB:CC:DD:EE:02","tx_airtime_ms":40,"rx_airtime_ms":60}]},
    "client_throughput_fairness": {"interval_seconds":10,"clients":[{"client_mac":"AA:BB:CC:DD:EE:01","tx_bytes":1000000,"rx_bytes":2000000},{"client_mac":"AA:BB:CC:DD:EE:02","tx_bytes":2000000,"rx_bytes":1000000}]},
    "dscp_traffic_distribution": {"samples":[{"dscp":46,"packets":120},{"dscp":0,"packets":80},{"dscp":46,"packets":20}]},
    "application_qos_policy_audit": {"policy":[{"application":"voice","dscp":46},{"application":"video","dscp":34}],"observations":[{"application":"voice","dscp":46},{"application":"video","dscp":0}]},
    "client_retry_rate": {"clients":[{"client_mac":"AA:BB:CC:DD:EE:01","tx_packets":900,"tx_retries":100}]},
    "phy_rate_asymmetry": {"clients":[{"client_mac":"AA:BB:CC:DD:EE:01","tx_rate_mbps":600,"rx_rate_mbps":300}]},
    "client_ap_capability_match": {"clients":[{"client_mac":"AA:BB:CC:DD:EE:01","bssid":"00:11:22:33:44:55","supported_bands":["5GHz","6GHz"],"required_features":["MLO"]}],"access_points":[{"bssid":"00:11:22:33:44:55","supported_bands":["5GHz"],"supported_features":["OFDMA"]}]},
    "ofdma_mu_mimo_evidence": {"observations":[{"ofdma_supported":True,"ofdma_active":True,"mu_mimo_supported":True,"mu_mimo_active":False,"ofdma_ppdu_count":25,"mu_mimo_ppdu_count":4},{"ofdma_supported":True,"ofdma_active":False}]},
    "twt_power_save_summary": {"clients":[{"client_mac":"AA:BB:CC:DD:EE:01","twt_supported":True,"twt_active":True,"twt_interval_ms":100,"twt_duration_ms":10}]},
    "bss_transition_capability_audit": {"access_points":[{"bssid":"00:11:22:33:44:55","dot11k_neighbor_report":True,"dot11v_bss_transition":True,"dot11r_fast_transition":False}]},
    "mobility_domain_consistency": {"access_points":[{"ssid":"Lab","bssid":"00:11:22:33:44:55","mobility_domain":"A1B2","dot11r_fast_transition":True},{"ssid":"Lab","bssid":"00:11:22:33:44:66","mobility_domain":"A1B3","dot11r_fast_transition":True}]},
    "dhcp_lease_audit": {"now":"2026-11-20T10:00:00Z","leases":[{"ip":"192.168.1.10","mac":"AA:BB:CC:DD:EE:01","expires_at":"2026-11-20T09:00:00Z"},{"ip":"192.168.1.10","mac":"AA:BB:CC:DD:EE:02","expires_at":"2026-11-20T11:00:00Z"}]},
    "dns_resolver_latency_compare": {"samples":[{"resolver":"1.1.1.1","success":True,"latency_ms":20},{"resolver":"1.1.1.1","success":True,"latency_ms":25},{"resolver":"9.9.9.9","success":False}]},
    "gateway_reachability_matrix": {"probes":[{"target":"192.168.1.1","reachable":True,"rtt_ms":1.5},{"target":"192.168.1.1","reachable":False},{"target":"1.1.1.1","reachable":True,"rtt_ms":18}]},
    "roaming_interruption_analysis": {"events":[{"client_mac":"AA:BB:CC:DD:EE:01","disconnected_at":"2026-11-20T09:00:00Z","reconnected_at":"2026-11-20T09:00:00.250Z","from_bssid":"00:11:22:33:44:55","to_bssid":"00:11:22:33:44:66"}]},
    "disconnect_reason_summary": {"events":[{"reason_code":4,"client_mac":"AA:BB:CC:DD:EE:01"},{"reason_code":15,"client_mac":"AA:BB:CC:DD:EE:02"}]},
    "association_rejection_summary": {"events":[{"status_code":17,"client_mac":"AA:BB:CC:DD:EE:01"},{"status_code":0,"client_mac":"AA:BB:CC:DD:EE:02"}]},
    "connection_health_evidence": {"clients":[{"client_mac":"AA:BB:CC:DD:EE:01","rssi_dbm":-81,"retry_rate_pct":25,"tx_rate_mbps":54,"rx_rate_mbps":48}],"diagnostics":{"packet_loss_pct":7,"latency_ms":120}},
    "site_inventory_snapshot": {"site_id":"home","access_points":[{"name":"Hall AP","bssid":"00:11:22:33:44:55","ssid":"Home","model":"AX AP","vendor":"Example","band":"5GHz","channel":36,"channel_width_mhz":80,"location":"hall"}]},

    "ap_topology_relationships": {"access_points":[{"ap_id":"ap-a","site_id":"home"},{"ap_id":"ap-b","site_id":"home"},{"ap_id":"ap-c","site_id":"branch"}],"links":[{"from_ap_id":"ap-a","to_ap_id":"ap-b","relationship":"wired_uplink","source":"lldp"},{"from_ap_id":"ap-b","to_ap_id":"ap-c","relationship":"mesh_backhaul","source":"controller"},{"from_ap_id":"ap-a","to_ap_id":"ap-c","relationship":"rf_neighbor","source":"beacon_observation"}]},

    "site_network_segment_correlation": {"segments":[{"segment_id":"main","site_id":"home","cidr":"192.168.1.0/24","gateway_ip":"192.168.1.1","vlan_id":10}],"access_points":[{"ap_id":"ap-1","site_id":"home","management_ip":"192.168.1.20"}]},

}


class FeatureCatalogTests(unittest.TestCase):
    def test_exactly_one_hundred_twenty_distinct_features_are_registered(self):
        entries = catalog()
        self.assertEqual(len(FEATURE_MODULES), 143)
        self.assertEqual(len(set(FEATURE_MODULES)), 143)
        self.assertEqual(count(), 143)
        self.assertEqual(len(entries), 143)
        self.assertEqual(len({entry["slug"] for entry in entries}), 143)
        self.assertEqual([entry["id"] for entry in entries], [f"F{i:03d}" for i in range(1, 144)])

    def test_each_feature_executes_with_its_sample_payload(self):
        for entry in catalog():
            with self.subTest(feature=entry["slug"]):
                self.assertIn(entry["slug"], PAYLOADS)
                result = run(entry["slug"], PAYLOADS[entry["slug"]])
                self.assertEqual(result["slug"], entry["slug"])
                self.assertIsInstance(result["result"], dict)

    def test_wpa3_and_six_ghz_parsing(self):
        result = run("parse_iw_scan", PAYLOADS["parse_iw_scan"])["result"]["networks"][0]
        self.assertEqual(result["channel"], 5)
        self.assertEqual(result["band"], "6GHz")
        self.assertEqual(result["security"], "WPA3")

    def test_measured_snr_is_not_fabricated(self):
        result = run("measured_snr", {"rssi": -55})["result"]
        self.assertFalse(result["available"])
        self.assertIsNone(result["snr_db"])

    def test_html_report_escapes_untrusted_network_names(self):
        result = run("export_html", {"networks": [{"ssid": "<script>alert(1)</script>"}]})["result"]
        self.assertNotIn("<script>", result["content"])
        self.assertIn("&lt;script&gt;", result["content"])

    def test_channel_recommendations_need_real_band_observations(self):
        for slug in ("recommend_24ghz_channel", "recommend_5ghz_channel", "recommend_6ghz_channel"):
            result = run(slug, {"networks": []})["result"]
            self.assertIsNone(result["recommended_channel"])
            self.assertEqual(result["status"], "insufficient_observations")

    def test_scan_validator_counts_non_object_records(self):
        result = run("validate_scan", {"networks": [SAMPLE[0], None, "bad"]})["result"]
        self.assertEqual(result["valid_count"], 1)
        self.assertEqual(result["invalid_count"], 2)

    def test_channel_width_uses_only_requested_band(self):
        result = run("recommend_channel_width", {"band": "5GHz", "networks": SAMPLE})["result"]
        self.assertEqual(result["observed_networks"], 1)

    def test_prometheus_labels_escape_special_characters(self):
        result = run("prometheus_metrics", {"networks": [{"bssid": 'aa"bb\\cc', "rssi": -50}]})["result"]["content"]
        self.assertIn('bssid="aa\\"bb\\\\cc"', result)

    def test_csv_export_quotes_delimiters(self):
        result = run("export_csv", {"networks": [{"ssid": "lab,west"}]})["result"]
        self.assertIn('"lab,west"', result["content"])


    def test_site_inventory_snapshot_reports_sites_bands_and_duplicate_bssids(self):
        result = run("site_inventory_snapshot", {
            "site_id": "home",
            "access_points": [
                {"name": "Hall", "bssid": "00:11:22:33:44:55", "model": "AX",
                 "band": "5GHz", "channel": 36, "channel_width_mhz": 80, "location": "hall"},
                {"name": "Garage", "bssid": "00:11:22:33:44:55", "model": "AX",
                 "band": "2.4GHz", "channel": 6, "channel_width_mhz": 20,
                 "location": "garage", "site_id": "remote"}
            ]
        })["result"]
        self.assertEqual(result["site_count"], 2)
        self.assertEqual(result["access_points_by_band"], {"2.4GHz": 1, "5GHz": 1})
        self.assertEqual(result["duplicate_bssid_count"], 1)
        self.assertEqual(result["inventory_field_coverage_pct"], 100.0)

    def test_site_inventory_snapshot_rejects_invalid_bssid_and_channel_width(self):
        with self.assertRaisesRegex(ValueError, "BSSID"):
            run("site_inventory_snapshot", {"access_points": [{"bssid": "not-a-mac"}]})
        with self.assertRaisesRegex(ValueError, "channel_width_mhz"):
            run("site_inventory_snapshot", {
                "access_points": [{"bssid": "00:11:22:33:44:55", "channel_width_mhz": 10}]
            })

    def test_site_inventory_snapshot_keeps_empty_inventory_unknown(self):
        result = run("site_inventory_snapshot", {"access_points": []})["result"]
        self.assertEqual(result["access_point_count"], 0)
        self.assertIsNone(result["inventory_field_coverage_pct"])


    def test_ap_topology_relationships_separates_physical_and_rf_edges(self):
        result = run("ap_topology_relationships", {
            "access_points": [{"ap_id": "a"}, {"ap_id": "b"}, {"ap_id": "c"}],
            "links": [
                {"from_ap_id": "a", "to_ap_id": "b", "relationship": "wired_uplink"},
                {"from_ap_id": "b", "to_ap_id": "c", "relationship": "mesh_backhaul"},
                {"from_ap_id": "a", "to_ap_id": "c", "relationship": "rf_neighbor"}
            ]
        })["result"]
        self.assertEqual(result["resolved_link_count"], 3)
        self.assertEqual(result["links_by_relationship"]["rf_neighbor"], 1)
        degrees = {item["ap_id"]: item["physical_degree"] for item in result["access_point_degrees"]}
        self.assertEqual(degrees, {"a": 1, "b": 2, "c": 1})

    def test_ap_topology_relationships_flags_duplicates_orphans_and_uplink_cycles(self):
        result = run("ap_topology_relationships", {
            "access_points": [{"ap_id": "a"}, {"ap_id": "b"}],
            "links": [
                {"from_ap_id": "a", "to_ap_id": "b", "relationship": "wired_uplink"},
                {"from_ap_id": "a", "to_ap_id": "b", "relationship": "wired_uplink"},
                {"from_ap_id": "b", "to_ap_id": "a", "relationship": "wired_uplink"},
                {"from_ap_id": "a", "to_ap_id": "missing", "relationship": "mesh_backhaul"}
            ]
        })["result"]
        self.assertEqual(result["duplicate_link_count"], 1)
        self.assertEqual(result["unresolved_link_count"], 1)
        self.assertEqual(len(result["wired_uplink_cycles"]), 1)

    def test_ap_topology_relationships_rejects_unknown_relationships(self):
        with self.assertRaisesRegex(ValueError, "relationship"):
            run("ap_topology_relationships", {
                "access_points": [{"ap_id": "a"}, {"ap_id": "b"}],
                "links": [{"from_ap_id": "a", "to_ap_id": "b", "relationship": "guessed"}]
            })


    def test_site_subnet_correlation_reports_ambiguous_membership(self):
        result = run("site_network_segment_correlation", {
            "segments": [
                {"segment_id": "main", "site_id": "home", "cidr": "10.0.0.0/24", "gateway_ip": "10.0.0.1"},
                {"segment_id": "overlap", "site_id": "home", "cidr": "10.0.0.128/25", "gateway_ip": "10.0.0.129"},
                {"segment_id": "remote", "site_id": "remote", "cidr": "172.16.0.0/16", "gateway_ip": "172.16.0.1"}
            ],
            "access_points": [
                {"ap_id": "ap-home", "site_id": "home", "management_ip": "10.0.0.150"},
                {"ap_id": "ap-remote", "site_id": "remote", "management_ip": "172.16.0.2"},
                {"ap_id": "ap-unaddressed", "site_id": "home"}
            ]
        })["result"]
        self.assertEqual(result["overlap_count"], 1)
        self.assertEqual(result["access_points_by_match_status"]["ambiguous"], 1)
        self.assertEqual(result["access_points_by_match_status"]["matched"], 1)
        self.assertEqual(result["access_points_by_match_status"]["missing_management_ip"], 1)

    def test_site_subnet_correlation_rejects_gateway_outside_cidr(self):
        with self.assertRaisesRegex(ValueError, "belong to the segment"):
            run("site_network_segment_correlation", {
                "segments": [{"segment_id": "main", "site_id": "home", "cidr": "192.168.1.0/24", "gateway_ip": "192.168.2.1"}]
            })


if __name__ == "__main__":
    unittest.main()
