"""Regression tests for the independently registered feature tools."""
import hashlib
import hashlib
import json
import unittest

from wifi_analyzer_backend.feature_plugins import catalog, run, count
from wifi_analyzer_backend.feature_plugins.registry import FEATURE_MODULES
from wifi_analyzer_backend.feature_plugins.feature_182_router_audit_report_bundle_builder import run as build_report_bundle

SAMPLE = [
    {"ssid": "Lab", "bssid": "02:11:22:33:44:55", "band": "2.4GHz", "channel": 6, "rssi": -52, "security": "WPA3"},
    {"ssid": "Lab", "bssid": "00:11:22:33:44:66", "band": "5GHz", "channel": 36, "rssi": -72, "security": "WPA2"},
    {"ssid": "Guest", "bssid": "00:11:22:33:44:77", "band": "6GHz", "channel": 5, "rssi": -88, "security": "Open"},
]

_SAMPLE_DELIVERY_REPORT = build_report_bundle({
    "report_id": "weekly-home",
    "title": "Sample weekly report",
    "generated_at": "2026-11-20T09:59:00Z",
    "sources": [{
        "source_id": "home-health",
        "source_type": "router_fleet_health_audit",
        "result": {"status": "audited", "summary": {"router_count": 1}, "routers": []}
    }]
})
_SAMPLE_DELIVERY_SCHEDULE = "daily-home"
_SAMPLE_DELIVERY_OCCURRENCE = "b" * 64
_SAMPLE_DELIVERY_REPORT_ID = "weekly-home"
_SAMPLE_DELIVERY_JOB_KEY = hashlib.sha256(json.dumps([
    _SAMPLE_DELIVERY_SCHEDULE,
    _SAMPLE_DELIVERY_OCCURRENCE,
    _SAMPLE_DELIVERY_REPORT_ID,
], separators=(",", ":")).encode()).hexdigest()
_SAMPLE_DELIVERY_PAYLOAD_HASH = hashlib.sha256(json.dumps(
    _SAMPLE_DELIVERY_REPORT,
    ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False,
).encode()).hexdigest()

PAYLOADS = {
    "interface_inventory": {},
    "pcap_capture_analyzer": {"capture_base64": "1MOyoQIABAAAAAAAAAAAAP//AAABAAAA"},
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

    "floor_plan_anchor_validation": {"floorplans":[{"floorplan_id":"level-1","site_id":"home","width_px":1600,"height_px":900}],"access_points":[{"ap_id":"ap-1","site_id":"home"}],"anchors":[{"ap_id":"ap-1","floorplan_id":"level-1","x":0.25,"y":0.5}]},

    "site_inventory_snapshot_diff": {"previous":[{"bssid":"00:11:22:33:44:55","site_id":"home","band":"5GHz","channel":36}],"current":[{"bssid":"00:11:22:33:44:55","site_id":"remote","band":"5GHz","channel":40},{"bssid":"00:11:22:33:44:66","site_id":"home","band":"2.4GHz","channel":6}]},

    "site_network_segment_capacity": {"segments":[{"segment_id":"home","site_id":"home","cidr":"192.168.1.0/24","in_use_count":200,"reserved_count":5},{"segment_id":"ipv6","site_id":"home","cidr":"2001:db8::/64"}]},

    "site_gateway_redundancy_audit": {"gateways":[{"gateway_id":"gw-a","site_id":"home","group_id":"edge","protocol":"vrrp","ip":"192.168.1.1","state":"active","priority":120},{"gateway_id":"gw-b","site_id":"home","group_id":"edge","protocol":"vrrp","ip":"192.168.1.2","state":"standby","priority":100}]},

    "floorplan_zone_assignment": {"zones":[{"floorplan_id":"level-1","zone_id":"left","name":"Left wing","polygon":[{"x":0,"y":0},{"x":0.6,"y":0},{"x":0.6,"y":1},{"x":0,"y":1}]},{"floorplan_id":"level-1","zone_id":"right","name":"Right wing","polygon":[{"x":0.4,"y":0},{"x":1,"y":0},{"x":1,"y":1},{"x":0.4,"y":1}]}],"anchors":[{"ap_id":"ap-left","floorplan_id":"level-1","x":0.2,"y":0.5},{"ap_id":"ap-center","floorplan_id":"level-1","x":0.5,"y":0.5}]},

    "site_topology_redundancy_audit": {"access_points":[{"ap_id":"a"},{"ap_id":"b"},{"ap_id":"c"},{"ap_id":"d"},{"ap_id":"e"}],"links":[{"from_ap_id":"a","to_ap_id":"b","relationship":"wired_uplink"},{"from_ap_id":"b","to_ap_id":"c","relationship":"wired_uplink"},{"from_ap_id":"c","to_ap_id":"a","relationship":"mesh_backhaul"},{"from_ap_id":"c","to_ap_id":"d","relationship":"wired_uplink"},{"from_ap_id":"a","to_ap_id":"e","relationship":"rf_neighbor"}]},

    "site_topology_snapshot_diff": {"previous":{"access_points":[{"ap_id":"a","site_id":"home"},{"ap_id":"b","site_id":"home"}],"links":[{"from_ap_id":"a","to_ap_id":"b","relationship":"wired_uplink"}]},"current":{"access_points":[{"ap_id":"a","site_id":"remote"},{"ap_id":"c","site_id":"home"}],"links":[{"from_ap_id":"a","to_ap_id":"c","relationship":"mesh_backhaul"}]}},

    "site_inventory_comparison": {"access_points":[{"bssid":"00:11:22:33:44:55","site_id":"home","band":"5GHz","vendor":"VendorA","model":"AX1"},{"bssid":"00:11:22:33:44:66","site_id":"branch","band":"2.4GHz","vendor":"VendorB","model":"AX2"}]},

    "ap_observation_freshness_audit": {"now":"2026-11-20T10:00:00Z","stale_after_seconds":900,"access_points":[{"ap_id":"ap-a","site_id":"home","last_seen":"2026-11-20T09:30:00Z"},{"ap_id":"ap-b","site_id":"home","last_seen":"2026-11-20T09:59:00Z"},{"ap_id":"ap-c","site_id":"branch"}]},

    "site_ap_channel_reuse_audit": {"radios":[{"radio_id":"r1","ap_id":"a","site_id":"home","band":"2.4GHz","channel":1,"channel_width_mhz":20},{"radio_id":"r2","ap_id":"b","site_id":"home","band":"2.4GHz","channel":3,"channel_width_mhz":20},{"radio_id":"r3","ap_id":"c","site_id":"home","band":"2.4GHz","channel":1,"channel_width_mhz":20}]} ,
    "site_topology_history_timeline": {"snapshots":[{"captured_at":"2026-11-20T09:00:00Z","access_points":[{"ap_id":"a","site_id":"home"},{"ap_id":"b","site_id":"home"}],"links":[{"from_ap_id":"a","to_ap_id":"b","relationship":"wired_uplink"}]},{"captured_at":"2026-11-20T10:00:00Z","access_points":[{"ap_id":"a","site_id":"home"},{"ap_id":"c","site_id":"home"}],"links":[{"from_ap_id":"a","to_ap_id":"c","relationship":"mesh_backhaul"}]}]},
    "site_topology_gateway_path_audit": {"access_points":[{"ap_id":"gw","site_id":"home"},{"ap_id":"ap-2","site_id":"home"},{"ap_id":"isolated","site_id":"home"},{"ap_id":"remote","site_id":"branch"}],"gateway_ap_ids":["gw"],"links":[{"from_ap_id":"gw","to_ap_id":"ap-2","relationship":"wired_uplink"},{"from_ap_id":"gw","to_ap_id":"isolated","relationship":"rf_neighbor"},{"from_ap_id":"ap-2","to_ap_id":"remote","relationship":"mesh_backhaul"}]},
    "site_radio_configuration_audit": {
        "radios": [
            {"radio_id":"home-5g","site_id":"home","band":"5GHz","channel_width_mhz":80,"security":"WPA3","tx_power_dbm":20},
            {"radio_id":"branch-5g","site_id":"branch","band":"5GHz","channel_width_mhz":40,"security":"WPA2","tx_power_dbm":30},
            {"radio_id":"guest-24g","site_id":"guest","band":"2.4GHz","channel_width_mhz":20,"security":"WPA2","tx_power_dbm":10}
        ],
        "standards": [
            {"site_id":"*","band":"5GHz","channel_width_mhz":80,"security":"WPA3","min_tx_power_dbm":5,"max_tx_power_dbm":23},
            {"site_id":"home","band":"5GHz","channel_width_mhz":80,"security":"WPA3","min_tx_power_dbm":10,"max_tx_power_dbm":22}
        ]
    },
    "site_topology_visualisation": {
        "access_points": [
            {"ap_id":"gw","site_id":"home","name":"Gateway"},
            {"ap_id":"ap-a","site_id":"home","name":"Hall AP"},
            {"ap_id":"ap-b","site_id":"home","name":"Office AP"},
            {"ap_id":"branch-ap","site_id":"branch","name":"Branch AP"}
        ],
        "gateway_ap_ids": ["gw"],
        "links": [
            {"from_ap_id":"gw","to_ap_id":"ap-a","relationship":"wired_uplink"},
            {"from_ap_id":"ap-a","to_ap_id":"ap-b","relationship":"mesh_backhaul"},
            {"from_ap_id":"gw","to_ap_id":"ap-b","relationship":"rf_neighbor"},
            {"from_ap_id":"ap-b","to_ap_id":"branch-ap","relationship":"wireless_backhaul"},
            {"from_ap_id":"missing","to_ap_id":"ap-a","relationship":"wired_uplink"}
        ]
    },
    "site_discovery_history_snapshot": {
        "site_id": "home",
        "captured_at": "2026-11-20T10:00:00+11:00",
        "access_points": [{"ap_id":"ap-hall","name":"Hall AP"}],
        "links": []
    },
    "site_to_site_change_report": {
        "sites": [
            {
                "site_id": "home",
                "previous": {
                    "snapshot_id": 1, "captured_at": "2026-11-20T09:00:00+00:00",
                    "snapshot": {
                        "site_id": "home",
                        "access_points": [
                            {"ap_id":"gw","site_id":"home","bssid":"00:11:22:33:44:55","band":"5GHz"},
                            {"ap_id":"old","site_id":"home","bssid":"00:11:22:33:44:66","band":"2.4GHz"}
                        ],
                        "links": [{"from_ap_id":"gw","to_ap_id":"old","relationship":"wired_uplink"}]
                    }
                },
                "current": {
                    "snapshot_id": 2, "captured_at": "2026-11-20T10:00:00+00:00",
                    "snapshot": {
                        "site_id": "home",
                        "access_points": [
                            {"ap_id":"gw","site_id":"home","bssid":"00:11:22:33:44:55","band":"5GHz"},
                            {"ap_id":"new","site_id":"home","bssid":"00:11:22:33:44:77","band":"6GHz"}
                        ],
                        "links": [{"from_ap_id":"gw","to_ap_id":"new","relationship":"mesh_backhaul"}]
                    }
                }
            },
            {
                "site_id": "branch",
                "previous": None,
                "current": {
                    "snapshot_id": 3, "captured_at": "2026-11-20T10:00:00+00:00",
                    "snapshot": {
                        "site_id": "branch",
                        "access_points": [{"ap_id":"branch-gw","site_id":"branch","bssid":"00:11:22:33:44:55","band":"5GHz"}],
                        "links": []
                    }
                }
            }
        ]
    },

    "consolidated_site_audit_report": {
        "sites": [{
            "site_id": "home",
            "access_points": [
                {"ap_id":"gw","name":"Gateway","bssid":"00:11:22:33:44:55","band":"5GHz"},
                {"ap_id":"ap-1","name":"Hall AP","bssid":"00:11:22:33:44:66","band":"2.4GHz"}
            ],
            "links": [{"from_ap_id":"gw","to_ap_id":"ap-1","relationship":"wired_uplink"}],
            "gateway_ap_ids": ["gw"],
            "radios": [{"radio_id":"ap-1-radio","site_id":"home","band":"5GHz","channel_width_mhz":40,"security":"WPA2","tx_power_dbm":30}],
            "radio_standards": [{"site_id":"home","band":"5GHz","channel_width_mhz":80,"security":"WPA3","min_tx_power_dbm":5,"max_tx_power_dbm":23}],
            "gateways": [{"gateway_id":"gw-a","site_id":"home","group_id":"edge","protocol":"vrrp","ip":"192.168.1.1","state":"active"}],
            "segments": [{"segment_id":"main","site_id":"home","cidr":"192.168.1.0/24","in_use_count":240,"reserved_count":5}]
        }]
    },
    "router_agent_capability_negotiation": {
        "adapter_id": "openwrt",
        "agent_version": "1.2.0",
        "advertised_capabilities": ["system.board", "system.health", "network.interfaces", "wireless.radios", "wireless.scan_results"],
        "requested_capabilities": ["system.board", "wireless.radios", "wireless.config.write"],
        "requested_permissions": ["read", "config.write"]
    },
    "openwrt_snapshot_normalizer": {
        "system_health": {
            "uptime_seconds": 1234,
            "load_average": {"1m": 1.0, "5m": 0.5, "15m": 0.25},
            "memory_bytes": {"total":1048576,"free":524288,"shared":8192,"buffered":16384,"available":540672,"cached":32768},
            "swap_bytes": {"total":262144,"free":131072}
        },
        "captured_at": "2026-11-20T10:00:00+11:00",
        "board": {"model":"Example OpenWrt Router","hostname":"router","kernel":"6.6.1","release":{"distribution":"OpenWrt","version":"24.10.0","target":"qualcommax/ipq807x"}},
        "interfaces": [{"interface":"lan","device":"br-lan","proto":"static","up":True,"ipv4-address":[{"address":"192.168.1.1","mask":24}]}],
        "wireless": [{"interface":"phy0-ap0","ssid":"Home","bssid":"00:11:22:33:44:55","frequency_mhz":2437,"channel":6,"channel_width_mhz":20,"signal":-52,"noise":-95,"txpower":20,"security":"WPA3","up":True,"password":"must-never-be-copied"}],
        "associations": [{"interface":"phy0-ap0","stations":[{"mac":"AA:BB:CC:DD:EE:01","signal":-61,"tx":{"rate":600},"rx":{"rate":433}}]}],
        "routes": [{"target":"0.0.0.0/0","nexthop":"192.168.1.254","device":"eth1","metric":10}]
    },
    "router_agent_health_report": {
        "now": "2026-11-20T10:00:00Z",
        "stale_after_seconds": 180,
        "agents": [
            {"agent_id":"openwrt-home","adapter_id":"openwrt","agent_version":"1.2.0","status":"healthy","last_seen_at":"2026-11-20T09:59:30Z","capabilities":["system.board","network.interfaces"]},
            {"agent_id":"openwrt-branch","adapter_id":"openwrt","agent_version":"1.0.0","status":"degraded","last_seen_at":"2026-11-20T09:50:00Z","capabilities":["system.board"]}
        ]
    }
,
    "openwrt_agent_snapshot_ingest": {
        "agent_id": "openwrt-home",
        "snapshot": {
            "captured_at":"2026-11-20T10:00:00Z",
            "board":{"model":"OpenWrt sample","release":{"distribution":"OpenWrt","version":"24.10.0"}},
            "interfaces":[{"interface":"lan","ipv4-address":[{"address":"192.168.1.1","mask":24}]}],
            "wireless":[{"interface":"phy0-ap0","ssid":"Home","bssid":"00:11:22:33:44:55","frequency_mhz":5180,"channel":36,"channel_width_mhz":80,"password":"never-store-me"}],
            "associations":[],
            "routes":[{"target":"0.0.0.0/0","nexthop":"192.168.1.1","device":"eth0"}]
        }
    }
,
    "openwrt_agent_snapshot_diff": {
        "previous": {
            "id": 10, "captured_at": "2026-11-20T09:00:00Z",
            "snapshot": {
                "adapter_id":"openwrt",
                "board":{"model":"Example router","kernel":"6.6.1"},
                "interfaces":[{"interface":"lan","device":"br-lan","protocol":"static","up":True,"ipv4_addresses":["192.168.1.1/24"],"ipv6_addresses":[]}],
                "wireless_radios":[{"interface":"phy0-ap0","ssid":"Home","bssid":"00:11:22:33:44:55","band":"5GHz","channel":36,"frequency_mhz":5180,"channel_width_mhz":80,"tx_power_dbm":20,"signal_dbm":-50,"noise_dbm":-95,"security":"WPA3","up":True}],
                "associations":[],
                "routes":[{"target":"0.0.0.0/0","gateway":"192.168.1.1","device":"eth0","metric":10}]
            }
        },
        "current": {
            "id": 11, "captured_at": "2026-11-20T10:00:00Z",
            "snapshot": {
                "adapter_id":"openwrt",
                "board":{"model":"Example router","kernel":"6.6.2"},
                "interfaces":[{"interface":"lan","device":"br-lan","protocol":"static","up":False,"ipv4_addresses":["192.168.1.1/24"],"ipv6_addresses":[]}],
                "wireless_radios":[{"interface":"phy0-ap0","ssid":"Home","bssid":"00:11:22:33:44:55","band":"5GHz","channel":40,"frequency_mhz":5200,"channel_width_mhz":80,"tx_power_dbm":20,"signal_dbm":-51,"noise_dbm":-95,"security":"WPA3","up":True}],
                "associations":[{"interface":"phy0-ap0","client_mac":"AA:BB:CC:DD:EE:01","signal_dbm":-60,"tx_rate_mbps":433,"rx_rate_mbps":600}],
                "routes":[{"target":"0.0.0.0/0","gateway":"192.168.1.254","device":"eth0","metric":10}]
            }
        }
    }
,
    "router_agent_credential_scope": {
        "agent_id": "openwrt-home",
        "adapter_id": "openwrt",
        "agent_version": "1.2.0",
        "advertised_capabilities": ["system.board", "inventory.snapshot", "network.interfaces"],
        "requested_capabilities": ["system.board", "inventory.snapshot"],
        "requested_permissions": ["read"]
    }
,
    "openwrt_snapshot_delivery_envelope": {
        "agent_id": "openwrt-home",
        "delivery_id": "6c6329b5-8611-4c45-8926-5d6a85bc9f7d",
        "snapshot": {
            "captured_at":"2026-11-20T10:00:00Z",
            "board":{"model":"OpenWrt sample","release":{"distribution":"OpenWrt","version":"24.10.0"}},
            "interfaces":[{"interface":"lan","ipv4-address":[{"address":"192.168.1.1","mask":24}]}],
            "wireless":[{"interface":"phy0-ap0","ssid":"Home","bssid":"00:11:22:33:44:55","frequency_mhz":5180,"channel":36,"channel_width_mhz":80,"password":"never-store-me"}],
            "associations":[],
            "routes":[{"target":"0.0.0.0/0","nexthop":"192.168.1.1","device":"eth0"}]
        }
    }
,
    "unifi_snapshot_normalizer": {
        "captured_at": "2026-11-20T10:00:00Z",
        "controller": {"model": "Cloud Gateway", "version": "9.0.1"},
        "devices": [{
            "_id": "ap-office", "mac": "00:11:22:33:44:55", "name": "Office AP",
            "model": "U7 Pro", "state": 1,
            "radio_table": [
                {"radio": "ng", "channel": 6, "ht": "HT20"},
                {"radio": "na", "channel": 36, "ht": "VHT80"}
            ]
        }],
        "clients": [{
            "mac": "aa:bb:cc:dd:ee:01", "ap_mac": "00:11:22:33:44:55",
            "essid": "Office", "signal": -57
        }],
        "networks": [{
            "_id": "network-office", "name": "Office", "vlan": 20,
            "ip_subnet": "192.0.2.0/24"
        }]
    },
    "router_scheduled_report_planner": {
        "now": "2026-11-20T00:00:00Z",
        "schedules": [{
            "schedule_id": "daily-home", "report_id": "weekly-home",
            "timezone": "Australia/Sydney", "frequency": "daily", "local_time": "18:30"
        }],
        "occurrences_per_schedule": 3
    },
    "router_webhook_subscription_router": {
        "subscriptions": [{
            "subscription_id": "home-health",
            "endpoint": "https://hooks.example.net/router/events",
            "allowed_hosts": ["hooks.example.net"],
            "key_id": "webhook-key-01",
            "event_types": ["router.health"],
            "minimum_severity": "warning",
            "site_allowlist": ["home"],
            "maximum_events_per_batch": 100,
            "maximum_batches": 10
        }],
        "events": [{
            "event_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "event_type": "router.health",
            "severity": "warning",
            "occurred_at": "2026-11-20T10:00:00Z",
            "site_id": "home",
            "router_id": "openwrt-home",
            "summary": "CPU pressure crossed warning threshold",
            "attributes": {"observed": 90, "threshold": 85}
        }]
    },
    "router_scheduled_report_delivery_package": {
        "now": "2026-11-20T10:00:00Z",
        "claimed_job": {
            "id": 1,
            "schedule_id": _SAMPLE_DELIVERY_SCHEDULE,
            "occurrence_id": _SAMPLE_DELIVERY_OCCURRENCE,
            "report_id": _SAMPLE_DELIVERY_REPORT_ID,
            "job_key": _SAMPLE_DELIVERY_JOB_KEY,
            "payload_hash": _SAMPLE_DELIVERY_PAYLOAD_HASH,
            "status": "leased",
            "lease_id": "00000000-0000-4000-8000-000000000001",
            "lease_owner": "sample-worker",
            "lease_expires_at": "2026-11-20T10:02:00Z",
            "report_bundle": _SAMPLE_DELIVERY_REPORT
        },
        "webhook": {
            "endpoint": "https://hooks.example.net/reports",
            "allowed_hosts": ["hooks.example.net"],
            "key_id": "sample-key",
            "signing_secret": "sample-webhook-secret-with-at-least-32-bytes"
        },
        "egress_evidence": {
            "resolution_at": "2026-11-20T09:59:55Z",
            "connected_at": "2026-11-20T10:00:00Z",
            "resolved_addresses": ["1.1.1.1", "2606:4700:4700::1111"],
            "peer_ip": "1.1.1.1",
            "connected_port": 443,
            "tls_version": "TLSv1.3",
            "tls_verified": True,
            "hostname_verified": True,
            "redirect_location": None
        }
    },
    "router_scheduled_report_job_intake": {
        "schedule_id": "daily-home",
        "occurrence_id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "scheduled_at": "2026-11-20T10:05:00Z",
        "report_bundle": build_report_bundle({
            "report_id": "weekly-home",
            "title": "Weekly router report",
            "generated_at": "2026-11-20T10:00:00Z",
            "sources": [{
                "source_id": "health-home",
                "source_type": "router_fleet_health_audit",
                "result": {"status": "audited", "summary": {"router_count": 1}, "routers": []}
            }]
        })
    },
    "router_webhook_egress_policy_verifier": {
        "endpoint": "https://hooks.example.net/router/events",
        "allowed_hosts": ["hooks.example.net"],
        "resolution_at": "2026-11-20T09:59:55Z",
        "connected_at": "2026-11-20T10:00:00Z",
        "resolved_addresses": ["1.1.1.1", "2606:4700:4700::1111"],
        "peer_ip": "1.1.1.1",
        "connected_port": 443,
        "tls_version": "TLSv1.3",
        "tls_verified": True,
        "hostname_verified": True,
        "redirect_location": None
    },
    "router_encrypted_report_archive": {
        "mode": "encrypt",
        "archive_id": "sample-backup-001",
        "created_at": "2026-11-20T10:00:00Z",
        "passphrase": "test-only-passphrase-for-encrypted-report-backup",
        "data": {
            "reports": [{"report_id": "weekly-home", "content_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}],
            "alerts": [{"alert_key": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "status": "acknowledged"}]
        }
    },
    "router_webhook_envelope_builder": {
        "now": "2026-11-20T10:00:00Z",
        "batch_id": "batch-sample",
        "key_id": "router-webhook-v1",
        "signing_secret": "test-only-secret-that-is-longer-than-thirty-two-bytes",
        "endpoint": "https://hooks.example.net/router/events",
        "allowed_hosts": ["hooks.example.net"],
        "events": [{
            "event_id": "event-sample", "event_type": "router.health.warning",
            "severity": "warning", "occurred_at": "2026-11-20T10:00:00Z",
            "site_id": "home", "router_id": "openwrt-home",
            "summary": "Router health warning", "attributes": {"observed": 91, "threshold": 85}
        }]
    },
    "router_audit_report_comparator": {
        "previous": {
                "schema_version": "1.0",
                "report_id": "sample-before",
                "title": "Sample router report",
                "generated_at": "2026-11-20T09:00:00+00:00",
                "period": {
                        "start": None,
                        "end": None
                },
                "filters": {
                        "site_allowlist": [],
                        "include_details": True,
                        "maximum_findings": 10
                },
                "summary": {
                        "source_count": 1,
                        "site_count": 0,
                        "finding_count": 0,
                        "critical_count": 0,
                        "warning_count": 0,
                        "info_count": 0,
                        "detail_count": 0,
                        "details_truncated": False
                },
                "sites": [],
                "sections": [
                        {
                                "source_id": "health",
                                "source_type": "router_fleet_health_audit",
                                "title": "Router fleet health",
                                "status": "audited",
                                "summary": {
                                        "router_count": 0
                                },
                                "finding_count": 0,
                                "findings_truncated": False
                        }
                ],
                "findings": [],
                "note": "This bundle contains allow-listed summaries and normalized finding evidence only. Raw snapshots, credentials, unknown fields, and untrusted source messages are not copied. Findings retain the limitations of their source audits and do not prove root cause or live reachability.",
                "content_hash": "71a6510ce8ac63d14947641b2e9689c8ac55f6a8e3ae40464b8f543079b08154"
        },
        "current": {
                "schema_version": "1.0",
                "report_id": "sample-after",
                "title": "Sample router report",
                "generated_at": "2026-11-20T10:00:00+00:00",
                "period": {
                        "start": None,
                        "end": None
                },
                "filters": {
                        "site_allowlist": [],
                        "include_details": True,
                        "maximum_findings": 10
                },
                "summary": {
                        "source_count": 1,
                        "site_count": 0,
                        "finding_count": 0,
                        "critical_count": 0,
                        "warning_count": 0,
                        "info_count": 0,
                        "detail_count": 0,
                        "details_truncated": False
                },
                "sites": [],
                "sections": [
                        {
                                "source_id": "health",
                                "source_type": "router_fleet_health_audit",
                                "title": "Router fleet health",
                                "status": "audited",
                                "summary": {
                                        "router_count": 0
                                },
                                "finding_count": 0,
                                "findings_truncated": False
                        }
                ],
                "findings": [],
                "note": "This bundle contains allow-listed summaries and normalized finding evidence only. Raw snapshots, credentials, unknown fields, and untrusted source messages are not copied. Findings retain the limitations of their source audits and do not prove root cause or live reachability.",
                "content_hash": "7ba5f846dbca3a65cd1e48e1863924a382ebafb425f78a0fc8f9b059346271fa"
        },
        "maximum_details": 10,
        "include_details": True
    },
    "router_audit_report_bundle_builder": {
        "report_id": "weekly-home",
        "title": "Weekly router audit",
        "generated_at": "2026-11-20T10:00:00Z",
        "period_start": "2026-11-19T00:00:00Z",
        "period_end": "2026-11-20T10:00:00Z",
        "sources": [{
            "source_id": "fleet-home",
            "source_type": "router_fleet_health_audit",
            "result": {
                "status": "audited",
                "summary": {"router_count": 1, "site_count": 1, "critical_count": 1},
                "routers": [{
                    "router_id": "openwrt-home",
                    "site_id": "home",
                    "findings": [{
                        "code": "resource.cpu_critical",
                        "severity": "critical",
                        "resource_type": "router",
                        "resource_id": "openwrt-home",
                        "observed": 99,
                        "threshold": 95
                    }]
                }]
            }
        }]
    },
    "router_incident_alert_policy_evaluator": {
        "generated_at": "2026-11-20T10:00:00Z",
        "policies": [{
            "policy_id": "router-health",
            "match_codes": ["resource.cpu_high", "resource.cpu_critical"],
            "minimum_severity": "warning",
            "group_by": "router"
        }],
        "findings": [
            {
                "site_id": "home", "router_id": "openwrt-home", "adapter_id": "openwrt",
                "code": "resource.cpu_high", "severity": "warning",
                "resource_type": "router", "resource_id": "openwrt-home",
                "observed": 91, "threshold": 85
            },
            {
                "site_id": "branch", "router_id": "mikrotik-branch", "adapter_id": "mikrotik",
                "code": "resource.cpu_critical", "severity": "critical",
                "resource_type": "router", "resource_id": "mikrotik-branch",
                "observed": 99, "threshold": 95
            }
        ]
    },
    "router_gateway_redundancy_audit": {
        "snapshots": [
            {
                "router_id": "openwrt-office",
                "site_id": "office",
                "snapshot": {
                    "adapter_id": "openwrt",
                    "captured_at": "2026-11-20T10:00:00Z",
                    "routes": [{
                        "target": "0.0.0.0/0", "gateway": "192.0.2.1",
                        "device": "wan", "metric": 10
                    }]
                }
            },
            {
                "router_id": "mikrotik-office",
                "site_id": "office",
                "snapshot": {
                    "adapter_id": "mikrotik",
                    "captured_at": "2026-11-20T10:00:00Z",
                    "routes": [{
                        "target": "0.0.0.0/0", "gateway": "198.51.100.1",
                        "gateway_interface": "ether1", "routing_table": "main",
                        "distance": 1, "active": True
                    }]
                }
            }
        ]
    },
    "router_vlan_segmentation_audit": {
        "snapshots": [
            {
                "router_id": "unifi-controller",
                "site_id": "office",
                "snapshot": {
                    "adapter_id": "unifi",
                    "captured_at": "2026-11-20T10:00:00Z",
                    "controller": {"hostname": "unifi.office.local"},
                    "networks": [{
                        "id": "office", "name": "Office", "vlan_enabled": True,
                        "vlan_id": 20, "ip_subnet": "192.0.2.0/24"
                    }]
                }
            },
            {
                "router_id": "mikrotik-switch",
                "site_id": "office",
                "snapshot": {
                    "adapter_id": "mikrotik",
                    "captured_at": "2026-11-20T10:00:00Z",
                    "interfaces": [{"name": "bridge", "type": "bridge"}],
                    "vlans": [{
                        "name": "vlan20", "interface": "bridge", "interface_known": True,
                        "vlan_id": 20, "running": True
                    }],
                    "addresses": [{"interface": "vlan20", "network": "192.0.2.0/24"}]
                }
            }
        ]
    },
    "router_route_table_audit": {
        "snapshots": [
            {
                "router_id": "openwrt-gateway",
                "site_id": "home",
                "snapshot": {
                    "adapter_id": "openwrt",
                    "captured_at": "2026-11-20T10:00:00Z",
                    "interfaces": [{"interface": "lan", "ipv4_addresses": ["192.0.2.2/24"]}],
                    "routes": [{
                        "target": "0.0.0.0/0", "gateway": "192.0.2.1",
                        "device": "wan", "metric": 10
                    }]
                }
            },
            {
                "router_id": "mikrotik-branch",
                "site_id": "branch",
                "snapshot": {
                    "adapter_id": "mikrotik",
                    "captured_at": "2026-11-20T10:00:00Z",
                    "addresses": [{"interface": "ether1", "network": "198.51.100.0/24"}],
                    "routes": [{
                        "target": "0.0.0.0/0", "gateway": "198.51.100.1",
                        "gateway_interface": "ether1", "routing_table": "main",
                        "distance": 1, "active": True
                    }]
                }
            }
        ]
    },
    "router_client_roaming_audit": {
        "snapshots": [{
            "router_id": "unifi-office",
            "site_id": "office",
            "snapshot": {
                "adapter_id": "unifi",
                "captured_at": "2026-11-20T10:00:00Z",
                "controller": {"hostname": "unifi.office.local"},
                "associations": [{
                    "client_mac": "AA:BB:CC:DD:EE:01",
                    "ap_mac": "00:11:22:33:44:55",
                    "ssid": "Office",
                    "signal_dbm": -55,
                    "is_wired": False
                }]
            }
        }]
    },
    "router_subnet_overlap_audit": {
        "snapshots": [
            {
                "router_id": "openwrt-gateway", "site_id": "home",
                "snapshot": {
                    "adapter_id": "openwrt", "captured_at": "2026-11-20T10:00:00Z",
                    "interfaces": [{"interface": "lan", "ipv4_addresses": ["192.0.2.1/24"]}]
                }
            },
            {
                "router_id": "unifi-controller", "site_id": "home",
                "snapshot": {
                    "adapter_id": "unifi", "captured_at": "2026-11-20T10:00:00Z",
                    "controller": {"hostname": "unifi.home.local"},
                    "networks": [{"id": "lan", "name": "LAN", "ip_subnet": "192.0.2.0/24"}]
                }
            }
        ]
    },
    "router_fleet_health_audit": {
        "now": "2026-11-20T10:00:00Z",
        "snapshots": [{
            "router_id": "office-router",
            "site_id": "office",
            "snapshot": {
                "adapter_id": "unifi",
                "captured_at": "2026-11-20T09:59:00Z",
                "controller": {"hostname": "unifi.office.local"},
                "access_points": [{"mac": "00:11:22:33:44:55", "status": "online"}],
                "wireless_radios": [{"ap_mac": "00:11:22:33:44:55", "radio": "na", "up": True}],
                "associations": [{"client_mac": "AA:BB:CC:DD:EE:01", "signal_dbm": -55}]
            }
        }]
    },
    "router_snapshot_drift_report": {
        "previous": {
            "adapter_id": "unifi", "captured_at": "2026-11-20T09:00:00Z",
            "access_points": [{"mac": "00:11:22:33:44:55", "name": "Office AP", "ip_address": "192.0.2.10"}],
            "wireless_radios": [{"ap_mac": "00:11:22:33:44:55", "radio": "ng", "channel": 1}],
            "associations": [], "networks": [{"id": "office", "name": "Office", "vlan_id": 10}]
        },
        "current": {
            "adapter_id": "unifi", "captured_at": "2026-11-20T10:00:00Z",
            "access_points": [{"mac": "00:11:22:33:44:55", "name": "Office AP", "ip_address": "192.0.2.11"}],
            "wireless_radios": [{"ap_mac": "00:11:22:33:44:55", "radio": "ng", "channel": 6}],
            "associations": [{"client_mac": "AA:BB:CC:DD:EE:01", "ap_mac": "00:11:22:33:44:55"}],
            "networks": [{"id": "office", "name": "Office", "vlan_id": 20}]
        }
    },
    "mikrotik_snapshot_normalizer": {
        "captured_at": "2026-11-20T06:00:00Z",
        "router": {"board_name": "MikroTik hAP ax3", "version": "7.17.2"},
        "resource": {"cpu_load": "12", "free_memory": "100", "total_memory": "200"},
        "interfaces": [{"name": "bridge", "type": "bridge", "running": True}],
        "wireless": [{
            "name": "wifi1", "ssid": "Lab", "band": "5ghz-ax",
            "channel": "36", "channel_width": "80mhz", "running": True
        }],
        "registrations": [{
            "mac_address": "AA:BB:CC:DD:EE:01",
            "interface": "wifi1", "signal_strength": "-61"
        }],
        "addresses": [{"interface": "bridge", "address": "192.0.2.1/24"}],
        "vlans": [{"name": "vlan20", "interface": "bridge", "vlan_id": "20"}],
        "dhcp_leases": [{
            "address": "192.0.2.25", "mac_address": "AA:BB:CC:DD:EE:01",
            "status": "bound"
        }]
    },
    "router_agent_negotiation_audit": {
        "agent_id": "openwrt-home",
        "adapter_id": "openwrt",
        "agent_version": "1.2.0",
        "adapter_version": "0.1.0",
        "capability_schema_version": "1.0",
        "advertised_capabilities": ["system.board", "network.interfaces", "wireless.radios"],
        "requested_capabilities": ["system.board", "wireless.radios"],
        "negotiated_capabilities": ["system.board", "wireless.radios"],
        "rejected_capabilities": [],
        "requested_permissions": ["read"],
        "negotiated_permissions": ["read"],
        "rejected_permissions": [],
        "permission": "read"
    }
}


class FeatureCatalogTests(unittest.TestCase):
    def test_registered_feature_ids_are_unique_and_catalogued(self):
        entries = catalog()
        self.assertEqual(len(FEATURE_MODULES), 188)
        self.assertEqual(len(set(FEATURE_MODULES)), 188)
        self.assertEqual(count(), 188)
        self.assertEqual(len(entries), 188)
        self.assertEqual(len({entry["slug"] for entry in entries}), 188)
        self.assertEqual(
            [entry["id"] for entry in entries],
            [f"F{i:03d}" for i in range(1, 169)]
            + ["F172", "F173", "F174", "F175", "F176", "F177", "F178", "F179", "F180", "F181", "F182", "F183", "F184", "F185", "F186", "F187", "F188", "F189", "F190", "F191"],
        )

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


    def test_floorplan_anchor_validation_reports_collocation_and_unanchored_aps(self):
        result = run("floor_plan_anchor_validation", {
            "floorplans": [{"floorplan_id": "level-1", "site_id": "home"}],
            "access_points": [{"ap_id": "a", "site_id": "home"}, {"ap_id": "b", "site_id": "home"}, {"ap_id": "c", "site_id": "home"}],
            "anchors": [
                {"ap_id": "a", "floorplan_id": "level-1", "x": 0.25, "y": 0.5},
                {"ap_id": "b", "floorplan_id": "level-1", "x": 0.25, "y": 0.5},
                {"ap_id": "missing-ap", "floorplan_id": "level-1", "x": 0.8, "y": 0.8}
            ]
        })["result"]
        self.assertEqual(result["anchor_count"], 2)
        self.assertEqual(result["unanchored_access_points"], ["c"])
        self.assertEqual(len(result["collocated_anchor_groups"]), 1)
        self.assertEqual(len(result["unresolved_anchors"]), 1)

    def test_floorplan_pixel_anchor_must_be_within_image_dimensions(self):
        with self.assertRaisesRegex(ValueError, "within floor-plan bounds"):
            run("floor_plan_anchor_validation", {
                "floorplans": [{"floorplan_id": "level-1", "site_id": "home", "width_px": 100, "height_px": 100}],
                "access_points": [{"ap_id": "a", "site_id": "home"}],
                "anchors": [{"ap_id": "a", "floorplan_id": "level-1", "coordinate_space": "pixels", "x": 101, "y": 50}]
            })

    def test_floorplan_ap_can_have_only_one_anchor_per_floorplan(self):
        with self.assertRaisesRegex(ValueError, "only one anchor"):
            run("floor_plan_anchor_validation", {
                "floorplans": [{"floorplan_id": "level-1", "site_id": "home"}],
                "access_points": [{"ap_id": "a", "site_id": "home"}],
                "anchors": [
                    {"ap_id": "a", "floorplan_id": "level-1", "x": 0.1, "y": 0.1},
                    {"ap_id": "a", "floorplan_id": "level-1", "x": 0.2, "y": 0.2}
                ]
            })


    def test_site_inventory_diff_reports_added_removed_changes_and_moves(self):
        result = run("site_inventory_snapshot_diff", {
            "previous": [
                {"bssid": "00:11:22:33:44:55", "site_id": "home", "channel": 36},
                {"bssid": "00:11:22:33:44:66", "site_id": "home"}
            ],
            "current": [
                {"bssid": "00:11:22:33:44:55", "site_id": "remote", "channel": 40},
                {"bssid": "00:11:22:33:44:77", "site_id": "home"}
            ]
        })["result"]
        self.assertEqual(len(result["added"]), 1)
        self.assertEqual(len(result["removed"]), 1)
        self.assertEqual(len(result["changed"]), 1)
        self.assertEqual(len(result["site_moves"]), 1)

    def test_site_segment_capacity_uses_only_supplied_counts(self):
        result = run("site_network_segment_capacity", {
            "segments": [
                {"segment_id": "main", "cidr": "192.168.1.0/24", "in_use_count": 200, "reserved_count": 5},
                {"segment_id": "unknown", "cidr": "192.168.2.0/24"}
            ]
        })["result"]
        self.assertEqual(result["segments"][0]["usable_capacity"], 254)
        self.assertEqual(result["segments"][0]["status"], "warning")
        self.assertEqual(result["unknown_segment_count"], 1)
        self.assertIsNone(result["segments"][1]["utilisation_pct"])

    def test_gateway_redundancy_audit_reports_missing_standby(self):
        result = run("site_gateway_redundancy_audit", {
            "gateways": [
                {"gateway_id": "a", "site_id": "home", "group_id": "g1", "protocol": "vrrp", "ip": "192.168.1.1", "state": "active"}
            ]
        })["result"]
        self.assertIn("no_confirmed_standby_gateway", result["groups"][0]["issues"])

    def test_floorplan_zones_identify_ambiguous_overlaps(self):
        result = run("floorplan_zone_assignment", {
            "zones": [
                {"floorplan_id": "f1", "zone_id": "a", "polygon": [{"x":0,"y":0},{"x":0.6,"y":0},{"x":0.6,"y":1},{"x":0,"y":1}]},
                {"floorplan_id": "f1", "zone_id": "b", "polygon": [{"x":0.4,"y":0},{"x":1,"y":0},{"x":1,"y":1},{"x":0.4,"y":1}]}
            ],
            "anchors": [
                {"ap_id": "left", "floorplan_id": "f1", "x":0.2,"y":0.5},
                {"ap_id": "overlap", "floorplan_id": "f1", "x":0.5,"y":0.5}
            ]
        })["result"]
        self.assertEqual(result["assigned_count"], 1)
        self.assertEqual(result["ambiguous_count"], 1)


    def test_topology_redundancy_finds_bridge_links_and_articulation_aps(self):
        result = run("site_topology_redundancy_audit", {
            "access_points": [{"ap_id": key} for key in "abcde"],
            "links": [
                {"from_ap_id": "a", "to_ap_id": "b", "relationship": "wired_uplink"},
                {"from_ap_id": "b", "to_ap_id": "c", "relationship": "wired_uplink"},
                {"from_ap_id": "c", "to_ap_id": "a", "relationship": "mesh_backhaul"},
                {"from_ap_id": "c", "to_ap_id": "d", "relationship": "wired_uplink"},
                {"from_ap_id": "a", "to_ap_id": "e", "relationship": "rf_neighbor"}
            ]
        })["result"]
        self.assertEqual(result["component_count"], 2)
        self.assertEqual(result["critical_access_points"], ["c"])
        self.assertEqual(result["critical_links"], [
            {"from_ap_id": "c", "to_ap_id": "d", "impact": "disconnects_component_if_removed"}
        ])
        self.assertEqual(result["rf_neighbor_links_excluded"], 1)

    def test_topology_diff_reports_ap_and_link_changes(self):
        result = run("site_topology_snapshot_diff", {
            "previous": {
                "access_points": [{"ap_id": "a", "site_id": "home"}, {"ap_id": "b", "site_id": "home"}],
                "links": [{"from_ap_id": "a", "to_ap_id": "b", "relationship": "wired_uplink"}]
            },
            "current": {
                "access_points": [{"ap_id": "a", "site_id": "remote"}, {"ap_id": "c", "site_id": "home"}],
                "links": [{"from_ap_id": "a", "to_ap_id": "c", "relationship": "mesh_backhaul"}]
            }
        })["result"]
        self.assertEqual(len(result["added_access_points"]), 1)
        self.assertEqual(len(result["removed_access_points"]), 1)
        self.assertEqual(len(result["changed_access_points"]), 1)
        self.assertEqual(result["added_link_count"], 1)
        self.assertEqual(result["removed_link_count"], 1)



    def test_cross_site_inventory_reports_bssid_collisions_and_missing_bands(self):
        result = run("site_inventory_comparison", {
            "access_points": [
                {"bssid": "00:11:22:33:44:55", "site_id": "home", "band": "5GHz"},
                {"bssid": "00:11:22:33:44:55", "site_id": "branch", "band": "2.4GHz"}
            ]
        })["result"]
        self.assertEqual(result["site_count"], 2)
        self.assertEqual(result["collision_count"], 1)
        self.assertEqual(result["cross_site_comparison"]["sites_missing_each_band"]["6GHz"], ["branch", "home"])

    def test_ap_freshness_separates_stale_unknown_and_future_records(self):
        result = run("ap_observation_freshness_audit", {
            "now": "2026-11-20T10:00:00Z",
            "stale_after_seconds": 900,
            "access_points": [
                {"ap_id": "stale", "last_seen": "2026-11-20T09:30:00Z"},
                {"ap_id": "fresh", "last_seen": "2026-11-20T09:59:00Z"},
                {"ap_id": "unknown"},
                {"ap_id": "future", "last_seen": "2026-11-20T10:01:00Z"}
            ]
        })["result"]
        self.assertEqual(result["status_counts"], {"fresh": 1, "stale": 1, "unknown": 1, "future_timestamp": 1})

    def test_site_channel_reuse_audit_reports_cochannel_and_adjacent_overlap(self):
        result = run("site_ap_channel_reuse_audit", {
            "radios": [
                {"radio_id": "r1", "ap_id": "a", "site_id": "home", "band": "2.4GHz", "channel": 1, "channel_width_mhz": 20},
                {"radio_id": "r2", "ap_id": "b", "site_id": "home", "band": "2.4GHz", "channel": 3, "channel_width_mhz": 20},
                {"radio_id": "r3", "ap_id": "c", "site_id": "home", "band": "2.4GHz", "channel": 1, "channel_width_mhz": 20}
            ]
        })["result"]
        self.assertEqual(result["co_channel_conflict_count"], 1)
        self.assertEqual(result["adjacent_overlap_count"], 2)

    def test_wide_channel_reuse_requires_center_frequency_evidence(self):
        with self.assertRaisesRegex(ValueError, "center_channel or center_frequency_mhz"):
            run("site_ap_channel_reuse_audit", {
                "radios": [{"radio_id": "r1", "ap_id": "a", "site_id": "home", "band": "5GHz", "channel": 36, "channel_width_mhz": 80}]
            })


    def test_site_topology_history_timeline_reports_snapshot_changes(self):
        result = run("site_topology_history_timeline", {
            "snapshots": [
                {
                    "captured_at": "2026-11-20T09:00:00Z",
                    "access_points": [
                        {"ap_id": "a", "site_id": "home", "name": "Hall"},
                        {"ap_id": "b", "site_id": "home", "name": "Office"},
                    ],
                    "links": [
                        {"from_ap_id": "a", "to_ap_id": "b", "relationship": "wired_uplink"}
                    ],
                },
                {
                    "captured_at": "2026-11-20T10:00:00+00:00",
                    "access_points": [
                        {"ap_id": "a", "site_id": "remote", "name": "Hall"},
                        {"ap_id": "c", "site_id": "home", "name": "Garage"},
                    ],
                    "links": [
                        {"from_ap_id": "a", "to_ap_id": "c", "relationship": "mesh_backhaul"}
                    ],
                },
            ]
        })["result"]
        self.assertEqual(result["summary"]["snapshot_count"], 2)
        self.assertEqual(result["summary"]["comparison_count"], 1)
        self.assertEqual(result["summary"]["total_topology_changes"], 5)
        window = result["change_windows"][0]
        self.assertEqual(window["interval_seconds"], 3600.0)
        self.assertEqual(window["added_access_points"][0]["ap_id"], "c")
        self.assertEqual(window["removed_access_points"][0]["ap_id"], "b")
        self.assertEqual(window["changed_access_points"][0]["ap_id"], "a")
        self.assertEqual(window["added_links"][0]["relationship"], "mesh_backhaul")
        self.assertEqual(window["removed_links"][0]["relationship"], "wired_uplink")

    def test_site_topology_history_timeline_rejects_non_monotonic_or_naive_times(self):
        with self.assertRaisesRegex(ValueError, "strictly increasing"):
            run("site_topology_history_timeline", {
                "snapshots": [
                    {"captured_at": "2026-11-20T10:00:00Z"},
                    {"captured_at": "2026-11-20T10:00:00+00:00"},
                ]
            })
        with self.assertRaisesRegex(ValueError, "timezone offset"):
            run("site_topology_history_timeline", {
                "snapshots": [{"captured_at": "2026-11-20T10:00:00"}]
            })

    def test_site_topology_history_timeline_validates_a_single_snapshot(self):
        result = run("site_topology_history_timeline", {
            "snapshots": [{
                "captured_at": "2026-11-20T10:00:00Z",
                "access_points": [{"ap_id": "a"}],
            }]
        })["result"]
        self.assertEqual(result["summary"]["snapshot_count"], 1)
        self.assertEqual(result["summary"]["comparison_count"], 0)
        self.assertEqual(result["summary"]["total_topology_changes"], 0)


    def test_site_gateway_path_audit_distinguishes_reachable_unreachable_and_unknown(self):
        result = run("site_topology_gateway_path_audit", {
            "access_points": [
                {"ap_id": "gw", "site_id": "home"},
                {"ap_id": "ap-2", "site_id": "home"},
                {"ap_id": "isolated", "site_id": "home"},
                {"ap_id": "remote", "site_id": "branch"},
            ],
            "gateway_ap_ids": ["gw"],
            "links": [
                {"from_ap_id": "gw", "to_ap_id": "ap-2", "relationship": "wired_uplink"},
                {"from_ap_id": "gw", "to_ap_id": "isolated", "relationship": "rf_neighbor"},
                {"from_ap_id": "ap-2", "to_ap_id": "remote", "relationship": "mesh_backhaul"},
            ],
        })["result"]
        self.assertEqual(result["summary"]["reachable_count"], 2)
        self.assertEqual(result["summary"]["unreachable_count"], 1)
        self.assertEqual(result["summary"]["unknown_count"], 1)
        self.assertEqual(result["summary"]["excluded_rf_neighbor_link_count"], 1)
        self.assertEqual(result["summary"]["excluded_cross_site_link_count"], 1)
        by_id = {item["ap_id"]: item for item in result["access_points"]}
        self.assertEqual(by_id["ap-2"]["path_ap_ids"], ["ap-2", "gw"])
        self.assertEqual(by_id["ap-2"]["path_relationships"], ["wired_uplink"])
        self.assertEqual(by_id["isolated"]["status"], "unreachable")
        self.assertEqual(by_id["remote"]["status"], "unknown")

    def test_site_gateway_path_audit_rejects_duplicate_gateways_and_preserves_unknown_ids(self):
        payload = {
            "access_points": [{"ap_id": "gw", "site_id": "home"}],
            "links": [],
        }
        with self.assertRaisesRegex(ValueError, "must be unique"):
            run("site_topology_gateway_path_audit", {**payload, "gateway_ap_ids": ["gw", "gw"]})
        result = run("site_topology_gateway_path_audit", {
            **payload, "gateway_ap_ids": ["missing"]
        })["result"]
        self.assertEqual(result["summary"]["unknown_gateway_ap_ids"], ["missing"])
        self.assertEqual(result["access_points"][0]["status"], "unknown")


    def test_site_radio_configuration_audit_applies_site_overrides_and_wildcard_defaults(self):
        result = run("site_radio_configuration_audit", PAYLOADS["site_radio_configuration_audit"])["result"]
        by_id = {item["radio_id"]: item for item in result["radios"]}
        self.assertEqual(by_id["home-5g"]["status"], "compliant")
        self.assertEqual(by_id["branch-5g"]["status"], "deviation")
        self.assertEqual(
            {item["field"] for item in by_id["branch-5g"]["deviations"]},
            {"channel_width_mhz", "security", "tx_power_dbm"},
        )
        self.assertEqual(by_id["guest-24g"]["status"], "no_standard")
        self.assertEqual(result["compliant_count"], 1)
        self.assertEqual(result["deviation_count"], 1)
        self.assertEqual(result["unknown_count"], 1)

    def test_site_radio_configuration_audit_keeps_missing_measurements_unknown(self):
        result = run("site_radio_configuration_audit", {
            "radios": [{"radio_id": "ap-1-radio-1", "site_id": "home", "band": "5GHz"}],
            "standards": [{"site_id": "home", "band": "5GHz", "min_tx_power_dbm": 5}],
        })["result"]
        self.assertEqual(result["radios"][0]["status"], "unknown")
        self.assertEqual(result["radios"][0]["unknown_fields"], ["tx_power_dbm"])

    def test_site_radio_configuration_audit_rejects_duplicate_and_invalid_records(self):
        with self.assertRaisesRegex(ValueError, "radio_id values must be unique"):
            run("site_radio_configuration_audit", {
                "radios": [
                    {"radio_id": "same", "site_id": "home", "band": "5GHz"},
                    {"radio_id": "same", "site_id": "home", "band": "5GHz"},
                ],
            })
        with self.assertRaisesRegex(ValueError, "site/band standard may be declared only once"):
            run("site_radio_configuration_audit", {
                "standards": [
                    {"site_id": "home", "band": "5GHz", "security": "WPA3"},
                    {"site_id": "home", "band": "5GHz", "channel_width_mhz": 80},
                ],
            })
        with self.assertRaisesRegex(ValueError, "must be a finite number"):
            run("site_radio_configuration_audit", {
                "radios": [{"radio_id": "ap-radio", "site_id": "home", "band": "5GHz", "tx_power_dbm": float("nan")}],
                "standards": [{"site_id": "home", "band": "5GHz", "min_tx_power_dbm": 5}],
            })
        with self.assertRaisesRegex(ValueError, "must be one of"):
            run("site_radio_configuration_audit", {
                "radios": [{"radio_id": "ap-radio", "site_id": "home", "band": "60GHz"}],
            })

    def test_site_topology_visualisation_builds_site_aware_deterministic_layers(self):
        payload = PAYLOADS["site_topology_visualisation"]
        result = run("site_topology_visualisation", payload)["result"]
        by_id = {item["ap_id"]: item for item in result["nodes"]}
        self.assertEqual(by_id["gw"]["layout_depth"], 0)
        self.assertEqual(by_id["ap-a"]["layout_depth"], 1)
        self.assertEqual(by_id["ap-b"]["layout_depth"], 2)
        self.assertTrue(by_id["ap-a"]["reachable_from_gateway"])
        self.assertIsNone(by_id["branch-ap"]["reachable_from_gateway"])
        self.assertEqual(result["summary"]["physical_link_count"], 2)
        self.assertEqual(result["summary"]["rf_neighbor_link_count"], 1)
        self.assertEqual(result["summary"]["cross_site_link_count"], 1)
        self.assertEqual(result["summary"]["unresolved_link_count"], 1)
        self.assertEqual(run("site_topology_visualisation", payload)["result"]["nodes"], result["nodes"])

    def test_site_topology_visualisation_keeps_missing_gateway_paths_unknown(self):
        result = run("site_topology_visualisation", {
            "access_points": [{"ap_id": "ap-a", "site_id": "home"}, {"ap_id": "ap-b", "site_id": "home"}],
            "links": [{"from_ap_id": "ap-a", "to_ap_id": "ap-b", "relationship": "wired_uplink"}],
        })["result"]
        self.assertTrue(all(node["reachable_from_gateway"] is None for node in result["nodes"]))
        self.assertEqual(result["site_groups"][0]["unknown_reachability_count"], 2)

    def test_site_topology_visualisation_rejects_duplicate_gateways_and_unknown_relationships(self):
        base = {"access_points": [{"ap_id": "gw", "site_id": "home"}]}
        with self.assertRaisesRegex(ValueError, "gateway_ap_ids must be unique"):
            run("site_topology_visualisation", {**base, "gateway_ap_ids": ["gw", "gw"]})
        with self.assertRaisesRegex(ValueError, "relationship must be one of"):
            run("site_topology_visualisation", {
                **base,
                "links": [{"from_ap_id": "gw", "to_ap_id": "other", "relationship": "invented"}],
            })

    def test_site_discovery_history_snapshot_normalises_site_and_timestamp(self):
        result = run("site_discovery_history_snapshot", {
            "site_id": " home ",
            "captured_at": "2026-11-20T10:00:00+11:00",
            "access_points": [{"ap_id": "ap-1", "name": "Hall"}],
            "links": [],
        })["result"]
        self.assertEqual(result["site_id"], "home")
        self.assertEqual(result["captured_at"], "2026-11-19T23:00:00+00:00")
        self.assertEqual(result["access_points"][0]["site_id"], "home")
        self.assertEqual(result["access_point_count"], 1)

    def test_site_discovery_history_snapshot_rejects_cross_site_aps_and_naive_timestamps(self):
        base = {"site_id": "home", "captured_at": "2026-11-20T10:00:00Z"}
        with self.assertRaisesRegex(ValueError, "different site"):
            run("site_discovery_history_snapshot", {
                **base, "access_points": [{"ap_id": "ap-1", "site_id": "branch"}],
            })
        with self.assertRaisesRegex(ValueError, "timezone"):
            run("site_discovery_history_snapshot", {
                "site_id": "home", "captured_at": "2026-11-20T10:00:00",
            })

    def test_site_to_site_change_report_compares_site_drift_and_cross_site_bssid_reuse(self):
        result = run("site_to_site_change_report", PAYLOADS["site_to_site_change_report"])["result"]
        self.assertEqual(result["summary"]["site_count"], 2)
        self.assertEqual(result["summary"]["sites_with_baseline"], 1)
        self.assertEqual(result["summary"]["sites_without_baseline"], 1)
        self.assertEqual(result["summary"]["added_access_point_count"], 1)
        self.assertEqual(result["summary"]["removed_access_point_count"], 1)
        self.assertEqual(result["summary"]["added_link_count"], 1)
        self.assertEqual(result["summary"]["removed_link_count"], 1)
        self.assertEqual(result["summary"]["cross_site_bssid_collision_count"], 1)
        home = next(item for item in result["sites"] if item["site_id"] == "home")
        self.assertEqual(home["changes"]["added_access_points"][0]["ap_id"], "new")
        self.assertEqual(home["changes"]["removed_access_points"][0]["ap_id"], "old")

    def test_site_to_site_change_report_handles_first_baseline_and_rejects_duplicate_sites(self):
        initial = run("site_to_site_change_report", {
            "sites": [{
                "site_id": "new-site", "previous": None,
                "current": {"snapshot": {"site_id": "new-site", "access_points": [], "links": []}},
            }]
        })["result"]
        self.assertEqual(initial["sites"][0]["baseline_status"], "initial_snapshot")
        with self.assertRaisesRegex(ValueError, "site_id values must be unique"):
            run("site_to_site_change_report", {
                "sites": [
                    {"site_id": "home", "current": {"snapshot": {"site_id": "home", "access_points": [], "links": []}}},
                    {"site_id": "home", "current": {"snapshot": {"site_id": "home", "access_points": [], "links": []}}},
                ]
            })

    def test_consolidated_site_audit_reuses_site_tools_and_aggregates_findings(self):
        result = run("consolidated_site_audit_report", PAYLOADS["consolidated_site_audit_report"])["result"]
        self.assertEqual(result["summary"]["site_count"], 1)
        self.assertEqual(result["summary"]["access_point_count"], 2)
        checks = result["sites"][0]["checks"]
        self.assertEqual(checks["inventory"]["status"], "complete")
        self.assertEqual(checks["topology_relationships"]["status"], "complete")
        self.assertEqual(checks["gateway_paths"]["status"], "complete")
        self.assertEqual(checks["radio_configuration"]["result"]["deviation_count"], 1)
        self.assertEqual(checks["gateway_redundancy"]["status"], "complete")
        self.assertEqual(checks["segment_capacity"]["status"], "complete")
        self.assertGreaterEqual(result["summary"]["warning_count"], 1)
        self.assertEqual(result["cross_site_inventory"]["status"], "complete")

    def test_consolidated_site_audit_marks_missing_evidence_not_run_and_rejects_duplicate_sites(self):
        result = run("consolidated_site_audit_report", {
            "sites": [{"site_id": "home", "access_points": [{"name": "AP without ID"}]}]
        })["result"]
        self.assertEqual(result["sites"][0]["checks"]["topology_redundancy"]["status"], "not_run")
        self.assertEqual(result["sites"][0]["checks"]["gateway_paths"]["status"], "not_run")
        self.assertGreater(result["summary"]["not_run_check_count"], 0)
        with self.assertRaisesRegex(ValueError, "site_id values must be unique"):
            run("consolidated_site_audit_report", {
                "sites": [
                    {"site_id": "home", "access_points": []},
                    {"site_id": "home", "access_points": []},
                ]
            })

    def test_router_agent_capability_negotiation_intersects_read_only_capabilities(self):
        result = run("router_agent_capability_negotiation", PAYLOADS["router_agent_capability_negotiation"])["result"]
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["negotiated_capabilities"], ["system.board", "wireless.radios"])
        self.assertEqual(result["negotiated_permissions"], ["read"])
        self.assertEqual(result["rejected_capabilities"][0]["reason"], "not_supported_by_adapter")
        self.assertEqual(result["rejected_permissions"][0]["reason"], "adapter_is_read_only")

    def test_router_agent_capability_negotiation_rejects_old_agents_and_unknown_adapters(self):
        old = run("router_agent_capability_negotiation", {
            "adapter_id": "openwrt", "agent_version": "0.9.0",
            "advertised_capabilities": ["system.board"],
            "requested_capabilities": ["system.board"],
        })["result"]
        self.assertEqual(old["status"], "version_incompatible")
        self.assertEqual(old["negotiated_capabilities"], [])
        unknown = run("router_agent_capability_negotiation", {
            "adapter_id": "future-router", "agent_version": "1.0.0",
            "requested_capabilities": ["system.board"],
        })["result"]
        self.assertEqual(unknown["status"], "unsupported_adapter")

    def test_router_agent_capability_negotiation_validates_versions_and_duplicate_caps(self):
        with self.assertRaisesRegex(ValueError, "major.minor.patch"):
            run("router_agent_capability_negotiation", {
                "adapter_id": "openwrt", "agent_version": "1.0",
            })
        with self.assertRaisesRegex(ValueError, "must be unique"):
            run("router_agent_capability_negotiation", {
                "adapter_id": "openwrt", "agent_version": "1.0.0",
                "advertised_capabilities": ["system.board", "system.board"],
            })

    def test_openwrt_snapshot_normalizer_maps_common_fields_and_drops_unrecognised_data(self):
        result = run("openwrt_snapshot_normalizer", PAYLOADS["openwrt_snapshot_normalizer"])["result"]
        self.assertEqual(result["captured_at"], "2026-11-19T23:00:00+00:00")
        self.assertEqual(result["board"]["distribution"], "OpenWrt")
        self.assertEqual(result["interfaces"][0]["ipv4_addresses"], ["192.168.1.1/24"])
        self.assertEqual(result["wireless_radios"][0]["band"], "2.4GHz")
        self.assertEqual(result["associations"][0]["rx_rate_mbps"], 433)
        self.assertEqual(result["routes"][0]["gateway"], "192.168.1.254")
        self.assertNotIn("password", result["wireless_radios"][0])
        self.assertEqual(result["summary"]["association_count"], 1)
        self.assertEqual(result["system_health"]["uptime_seconds"], 1234)
        self.assertEqual(result["system_health"]["load_average"]["1m"], 1.0)
        self.assertEqual(result["system_health"]["memory_bytes"]["available"], 540672)
        self.assertNotIn("secret", json.dumps(result["system_health"]))

    def test_openwrt_snapshot_normalizer_rejects_invalid_addresses_timestamps_and_bounds(self):
        with self.assertRaisesRegex(ValueError, "timezone offset"):
            run("openwrt_snapshot_normalizer", {"captured_at":"2026-11-20T10:00:00","board":{}})
        with self.assertRaisesRegex(ValueError, "valid BSSID"):
            run("openwrt_snapshot_normalizer", {"captured_at":"2026-11-20T10:00:00Z","wireless":[{"interface":"wlan0","bssid":"invalid"}]})
        with self.assertRaisesRegex(ValueError, "IPv4 interface address"):
            run("openwrt_snapshot_normalizer", {"captured_at":"2026-11-20T10:00:00Z","interfaces":[{"interface":"lan","ipv4-address":[{"address":"999.1.1.1","mask":24}]}]})

    def test_openwrt_snapshot_normalizer_rejects_invalid_system_health_values(self):
        base = {
            "captured_at":"2026-11-20T10:00:00Z",
            "system_health":{
                "uptime_seconds":10,
                "load_average":{"1m":0.5,"5m":0.4,"15m":0.3},
                "memory_bytes":{"total":1024,"free":512},
                "swap_bytes":{"total":0,"free":0},
            },
        }
        with self.assertRaisesRegex(ValueError, "load_average.1m"):
            run("openwrt_snapshot_normalizer", {
                **base,
                "system_health":{**base["system_health"],"load_average":{"1m":-0.1,"5m":0.4,"15m":0.3}},
            })
        with self.assertRaisesRegex(ValueError, "free cannot exceed total"):
            run("openwrt_snapshot_normalizer", {
                **base,
                "system_health":{**base["system_health"],"memory_bytes":{"total":1024,"free":2048}},
            })
        with self.assertRaisesRegex(ValueError, "uptime_seconds"):
            run("openwrt_snapshot_normalizer", {
                **base,
                "system_health":{**base["system_health"],"uptime_seconds":True},
            })

    def test_router_agent_health_report_classifies_healthy_degraded_and_stale_agents(self):
        result = run("router_agent_health_report", PAYLOADS["router_agent_health_report"])["result"]
        self.assertEqual(result["summary"]["agent_count"], 2)
        by_id = {agent["agent_id"]: agent for agent in result["agents"]}
        self.assertEqual(by_id["openwrt-home"]["health_status"], "healthy")
        self.assertEqual(by_id["openwrt-branch"]["health_status"], "stale")
        self.assertEqual(result["summary"]["status_counts"]["stale"], 1)

    def test_router_agent_health_report_rejects_naive_times_duplicate_ids_and_bad_thresholds(self):
        with self.assertRaisesRegex(ValueError, "timezone offset"):
            run("router_agent_health_report", {"now":"2026-11-20T10:00:00","agents":[]})
        with self.assertRaisesRegex(ValueError, "unique"):
            run("router_agent_health_report", {"now":"2026-11-20T10:00:00Z","agents":[
                {"agent_id":"a","status":"healthy","last_seen_at":"2026-11-20T09:59:59Z"},
                {"agent_id":"a","status":"healthy","last_seen_at":"2026-11-20T09:59:58Z"},
            ]})
        with self.assertRaisesRegex(ValueError, "between 10 and 86400"):
            run("router_agent_health_report", {"now":"2026-11-20T10:00:00Z","stale_after_seconds":5})

    def test_openwrt_agent_snapshot_ingest_normalises_envelope_and_drops_secret_fields(self):
        result = run("openwrt_agent_snapshot_ingest", PAYLOADS["openwrt_agent_snapshot_ingest"])["result"]
        self.assertEqual(result["agent_id"], "openwrt-home")
        self.assertEqual(result["snapshot"]["adapter_id"], "openwrt")
        self.assertEqual(result["summary"]["wireless_radio_count"], 1)
        self.assertNotIn("password", result["snapshot"]["wireless_radios"][0])

    def test_openwrt_agent_snapshot_ingest_rejects_invalid_agent_identity(self):
        with self.assertRaisesRegex(ValueError, "agent_id"):
            run("openwrt_agent_snapshot_ingest", {
                "agent_id":"../admin", "snapshot":{"captured_at":"2026-11-20T10:00:00Z"}
            })

    def test_openwrt_agent_snapshot_diff_reports_board_interface_radio_client_and_route_changes(self):
        result = run("openwrt_agent_snapshot_diff", PAYLOADS["openwrt_agent_snapshot_diff"])["result"]
        self.assertEqual(result["status"], "compared")
        self.assertEqual(result["previous_snapshot_id"], 10)
        self.assertEqual(result["current_snapshot_id"], 11)
        self.assertEqual(result["summary"]["board_changed_field_count"], 1)
        self.assertEqual(result["summary"]["interface_changed"], 1)
        self.assertEqual(result["summary"]["radio_changed"], 1)
        self.assertEqual(result["summary"]["association_added"], 1)
        self.assertEqual(result["summary"]["route_changed"], 1)
        self.assertEqual(result["changes"]["wireless_radios"]["changed"][0]["identity"]["interface"], "phy0-ap0")

    def test_openwrt_agent_snapshot_diff_marks_initial_baseline_and_rejects_duplicate_interfaces(self):
        current = PAYLOADS["openwrt_agent_snapshot_diff"]["current"]
        initial = run("openwrt_agent_snapshot_diff", {"current": current})["result"]
        self.assertEqual(initial["status"], "initial_snapshot")
        self.assertEqual(initial["summary"]["total_changes"], 0)
        duplicate = {
            "adapter_id":"openwrt", "captured_at":"2026-11-20T10:00:00Z",
            "interfaces":[{"interface":"lan"},{"interface":"lan"}],
        }
        with self.assertRaisesRegex(ValueError, "duplicate identities"):
            run("openwrt_agent_snapshot_diff", {
                "current":{"snapshot":duplicate,"captured_at":"2026-11-20T10:00:00Z"}
            })

    def test_router_agent_credential_scope_accepts_only_supported_read_capabilities(self):
        result = run("router_agent_credential_scope", PAYLOADS["router_agent_credential_scope"])["result"]
        self.assertEqual(result["agent_id"], "openwrt-home")
        self.assertEqual(result["permission"], "read")
        self.assertEqual(result["allowed_capabilities"], ["inventory.snapshot", "system.board"])

    def test_router_agent_credential_scope_rejects_write_and_unknown_capabilities(self):
        with self.assertRaisesRegex(ValueError, "read permission"):
            run("router_agent_credential_scope", {
                **PAYLOADS["router_agent_credential_scope"],
                "requested_permissions": ["read", "config.write"],
            })
        with self.assertRaisesRegex(ValueError, "not fully supported"):
            run("router_agent_credential_scope", {
                **PAYLOADS["router_agent_credential_scope"],
                "requested_capabilities": ["system.board", "wireless.config.write"],
            })

    def test_openwrt_snapshot_delivery_envelope_normalises_uuid_and_snapshot(self):
        result = run("openwrt_snapshot_delivery_envelope", PAYLOADS["openwrt_snapshot_delivery_envelope"])["result"]
        self.assertEqual(result["agent_id"], "openwrt-home")
        self.assertEqual(result["delivery_id"], "6c6329b5-8611-4c45-8926-5d6a85bc9f7d")
        self.assertEqual(result["summary"]["wireless_radio_count"], 1)
        self.assertNotIn("password", result["snapshot"]["wireless_radios"][0])

    def test_openwrt_snapshot_delivery_envelope_rejects_invalid_ids(self):
        with self.assertRaisesRegex(ValueError, "UUID"):
            run("openwrt_snapshot_delivery_envelope", {
                "agent_id":"openwrt-home","delivery_id":"not-a-uuid",
                "snapshot":{"captured_at":"2026-11-20T10:00:00Z"},
            })
        with self.assertRaisesRegex(ValueError, "agent_id"):
            run("openwrt_snapshot_delivery_envelope", {
                "agent_id":"../admin","delivery_id":"6c6329b5-8611-4c45-8926-5d6a85bc9f7d",
                "snapshot":{"captured_at":"2026-11-20T10:00:00Z"},
            })

    def test_router_agent_negotiation_audit_preserves_versioned_read_only_scope(self):
        result = run("router_agent_negotiation_audit", PAYLOADS["router_agent_negotiation_audit"])["result"]
        self.assertEqual(result["adapter_id"], "openwrt")
        self.assertEqual(result["adapter_version"], "0.1.0")
        self.assertEqual(result["capability_schema_version"], "1.0")
        self.assertEqual(result["negotiated_capabilities"], ["system.board", "wireless.radios"])
        self.assertEqual(result["negotiated_permissions"], ["read"])
        self.assertEqual(result["rejected_capabilities"], [])
        self.assertEqual(result["permission"], "read")

    def test_router_agent_negotiation_audit_rejects_write_permissions_and_unadvertised_scopes(self):
        payload = PAYLOADS["router_agent_negotiation_audit"]
        with self.assertRaisesRegex(ValueError, "read permission"):
            run("router_agent_negotiation_audit", {**payload, "requested_permissions":["read","config.write"]})
        with self.assertRaisesRegex(ValueError, "both requested and advertised"):
            run("router_agent_negotiation_audit", {
                **payload,
                "negotiated_capabilities":["system.board","network.routes"],
            })
        with self.assertRaisesRegex(ValueError, "version syntax"):
            run("router_agent_negotiation_audit", {**payload, "adapter_version":"v0.1"})

if __name__ == "__main__":
    unittest.main()
