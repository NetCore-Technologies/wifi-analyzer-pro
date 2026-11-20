# 100 WiFi Analyzer Pro feature tools

The tool API is exposed at `GET /api/features` and `POST /api/features/{slug}`. Each module has a stable F-number; modules are grouped in pairs across the 50 feature commits. Tools are read-only; network-changing actions are deliberately excluded.

| ID | Feature | Category | Description |
|---:|---|---|---|
| F001 | Interface inventory (`interface_inventory`) | Discovery | List local interfaces, addresses, status and MTU. |
| F002 | Wireless interface inventory (`wireless_interface_inventory`) | Discovery | Find Linux wireless interfaces without assuming a specific adapter name. |
| F003 | Wi-Fi scan execution (`wifi_scan`) | Discovery | Trigger the existing platform scanner or validate supplied scan observations. |
| F004 | Normalise BSSID (`normalise_bssid`) | Scan data | Validate and canonicalise a BSSID/MAC address. |
| F005 | Normalise SSID (`normalise_ssid`) | Scan data | Remove control characters and preserve hidden SSIDs as an empty string. |
| F006 | Classify frequency band (`classify_frequency_band`) | RF analysis | Map a frequency in MHz to 2.4, 5 or 6 GHz. |
| F007 | Frequency to channel (`frequency_to_channel`) | RF analysis | Convert a Wi-Fi frequency in MHz to its channel number. |
| F008 | Channel to frequency (`channel_to_frequency`) | RF analysis | Convert a channel to MHz when its band is specified. |
| F009 | Signal quality score (`signal_quality`) | RF analysis | Calculate a bounded 0–100 RSSI quality score. |
| F010 | Signal strength class (`classify_signal`) | RF analysis | Classify RSSI using conservative signal-strength bands. |
| F011 | Measured SNR (`measured_snr`) | RF analysis | Calculate SNR only when a real noise measurement was supplied. |
| F012 | Sort by signal (`sort_networks_by_signal`) | Scan data | Sort detected access points from strongest to weakest RSSI. |
| F013 | Filter by band (`filter_networks_by_band`) | Scan data | Filter the current scan by 2.4, 5 or 6 GHz. |
| F014 | Filter by security (`filter_networks_by_security`) | Scan data | Filter networks by a security label, case-insensitively. |
| F015 | Open access points (`open_access_points`) | Security | List networks that advertise no link-layer security. |
| F016 | WPA3 access points (`wpa3_access_points`) | Security | List networks advertising WPA3 or SAE. |
| F017 | Hidden SSIDs (`hidden_networks`) | Scan data | List BSS entries that do not disclose an SSID. |
| F018 | Deduplicate scan (`deduplicate_scan`) | Scan data | Keep one record per BSSID, preferring the strongest observation. |
| F019 | Compare scans (`scan_delta`) | Scan history | Compare current and previous scans by BSSID. |
| F020 | Scan summary (`scan_summary`) | Scan data | Summarise network counts, bands, security and average measured RSSI. |
| F021 | Strongest networks (`strongest_networks`) | Scan data | Return the top N strongest networks. |
| F022 | Weakest networks (`weakest_networks`) | Scan data | Return the weakest N networks to identify edge-of-coverage APs. |
| F023 | Group by SSID (`group_by_ssid`) | Scan data | Group BSS records by visible SSID, preserving hidden entries separately. |
| F024 | Strongest BSSID per SSID (`strongest_per_ssid`) | Scan data | Select the strongest BSSID observation for each SSID. |
| F025 | OUI vendor lookup (`oui_vendor_lookup`) | Discovery | Resolve common locally bundled OUI prefixes without making a network call. |
| F026 | Locally administered MAC check (`locally_administered_mac`) | Security | Inspect the locally-administered and multicast bits in a MAC address. |
| F027 | Randomised MAC indicator (`randomized_mac_detect`) | Security | Flag MAC addresses whose locally-administered bit is set. |
| F028 | Channel congestion map (`channel_congestion`) | RF planning | Count nearby BSS and adjacent 2.4 GHz channel overlap. |
| F029 | 2.4 GHz overlap analysis (`overlap_24ghz`) | RF planning | Estimate co-channel and adjacent-channel overlap using 20 MHz channel spacing. |
| F030 | Recommend 2.4 GHz channel (`recommend_24ghz_channel`) | RF planning | Rank channels 1, 6 and 11 by observed adjacent BSS count. |
| F031 | Recommend 5 GHz channel (`recommend_5ghz_channel`) | RF planning | Rank common non-DFS 5 GHz channels by observed occupancy. |
| F032 | Recommend 6 GHz channel (`recommend_6ghz_channel`) | RF planning | Rank 6 GHz preferred scanning channels by observed occupancy. |
| F033 | Channel quality score (`channel_quality`) | RF planning | Calculate relative channel score from observed congestion counts. |
| F034 | DFS channel check (`dfs_channel_detect`) | RF planning | Identify common 5 GHz DFS channels. |
| F035 | 6 GHz PSC check (`six_ghz_psc_detect`) | RF planning | Check whether a 6 GHz channel is a Preferred Scanning Channel. |
| F036 | Recommend channel width (`recommend_channel_width`) | RF planning | Suggest a conservative channel width using observations from the selected band. |
| F037 | Band distribution (`band_distribution`) | RF planning | Count BSS entries in each Wi-Fi band. |
| F038 | Security distribution (`security_distribution`) | Security | Count observed networks by advertised security label. |
| F039 | Vendor distribution (`vendor_distribution`) | Discovery | Count networks by locally known OUI vendor prefix. |
| F040 | Parse iw scan output (`parse_iw_scan`) | Parsers | Parse Linux iw BSS blocks into structured network observations. |
| F041 | Parse iwlist scan output (`parse_iwlist_scan`) | Parsers | Parse common iwlist scan cells. |
| F042 | Parse Windows netsh scan output (`parse_netsh_scan`) | Parsers | Parse netsh wlan show networks mode=bssid text. |
| F043 | Parse macOS airport scan output (`parse_airport_scan`) | Parsers | Parse the legacy airport -s tabular output. |
| F044 | Parse macOS system_profiler JSON (`parse_system_profiler`) | Parsers | Extract nearby wireless networks from system_profiler JSON. |
| F045 | Parse iw station dump (`parse_station_dump`) | Parsers | Extract station counters from iw station dump output. |
| F046 | Parse iw link (`parse_iw_link`) | Parsers | Extract connected SSID, BSSID, frequency and signal from iw link. |
| F047 | Parse ethtool link details (`parse_ethtool`) | Parsers | Parse speed, duplex, link state and autonegotiation from ethtool output. |
| F048 | Parse Linux IPv4 default route (`parse_route_table`) | Parsers | Extract gateway and interface from ip route output. |
| F049 | Parse Linux ARP/neighbour table (`parse_arp_linux`) | Parsers | Parse common arp -an output into IP/MAC pairs. |
| F050 | Parse Windows ARP table (`parse_arp_windows`) | Parsers | Parse arp -a IPv4 entries on Windows. |
| F051 | Parse resolv.conf (`parse_resolv_conf`) | Parsers | Extract valid nameserver IPs from resolv.conf text. |
| F052 | Parse ping output (`parse_ping_output`) | Parsers | Extract transmitted, received, loss and RTT summary from ping text. |
| F053 | Parse traceroute output (`parse_traceroute`) | Parsers | Extract hop number, host and RTT samples from traceroute text. |
| F054 | Validate network record (`validate_network_record`) | Data quality | Validate essential fields and report missing/invalid observations. |
| F055 | Validate scan payload (`validate_scan`) | Data quality | Check a list of network records and return valid/invalid counts. |
| F056 | Subnet summary (`subnet_summary`) | Diagnostics | Summarise an IPv4 or IPv6 interface/CIDR. |
| F057 | IP in subnet check (`ip_in_subnet`) | Diagnostics | Check whether an address belongs to a supplied subnet. |
| F058 | Default gateway lookup (`default_gateway_from_route`) | Diagnostics | Extract the first default gateway from supplied route output. |
| F059 | DNS server extraction (`dns_servers_from_config`) | Diagnostics | Collect DNS resolver addresses from resolv.conf or supplied list. |
| F060 | Reverse DNS lookup (`reverse_dns_lookup`) | Diagnostics | Resolve a supplied IP address using the system resolver. |
| F061 | DNS lookup timing (`dns_lookup_timing`) | Diagnostics | Time a hostname lookup using the system resolver. |
| F062 | Latency summary (`latency_summary`) | Diagnostics | Summarise latency samples with min, median, p95 and max. |
| F063 | Packet loss calculator (`packet_loss_calculator`) | Diagnostics | Calculate packet loss percentage from sent and received counters. |
| F064 | Jitter calculator (`jitter_calculator`) | Diagnostics | Calculate mean absolute consecutive RTT variation. |
| F065 | Interface counter delta (`interface_counter_delta`) | Diagnostics | Calculate monotonic counter deltas and handle counter resets. |
| F066 | Interface throughput (`interface_throughput`) | Diagnostics | Calculate RX/TX throughput in Mbps from byte-counter snapshots. |
| F067 | Packet error rate (`packet_error_rate`) | Diagnostics | Compute RX/TX error ratio from interface packet counters. |
| F068 | URL inspection (`inspect_url`) | Diagnostics | Validate a URL scheme and return parsed host, port and path without fetching it. |
| F069 | TLS certificate expiry (`tls_certificate_expiry`) | Diagnostics | Read the expiry date of a TLS certificate with a short connection timeout. |
| F070 | Security strength rank (`security_rank`) | Security | Rank a network security mode from open through WPA3. |
| F071 | Security warnings (`security_warnings`) | Security | Generate transparent warnings for open, WEP and legacy WPA observations. |
| F072 | Rogue AP candidates (`rogue_ap_candidates`) | Security | Flag same-SSID BSSIDs that are not in a supplied trusted BSSID list. |
| F073 | Evil-twin similarity check (`evil_twin_candidates`) | Security | Find different BSSIDs advertising the same non-empty SSID. |
| F074 | Duplicate BSSID check (`duplicate_bssid_check`) | Security | Detect duplicate BSSID records in one scan. |
| F075 | Weak signal alerts (`weak_signal_alerts`) | Alerts | Generate alerts for networks below a configurable RSSI threshold. |
| F076 | Open Wi-Fi alerts (`open_wifi_alerts`) | Alerts | Create alert records for open access points. |
| F077 | WPA2/WPA3 transition mode (`transition_mode_detect`) | Security | Identify networks advertising both SAE and PSK transition security. |
| F078 | Redact MAC address (`redact_mac`) | Privacy | Mask the final three octets of a MAC address for sharing. |
| F079 | Redact SSID (`redact_ssid`) | Privacy | Replace visible SSIDs with stable labels for sharing. |
| F080 | Anonymise scan (`anonymise_scan`) | Privacy | Redact SSIDs and BSSIDs before exporting a scan. |
| F081 | Stable SSID hash (`ssid_hash`) | Privacy | Create a non-reversible SHA-256 fingerprint of an SSID. |
| F082 | Scan fingerprint (`scan_fingerprint`) | Privacy | Fingerprint a canonicalised scan for integrity/change tracking. |
| F083 | Alert severity classifier (`alert_severity`) | Alerts | Assign a severity for common Wi-Fi alert types. |
| F084 | Deduplicate alerts (`deduplicate_alerts`) | Alerts | Remove repeated alerts by type, BSSID and message. |
| F085 | Alert threshold evaluator (`alert_threshold`) | Alerts | Compare a numeric metric with a configured warning/critical threshold. |
| F086 | Export JSON (`export_json`) | Reports | Serialise current networks and optional metadata as formatted JSON. |
| F087 | Export CSV (`export_csv`) | Reports | Export network records as RFC-compliant CSV. |
| F088 | Export HTML report (`export_html`) | Reports | Generate an escaped standalone HTML table report from scan observations. |
| F089 | Prometheus scan metrics (`prometheus_metrics`) | Integrations | Export counts and RSSI gauges in Prometheus text format. |
| F090 | Network health report (`network_report`) | Reports | Build a concise evidence-based report from supplied live observations. |
| F091 | Trim signal history window (`history_window`) | History | Return only the most recent N signal history samples. |
| F092 | Signal trend (`signal_trend`) | History | Estimate signal trend from ordered RSSI samples using least-squares slope. |
| F093 | Signal percentiles (`signal_percentiles`) | History | Calculate RSSI p10, median and p90 for the provided sample set. |
| F094 | Rank channels (`channel_rank`) | RF planning | Rank observed channel occupancy within a requested band. |
| F095 | Format bytes (`format_bytes`) | Utilities | Format a byte count using IEC units. |
| F096 | Format duration (`format_duration`) | Utilities | Format elapsed seconds as days, hours, minutes and seconds. |
| F097 | Safe filename (`safe_filename`) | Utilities | Normalise a name for a local export filename. |
| F098 | Validate application settings (`validate_settings`) | Utilities | Validate polling and scan settings before saving. |
| F099 | Backend health report (`health_report`) | System | Return runtime version, mode and feature-plugin count. |
| F100 | Wi-Fi generation classifier (`wifi_generation_classify`) | RF analysis | Infer the highest advertised PHY generation from supplied PHY capability flags. |

## Authentication and UI

The app now has first-run local password setup, login, logout, expiring in-memory bearer sessions, failed-login lockout, and a searchable feature workbench. The password verifier is stored under `~/.config/wifi-analyzer-pro/auth.json` with restrictive permissions; it is never written to the repository. The backend API is protected after setup. An expired bearer token clears the browser session and returns the UI to the sign-in screen. For LAN/remote access, continue to use a VPN or authenticated reverse proxy and explicitly configure allowed CORS origins.

## Important measurement caveats

- Channel scores are relative BSS-count heuristics, not airtime utilisation measurements.
- Rogue/evil-twin checks identify candidates only; matching SSIDs across multiple BSSIDs is normal in mesh and enterprise deployments.
- SNR is calculated only if a real noise measurement is present.
- Vendor identification uses a small bundled OUI subset and may return Unknown.
- DNS and TLS probes perform read-only lookups/connections to the host provided in the tool input.
