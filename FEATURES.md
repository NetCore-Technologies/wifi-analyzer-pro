# 170 WiFi Analyzer Pro feature tools (F001–F168, F172–F173)

The tool API is exposed at `GET /api/features` and `POST /api/features/{slug}`. Each module has a stable F-number; each feature is independently committed and callable. Tools are read-only; network-changing actions are deliberately excluded.

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

| 101 | Same-SSID band presence (`same_ssid_band_presence`) | Roaming | Group visible SSIDs by advertised band and count their BSSID observations. |
| 102 | Band-steering evidence (`band_steering_evidence`) | Roaming | Compare measured RSSI for the same SSID across bands without inferring AP steering decisions. |
| 103 | Roaming candidate ranking (`roaming_candidate_ranking`) | Roaming | Rank same-SSID BSSIDs by measured signal improvement over the connected BSSID. |
| 104 | Association roam events (`association_roam_events`) | Roaming | Diff client association snapshots and classify roam, network-change, connect and disconnect events. |
| 105 | Roaming timeline summary (`roaming_timeline_summary`) | Roaming | Summarise observed roaming and network-change events per client from association diffs. |
| 106 | Sticky-client candidates (`sticky_client_candidates`) | Roaming | Flag weak client associations when supplied AP-side observations show a stronger same-SSID alternative. |
| 107 | Association dwell summary (`association_dwell_summary`) | Roaming | Calculate per-client and per-BSSID association dwell durations from supplied timestamp intervals. |
| 108 | Roam latency summary (`roam_latency_summary`) | Roaming | Compare latency measurements before and after roaming, preserving sample counts and median values. |
| 109 | Roaming stability score (`roaming_stability_score`) | Roaming | Calculate a transparent heuristic from observed roam events per client and a chosen time window. |
| 110 | Band occupancy delta (`band_occupancy_delta`) | RF planning | Compare per-band BSS observation counts between two scans. |
| 111 | Channel width frequency range (`channel_width_frequency_range`) | RF planning | Calculate the nominal occupied frequency span for a channel centre and channel width. |
| 112 | Frequency overlap score (`frequency_overlap_score`) | RF planning | Compute frequency-span overlap between two channel observations with measured widths. |
| 113 | Channel separation ranking (`channel_separation_rank`) | RF planning | Rank candidate channel centres by minimum non-overlap separation from observed channel spans. |
| 114 | Channel overlap pairs (`channel_overlap_pairs`) | RF planning | Find overlapping nominal channel spans in a set of access-point observations. |
| 115 | DFS frequency intersection (`dfs_frequency_intersection`) | RF planning | Check whether a nominal 5 GHz channel span intersects the commonly used DFS frequency range. |
| 116 | 6 GHz PSC availability plan (`six_ghz_psc_plan`) | RF planning | List Preferred Scanning Channels not present in a supplied 6 GHz scan. |
| 117 | Wi-Fi 7 EHT capability summary (`wifi7_eht_summary`) | PHY analysis | Summarise explicitly supplied EHT and Wi-Fi 7 capability flags without inferring unsupported features. |
| 118 | Multi-Link Operation summary (`multi_link_operation_summary`) | PHY analysis | Summarise supplied Wi-Fi 7 MLO link records by active state, band and signal. |
| 119 | Protected Management Frames audit (`pmf_security_audit`) | Security | Audit explicit PMF/802.11w states from scan or controller observations. |
| 120 | Regulatory channel allowlist check (`regulatory_channel_allowlist_check`) | RF planning | Compare observed channels against an OS/controller-supplied regional allowlist. |

| 121 | Client association inventory (`client_association_inventory`) | Client operations | Join AP/controller client associations to advertised BSS records and report unmatched associations. |
| 122 | Stale client detector (`stale_client_detector`) | Client operations | Identify client records whose supplied last-seen timestamps exceed a configurable age threshold. |
| 123 | Airtime fairness summary (`airtime_fairness_summary`) | Client QoS | Calculate measured per-client airtime allocation and Jain fairness from AP/controller counters. |
| 124 | Client throughput fairness (`client_throughput_fairness`) | Client QoS | Calculate per-client transmit/receive throughput and Jain fairness from byte deltas over a measured interval. |
| 125 | DSCP traffic distribution (`dscp_traffic_distribution`) | Client QoS | Summarise packet counts by observed six-bit DSCP value from a supplied capture or controller export. |
| 126 | Application QoS policy audit (`application_qos_policy_audit`) | Client QoS | Compare observed per-application DSCP markings with an explicit operator-supplied policy map. |
| 127 | Client retry rate (`client_retry_rate`) | Client QoS | Calculate per-client retransmission ratios from AP-reported transmit and retry counters. |
| 128 | PHY rate asymmetry (`phy_rate_asymmetry`) | Client QoS | Compare measured uplink and downlink PHY rates for associated clients. |
| 129 | Client/AP capability compatibility (`client_ap_capability_match`) | Client operations | Compare advertised client and AP band/feature sets and list unsupported client requirements. |
| 130 | OFDMA and MU-MIMO evidence (`ofdma_mu_mimo_evidence`) | PHY analysis | Summarise explicit AP/controller OFDMA and MU-MIMO support and usage counters. |
| 131 | Target Wake Time summary (`twt_power_save_summary`) | PHY analysis | Summarise explicitly advertised and active 802.11ax Target Wake Time sessions. |
| 132 | 802.11k/v/r capability audit (`bss_transition_capability_audit`) | Roaming | Report explicit neighbour-report, BSS-transition and fast-transition capabilities per AP. |
| 133 | Mobility domain consistency (`mobility_domain_consistency`) | Roaming | Find same-ESS APs with missing or inconsistent 802.11r mobility-domain identifiers. |
| 134 | DHCP lease audit (`dhcp_lease_audit`) | Network operations | Find expired leases and duplicate IP or MAC assignments in a supplied DHCP lease snapshot. |
| 135 | DNS resolver latency comparison (`dns_resolver_latency_compare`) | Network operations | Compare measured resolver lookup success, median and p95 latency across supplied probes. |
| 136 | Gateway reachability matrix (`gateway_reachability_matrix`) | Network operations | Summarise reachability and latency evidence from explicit gateway/next-hop probes. |
| 137 | Roaming interruption analysis (`roaming_interruption_analysis`) | Roaming | Measure disconnect-to-reconnect interruption duration for client handover event pairs. |
| 138 | Disconnect reason summary (`disconnect_reason_summary`) | Client operations | Classify and count IEEE 802.11 disassociation/deauthentication reason codes in supplied logs. |
| 139 | Association rejection summary (`association_rejection_summary`) | Client operations | Classify IEEE 802.11 association response status codes from supplied AP/controller logs. |
| 140 | Connection health evidence (`connection_health_evidence`) | Client QoS | Flag measured per-client link quality concerns using explicit and configurable signal, retry, rate, loss and latency evidence. |

| 141 | Multi-site access-point inventory snapshot (`site_inventory_snapshot`) | Site inventory | Normalise AP inventories across sites, detect duplicate BSSIDs and report metadata coverage. |
| 142 | Access-point topology relationships (`ap_topology_relationships`) | Site inventory | Separate physical/backhaul and RF-neighbour relationships while flagging unresolved or cyclic links. |
| 143 | Site subnet and gateway correlation (`site_network_segment_correlation`) | Site inventory | Match AP management addresses to explicit site CIDRs and report ambiguous or invalid gateway relationships. |
| 144 | Floor-plan AP anchor validation (`floor_plan_anchor_validation`) | Site inventory | Validate AP floor-plan coordinates and surface missing references or collocated anchors. |
| 145 | Site inventory snapshot diff (`site_inventory_snapshot_diff`) | Site inventory | Compare AP snapshots for additions, removals, metadata changes and site moves. |
| 146 | Site network segment capacity (`site_network_segment_capacity`) | Site inventory | Calculate subnet capacity and utilisation from explicitly supplied allocation counts. |
| 147 | Site gateway redundancy audit (`site_gateway_redundancy_audit`) | Site inventory | Review gateway failover groups, duplicate addresses and reported active/standby state. |
| 148 | Floor-plan zone assignment (`floorplan_zone_assignment`) | Site inventory | Assign AP anchors to explicit room polygons and surface out-of-zone or overlapping placements. |
| 149 | Site topology redundancy audit (`site_topology_redundancy_audit`) | Site inventory | Identify physical-backhaul cut links, articulation APs and disconnected components. |
| 150 | Site topology snapshot diff (`site_topology_snapshot_diff`) | Site inventory | Compare AP inventory and explicit physical/RF topology edges between two snapshots. |
| 151 | Multi-site AP inventory comparison (`site_inventory_comparison`) | Site inventory | Compare AP counts, bands, vendors, models and firmware distributions and flag cross-site BSSID reuse. |
| 152 | AP observation freshness audit (`ap_observation_freshness_audit`) | Site inventory | Detect stale and future-dated AP observations while treating missing timestamps as unknown. |
| 153 | Site AP channel reuse audit (`site_ap_channel_reuse_audit`) | Site inventory | Identify co-channel reuse and adjacent-channel overlap from supplied same-site radio widths and centres. |
| 154 | Site topology history timeline (`site_topology_history_timeline`) | Site inventory | Summarise AP and link changes across up to 256 timestamped, caller-supplied topology snapshots. |
| 155 | Site AP-to-gateway path audit (`site_topology_gateway_path_audit`) | Site inventory | Trace AP backhaul paths to supplied gateway APs and distinguish unreachable, unknown and cross-site evidence. |
| 156 | Site radio configuration audit (`site_radio_configuration_audit`) | Site inventory | Compare AP radio channel widths, security and transmit power with explicit site/band standards; missing observations remain unknown. |
| 157 | Interactive site topology visualisation (`site_topology_visualisation`) | Site inventory | Create deterministic, per-site AP layers and typed physical/RF/cross-site links for interactive inspection in the Workbench. |
| 158 | Persistent site discovery history snapshot (`site_discovery_history_snapshot`) | Site inventory | Validate bounded timestamped AP/topology snapshots before saving to a local SQLite history database with per-site retention. |
| 159 | Site-to-site change report (`site_to_site_change_report`) | Site inventory | Compare each site’s latest two stored snapshots, report AP/topology drift, and flag BSSID reuse across sites. |
| 160 | Consolidated site audit report (`consolidated_site_audit_report`) | Site inventory | Combine inventory, topology, gateway, radio standards, subnet capacity, cross-site inventory and optional saved-history results into one evidence-based report. |
| 161 | Router agent capability negotiation (`router_agent_capability_negotiation`) | Router integrations | Negotiate versioned, advertised read-only capabilities against the OpenWrt adapter manifest and reject unsupported operations or write permissions. |
| 162 | OpenWrt snapshot normalizer (`openwrt_snapshot_normalizer`) | Router integrations | Normalise bounded board, interface, radio, station and route snapshots into a credential-free common schema. |
| 163 | Router agent health report (`router_agent_health_report`) | Router integrations | Track authenticated agent heartbeats and classify healthy, degraded, unhealthy, stale and future-dated status using server timestamps. |
| 164 | OpenWrt agent snapshot ingestion (`openwrt_agent_snapshot_ingest`) | Router integrations | Accept authenticated snapshots from registered agents, normalise before persistence, retain bounded history, and expose latest inventory data. |
| 165 | OpenWrt agent snapshot diff (`openwrt_agent_snapshot_diff`) | Router integrations | Compare retained snapshots and identify board, interface, radio, client-association and route changes. |
| 166 | Router agent credential scope (`router_agent_credential_scope`) | Router integrations | Issue per-agent, read-only scoped bearer credentials with expiry, rotation and revocation; store only token hashes. |
| 167 | OpenWrt idempotent snapshot delivery (`openwrt_snapshot_delivery_envelope`) | Router integrations | Accept UUID-keyed snapshot deliveries with safe retries, duplicate-content detection and bounded idempotency retention. |
| 168 | Router agent negotiation audit (`router_agent_negotiation_audit`) | Router integrations | Persist bounded, append-only records of adapter/schema versions and advertised, requested, negotiated and rejected read-only scopes. |


## Authentication and UI

The app now has first-run local password setup, login, logout, expiring in-memory bearer sessions, failed-login lockout, a searchable feature workbench, authenticated local site-history endpoints backed by SQLite, and a Router Agent Console for OpenWrt enrolment, health, credential lifecycle, negotiation audit, inventory and drift. The password verifier is stored under `~/.config/wifi-analyzer-pro/auth.json` with restrictive permissions; it is never written to the repository. The backend API is protected after setup. An expired bearer token clears the browser session and returns the UI to the sign-in screen. The Router Agent Console uses this existing administrator session; it never lists stored agent token hashes, and a newly issued agent token is displayed once in the current page session. For LAN/remote access, continue to use a VPN or authenticated reverse proxy and explicitly configure allowed CORS origins. Site snapshots are stored locally under the platform state directory (or `WIFI_ANALYZER_HISTORY_DB` when set), with restrictive file permissions, a 90-day default retention window and a 1,000-snapshot per-site cap.

## Important measurement caveats

- Channel scores are relative BSS-count heuristics, not airtime utilisation measurements.
- Rogue/evil-twin checks identify candidates only; matching SSIDs across multiple BSSIDs is normal in mesh and enterprise deployments.
- SNR is calculated only if a real noise measurement is present.
- Vendor identification uses a small bundled OUI subset and may return Unknown.
- DNS and TLS probes perform read-only lookups/connections to the host provided in the tool input.

| F172 | UniFi controller snapshot normalizer (`unifi_snapshot_normalizer`) | Router integrations | Import bounded, caller-supplied UniFi Network exports into the common AP, radio, client and network schema; omit secrets and make no controller connection. |
| F173 | MikroTik RouterOS snapshot normalizer (`mikrotik_snapshot_normalizer`) | Router integrations | Import bounded RouterOS exports covering board/resource health, interfaces, wireless registrations, IP addresses, VLANs and DHCP leases; omit secrets and make no router connection. |
