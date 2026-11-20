# WiFi Analyzer Pro — 50-commit implementation plan

The sequence below creates **exactly 50 signed commits** on the existing `main` branch. Commit 1 integrates the feature API, auth, UI, packaging and tests and introduces features F001–F002. Commits 2–50 each introduce exactly two feature modules. No artificial authors, dates, messages or signatures are generated.

## Commit 01 of 50
`feat: add feature engine, local login, and core discovery tools`
Integration baseline, authenticated feature registry and workbench, telemetry provenance cleanup, package/Vite fixes, packaging manifests, and tests.

## Commit 02 of 50
`feat: add wifi scan and normalise bssid`
Wi-Fi scan execution (F003) and Normalise BSSID (F004).

## Commit 03 of 50
`feat: add normalise ssid and classify frequency band`
Normalise SSID (F005) and Classify frequency band (F006).

## Commit 04 of 50
`feat: add frequency to channel and channel to frequency`
Frequency to channel (F007) and Channel to frequency (F008).

## Commit 05 of 50
`feat: add signal quality and classify signal`
Signal quality score (F009) and Signal strength class (F010).

## Commit 06 of 50
`feat: add measured snr and sort networks by signal`
Measured SNR (F011) and Sort by signal (F012).

## Commit 07 of 50
`feat: add filter networks by band and filter networks by security`
Filter by band (F013) and Filter by security (F014).

## Commit 08 of 50
`feat: add open access points and wpa3 access points`
Open access points (F015) and WPA3 access points (F016).

## Commit 09 of 50
`feat: add hidden networks and deduplicate scan`
Hidden SSIDs (F017) and Deduplicate scan (F018).

## Commit 10 of 50
`feat: add scan delta and scan summary`
Compare scans (F019) and Scan summary (F020).

## Commit 11 of 50
`feat: add strongest networks and weakest networks`
Strongest networks (F021) and Weakest networks (F022).

## Commit 12 of 50
`feat: add group by ssid and strongest per ssid`
Group by SSID (F023) and Strongest BSSID per SSID (F024).

## Commit 13 of 50
`feat: add oui vendor lookup and locally administered mac`
OUI vendor lookup (F025) and Locally administered MAC check (F026).

## Commit 14 of 50
`feat: add randomized mac detect and channel congestion`
Randomised MAC indicator (F027) and Channel congestion map (F028).

## Commit 15 of 50
`feat: add overlap 24ghz and recommend 24ghz channel`
2.4 GHz overlap analysis (F029) and Recommend 2.4 GHz channel (F030).

## Commit 16 of 50
`feat: add recommend 5ghz channel and recommend 6ghz channel`
Recommend 5 GHz channel (F031) and Recommend 6 GHz channel (F032).

## Commit 17 of 50
`feat: add channel quality and dfs channel detect`
Channel quality score (F033) and DFS channel check (F034).

## Commit 18 of 50
`feat: add six ghz psc detect and recommend channel width`
6 GHz PSC check (F035) and Recommend channel width (F036).

## Commit 19 of 50
`feat: add band distribution and security distribution`
Band distribution (F037) and Security distribution (F038).

## Commit 20 of 50
`feat: add vendor distribution and parse iw scan`
Vendor distribution (F039) and Parse iw scan output (F040).

## Commit 21 of 50
`feat: add parse iwlist scan and parse netsh scan`
Parse iwlist scan output (F041) and Parse Windows netsh scan output (F042).

## Commit 22 of 50
`feat: add parse airport scan and parse system profiler`
Parse macOS airport scan output (F043) and Parse macOS system_profiler JSON (F044).

## Commit 23 of 50
`feat: add parse station dump and parse iw link`
Parse iw station dump (F045) and Parse iw link (F046).

## Commit 24 of 50
`feat: add parse ethtool and parse route table`
Parse ethtool link details (F047) and Parse Linux IPv4 default route (F048).

## Commit 25 of 50
`feat: add parse arp linux and parse arp windows`
Parse Linux ARP/neighbour table (F049) and Parse Windows ARP table (F050).

## Commit 26 of 50
`feat: add parse resolv conf and parse ping output`
Parse resolv.conf (F051) and Parse ping output (F052).

## Commit 27 of 50
`feat: add parse traceroute and validate network record`
Parse traceroute output (F053) and Validate network record (F054).

## Commit 28 of 50
`feat: add validate scan and subnet summary`
Validate scan payload (F055) and Subnet summary (F056).

## Commit 29 of 50
`feat: add ip in subnet and default gateway from route`
IP in subnet check (F057) and Default gateway lookup (F058).

## Commit 30 of 50
`feat: add dns servers from config and reverse dns lookup`
DNS server extraction (F059) and Reverse DNS lookup (F060).

## Commit 31 of 50
`feat: add dns lookup timing and latency summary`
DNS lookup timing (F061) and Latency summary (F062).

## Commit 32 of 50
`feat: add packet loss calculator and jitter calculator`
Packet loss calculator (F063) and Jitter calculator (F064).

## Commit 33 of 50
`feat: add interface counter delta and interface throughput`
Interface counter delta (F065) and Interface throughput (F066).

## Commit 34 of 50
`feat: add packet error rate and inspect url`
Packet error rate (F067) and URL inspection (F068).

## Commit 35 of 50
`feat: add tls certificate expiry and security rank`
TLS certificate expiry (F069) and Security strength rank (F070).

## Commit 36 of 50
`feat: add security warnings and rogue ap candidates`
Security warnings (F071) and Rogue AP candidates (F072).

## Commit 37 of 50
`feat: add evil twin candidates and duplicate bssid check`
Evil-twin similarity check (F073) and Duplicate BSSID check (F074).

## Commit 38 of 50
`feat: add weak signal alerts and open wifi alerts`
Weak signal alerts (F075) and Open Wi-Fi alerts (F076).

## Commit 39 of 50
`feat: add transition mode detect and redact mac`
WPA2/WPA3 transition mode (F077) and Redact MAC address (F078).

## Commit 40 of 50
`feat: add redact ssid and anonymise scan`
Redact SSID (F079) and Anonymise scan (F080).

## Commit 41 of 50
`feat: add ssid hash and scan fingerprint`
Stable SSID hash (F081) and Scan fingerprint (F082).

## Commit 42 of 50
`feat: add alert severity and deduplicate alerts`
Alert severity classifier (F083) and Deduplicate alerts (F084).

## Commit 43 of 50
`feat: add alert threshold and export json`
Alert threshold evaluator (F085) and Export JSON (F086).

## Commit 44 of 50
`feat: add export csv and export html`
Export CSV (F087) and Export HTML report (F088).

## Commit 45 of 50
`feat: add prometheus metrics and network report`
Prometheus scan metrics (F089) and Network health report (F090).

## Commit 46 of 50
`feat: add history window and signal trend`
Trim signal history window (F091) and Signal trend (F092).

## Commit 47 of 50
`feat: add signal percentiles and channel rank`
Signal percentiles (F093) and Rank channels (F094).

## Commit 48 of 50
`feat: add format bytes and format duration`
Format bytes (F095) and Format duration (F096).

## Commit 49 of 50
`feat: add safe filename and validate settings`
Safe filename (F097) and Validate application settings (F098).

## Commit 50 of 50
`feat: add health report and wifi generation classify`
Backend health report (F099) and Wi-Fi generation classifier (F100).

