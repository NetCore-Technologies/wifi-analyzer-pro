# Scan evidence and measurement semantics

WiFi Analyzer Pro separates values reported by an operating-system adapter from values that can be derived with a documented formula. A missing adapter field remains unknown. The scanner must not substitute a typical channel, a nominal noise floor, a default RSSI, or a claimed radio capability to fill a gap.

## Platform adapters

| Adapter | Evidence accepted | Fields deliberately left unknown when absent |
|---|---|---|
| Linux iw | BSSID, SSID, frequency, primary channel when reported, signal in dBm, security information | RSSI, channel, band, frequency, noise and optional PHY capabilities |
| Linux iwlist | Cell BSSID, SSID, frequency, channel and signal level when reported | RSSI, channel, band and frequency |
| Windows netsh wlan show networks mode=bssid | BSSID, SSID, signal percentage, channel and authentication | dBm RSSI, noise, frequency and band unless output explicitly supplies a band |
| macOS airport -s | SSID, BSSID, RSSI and channel when present | Band and frequency where the output does not disambiguate them |
| macOS system_profiler | SSID, BSSID, signal/noise pair and channel/band when explicitly reported | Missing signal, noise, channel, band and frequency |

Windows signal percentage is retained separately as signal_pct; it is not converted into dBm. A percentage is not a calibrated RSSI measurement. Likewise, a channel number alone does not identify the band when channel numbering overlaps across 2.4, 5 and 6 GHz.

A channel calculated from a measured centre frequency is a deterministic conversion, not an additional independent RF measurement. RSSI quality is calculated only for a validated RSSI. SNR is calculated only when both RSSI and noise floor are measured and valid.

## Capability and security fields

An adapter that does not report WMM, HT/VHT/HE/EHT, 802.11k/v/r, DFS, PMF or multi-link operation cannot be used to assert support or lack of support for those capabilities. UI values use Not reported until a controller snapshot, management frame parser or hardware capability source supplies the evidence.

A beacon's advertised security information is not a complete enterprise configuration audit. RADIUS policy, EAP server certificate validation, segmentation and client isolation must be assessed from controller/configuration evidence, not inferred from the SSID or a simplified scan label.

## Interpretation boundaries

A BSS count on a channel is a scan observation, not airtime utilisation, interference power, channel busy time, capacity or a regulatory channel plan. An SSID observed on multiple bands does not prove the BSSIDs belong to one physical AP or that band steering is configured. An unfamiliar BSSID under a trusted SSID is a review candidate, not proof of an evil twin.

Use controller inventory, a measured site survey and country-specific radio regulatory data before making production changes.