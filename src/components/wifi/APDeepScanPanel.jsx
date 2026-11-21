import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { ChevronDown, Wifi } from 'lucide-react';
import { getSignalColor } from './SignalStrengthBar';

function measured(value, unit = '') {
  if (value === null || value === undefined || value === '') return 'Not reported';
  const number = Number(value);
  return Number.isFinite(number) ? String(number) + unit : String(value);
}

function frequency(value) {
  if (value === null || value === undefined || value === '') return 'Not reported';
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) return 'Not reported';
  return number >= 1000 ? String(number) + ' MHz' : String(number) + ' GHz';
}

function InfoRow({ label, value, mono = true, color }) {
  return (
    <div className="flex items-start justify-between gap-2 text-xs">
      <span className="text-muted-foreground flex-shrink-0">{label}</span>
      <span className={`text-right ${mono ? 'font-mono' : ''} ${color || 'text-foreground'} break-all`}>{value ?? 'Not reported'}</span>
    </div>
  );
}

function EvidenceBoolean({ value }) {
  if (value === true) return 'Supported';
  if (value === false) return 'Not supported';
  return 'Not reported by scan adapter';
}

export default function APDeepScanPanel({ networks = [] }) {
  const [expanded, setExpanded] = useState(null);
  if (!Array.isArray(networks) || networks.length === 0) {
    return <div className="glass rounded-xl p-8 text-center text-sm text-muted-foreground">No access-point observations are available for this scan.</div>;
  }

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-2">
      <p className="text-xs text-muted-foreground">
        This view shows fields actually returned by the active scan adapter. Client capabilities, channel width, noise floor and optional PHY features remain unknown when the adapter does not report them.
      </p>
      {networks.map((net, index) => {
        const color = getSignalColor(net?.rssi);
        const key = net?.bssid || (net?.ssid || 'network') + '-' + index;
        const isOpen = expanded === key;
        const security = net?.security || 'Not reported';
        const openSecurity = security === 'Open';
        const signalValue = net?.rssi === null || net?.rssi === undefined ? 'Not measured' : measured(net.rssi, ' dBm');

        return (
          <div key={key} className="glass rounded-xl overflow-hidden">
            <button type="button" aria-expanded={isOpen} aria-controls={'ap-details-' + index}
              className="w-full flex items-center justify-between p-4 text-left hover:bg-secondary/20 transition-colors"
              onClick={() => setExpanded(isOpen ? null : key)}>
              <div className="flex items-center gap-3 min-w-0">
                <div className={`p-1.5 rounded-lg ${color.bg}/10 border ${color.border}`}>
                  <Wifi className={`w-3.5 h-3.5 ${color.text}`} />
                </div>
                <div className="min-w-0">
                  <div className="font-semibold text-sm truncate">{net?.ssid || '<Hidden SSID>'}</div>
                  <div className="text-xs font-mono text-muted-foreground">
                    {net?.bssid && net.bssid !== 'N/A' ? net.bssid : 'BSSID not reported'}
                    {' · '}{net?.vendor || 'Vendor not resolved'}
                  </div>
                  <div className="text-[11px] text-muted-foreground mt-1">
                    {net?.band || 'Band unknown'} · {net?.channel == null ? 'Channel unknown' : 'Ch ' + net.channel}
                    {' · '}{security}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-3 flex-shrink-0">
                <span className={`text-sm font-mono font-bold ${color.text}`}>{signalValue}</span>
                <ChevronDown className={`w-4 h-4 text-muted-foreground transition-transform ${isOpen ? 'rotate-180' : ''}`} />
              </div>
            </button>

            <AnimatePresence>
              {isOpen && (
                <motion.div id={'ap-details-' + index} initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }} transition={{ duration: 0.2 }} className="overflow-hidden">
                  <div className="px-4 pb-4 grid grid-cols-1 sm:grid-cols-2 gap-4 border-t border-border/50 pt-4">
                    <div className="space-y-2">
                      <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Identity</h4>
                      <InfoRow label="SSID" value={net?.ssid || '<Hidden>'} mono={false} />
                      <InfoRow label="BSSID (AP MAC)" value={net?.bssid && net.bssid !== 'N/A' ? net.bssid : null} />
                      <InfoRow label="Vendor" value={net?.vendor} mono={false} />
                      <InfoRow label="Scan interface" value={net?.interface} />
                      <InfoRow label="Observation source" value={net?.source} mono={false} />
                    </div>
                    <div className="space-y-2">
                      <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Security evidence</h4>
                      <InfoRow label="Advertised security" value={security} mono={false}
                        color={openSecurity ? 'text-red-400' : security === 'Not reported' ? 'text-muted-foreground' : 'text-foreground'} />
                      <InfoRow label="Security detail" value={net?.security_detail} mono={false} />
                      <InfoRow label="Key management" value={net?.key_management || net?.key_mgmt} mono={false} />
                      <InfoRow label="PMF" value={net?.pmf_state || net?.pmf} mono={false} />
                      <InfoRow label="Hidden SSID" value={net?.ssid ? 'No' : 'Yes'} mono={false} />
                    </div>
                    <div className="space-y-2">
                      <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Radio measurements</h4>
                      <InfoRow label="Band" value={net?.band} />
                      <InfoRow label="Primary channel" value={net?.channel} />
                      <InfoRow label="Frequency" value={frequency(net?.frequency)} />
                      <InfoRow label="Channel width" value={measured(net?.channel_width_mhz, ' MHz')} />
                      <InfoRow label="RSSI" value={measured(net?.rssi, ' dBm')} color={color.text} />
                      <InfoRow label="Driver signal quality" value={measured(net?.signal_pct, '%')} />
                      <InfoRow label="Noise floor" value={measured(net?.noise, ' dBm')} />
                      <InfoRow label="Measured SNR" value={measured(net?.snr, ' dB')} />
                      <InfoRow label="RSRP" value={measured(net?.rsrp, ' dBm')} />
                      <InfoRow label="RSRQ" value={measured(net?.rsrq, ' dB')} />
                      <InfoRow label="SINR" value={measured(net?.sinr, ' dB')} />
                      <InfoRow label="TX/RX link rate" value={measured(net?.link_speed, ' Mbps')} />
                    </div>
                    <div className="space-y-2">
                      <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Capabilities (when reported)</h4>
                      <InfoRow label="802.11n / HT" value={EvidenceBoolean({ value: net?.ht_support })} mono={false} />
                      <InfoRow label="802.11ac / VHT" value={EvidenceBoolean({ value: net?.vht_support })} mono={false} />
                      <InfoRow label="802.11ax / HE" value={EvidenceBoolean({ value: net?.he_support })} mono={false} />
                      <InfoRow label="802.11be / EHT" value={EvidenceBoolean({ value: net?.eht_support })} mono={false} />
                      <InfoRow label="WMM / QoS" value={EvidenceBoolean({ value: net?.wmm_supported })} mono={false} />
                      <InfoRow label="802.11k" value={EvidenceBoolean({ value: net?.supports_80211k })} mono={false} />
                      <InfoRow label="802.11v" value={EvidenceBoolean({ value: net?.supports_80211v })} mono={false} />
                      <InfoRow label="802.11r" value={EvidenceBoolean({ value: net?.supports_80211r })} mono={false} />
                      <InfoRow label="DFS" value={EvidenceBoolean({ value: net?.dfs })} mono={false} />
                      <InfoRow label="Multi-link operation" value={EvidenceBoolean({ value: net?.mlo })} mono={false} />
                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        );
      })}
    </motion.div>
  );
}
