import React from 'react';
import { motion } from 'framer-motion';
import { SignalStrengthBar } from './SignalStrengthBar';

/* A scan without physical AP coordinates cannot produce a floor-plan heatmap. */
export default function HeatmapGrid({ networks }) {
  const observations = (Array.isArray(networks) ? networks : [])
    .filter(net => net?.rssi !== null && net?.rssi !== undefined && Number.isFinite(Number(net.rssi)) && Number(net.rssi) >= -127 && Number(net.rssi) <= 0)
    .slice().sort((a, b) => Number(b.rssi) - Number(a.rssi));
  if (!observations.length) return <div className="glass rounded-xl p-8 text-center text-sm text-muted-foreground">No measured RSSI observations are available for comparison.</div>;

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-2">
      <div className="text-xs text-muted-foreground">{observations.length} measured signals · strongest first · physical AP positions are not inferred</div>
      {observations.map((net, index) => (
        <div key={net.bssid || (net.ssid || 'network') + '-' + index} className="glass rounded-xl p-3 grid grid-cols-1 sm:grid-cols-[minmax(0,1fr),minmax(180px,1fr)] gap-3 items-center">
          <div className="min-w-0">
            <div className="text-sm font-medium text-foreground truncate">{net.ssid || 'Hidden network'}</div>
            <div className="text-xs font-mono text-muted-foreground truncate">{net.bssid || 'BSSID unavailable'}</div>
            <div className="mt-1 flex gap-2 text-xs text-muted-foreground"><span>{net.band || 'Band unknown'}</span><span>{net.channel == null ? 'Channel unknown' : 'Channel ' + net.channel}</span></div>
          </div>
          <SignalStrengthBar rssi={net.rssi} />
        </div>
      ))}
    </motion.div>
  );
}
