import React from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { motion } from 'framer-motion';
import { WIFI_BANDS, countObservedChannels } from '../../lib/rfPlanningEvidence.js';

function channelRows(networks, band, congestion) {
  const actualCounts = countObservedChannels(networks, band);
  const channels = new Set(actualCounts.keys());
  if (band === '2.4GHz') {
    Object.keys(congestion?.[band] || {}).forEach(value => {
      const channel = Number(value);
      if (Number.isInteger(channel) && channel >= 1 && channel <= 14) channels.add(channel);
    });
  }
  return [...channels].sort((a, b) => a - b).map(channel => {
    const tally = Number(congestion?.[band]?.[channel]);
    return {
      channel,
      records: actualCounts.get(channel) || 0,
      adjacentTally: Number.isFinite(tally) ? tally : null,
    };
  });
}

function barColor(count, maximum) {
  if (!count) return 'hsl(222, 35%, 20%)';
  const ratio = count / Math.max(1, maximum);
  return ratio >= 0.75 ? 'hsl(0,72%,55%)' : ratio >= 0.4 ? 'hsl(45,93%,58%)' : 'hsl(188,100%,50%)';
}

function BandChart({ band, data }) {
  if (!data.length) return <div className="glass rounded-xl p-4 text-xs text-muted-foreground">{band}: no channel observations in this scan.</div>;
  const maximum = Math.max(...data.map(item => item.records), 1);
  const tooltip = ({ active, payload, label }) => {
    if (!active || !payload?.length) return null;
    const item = payload[0].payload;
    return (
      <div className="glass rounded-lg p-3 text-xs border border-border space-y-1">
        <div className="font-medium text-foreground">{band} · Channel {label}</div>
        <div className="text-primary">Observed BSS records: {item.records}</div>
        {item.adjacentTally !== null && band === '2.4GHz' && <div className="text-muted-foreground">Adjacent-channel tally: {item.adjacentTally}</div>}
        <div className="text-muted-foreground">Not an airtime or RF-utilisation measurement</div>
      </div>
    );
  };
  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-2">
      <h3 className="text-sm font-semibold text-muted-foreground">{band}</h3>
      <div className="glass rounded-xl p-4" style={{ height: 170 }}>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 5, right: 5, bottom: 5, left: -20 }}>
            <XAxis dataKey="channel" tick={{ fill: '#64748b', fontSize: 10, fontFamily: 'JetBrains Mono' }} axisLine={false} tickLine={false} />
            <YAxis tick={{ fill: '#64748b', fontSize: 10 }} axisLine={false} tickLine={false} allowDecimals={false} />
            <Tooltip content={tooltip} cursor={{ fill: 'rgba(255,255,255,0.03)' }} />
            <Bar dataKey="records" radius={[4,4,0,0]} maxBarSize={28}>
              {data.map(item => <Cell key={item.channel} fill={barColor(item.records, maximum)} />)}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </motion.div>
  );
}

export default function ChannelChart({ networks = [], congestion = {} }) {
  return (
    <div className="space-y-4">
      <p className="text-xs text-muted-foreground">Observed BSS counts by primary channel. Counts describe this scan only; channel airtime, interference power, channel width and DFS availability are not measured here.</p>
      {WIFI_BANDS.map(band => <BandChart key={band} band={band} data={channelRows(networks, band, congestion)} />)}
    </div>
  );
}
