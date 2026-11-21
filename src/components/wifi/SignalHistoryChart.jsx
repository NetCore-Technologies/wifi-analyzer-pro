import React from 'react';
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, ReferenceLine } from 'recharts';
import { motion } from 'framer-motion';

const COLORS = ['hsl(188,100%,50%)', 'hsl(263,70%,65%)', 'hsl(142,71%,50%)', 'hsl(45,93%,58%)', 'hsl(0,72%,60%)'];

export default function SignalHistoryChart({ networks, history }) {
  const top5 = (Array.isArray(networks) ? networks : []).filter(net => typeof net?.bssid === 'string' && net.bssid);
  const samplesByTime = new Map();
  top5.forEach(net => {
    (Array.isArray(history?.[net.bssid]) ? history[net.bssid] : []).forEach(sample => {
      if (!Number.isFinite(sample?.t) || !Number.isFinite(sample?.rssi)) return;
      if (!samplesByTime.has(sample.t)) samplesByTime.set(sample.t, { t: sample.t });
      samplesByTime.get(sample.t)[net.bssid] = sample.rssi;
    });
  });
  const data = [...samplesByTime.values()].sort((a, b) => a.t - b.t);

  if (data.length < 2) {
    return (
      <div className="glass rounded-xl p-8 text-center space-y-2">
        <div className="text-sm font-semibold text-foreground">{data.length === 1 ? 'One measured sample recorded' : 'No signal history recorded yet'}</div>
        <p className="text-xs text-muted-foreground max-w-lg mx-auto">
          {data.length === 1
            ? 'A trend requires at least two timestamped observations. Another successful scan will add the next sample.'
            : 'Historical RSSI values are collected only from successful scans. No synthetic trend is displayed.'}
        </p>
      </div>
    );
  }

  const CustomTooltip = ({ active, payload, label }) => {
    if (!active || !payload?.length) return null;
    return (
      <div className="glass rounded-lg p-3 text-xs border border-border space-y-1">
        <div className="text-muted-foreground">{new Date(label).toLocaleString()}</div>
        {payload.map((point, index) => {
          const net = top5.find(item => item.bssid === point.dataKey);
          return (
            <div key={point.dataKey || index} className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full" style={{ background: point.color }} />
              <span className="text-muted-foreground">{net?.ssid || 'Hidden network'}:</span>
              <span className="font-mono font-medium" style={{ color: point.color }}>{point.value} dBm</span>
            </div>
          );
        })}
      </div>
    );
  };

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-3">
      <div className="glass rounded-xl p-4" style={{ height: 220 }}>
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={data} margin={{ top: 5, right: 10, bottom: 5, left: -10 }}>
            <XAxis dataKey="t" hide />
            <YAxis domain={[-100, -30]} tick={{ fill: '#64748b', fontSize: 10, fontFamily: 'JetBrains Mono' }} axisLine={false} tickLine={false} />
            <Tooltip content={CustomTooltip} />
            <ReferenceLine y={-55} stroke="hsl(142,71%,45%)" strokeDasharray="4 4" strokeOpacity={0.4} />
            <ReferenceLine y={-75} stroke="hsl(45,93%,58%)" strokeDasharray="4 4" strokeOpacity={0.4} />
            <ReferenceLine y={-85} stroke="hsl(0,72%,55%)" strokeDasharray="4 4" strokeOpacity={0.4} />
            {top5.map((net, index) => (
              <Line key={net.bssid} type="monotone" dataKey={net.bssid} stroke={COLORS[index % COLORS.length]}
                strokeWidth={2} dot={false} activeDot={{ r: 4 }} connectNulls={false} />
            ))}
          </LineChart>
        </ResponsiveContainer>
      </div>
      <div className="flex flex-wrap gap-3">
        {top5.filter(net => history?.[net.bssid]?.length > 0).map((net, index) => (
          <div key={net.bssid} className="flex items-center gap-1.5 text-xs">
            <span className="w-3 h-0.5 rounded-full inline-block" style={{ background: COLORS[index % COLORS.length] }} />
            <span className="text-muted-foreground truncate max-w-[140px]">{net.ssid || 'Hidden network'}</span>
          </div>
        ))}
      </div>
    </motion.div>
  );
}
