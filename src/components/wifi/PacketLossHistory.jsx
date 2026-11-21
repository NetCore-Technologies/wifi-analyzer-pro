import React from 'react';
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { motion } from 'framer-motion';
import { Activity } from 'lucide-react';
import { summariseMetric } from '../../lib/telemetryHistory.js';

function MetricCard({ label, value, unit, samples, color }) {
  return (
    <div className="glass rounded-xl p-3 text-center">
      <div className={`text-2xl font-bold font-mono ${color}`}>{value === null ? '—' : value + unit}</div>
      <div className="text-xs text-muted-foreground mt-0.5">{label}</div>
      <div className="text-[11px] text-muted-foreground">{samples} measured sample{samples === 1 ? '' : 's'}</div>
    </div>
  );
}

function MetricChart({ data, dataKey, title, unit, color, maximum }) {
  if (!data.some(sample => sample[dataKey] !== null)) {
    return <div className="glass rounded-xl p-4 space-y-1"><div className="text-sm font-semibold text-foreground">{title}</div><div className="text-xs text-muted-foreground">No measurements available for this metric.</div></div>;
  }
  return (
    <div className="glass rounded-xl p-4 space-y-3">
      <div className="flex items-center gap-2"><Activity className="w-4 h-4" style={{ color }} /><span className="text-sm font-semibold text-foreground">{title}</span></div>
      <ResponsiveContainer width="100%" height={170}>
        <LineChart data={data} margin={{ top: 6, right: 8, bottom: 4, left: -18 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
          <XAxis dataKey="sampled_at" hide />
          <YAxis domain={[0, maximum || 'auto']} tick={{ fontSize: 10, fill: 'var(--muted-foreground)' }} tickFormatter={value => value + unit} />
          <Tooltip formatter={value => [Number(value).toFixed(2) + unit, title]}
            labelFormatter={value => new Date(Number(value)).toLocaleString()}
            contentStyle={{ background: 'var(--background)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }} />
          <Line type="monotone" dataKey={dataKey} stroke={color} strokeWidth={2} dot={false} activeDot={{ r: 4 }} connectNulls={false} name={title} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

export default function PacketLossHistory({ diagnosticsHistory }) {
  const samples = (Array.isArray(diagnosticsHistory) ? diagnosticsHistory : []).map((item, index) => ({
    sampled_at: Number.isFinite(item?.sampled_at) ? item.sampled_at : index + 1,
    loss: item?.packet_loss_pct ?? null,
    latency: item?.latency_ms ?? null,
    jitter: item?.jitter_ms ?? null,
  }));
  const loss = summariseMetric(samples, 'loss');
  const latency = summariseMetric(samples, 'latency');
  const jitter = summariseMetric(samples, 'jitter');
  const latest = samples[samples.length - 1] || {};
  if (!samples.length) return <div className="glass rounded-xl p-8 text-center text-sm text-muted-foreground">No diagnostic history recorded yet. Metrics are added only when a diagnostic sample is received.</div>;

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-4">
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <MetricCard label="Latest packet loss" value={latest.loss === null ? null : Number(latest.loss).toFixed(1)} unit="%" samples={loss.count} color={loss.last === 0 ? 'text-green-400' : 'text-yellow-400'} />
        <MetricCard label="Mean latency" value={latency.mean === null ? null : latency.mean.toFixed(1)} unit=" ms" samples={latency.count} color="text-primary" />
        <MetricCard label="Peak jitter" value={jitter.max === null ? null : jitter.max.toFixed(1)} unit=" ms" samples={jitter.count} color="text-blue-400" />
      </div>
      <MetricChart data={samples} dataKey="loss" title="Packet loss" unit="%" color="#f87171" maximum={100} />
      <MetricChart data={samples} dataKey="latency" title="Round-trip latency" unit=" ms" color="#facc15" />
      <MetricChart data={samples} dataKey="jitter" title="Jitter" unit=" ms" color="#60a5fa" />
    </motion.div>
  );
}
