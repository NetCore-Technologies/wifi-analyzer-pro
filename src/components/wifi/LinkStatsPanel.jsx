import React from 'react';
import { motion } from 'framer-motion';
import { ArrowUp, ArrowDown, AlertTriangle, Activity } from 'lucide-react';

function measuredNumber(value) {
  if (value === null || value === undefined || value === '') return null;
  const number = Number(value);
  return Number.isFinite(number) && number >= 0 ? number : null;
}
function StatCard({ label, value, sub, color = 'text-foreground', icon: Icon }) {
  return <div className="glass rounded-xl p-3"><div className="flex items-center gap-1.5 text-xs text-muted-foreground mb-1">{Icon && <Icon className="w-3 h-3" />}{label}</div><div className={`text-lg font-bold font-mono ${color}`}>{value}</div>{sub && <div className="text-xs text-muted-foreground mt-0.5">{sub}</div>}</div>;
}
function formatBytes(value) {
  const bytes = measuredNumber(value);
  if (bytes === null) return '—';
  if (bytes >= 1e9) return (bytes / 1e9).toFixed(2) + ' GB';
  if (bytes >= 1e6) return (bytes / 1e6).toFixed(1) + ' MB';
  if (bytes >= 1e3) return (bytes / 1e3).toFixed(0) + ' KB';
  return bytes + ' B';
}
function formatCount(value) {
  const count = measuredNumber(value);
  return count === null ? '—' : Math.round(count).toLocaleString();
}

export default function LinkStatsPanel({ link, loading }) {
  if (loading) return <div className="text-center py-8 text-muted-foreground text-sm">Loading link stats...</div>;
  if (!link || typeof link !== 'object') return <div className="glass rounded-xl p-8 text-center text-sm text-muted-foreground">No interface-counter sample is available yet.</div>;

  const packets = measuredNumber(link.tx_packets);
  const retries = measuredNumber(link.tx_retries);
  const retryRate = packets !== null && packets > 0 && retries !== null ? (retries / packets * 100).toFixed(2) + '%' : '—';
  const quality = measuredNumber(link.link_quality);
  const qualityMax = measuredNumber(link.link_quality_max);
  const qualityPct = quality !== null && qualityMax !== null && qualityMax > 0 ? Math.max(0, Math.min(100, quality / qualityMax * 100)) : null;

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-4">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <StatCard label="TX Packets" value={formatCount(link.tx_packets)} icon={ArrowUp} color="text-cyan-400" />
        <StatCard label="RX Packets" value={formatCount(link.rx_packets)} icon={ArrowDown} color="text-purple" />
        <StatCard label="TX Data" value={formatBytes(link.tx_bytes)} icon={ArrowUp} color="text-cyan-400" />
        <StatCard label="RX Data" value={formatBytes(link.rx_bytes)} icon={ArrowDown} color="text-purple" />
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <StatCard label="TX Errors" value={formatCount(link.tx_errors)} color={measuredNumber(link.tx_errors) > 0 ? 'text-orange-400' : 'text-green-400'} icon={AlertTriangle} />
        <StatCard label="RX Errors" value={formatCount(link.rx_errors)} color={measuredNumber(link.rx_errors) > 0 ? 'text-orange-400' : 'text-green-400'} icon={AlertTriangle} />
        <StatCard label="TX Dropped" value={formatCount(link.tx_dropped)} color={measuredNumber(link.tx_dropped) > 0 ? 'text-yellow-400' : 'text-green-400'} />
        <StatCard label="RX Dropped" value={formatCount(link.rx_dropped)} color={measuredNumber(link.rx_dropped) > 0 ? 'text-yellow-400' : 'text-green-400'} />
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <StatCard label="TX Retries" value={formatCount(link.tx_retries)} sub={retryRate + ' retry rate'} color="text-yellow-400" icon={Activity} />
        <StatCard label="TX Failed" value={formatCount(link.tx_failed)} color={measuredNumber(link.tx_failed) > 0 ? 'text-red-400' : 'text-green-400'} icon={AlertTriangle} />
        <StatCard label="Missed Beacons" value={formatCount(link.missed_beacons)} color={measuredNumber(link.missed_beacons) > 5 ? 'text-orange-400' : 'text-green-400'} />
      </div>
      <div className="glass rounded-xl p-4 grid grid-cols-2 gap-4">
        <div>
          <div className="text-xs text-muted-foreground mb-1">Link Quality</div>
          <div className="text-2xl font-bold font-mono text-primary">{quality === null || qualityMax === null ? '—' : quality + '/' + qualityMax}</div>
          <div className="h-2 bg-muted/40 rounded-full mt-2 overflow-hidden">{qualityPct !== null && <div className="h-full bg-primary rounded-full transition-all duration-700" style={{ width: qualityPct + '%' }} />}</div>
          {qualityPct === null && <div className="text-xs text-muted-foreground mt-1">Not reported by this adapter</div>}
        </div>
        <div><div className="text-xs text-muted-foreground mb-1">Invalid / Misc</div><div className="text-2xl font-bold font-mono text-foreground">{formatCount(link.invalid_misc)}</div><div className="text-xs text-muted-foreground mt-1">Malformed frames</div></div>
      </div>
    </motion.div>
  );
}
