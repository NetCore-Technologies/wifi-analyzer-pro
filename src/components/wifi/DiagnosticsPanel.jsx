import React from 'react';
import { motion } from 'framer-motion';
import { Globe, Server, Network, CheckCircle, AlertCircle, Info } from 'lucide-react';

function present(value, suffix = '') {
  if (value === null || value === undefined || value === '') return '—';
  const number = Number(value);
  return Number.isFinite(number) ? String(number) + suffix : '—';
}
function statusFor(value, goodBelow, warnBelow) {
  if (value === null || value === undefined || value === '') return 'unknown';
  const number = Number(value);
  if (!Number.isFinite(number)) return 'unknown';
  return number < goodBelow ? 'good' : number < warnBelow ? 'warn' : 'bad';
}
function Row({ label, value, mono = true, color }) {
  return <div className="flex items-center justify-between py-2 border-b border-border/50 last:border-0"><span className="text-xs text-muted-foreground">{label}</span><span className={`text-xs font-medium ${mono ? 'font-mono' : ''} ${color || 'text-foreground'}`}>{value ?? '—'}</span></div>;
}
function Section({ title, icon: Icon, children }) {
  return <div className="glass rounded-xl p-4"><div className="flex items-center gap-2 mb-3"><Icon className="w-4 h-4 text-primary" /><h3 className="text-sm font-semibold">{title}</h3></div>{children}</div>;
}
function MetricCard({ label, value, unit, color, status }) {
  const statusColor = status === 'good' ? 'text-green-400' : status === 'warn' ? 'text-yellow-400' : status === 'bad' ? 'text-red-400' : 'text-muted-foreground';
  return <div className="glass rounded-xl p-3 text-center"><div className="text-xs text-muted-foreground mb-1">{label}</div><div className={`text-2xl font-bold font-mono ${color || statusColor}`}>{value}</div>{unit && <div className="text-xs text-muted-foreground">{unit}</div>}{status === 'unknown' && <div className="text-[11px] text-muted-foreground">Not measured</div>}</div>;
}

export default function DiagnosticsPanel({ diag, loading }) {
  if (loading) return <div className="text-center py-8 text-muted-foreground text-sm">Running diagnostics...</div>;
  if (!diag || typeof diag !== 'object') return <div className="glass rounded-xl p-8 text-center text-sm text-muted-foreground">No diagnostic result is available yet.</div>;

  const latency = statusFor(diag.latency_ms, 10, 50);
  const jitter = statusFor(diag.jitter_ms, 5, 20);
  const loss = statusFor(diag.packet_loss_pct, 1, 5);
  const dns = statusFor(diag.dns_resolution_ms, 50, 100);
  const route = statusFor(diag.route_hops, 5, 15);
  const gateway = diag.gateway ? 'good' : diag.gateway == null || diag.gateway === '' ? 'unknown' : 'bad';
  const summary = [
    { label: 'Latency', status: latency, detail: present(diag.latency_ms, ' ms') },
    { label: 'Jitter', status: jitter, detail: present(diag.jitter_ms, ' ms') },
    { label: 'Packet loss', status: loss, detail: present(diag.packet_loss_pct, '%') },
    { label: 'DNS', status: dns, detail: present(diag.dns_resolution_ms, ' ms') },
    { label: 'Gateway', status: gateway, detail: diag.gateway || 'Not reported' },
    { label: 'Route', status: route, detail: diag.route_hops == null ? 'Not reported' : String(diag.route_hops) + ' hops' },
  ];
  const StatusIcon = ({ status }) => status === 'good'
    ? <CheckCircle className="w-3.5 h-3.5 text-green-400 flex-shrink-0" />
    : status === 'unknown'
      ? <Info className="w-3.5 h-3.5 text-muted-foreground flex-shrink-0" />
      : <AlertCircle className="w-3.5 h-3.5 text-yellow-400 flex-shrink-0" />;

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-4">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <MetricCard label="Latency" value={present(diag.latency_ms)} unit="ms" status={latency} />
        <MetricCard label="Jitter" value={present(diag.jitter_ms)} unit="ms" status={jitter} />
        <MetricCard label="Packet Loss" value={present(diag.packet_loss_pct)} unit="%" status={loss} />
        <MetricCard label="DNS Resolve" value={present(diag.dns_resolution_ms)} unit="ms" status={dns} />
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <MetricCard label="Min Latency" value={present(diag.latency_min_ms)} unit="ms" color="text-green-400" status={diag.latency_min_ms == null ? 'unknown' : undefined} />
        <MetricCard label="Max Latency" value={present(diag.latency_max_ms)} unit="ms" color="text-orange-400" status={diag.latency_max_ms == null ? 'unknown' : undefined} />
        <MetricCard label="Route Hops" value={present(diag.route_hops)} color="text-cyan-400" status={diag.route_hops == null ? 'unknown' : undefined} />
        <MetricCard label="MTU" value={present(diag.mtu)} color="text-foreground" status={diag.mtu == null ? 'unknown' : undefined} />
      </div>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Section title="Network Interface" icon={Network}>
          <Row label="Local IP" value={diag.local_ip} color="text-primary" />
          <Row label="Subnet Mask" value={diag.subnet_mask} />
          <Row label="Default Gateway" value={diag.gateway} color="text-cyan-400" />
          <Row label="Gateway MAC" value={diag.gateway_mac} />
          <Row label="MTU" value={present(diag.mtu)} />
        </Section>
        <Section title="DNS Servers" icon={Server}>
          {Array.isArray(diag.dns_servers) && diag.dns_servers.length
            ? diag.dns_servers.map((server, index) => <Row key={server || index} label={'DNS ' + (index + 1)} value={server} color="text-purple" />)
            : <Row label="Resolver configuration" value="Not reported" mono={false} />}
          <Row label="Resolution Time" value={present(diag.dns_resolution_ms, ' ms')} color={dns === 'good' ? 'text-green-400' : dns === 'unknown' ? 'text-muted-foreground' : 'text-yellow-400'} />
        </Section>
      </div>
      <Section title="Connection Quality Summary" icon={Globe}>
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 mt-1">
          {summary.map(item => (
            <div key={item.label} className="bg-secondary/40 rounded-lg p-2 flex items-center gap-2">
              <StatusIcon status={item.status} />
              <div className="min-w-0"><div className="text-xs font-medium text-foreground">{item.label}</div><div className="text-xs font-mono text-muted-foreground truncate">{item.detail}</div></div>
            </div>
          ))}
        </div>
      </Section>
    </motion.div>
  );
}
