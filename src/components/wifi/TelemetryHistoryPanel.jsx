import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Activity, RefreshCw, Database, ShieldCheck, AlertCircle } from 'lucide-react';
import {
  CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis,
} from 'recharts';
import { apiBase, apiFetch } from '../../lib/api.js';
import { buildTelemetryChartData, summariseTelemetry } from '../../lib/telemetryChartData.js';

const SITE_COLORS = [
  '#06d6f0', '#a78bfa', '#34d399', '#fbbf24', '#fb7185',
  '#60a5fa', '#f97316', '#e879f9', '#a3e635', '#94a3b8',
];

function MetricChart({ title, metric, unit, description, rollups, domain }) {
  const chart = useMemo(() => buildTelemetryChartData(rollups, metric), [rollups, metric]);
  if (!chart.measuredValueCount) {
    return (
      <section className="glass rounded-xl p-4 space-y-2">
        <div className="text-sm font-semibold text-foreground">{title}</div>
        <div className="text-xs text-muted-foreground">No measured samples are available for this metric in the selected period.</div>
      </section>
    );
  }
  return (
    <section className="glass rounded-xl p-4 space-y-3">
      <div>
        <div className="text-sm font-semibold text-foreground">{title}</div>
        <div className="text-xs text-muted-foreground">{description}</div>
      </div>
      <div style={{ height: 220 }}>
        <ResponsiveContainer width="100%" height="100%">
          <LineChart data={chart.data} margin={{ top: 8, right: 12, bottom: 8, left: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.14)" />
            <XAxis dataKey="minute_utc" tick={{ fontSize: 10, fill: '#94a3b8' }}
              tickFormatter={value => new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
              minTickGap={28} />
            <YAxis domain={domain || ['auto', 'auto']} tick={{ fontSize: 10, fill: '#94a3b8' }}
              tickFormatter={value => String(value) + unit} width={58} />
            <Tooltip
              labelFormatter={value => new Date(value).toLocaleString()}
              formatter={(value, name) => [Number(value).toFixed(1) + unit, String(name).replace(/^site:/, '')]}
              contentStyle={{ background: 'var(--background)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }}
            />
            {chart.sites.map((site, index) => (
              <Line key={site} type="monotone" dataKey={'site:' + site}
                name={site} stroke={SITE_COLORS[index % SITE_COLORS.length]}
                strokeWidth={2} dot={false} activeDot={{ r: 4 }} connectNulls={false} />
            ))}
          </LineChart>
        </ResponsiveContainer>
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-2">
        {chart.sites.map((site, index) => (
          <div key={site} className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <span className="w-3 h-0.5 rounded-full" style={{ background: SITE_COLORS[index % SITE_COLORS.length] }} />
            {site}
          </div>
        ))}
      </div>
    </section>
  );
}

function SummaryCard({ label, value, detail }) {
  return (
    <div className="glass rounded-xl p-3">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="text-2xl font-bold font-mono text-primary mt-1">{value}</div>
      <div className="text-xs text-muted-foreground mt-0.5">{detail}</div>
    </div>
  );
}

export default function TelemetryHistoryPanel() {
  const [days, setDays] = useState(7);
  const [rollups, setRollups] = useState([]);
  const [retentionDays, setRetentionDays] = useState(90);
  const [privacy, setPrivacy] = useState('');
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState('');

  const refresh = useCallback(async () => {
    setRefreshing(true);
    setError('');
    try {
      const response = await apiFetch(apiBase() + '/api/telemetry/history?days=' + days, {
        signal: AbortSignal.timeout(15000),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Historical telemetry request failed.');
      if (!Array.isArray(data.rollups)) throw new Error('The telemetry API returned an invalid history response.');
      setRollups(data.rollups);
      setRetentionDays(Number.isInteger(data.retention_days) ? data.retention_days : 90);
      setPrivacy(typeof data.privacy === 'string' ? data.privacy : '');
    } catch (requestError) {
      setError(requestError.message || 'Unable to load historical telemetry.');
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [days]);

  useEffect(() => { void refresh(); }, [refresh]);

  const summary = useMemo(() => summariseTelemetry(rollups), [rollups]);

  return (
    <div className="space-y-4">
      <div className="glass rounded-xl p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2 min-w-0">
          <Database className="w-4 h-4 text-primary flex-shrink-0" />
          <div>
            <div className="text-sm font-semibold text-foreground">Persistent site telemetry</div>
            <div className="text-xs text-muted-foreground">One-minute aggregates from successful local scans and diagnostic probes</div>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <select aria-label="History window" value={days} onChange={event => setDays(Number(event.target.value))}
            className="px-3 py-2 rounded-lg bg-secondary border border-border text-sm text-foreground">
            {[1, 7, 30, 90].filter(value => value <= retentionDays).map(value => <option key={value} value={value}>{value} day{value === 1 ? '' : 's'}</option>)}
          </select>
          <button type="button" onClick={refresh} disabled={refreshing}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-primary/10 border border-primary/30 text-primary text-sm disabled:opacity-50">
            <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      </div>

      {error && <div role="alert" className="glass rounded-xl p-4 border border-red-400/30 text-sm text-red-400 flex items-center gap-2"><AlertCircle className="w-4 h-4 flex-shrink-0" />{error}</div>}

      {loading ? (
        <div className="glass rounded-xl p-8 text-center text-sm text-muted-foreground">Loading persisted measurements…</div>
      ) : !error && rollups.length === 0 ? (
        <div className="glass rounded-xl p-8 text-center space-y-2">
          <Activity className="w-6 h-6 text-primary mx-auto" />
          <div className="text-sm font-semibold text-foreground">No historical measurements yet</div>
          <p className="text-xs text-muted-foreground max-w-xl mx-auto">Historical rollups are populated automatically by successful live scans and measured diagnostic probes. Demo observations are intentionally excluded.</p>
        </div>
      ) : !error && (
        <>
          <div className="grid grid-cols-2 xl:grid-cols-4 gap-3">
            <SummaryCard label="Measurement buckets" value={summary.buckets.toLocaleString()} detail="One-minute UTC windows" />
            <SummaryCard label="Scan samples" value={summary.scanSamples.toLocaleString()} detail="Successful live scans" />
            <SummaryCard label="Diagnostic samples" value={summary.diagnosticSamples.toLocaleString()} detail="Valid probe results" />
            <SummaryCard label="Sites with data" value={summary.siteCount.toLocaleString()} detail="Within your assigned scope" />
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            <MetricChart title="Average measured RSSI" metric="average_rssi_dbm" unit=" dBm"
              description="Mean of valid BSS signal readings within each minute."
              rollups={rollups} domain={[-100, -30]} />
            <MetricChart title="Average observed network count" metric="average_network_count" unit=""
              description="Mean number of BSS records returned by scans within each minute."
              rollups={rollups} domain={[0, 'auto']} />
            <MetricChart title="Round-trip latency" metric="average_latency_ms" unit=" ms"
              description="Mean of measured latency probes; missing measurements remain absent."
              rollups={rollups} domain={[0, 'auto']} />
            <MetricChart title="Packet loss" metric="average_packet_loss_pct" unit="%"
              description="Mean measured packet loss percentage; zero is shown only when measured."
              rollups={rollups} domain={[0, 100]} />
          </div>
        </>
      )}

      <div className="glass rounded-xl p-3 flex items-start gap-2">
        <ShieldCheck className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
        <div className="text-xs text-muted-foreground">
          {privacy || 'Only aggregate metrics are retained. Raw SSIDs, BSSIDs and client identifiers are not stored in this history.'}
          {' '}Retention: up to {retentionDays} days, subject to a per-site rollup cap.
        </div>
      </div>
    </div>
  );
}
