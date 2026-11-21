import { useState } from 'react';
import { apiFetch, apiBase } from '../lib/api.js';
import { parseClientExperienceCsv } from '../lib/clientExperienceCsv.js';
import { Activity, AlertCircle, Play, ShieldCheck } from 'lucide-react';

const panel = { background: '#0c1120', border: '1px solid #1e2d47', borderRadius: 10, padding: 14 };
const field = { width: '100%', minWidth: 0, boxSizing: 'border-box', background: '#070b14', color: '#e2e8f0', border: '1px solid #263956', borderRadius: 7, padding: '8px 9px', fontSize: 12 };
const muted = { color: '#94a3b8', fontSize: 11, lineHeight: 1.55 };
const labelStyle = { display: 'block', color: '#94a3b8', fontSize: 10, fontWeight: 650, marginBottom: 5 };
const METRICS = [
  ['rssi_dbm', 'RSSI'],
  ['snr_db', 'SNR'],
  ['retry_rate_pct', 'TX retries'],
  ['airtime_utilization_pct', 'Airtime'],
  ['packet_loss_pct', 'Packet loss'],
  ['rtt_ms', 'RTT'],
  ['jitter_ms', 'Jitter'],
  ['throughput_mbps', 'Throughput'],
];
const DEFAULT_REQUIRED = ['rssi_dbm', 'packet_loss_pct', 'rtt_ms'];
const THRESHOLDS = [
  ['rssi_dbm', 'Minimum RSSI', '-70'],
  ['snr_db', 'Minimum SNR', '20'],
  ['retry_rate_pct', 'Maximum retries (%)', '15'],
  ['airtime_utilization_pct', 'Maximum airtime (%)', '80'],
  ['packet_loss_pct', 'Maximum packet loss (%)', '1'],
  ['rtt_ms', 'Maximum RTT (ms)', '100'],
  ['jitter_ms', 'Maximum jitter (ms)', '30'],
  ['throughput_mbps', 'Minimum throughput (Mbps)', 'Disabled by default'],
];

function MetricCard({ label, value, detail }) {
  return (
    <div style={{ background: '#070b14', border: '1px solid #1e2d47', borderRadius: 8, padding: 10 }}>
      <div style={muted}>{label}</div>
      <div style={{ color: '#e2e8f0', fontSize: 19, fontWeight: 750, marginTop: 4 }}>{value}</div>
      {detail ? <div style={{ ...muted, marginTop: 4 }}>{detail}</div> : null}
    </div>
  );
}

export default function ClientExperienceSloPanel() {
  const [samplesText, setSamplesText] = useState('[\n]\n');
  const [requiredMetrics, setRequiredMetrics] = useState(DEFAULT_REQUIRED);
  const [thresholdOverrides, setThresholdOverrides] = useState({});
  const [maxAgeDays, setMaxAgeDays] = useState('7');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);

  async function importCsv(event) {
    const inputElement = event.currentTarget;
    const file = inputElement.files?.[0];
    if (!file) return;
    setError('');
    try {
      if (file.size > 1024 * 1024) throw new Error('CSV exceeds the 1 MiB import limit.');
      const samples = parseClientExperienceCsv(await file.text());
      setSamplesText(JSON.stringify(samples, null, 2));
      setResult(null);
    } catch (err) {
      setError(err.message || 'Unable to import client observations from CSV.');
    } finally {
      inputElement.value = '';
    }
  }

  function toggleMetric(key, checked) {
    setRequiredMetrics(current => checked ? [...current, key] : current.filter(item => item !== key));
    setResult(null);
  }

  async function evaluate() {
    setBusy(true);
    setError('');
    setResult(null);
    try {
      const samples = JSON.parse(samplesText);
      if (!Array.isArray(samples) || samples.length === 0) {
        throw new Error('Provide a non-empty JSON array of timestamped client observation records.');
      }
      const age = Number(maxAgeDays);
      if (!Number.isInteger(age) || age < 1 || age > 30) {
        throw new Error('Freshness window must be a whole number from 1 to 30 days.');
      }
      const thresholds = {};
      for (const [key] of THRESHOLDS) {
        const value = thresholdOverrides[key]?.trim();
        if (value === '' || value == null) continue;
        const number = Number(value);
        if (!Number.isFinite(number)) throw new Error('Threshold ' + key + ' must be numeric.');
        thresholds[key] = number;
      }
      const payload = {
        samples,
        max_age_days: age,
        ...(requiredMetrics.length ? { required_metrics: requiredMetrics } : {}),
        ...(Object.keys(thresholds).length ? { thresholds } : {}),
      };
      const response = await apiFetch(apiBase() + '/api/features/client_experience_slo_evaluator', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(20000),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'SLO evaluator returned HTTP ' + response.status);
      setResult(data.result || data);
    } catch (err) {
      setError(err.message || 'Unable to evaluate client experience SLOs.');
    } finally {
      setBusy(false);
    }
  }

  const summary = result?.summary;
  const statusText = result?.status === 'within_thresholds'
    ? 'Within thresholds'
    : result?.status === 'threshold_breaches' ? 'Threshold breaches' : 'Insufficient evidence';
  const statusColor = result?.status === 'within_thresholds' ? '#34d399'
    : result?.status === 'threshold_breaches' ? '#fbbf24' : '#94a3b8';

  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <section style={{ ...panel, borderColor: '#24506a' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 7 }}>
          <Activity size={17} color="#06d6f0"/>
          <strong style={{ color: '#e2e8f0', fontSize: 13 }}>Client experience SLO evaluator</strong>
          <span style={{ marginLeft: 'auto', color: '#94a3b8', fontSize: 10 }}>F292 · MEASURED DATA ONLY</span>
        </div>
        <p style={{ ...muted, margin: 0 }}>Paste timestamped per-client measurements from a controller, managed agent, client telemetry export or active probe. Missing required metrics are excluded from the SLA denominator, not counted as healthy.</p>
      </section>

      <section style={panel}>
        <div style={{ display: 'flex', alignItems: 'end', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap', marginBottom: 10 }}>
          <div>
            <div style={{ color: '#cbd5e1', fontSize: 11, fontWeight: 700 }}>Import controller or client CSV</div>
            <p style={{ ...muted, margin: '4px 0 0' }}>Strict columns: sample_id, site_id, client_ref, observed_at, evidence_source, optional ap_id, and supported metric columns.</p>
          </div>
          <label style={{ ...field, width: 'auto', display: 'inline-flex', alignItems: 'center', cursor: 'pointer' }}>
            Import CSV
            <input type="file" accept=".csv,text/csv" onChange={importCsv} aria-label="Import client experience CSV" style={{ width: 1, height: 1, opacity: 0, position: 'absolute', pointerEvents: 'none' }}/>
          </label>
        </div>
        <label style={{ display: 'block', color: '#cbd5e1', fontSize: 11, fontWeight: 700, marginBottom: 7 }}>Client observation records (JSON array)</label>
        <textarea
          value={samplesText}
          onChange={event => { setSamplesText(event.target.value); setResult(null); }}
          rows={13}
          spellCheck="false"
          aria-label="Timestamped client experience observations JSON"
          placeholder={'[\n  {\n    "sample_id": "probe-001",\n    "site_id": "office",\n    "client_ref": "station-opaque-01",\n    "ap_id": "ap-01",\n    "observed_at": "2026-11-21T10:00:00Z",\n    "evidence_source": "probe",\n    "metrics": {\n      "rssi_dbm": -62,\n      "packet_loss_pct": 0.1,\n      "rtt_ms": 24,\n      "jitter_ms": 3.5\n    }\n  }\n]'}
          style={{ ...field, resize: 'vertical', fontFamily: 'ui-monospace, monospace', lineHeight: 1.5 }}
        />
        <p style={muted}>Each record needs sample_id, site_id, pseudonymous client_ref, timezone-aware observed_at and evidence_source. Add only metrics you actually measured. Do not enter MAC addresses or user identities.</p>
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(170px,240px) 1fr', gap: 10, alignItems: 'end' }}>
          <label><span style={labelStyle}>Freshness window (days)</span><input type="number" min="1" max="30" step="1" value={maxAgeDays} onChange={event => { setMaxAgeDays(event.target.value); setResult(null); }} style={field}/></label>
          <div style={muted}>Observations older than this window are excluded. Future-dated samples beyond the clock-skew allowance are rejected.</div>
        </div>
      </section>

      <section style={panel}>
        <div style={{ color: '#e2e8f0', fontSize: 12, fontWeight: 700, marginBottom: 8 }}>SLO eligibility and thresholds</div>
        <div style={{ color: '#cbd5e1', fontSize: 11, marginBottom: 7 }}>Required metrics: a sample missing any selected metric is incomplete and excluded from SLA attainment.</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(145px,1fr))', gap: 7 }}>
          {METRICS.map(([key, label]) => <label key={key} style={{ display: 'flex', alignItems: 'center', gap: 7, color: '#94a3b8', fontSize: 11 }}>
            <input type="checkbox" checked={requiredMetrics.includes(key)} onChange={event => toggleMetric(key, event.target.checked)}/>
            {label}
          </label>)}
        </div>
        <details style={{ marginTop: 12 }}>
          <summary style={{ color: '#a5f3fc', fontSize: 11, cursor: 'pointer' }}>Advanced threshold overrides</summary>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(145px,1fr))', gap: 8, marginTop: 9 }}>
            {THRESHOLDS.map(([key, label, placeholder]) => <label key={key}><span style={labelStyle}>{label}</span><input type="number" value={thresholdOverrides[key] || ''} onChange={event => { setThresholdOverrides(current => ({ ...current, [key]: event.target.value })); setResult(null); }} placeholder={placeholder} style={field}/></label>)}
          </div>
          <p style={{ ...muted, marginBottom: 0 }}>Blank fields use the evaluator defaults. Throughput remains unscored unless a minimum throughput threshold is supplied.</p>
        </details>
        {error ? <div role="alert" style={{ ...muted, color: '#fca5a5', marginTop: 10 }}><AlertCircle size={13} style={{ verticalAlign: 'middle', marginRight: 5 }}/>{error}</div> : null}
        <button type="button" onClick={evaluate} disabled={busy} style={{ display: 'inline-flex', alignItems: 'center', gap: 7, marginTop: 12, border: '1px solid #06d6f0', background: 'rgba(6,214,240,.13)', color: '#06d6f0', borderRadius: 7, padding: '9px 13px', fontSize: 12, fontWeight: 700, cursor: busy ? 'wait' : 'pointer', opacity: busy ? 0.5 : 1 }}>
          <Play size={13}/>{busy ? 'Evaluating…' : 'Evaluate client SLOs'}
        </button>
      </section>

      {summary ? <section style={panel}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
          <ShieldCheck size={15} color={statusColor}/>
          <strong style={{ color: '#e2e8f0', fontSize: 12 }}>Client experience report</strong>
          <span style={{ marginLeft: 'auto', fontSize: 10, fontWeight: 700, color: statusColor }}>{statusText.toUpperCase()}</span>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(125px,1fr))', gap: 8 }}>
          <MetricCard label="SLA attainment" value={summary.sla_attainment_pct == null ? 'n/a' : summary.sla_attainment_pct + '%'} detail={summary.eligible_slo_sample_count + ' eligible samples'}/>
          <MetricCard label="Threshold breaches" value={summary.breached_slo_sample_count} detail="Eligible samples only"/>
          <MetricCard label="Fresh / stale" value={result.fresh_sample_count + ' / ' + result.stale_sample_count} detail="Stale samples excluded"/>
          <MetricCard label="Clients / sites" value={result.reported_client_count + ' / ' + result.reported_site_count}/>
        </div>
        <div style={{ overflowX: 'auto', marginTop: 13 }}>
          <strong style={{ color: '#cbd5e1', fontSize: 11 }}>Metric coverage and distribution</strong>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, textAlign: 'left', marginTop: 6 }}>
            <thead><tr>{['Metric','Samples','Coverage','Median','P95','Threshold','Breaches'].map(item => <th key={item} style={{ padding: 7, color: '#94a3b8', borderBottom: '1px solid #263956', whiteSpace: 'nowrap' }}>{item}</th>)}</tr></thead>
            <tbody>{METRICS.map(([key, label]) => {
              const stat = summary.metric_summary[key];
              const suffix = key.endsWith('_pct') ? '%' : key.endsWith('_ms') ? ' ms' : key.endsWith('_mbps') ? ' Mbps' : key === 'rssi_dbm' ? ' dBm' : ' dB';
              const threshold = stat.threshold == null ? 'disabled' : (stat.direction === 'min' ? '≥ ' : '≤ ') + stat.threshold;
              return <tr key={key}>
                {[label, stat.sample_count, stat.coverage_pct == null ? '—' : stat.coverage_pct + '%', stat.median == null ? '—' : stat.median + suffix, stat.p95 == null ? '—' : stat.p95 + suffix, threshold, stat.breach_count].map((value, index) => <td key={index} style={{ padding: 7, color: '#cbd5e1', borderBottom: '1px solid #1e2d47', whiteSpace: 'nowrap' }}>{value}</td>)}
              </tr>;
            })}</tbody>
          </table>
        </div>
        <div style={{ overflowX: 'auto', marginTop: 13 }}>
          <strong style={{ color: '#cbd5e1', fontSize: 11 }}>Client SLO results</strong>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, textAlign: 'left', marginTop: 6 }}>
            <thead><tr>{['Client alias','Site','Status','Attainment','Eligible','Incomplete','Median RTT','P95 RTT'].map(item => <th key={item} style={{ padding: 7, color: '#94a3b8', borderBottom: '1px solid #263956', whiteSpace: 'nowrap' }}>{item}</th>)}</tr></thead>
            <tbody>{result.clients.map(client => <tr key={client.site_id + '-' + client.client_ref}>
              {[client.client_ref,client.site_id,client.status.replaceAll('_',' '),client.sla_attainment_pct == null ? 'n/a' : client.sla_attainment_pct + '%',client.eligible_slo_sample_count,client.incomplete_required_sample_count,client.metric_summary.rtt_ms.median == null ? '—' : client.metric_summary.rtt_ms.median + ' ms',client.metric_summary.rtt_ms.p95 == null ? '—' : client.metric_summary.rtt_ms.p95 + ' ms'].map((value,index) => <td key={index} style={{ padding: 7, color: index === 2 && client.status === 'threshold_breaches' ? '#fbbf24' : '#cbd5e1', borderBottom: '1px solid #1e2d47', whiteSpace: 'nowrap' }}>{value}</td>)}
            </tr>)}</tbody>
          </table>
        </div>
        {result.client_details_truncated ? <p style={muted}>Client detail output is limited to the first 500 aliases; aggregate site and overall summaries include all accepted samples.</p> : null}
        <div style={{ ...muted, marginTop: 10 }}>{result.note}</div>
      </section> : null}
    </div>
  );
}
