import { useState } from 'react';
import { apiFetch, apiBase } from '../lib/api.js';
import { parseClientExperienceCsv } from '../lib/clientExperienceCsv.js';
import { Activity, AlertCircle, Play, ShieldCheck } from 'lucide-react';

const panel = { background: '#0c1120', border: '1px solid #1e2d47', borderRadius: 10, padding: 14 };
const field = { width: '100%', minWidth: 0, boxSizing: 'border-box', background: '#070b14', color: '#e2e8f0', border: '1px solid #263956', borderRadius: 7, padding: '8px 9px', fontSize: 12 };
const muted = { color: '#94a3b8', fontSize: 11, lineHeight: 1.55 };
const METRICS = [
  ['rssi_dbm', 'RSSI'], ['snr_db', 'SNR'], ['retry_rate_pct', 'TX retries'],
  ['airtime_utilization_pct', 'Airtime'], ['packet_loss_pct', 'Packet loss'],
  ['rtt_ms', 'RTT'], ['jitter_ms', 'Jitter'], ['throughput_mbps', 'Throughput'],
];
const DEFAULT_REQUIRED = ['rssi_dbm', 'packet_loss_pct', 'rtt_ms'];

function Metric({ label, value, detail }) {
  return <div style={{ background: '#070b14', border: '1px solid #1e2d47', borderRadius: 8, padding: 10 }}>
    <div style={muted}>{label}</div>
    <div style={{ color: '#e2e8f0', fontSize: 19, fontWeight: 750, marginTop: 4 }}>{value}</div>
    {detail ? <div style={{ ...muted, marginTop: 4 }}>{detail}</div> : null}
  </div>;
}

export default function ClientExperienceSloWindowComparator() {
  const [baselineAsOf, setBaselineAsOf] = useState('');
  const [comparisonAsOf, setComparisonAsOf] = useState('');
  const [baselineText, setBaselineText] = useState('[\n]\n');
  const [comparisonText, setComparisonText] = useState('[\n]\n');
  const [requiredMetrics, setRequiredMetrics] = useState(DEFAULT_REQUIRED);
  const [thresholdOverrides, setThresholdOverrides] = useState({});
  const [maxAgeDays, setMaxAgeDays] = useState('7');
  const [minimumSamples, setMinimumSamples] = useState('5');
  const [regressionThreshold, setRegressionThreshold] = useState('5');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);

  async function importCsv(event, windowName) {
    const element = event.currentTarget;
    const file = element.files?.[0];
    if (!file) return;
    setError('');
    try {
      if (file.size > 1024 * 1024) throw new Error('CSV exceeds the 1 MiB import limit.');
      const samples = parseClientExperienceCsv(await file.text());
      const setter = windowName === 'baseline' ? setBaselineText : setComparisonText;
      setter(JSON.stringify(samples, null, 2));
      setResult(null);
    } catch (err) {
      setError(err.message || 'Unable to import client observations from CSV.');
    } finally {
      element.value = '';
    }
  }

  function toggleMetric(key, checked) {
    setRequiredMetrics(current => checked ? [...current, key] : current.filter(item => item !== key));
    setResult(null);
  }

  async function compare() {
    setBusy(true);
    setError('');
    setResult(null);
    try {
      const baselineSamples = JSON.parse(baselineText);
      const timezoneAware = value => /(?:Z|[+-]\d{2}:\d{2})$/i.test(value) && Number.isFinite(Date.parse(value));
      if (!baselineAsOf.trim() || !timezoneAware(baselineAsOf.trim())) {
        throw new Error('Enter a valid timezone-aware baseline window end timestamp.');
      }
      if (!comparisonAsOf.trim() || !timezoneAware(comparisonAsOf.trim())) {
        throw new Error('Enter a valid timezone-aware comparison window end timestamp.');
      }
      const comparisonSamples = JSON.parse(comparisonText);
      if (!Array.isArray(baselineSamples) || !baselineSamples.length) throw new Error('Provide baseline observation records.');
      if (!Array.isArray(comparisonSamples) || !comparisonSamples.length) throw new Error('Provide comparison observation records.');
      const age = Number(maxAgeDays);
      const minimum = Number(minimumSamples);
      const regression = Number(regressionThreshold);
      if (!Number.isInteger(age) || age < 1 || age > 30) throw new Error('Freshness window must be a whole number from 1 to 30 days.');
      if (!Number.isInteger(minimum) || minimum < 1 || minimum > 10000) throw new Error('Minimum eligible samples must be a whole number from 1 to 10000.');
      if (!Number.isFinite(regression) || regression < 0.1 || regression > 100) throw new Error('Regression threshold must be from 0.1 to 100 percentage points.');
      if (Date.parse(comparisonAsOf) <= Date.parse(baselineAsOf) + age * 86400000) {
        throw new Error('Baseline and comparison window ends must be more than the freshness window apart.');
      }
      if (!requiredMetrics.length) throw new Error('Select at least one required metric so incomplete samples cannot be treated as healthy.');
      if (requiredMetrics.includes('throughput_mbps') && !thresholdOverrides.throughput_mbps?.trim()) {
        throw new Error('Set a minimum throughput threshold before making throughput a required metric.');
      }
      const thresholds = {};
      for (const [key] of METRICS) {
        const value = thresholdOverrides[key]?.trim();
        if (!value) continue;
        const number = Number(value);
        if (!Number.isFinite(number)) throw new Error('Threshold ' + key + ' must be numeric.');
        thresholds[key] = number;
      }
      const response = await apiFetch(apiBase() + '/api/features/client_experience_slo_window_comparator', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          baseline: { as_of: baselineAsOf, samples: baselineSamples },
          comparison: { as_of: comparisonAsOf, samples: comparisonSamples },
          max_age_days: age,
          minimum_eligible_samples: minimum,
          regression_threshold_pct_points: regression,
          ...(requiredMetrics.length ? { required_metrics: requiredMetrics } : {}),
          ...(Object.keys(thresholds).length ? { thresholds } : {}),
        }),
        signal: AbortSignal.timeout(30000),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'SLO comparison returned HTTP ' + response.status);
      setResult(data.result || data);
    } catch (err) {
      setError(err.message || 'Unable to compare client experience windows.');
    } finally {
      setBusy(false);
    }
  }

  const summary = result?.summary;
  const status = result?.status || '';
  const statusColor = status === 'regression_detected' || status === 'partial_evidence' ? '#fbbf24'
    : status === 'improvement_detected' ? '#34d399'
      : status === 'stable' ? '#38bdf8' : '#94a3b8';

  return <div style={{ display: 'grid', gap: 12 }}>
    <section style={{ ...panel, borderColor: '#24506a' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 7 }}>
        <Activity size={17} color="#06d6f0"/>
        <strong style={{ color: '#e2e8f0', fontSize: 13 }}>Client experience SLO window comparison</strong>
        <span style={{ marginLeft: 'auto', color: '#94a3b8', fontSize: 10 }}>F293 · F292 MODEL</span>
      </div>
      <p style={{ ...muted, margin: 0 }}>Compare two non-overlapping periods using the same thresholds and sample eligibility rules. This reports sample-weighted attainment and descriptive metric changes—not duration-weighted uptime or statistical confidence.</p>
    </section>
    <section style={panel}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(220px,1fr))', gap: 10 }}>
        <label><span style={muted}>Baseline window end (timezone-aware ISO-8601)</span><input value={baselineAsOf} onChange={event => { setBaselineAsOf(event.target.value); setResult(null); }} placeholder="2026-11-13T12:00:00Z" style={field}/></label>
        <label><span style={muted}>Comparison window end (timezone-aware ISO-8601)</span><input value={comparisonAsOf} onChange={event => { setComparisonAsOf(event.target.value); setResult(null); }} placeholder="2026-11-21T12:00:00Z" style={field}/></label>
      </div>
      <p style={muted}>The window end timestamps must be more than the freshness-window length apart so their measured periods do not overlap. Each sample must be timestamped at or before its own window end.</p>
    </section>
    <section style={panel}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8, marginBottom: 7 }}>
        <strong style={{ color: '#cbd5e1', fontSize: 11 }}>Baseline observations</strong>
        <label style={{ ...field, width: 'auto', cursor: 'pointer' }}>Import baseline CSV
          <input type="file" accept=".csv,text/csv" onChange={event => importCsv(event, 'baseline')} aria-label="Import baseline client observation CSV" style={{ width: 1, height: 1, opacity: 0, position: 'absolute', pointerEvents: 'none' }}/>
        </label>
      </div>
      <textarea value={baselineText} onChange={event => { setBaselineText(event.target.value); setResult(null); }} rows={8} spellCheck="false" aria-label="Baseline client observations JSON" style={{ ...field, resize: 'vertical', fontFamily: 'ui-monospace, monospace' }}/>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 8, margin: '14px 0 7px' }}>
        <strong style={{ color: '#cbd5e1', fontSize: 11 }}>Comparison observations</strong>
        <label style={{ ...field, width: 'auto', cursor: 'pointer' }}>Import comparison CSV
          <input type="file" accept=".csv,text/csv" onChange={event => importCsv(event, 'comparison')} aria-label="Import comparison client observation CSV" style={{ width: 1, height: 1, opacity: 0, position: 'absolute', pointerEvents: 'none' }}/>
        </label>
      </div>
      <textarea value={comparisonText} onChange={event => { setComparisonText(event.target.value); setResult(null); }} rows={8} spellCheck="false" aria-label="Comparison client observations JSON" style={{ ...field, resize: 'vertical', fontFamily: 'ui-monospace, monospace' }}/>
      <p style={muted}>CSV import follows the F292 observation format. Site IDs and pseudonymous client references are used to aggregate per-site results; no client aliases or sample IDs are returned by F293.</p>
    </section>
    <section style={panel}>
      <strong style={{ color: '#e2e8f0', fontSize: 12 }}>Shared SLO eligibility and thresholds</strong>
      <div style={{ color: '#cbd5e1', fontSize: 11, margin: '8px 0' }}>Required metrics: samples missing any selected metric are excluded from both denominators.</div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(140px,1fr))', gap: 8 }}>
        {METRICS.map(([key, label]) => <label key={key} style={{ display: 'flex', alignItems: 'center', gap: 7, color: '#94a3b8', fontSize: 11 }}>
          <input type="checkbox" checked={requiredMetrics.includes(key)} onChange={event => toggleMetric(key, event.target.checked)}/>{label}
        </label>)}
      </div>
      <details style={{ marginTop: 12 }}>
        <summary style={{ color: '#a5f3fc', fontSize: 11, cursor: 'pointer' }}>Advanced shared metric thresholds</summary>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(145px,1fr))', gap: 8, marginTop: 9 }}>
          {[
            ['rssi_dbm','Minimum RSSI','-70'],['snr_db','Minimum SNR','20'],
            ['retry_rate_pct','Maximum retries (%)','15'],['airtime_utilization_pct','Maximum airtime (%)','80'],
            ['packet_loss_pct','Maximum packet loss (%)','1'],['rtt_ms','Maximum RTT (ms)','100'],
            ['jitter_ms','Maximum jitter (ms)','30'],['throughput_mbps','Minimum throughput (Mbps)','Disabled'],
          ].map(([key,label,placeholder]) => <label key={key}><span style={muted}>{label}</span><input type="number" value={thresholdOverrides[key] || ''} onChange={event => { setThresholdOverrides(current => ({ ...current, [key]: event.target.value })); setResult(null); }} placeholder={placeholder} style={field}/></label>)}
        </div>
        <p style={muted}>Blank fields use F292 defaults. Throughput remains unscored unless a minimum target is supplied.</p>
      </details>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(150px,1fr))', gap: 8, marginTop: 12 }}>
        <label><span style={muted}>Freshness window (days)</span><input type="number" min="1" max="30" value={maxAgeDays} onChange={event => { setMaxAgeDays(event.target.value); setResult(null); }} style={field}/></label>
        <label><span style={muted}>Minimum eligible samples / window</span><input type="number" min="1" max="10000" value={minimumSamples} onChange={event => { setMinimumSamples(event.target.value); setResult(null); }} style={field}/></label>
        <label><span style={muted}>Regression threshold (percentage points)</span><input type="number" min="0.1" max="100" step="0.1" value={regressionThreshold} onChange={event => { setRegressionThreshold(event.target.value); setResult(null); }} style={field}/></label>
      </div>
      {error ? <div role="alert" style={{ ...muted, color: '#fca5a5', marginTop: 10 }}><AlertCircle size={13} style={{ verticalAlign: 'middle', marginRight: 5 }}/>{error}</div> : null}
      <button type="button" onClick={compare} disabled={busy} style={{ display: 'inline-flex', alignItems: 'center', gap: 7, marginTop: 12, border: '1px solid #06d6f0', background: 'rgba(6,214,240,.13)', color: '#06d6f0', borderRadius: 7, padding: '9px 13px', fontSize: 12, fontWeight: 700, cursor: busy ? 'wait' : 'pointer', opacity: busy ? .5 : 1 }}>
        <Play size={13}/>{busy ? 'Comparing…' : 'Compare SLO windows'}
      </button>
    </section>
    {summary ? <section style={panel}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
        <ShieldCheck size={15} color={statusColor}/>
        <strong style={{ color: '#e2e8f0', fontSize: 12 }}>SLO comparison report</strong>
        <span style={{ marginLeft: 'auto', fontSize: 10, fontWeight: 700, color: statusColor }}>{status.replaceAll('_',' ').toUpperCase()}</span>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(125px,1fr))', gap: 8 }}>
        <Metric label="SLA attainment delta" value={summary.sla_attainment_delta_pct_points == null ? 'n/a' : (summary.sla_attainment_delta_pct_points > 0 ? '+' : '') + summary.sla_attainment_delta_pct_points + ' pp'}/>
        <Metric label="Regressing sites" value={summary.regressing_site_count}/>
        <Metric label="Improving sites" value={summary.improving_site_count}/>
        <Metric label="Comparable sites" value={summary.comparable_site_count}/>
        <Metric label="Site coverage" value={summary.site_coverage_pct == null ? "n/a" : summary.site_coverage_pct + "%"}/>
        <Metric label="Incomplete sites" value={summary.incomplete_site_count}/>
        <Metric label="Eligible baseline samples" value={summary.baseline_eligible_sample_count}/>
        <Metric label="Eligible comparison samples" value={summary.comparison_eligible_sample_count}/>
      </div>
      <div style={{ overflowX: 'auto', marginTop: 12 }}>
        <strong style={{ color: '#cbd5e1', fontSize: 11 }}>Site-level comparison</strong>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, textAlign: 'left', marginTop: 6 }}>
          <thead><tr>{['Site','Status','Baseline attainment','Comparison attainment','Delta (pp)','Eligible samples'].map(item => <th key={item} style={{ padding: 7, color: '#94a3b8', borderBottom: '1px solid #263956', whiteSpace: 'nowrap' }}>{item}</th>)}</tr></thead>
          <tbody>{result.sites.map(site => {
            const before = site.baseline;
            const after = site.comparison;
            return <tr key={site.site_id}>{[
              site.site_id,site.status.replaceAll('_',' '),
              before?.sla_attainment_pct == null ? 'n/a' : before.sla_attainment_pct + '%',
              after?.sla_attainment_pct == null ? 'n/a' : after.sla_attainment_pct + '%',
              site.sla_attainment_delta_pct_points == null ? 'n/a' : site.sla_attainment_delta_pct_points + ' pp',
              (before?.eligible_slo_sample_count ?? 0) + ' / ' + (after?.eligible_slo_sample_count ?? 0),
            ].map((value,index) => <td key={index} style={{ padding: 7, color: '#cbd5e1', borderBottom: '1px solid #1e2d47', whiteSpace: 'nowrap' }}>{value}</td>)}</tr>;
          })}</tbody>
        </table>
      </div>
      <div style={{ overflowX: 'auto', marginTop: 12 }}>
        <strong style={{ color: '#cbd5e1', fontSize: 11 }}>Descriptive metric p95 deltas</strong>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, textAlign: 'left', marginTop: 6 }}>
          <thead><tr>{['Metric','Baseline p95','Comparison p95','Delta','Samples (before / after)'].map(item => <th key={item} style={{ padding: 7, color: '#94a3b8', borderBottom: '1px solid #263956', whiteSpace: 'nowrap' }}>{item}</th>)}</tr></thead>
          <tbody>{Object.entries(result.overall.metric_deltas).map(([name,item]) => <tr key={name}>{[
            name,item.baseline_p95 == null ? '—' : item.baseline_p95,
            item.comparison_p95 == null ? '—' : item.comparison_p95,
            item.p95_delta == null ? '—' : item.p95_delta,
            item.baseline_sample_count + ' / ' + item.comparison_sample_count,
          ].map((value,index) => <td key={index} style={{ padding: 7, color: '#cbd5e1', borderBottom: '1px solid #1e2d47', whiteSpace: 'nowrap' }}>{value}</td>)}</tr>)}</tbody>
        </table>
      </div>
      {status === "partial_evidence" ? <p role="status" style={{ ...muted, color: "#fbbf24", marginBottom: 8 }}>Fleet-wide improvement is not declared because one or more sites lack sufficient comparable telemetry. Review the site-level evidence gaps before drawing a fleet conclusion.</p> : null}
      <p style={{ ...muted, marginBottom: 0 }}>{result.note}</p>
    </section> : null}
  </div>;
}
