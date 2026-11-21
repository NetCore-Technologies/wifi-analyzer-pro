import { useState } from 'react';
import { apiFetch, apiBase } from '../lib/api.js';
import { Activity, AlertCircle, ShieldCheck } from 'lucide-react';

const panel = { background: '#0c1120', border: '1px solid #1e2d47', borderRadius: 10, padding: 14 };
const field = { width: '100%', boxSizing: 'border-box', background: '#070b14', color: '#e2e8f0', border: '1px solid #263956', borderRadius: 7, padding: '9px 10px', fontSize: 12 };
const muted = { color: '#94a3b8', fontSize: 11, lineHeight: 1.55 };
const metricCard = { background: '#070b14', border: '1px solid #1e2d47', borderRadius: 8, padding: 10 };

function Metric({ label, value, detail }) {
  return <div style={metricCard}><div style={muted}>{label}</div><div style={{ color: '#e2e8f0', fontSize: 19, fontWeight: 750, marginTop: 4 }}>{value ?? '—'}</div>{detail ? <div style={{ ...muted, marginTop: 4 }}>{detail}</div> : null}</div>;
}

export default function ClientRoamTransactionAnalyzer() {
  const [eventsText, setEventsText] = useState('');
  const [threshold, setThreshold] = useState('1000');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);

  async function analyse() {
    setBusy(true);
    setError('');
    setResult(null);
    try {
      const events = JSON.parse(eventsText);
      if (!Array.isArray(events) || events.length === 0) throw new Error('Provide a non-empty JSON array of controller, agent or client events.');
      const thresholdValue = Number(threshold);
      if (!Number.isInteger(thresholdValue) || thresholdValue < 50 || thresholdValue > 30000) {
        throw new Error('Slow-roam threshold must be an integer between 50 and 30000 ms.');
      }
      const response = await apiFetch(apiBase() + '/api/features/client_roam_transaction_analyzer', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ events, slow_roam_threshold_ms: thresholdValue }),
        signal: AbortSignal.timeout(20000),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Roam analyzer returned HTTP ' + response.status);
      setResult(data.result || data);
    } catch (err) {
      setError(err.message || 'Unable to analyse client roam transactions.');
    } finally {
      setBusy(false);
    }
  }

  const summary = result?.summary;
  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <section style={{ ...panel, borderColor: '#24506a' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 7 }}>
          <Activity size={17} color="#06d6f0"/>
          <strong style={{ color: '#e2e8f0', fontSize: 13 }}>Client roam transaction analyzer</strong>
          <span style={{ marginLeft: 'auto', color: '#94a3b8', fontSize: 10 }}>F291 · OFFLINE EVENT ANALYSIS</span>
        </div>
        <p style={{ ...muted, margin: 0 }}>Correlate explicit roam-start, roam-complete and roam-failure telemetry. Roam latency is calculated only from matched timestamps; incomplete event pairs are reported separately and never estimated from snapshot intervals.</p>
      </section>
      <section style={panel}>
        <label style={{ display: 'block', color: '#cbd5e1', fontSize: 11, fontWeight: 700, marginBottom: 7 }}>Controller / agent / client event export (JSON array)</label>
        <textarea
          value={eventsText}
          onChange={event => setEventsText(event.target.value)}
          rows={12}
          spellCheck="false"
          aria-label="Client roaming transaction events JSON"
          placeholder={'[\n  {\n    "event_id": "event-001",\n    "site_id": "office",\n    "client_ref": "station-opaque-01",\n    "event_type": "roam_start",\n    "roam_id": "transaction-01",\n    "from_ap_id": "ap-01",\n    "to_ap_id": "ap-02",\n    "occurred_at": "2026-11-20T10:00:00Z",\n    "evidence_source": "controller"\n  },\n  {\n    "event_id": "event-002",\n    "site_id": "office",\n    "client_ref": "station-opaque-01",\n    "event_type": "roam_complete",\n    "roam_id": "transaction-01",\n    "occurred_at": "2026-11-20T10:00:00.250Z",\n    "evidence_source": "controller"\n  }\n]'}
          style={{ ...field, resize: 'vertical', fontFamily: 'ui-monospace, monospace', lineHeight: 1.5 }}
        />
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(170px,240px) 1fr', gap: 10, alignItems: 'end', marginTop: 10 }}>
          <label><span style={{ ...muted, display: 'block', marginBottom: 5 }}>Slow-roam threshold (ms)</span><input type="number" min="50" max="30000" step="1" value={threshold} onChange={event => setThreshold(event.target.value)} style={field}/></label>
          <div style={muted}>Use a consistent, report-local client reference. Returned client aliases are report-local; raw event and transaction IDs are not returned.</div>
        </div>
        {error ? <div role="alert" style={{ ...muted, color: '#fca5a5', marginTop: 9 }}><AlertCircle size={13} style={{ verticalAlign: 'middle', marginRight: 5 }}/>{error}</div> : null}
        <button type="button" onClick={analyse} disabled={busy || !eventsText.trim()} style={{ marginTop: 10, display: 'inline-flex', alignItems: 'center', gap: 7, background: 'rgba(6,214,240,.13)', color: '#06d6f0', border: '1px solid #06d6f0', borderRadius: 7, padding: '9px 14px', fontSize: 12, fontWeight: 700, cursor: busy ? 'wait' : 'pointer', opacity: busy || !eventsText.trim() ? .5 : 1 }}>
          {busy ? 'Analysing…' : 'Analyse roam transactions'}
        </button>
      </section>
      {summary ? <section style={panel}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
          <ShieldCheck size={15} color="#34d399"/>
          <strong style={{ color: '#e2e8f0', fontSize: 12 }}>Roaming evidence summary</strong>
          <span style={{ marginLeft: 'auto', color: '#94a3b8', fontSize: 10 }}>{summary.event_count} input events</span>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(125px,1fr))', gap: 8 }}>
          <Metric label="Completed roams" value={summary.completed_roams}/>
          <Metric label="Failed roams" value={summary.failed_roams}/>
          <Metric label="Incomplete telemetry" value={summary.incomplete_transactions}/>
          <Metric label="Failure rate" value={summary.roam_failure_rate_pct == null ? 'n/a' : summary.roam_failure_rate_pct + '%'} detail="Matched transactions only"/>
          <Metric label="Median latency" value={summary.median_roam_latency_ms == null ? 'n/a' : summary.median_roam_latency_ms + ' ms'} detail={summary.latency_sample_count + ' successful samples'}/>
          <Metric label="P95 latency" value={summary.p95_roam_latency_ms == null ? 'n/a' : summary.p95_roam_latency_ms + ' ms'}/>
          <Metric label="Slow roams" value={summary.slow_roam_count}/>
          <Metric label="Clients" value={summary.client_count}/>
        </div>
        {result.transactions?.length ? <div style={{ overflowX: 'auto', marginTop: 12 }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, textAlign: 'left' }}>
            <thead><tr>{['Client alias','Site','From AP','To AP','Status','Roam latency','Failure time'].map(item => <th key={item} style={{ padding: 8, color: '#94a3b8', borderBottom: '1px solid #263956', whiteSpace: 'nowrap' }}>{item}</th>)}</tr></thead>
            <tbody>{result.transactions.map(row => <tr key={row.transaction_ref}>{[row.client_ref,row.site_id,row.from_ap_id || '—',row.to_ap_id || '—',row.status.replaceAll('_',' '),row.roam_latency_ms == null ? '—' : row.roam_latency_ms + ' ms',row.time_to_failure_ms == null ? '—' : row.time_to_failure_ms + ' ms'].map((value,index) => <td key={index} style={{ padding: 8, color: index === 4 && row.status !== 'completed' ? '#fbbf24' : '#cbd5e1', borderBottom: '1px solid #1e2d47', whiteSpace: 'nowrap' }}>{value}</td>)}</tr>)}</tbody>
          </table>
        </div> : null}
        {result.details_truncated ? <p style={muted}>Transaction detail output was truncated to the first 500 records; summary metrics include all accepted events.</p> : null}
        <div style={{ ...muted, marginTop: 10 }}>{result.note}</div>
      </section> : null}
    </div>
  );
}
