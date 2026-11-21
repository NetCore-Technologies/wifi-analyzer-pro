import { useEffect, useMemo, useState } from 'react';
import { apiFetch, apiBase } from '../lib/api.js';
import SiteTopologyGraph from './SiteTopologyGraph.jsx';
import SiteChangeReport from './SiteChangeReport.jsx';
import SiteAuditReport from './SiteAuditReport.jsx';
import MultiApChannelPlanner from './MultiApChannelPlanner.jsx';
import ClientRoamTransactionAnalyzer from './ClientRoamTransactionAnalyzer.jsx';
import ClientExperienceSloPanel from './ClientExperienceSloPanel.jsx';
import ClientExperienceSloWindowComparator from './ClientExperienceSloWindowComparator.jsx';
import { Play, Search, RefreshCw, Braces, Wifi, AlertCircle } from 'lucide-react';

const panel = { background: '#0c1120', border: '1px solid #1e2d47', borderRadius: 10, padding: 14 };
const input = { width: '100%', boxSizing: 'border-box', background: '#070b14', color: '#e2e8f0', border: '1px solid #263956', borderRadius: 7, padding: '9px 10px', fontSize: 12 };

export default function FeatureWorkbench() {
  const [catalog, setCatalog] = useState([]);
  const [selected, setSelected] = useState('scan_summary');
  const [search, setSearch] = useState('');
  const [payloadText, setPayloadText] = useState('{\n  "networks": []\n}');
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  const loadCatalog = async () => {
    setLoading(true); setError('');
    try {
      const response = await apiFetch(`${apiBase()}/api/features`, { signal: AbortSignal.timeout(8000) });
      if (!response.ok) throw new Error(`Feature catalog returned HTTP ${response.status}`);
      const data = await response.json();
      setCatalog(Array.isArray(data.features) ? data.features : []);
      if (data.features?.length && !data.features.some(f => f.slug === selected)) setSelected(data.features[0].slug);
    } catch (err) { setError(err.message || 'Unable to load feature catalog.'); }
    finally { setLoading(false); }
  };

  useEffect(() => { loadCatalog(); }, []);

  const filtered = useMemo(() => catalog.filter(feature =>
    `${feature.name} ${feature.slug} ${feature.category} ${feature.description}`.toLowerCase().includes(search.toLowerCase())
  ), [catalog, search]);
  const current = catalog.find(feature => feature.slug === selected);

  const useLatestScan = async () => {
    setBusy(true); setError('');
    try {
      const response = await apiFetch(`${apiBase()}/api/scan`, { signal: AbortSignal.timeout(20000) });
      if (!response.ok) throw new Error(`Scan returned HTTP ${response.status}`);
      const data = await response.json();
      setPayloadText(JSON.stringify({ networks: data.networks || [], timestamp: data.timestamp, source: data.source }, null, 2));
    } catch (err) { setError(err.message || 'Could not load the latest scan.'); }
    finally { setBusy(false); }
  };


  const loadStoredHistoryReport = async () => {
    setBusy(true); setError(''); setResult(null);
    try {
      const response = await apiFetch(`${apiBase()}/api/sites/history/report`, {
        signal: AbortSignal.timeout(20000),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || `History report returned HTTP ${response.status}`);
      setResult(data.report);
    } catch (err) { setError(err.message || 'Unable to build the stored site history report.'); }
    finally { setBusy(false); }
  };

  const run = async () => {
    setBusy(true); setError(''); setResult(null);
    try {
      const body = JSON.parse(payloadText);
      if (!body || Array.isArray(body) || typeof body !== 'object') throw new Error('Input must be a JSON object.');
      const response = await apiFetch(`${apiBase()}/api/features/${encodeURIComponent(selected)}`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(15000),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || `Feature returned HTTP ${response.status}`);
      setResult(data);
    } catch (err) { setError(err.message || 'Feature execution failed.'); }
    finally { setBusy(false); }
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(220px, 280px) minmax(0, 1fr)', gap: 12, alignItems: 'start' }}>
      <section style={{ ...panel, maxHeight: 'calc(100vh - 150px)', overflow: 'auto' }}>
        <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 4, color: '#e2e8f0' }}>Feature library</div>
        <div style={{ fontSize: 11, color: '#64748b', marginBottom: 12 }}>{loading ? 'Loading…' : `${catalog.length} independently callable tools`}</div>
        <div style={{ position: 'relative', marginBottom: 10 }}><Search size={13} color="#64748b" style={{ position: 'absolute', top: 10, left: 9 }}/><input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search features…" aria-label="Search features" style={{ ...input, paddingLeft: 29 }}/></div>
        {filtered.map(feature => <button key={feature.slug} onClick={() => { setSelected(feature.slug); setResult(null); }} style={{ width: '100%', textAlign: 'left', padding: '9px 10px', borderRadius: 7, marginBottom: 5, border: `1px solid ${selected === feature.slug ? '#06d6f0' : '#1e2d47'}`, background: selected === feature.slug ? 'rgba(6,214,240,.09)' : 'transparent', color: selected === feature.slug ? '#06d6f0' : '#cbd5e1', cursor: 'pointer' }}><div style={{ fontSize: 11, fontWeight: 650 }}>{feature.id} · {feature.name}</div><div style={{ fontSize: 10, color: '#64748b', marginTop: 2 }}>{feature.category}</div></button>)}
        {!loading && filtered.length === 0 ? <p style={{ fontSize: 11, color: '#64748b' }}>No matching features.</p> : null}
      </section>
      <section style={{ display: 'grid', gap: 12, minWidth: 0 }}>
        <div style={panel}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap' }}>
            <div><div style={{ color: '#06d6f0', fontSize: 10, fontWeight: 700, letterSpacing: 1 }}>{current?.id || 'FEATURE'} · {current?.category || 'TOOLS'}</div><h2 style={{ margin: '4px 0', fontSize: 18 }}>{current?.name || 'Select a feature'}</h2><p style={{ fontSize: 12, color: '#94a3b8', margin: 0 }}>{current?.description || 'Choose a tool from the feature library.'}</p></div>
            <button onClick={loadCatalog} disabled={loading} title="Refresh feature list" style={{ background: '#111827', border: '1px solid #263956', color: '#94a3b8', borderRadius: 7, padding: 9, cursor: 'pointer' }}><RefreshCw size={15}/></button>
          </div>
          {current?.parameters && Object.keys(current.parameters).length ? <div style={{ marginTop: 10, fontSize: 11, color: '#64748b' }}>Inputs: {Object.entries(current.parameters).map(([k,v]) => `${k} (${v})`).join(' · ')}</div> : null}
        </div>
        {selected === 'multi_ap_channel_reuse_planner' ? <MultiApChannelPlanner /> : selected === 'client_roam_transaction_analyzer' ? <ClientRoamTransactionAnalyzer /> : selected === 'client_experience_slo_evaluator' ? <ClientExperienceSloPanel /> : selected === 'client_experience_slo_window_comparator' ? <ClientExperienceSloWindowComparator /> : <div style={panel}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 8 }}><div style={{ fontSize: 12, fontWeight: 700 }}>JSON input</div><button onClick={useLatestScan} disabled={busy} style={{ border: '1px solid #263956', background: '#111827', color: '#06d6f0', borderRadius: 7, padding: '7px 9px', fontSize: 11, cursor: 'pointer' }}><Wifi size={12} style={{ verticalAlign: 'middle', marginRight: 5 }}/>Use latest scan</button></div>
          <textarea value={payloadText} onChange={e => setPayloadText(e.target.value)} rows={12} spellCheck="false" aria-label="Feature JSON input" style={{ ...input, resize: 'vertical', fontFamily: 'ui-monospace, monospace', lineHeight: 1.55 }}/>
          <button onClick={run} disabled={busy || !current} style={{ marginTop: 10, display: 'inline-flex', alignItems: 'center', gap: 7, background: 'rgba(6,214,240,.13)', color: '#06d6f0', border: '1px solid #06d6f0', borderRadius: 7, padding: '9px 15px', fontSize: 12, fontWeight: 700, cursor: busy ? 'wait' : 'pointer', opacity: busy ? .6 : 1 }}><Play size={13}/>{busy ? 'Running…' : 'Run feature'}</button>
          {selected === 'site_to_site_change_report' ? <button onClick={loadStoredHistoryReport} disabled={busy} style={{ marginTop: 10, marginLeft: 8, display: 'inline-flex', alignItems: 'center', gap: 7, background: '#111827', color: '#a5f3fc', border: '1px solid #256779', borderRadius: 7, padding: '9px 12px', fontSize: 11, cursor: busy ? 'wait' : 'pointer' }}>Build report from saved history</button> : null}
        </div>}
        {error && selected !== 'multi_ap_channel_reuse_planner' && selected !== 'client_roam_transaction_analyzer' && selected !== 'client_experience_slo_evaluator' && selected !== 'client_experience_slo_window_comparator' ? <div role="alert" style={{ ...panel, borderColor: '#ef4444', color: '#fca5a5', fontSize: 12 }}><AlertCircle size={14} style={{ verticalAlign: 'middle', marginRight: 6 }}/>{error}</div> : null}
        {result && selected !== 'multi_ap_channel_reuse_planner' && selected !== 'client_roam_transaction_analyzer' && selected !== 'client_experience_slo_evaluator' && selected !== 'client_experience_slo_window_comparator' ? <div style={panel}><div style={{ fontSize: 12, fontWeight: 700, marginBottom: 8 }}><Braces size={14} style={{ verticalAlign: 'middle', marginRight: 6, color: '#06d6f0' }}/>Result</div>{selected === 'site_topology_visualisation' ? <SiteTopologyGraph data={result.result} /> : selected === 'site_to_site_change_report' ? <SiteChangeReport data={result.result} /> : selected === 'consolidated_site_audit_report' ? <SiteAuditReport data={result.result} /> : <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', maxHeight: 420, overflow: 'auto', margin: 0, color: '#cbd5e1', fontSize: 11, lineHeight: 1.55 }}>{JSON.stringify(result, null, 2)}</pre>}</div> : null}
      </section>
    </div>
  );
}
