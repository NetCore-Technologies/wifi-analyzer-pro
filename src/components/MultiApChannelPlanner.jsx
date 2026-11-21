import { useMemo, useState } from 'react';
import { apiFetch, apiBase } from '../lib/api.js';
import { buildMultiApPlannerPayload, mapSavedSiteSnapshotToPlannerRadios } from '../lib/multiApChannelPlanner.js';
import { Plus, Trash2, Play, AlertCircle, ShieldCheck, RadioTower, Info } from 'lucide-react';

const panel = { background: '#0c1120', border: '1px solid #1e2d47', borderRadius: 10, padding: 14 };
const field = { width: '100%', minWidth: 0, boxSizing: 'border-box', background: '#070b14', color: '#e2e8f0', border: '1px solid #263956', borderRadius: 7, padding: '8px 9px', fontSize: 12 };
const label = { display: 'block', fontSize: 10, color: '#94a3b8', marginBottom: 5, fontWeight: 650 };
const muted = { color: '#64748b', fontSize: 11, lineHeight: 1.55 };
const action = { display: 'inline-flex', alignItems: 'center', gap: 7, border: '1px solid #06d6f0', background: 'rgba(6,214,240,.13)', color: '#06d6f0', borderRadius: 7, padding: '9px 13px', fontSize: 12, fontWeight: 700, cursor: 'pointer' };
const secondary = { display: 'inline-flex', alignItems: 'center', gap: 6, border: '1px solid #263956', background: '#111827', color: '#cbd5e1', borderRadius: 7, padding: '7px 9px', fontSize: 11, cursor: 'pointer' };
const bands = ['2.4GHz', '5GHz', '6GHz'];
const widths = [20, 40, 80, 160, 320];

const blankRadio = id => ({ rowId: id, radio_id: '', ap_id: '', site_id: '', band: '2.4GHz', width: '20', current_channel: '', options: '' });
const blankEdge = id => ({ rowId: id, left: '', right: '', weight: '', source: '' });

export default function MultiApChannelPlanner() {
  const [radios, setRadios] = useState([blankRadio(1), blankRadio(2)]);
  const [edges, setEdges] = useState([blankEdge(1)]);
  const [penalty, setPenalty] = useState('0.05');
  const [radioSequence, setRadioSequence] = useState(3);
  const [edgeSequence, setEdgeSequence] = useState(2);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState(null);
  const choices = useMemo(() => radios.filter(radio => radio.radio_id.trim()), [radios]);
  const [snapshotId, setSnapshotId] = useState('');
  const [importBusy, setImportBusy] = useState(false);
  const [importMessage, setImportMessage] = useState('');
  const [importError, setImportError] = useState('');

  async function importSavedSnapshot(event) {
    event.preventDefault();
    if (!/^\\d+$/.test(snapshotId.trim())) {
      setImportError('Enter a saved snapshot ID.');
      return;
    }
    setImportBusy(true);
    setImportError('');
    setImportMessage('');
    try {
      const response = await apiFetch(apiBase() + '/api/sites/history/' + encodeURIComponent(snapshotId.trim()), {
        signal: AbortSignal.timeout(12000),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || 'Unable to load the saved snapshot.');
      const mapped = mapSavedSiteSnapshotToPlannerRadios(data.snapshot?.snapshot);
      if (!mapped.radios.length) throw new Error('No 20 MHz AP radio records with site, band and channel evidence were available to import.');
      const rows = mapped.radios.map((radio, index) => ({ ...radio, rowId: radioSequence + index }));
      setRadios(rows);
      setRadioSequence(value => value + rows.length);
      setEdges([blankEdge(edgeSequence)]);
      setEdgeSequence(value => value + 1);
      setResult(null);
      setImportMessage(
        'Imported ' + rows.length + ' radio records. Skipped ' + mapped.skipped_incomplete_count
        + ' incomplete records, ' + mapped.skipped_wide_channel_count
        + ' wide-channel records without a safe centre-frequency value, and '
        + mapped.skipped_cross_site_count + ' cross-site records. Candidate options contain only the observed current channel; add legally permitted alternatives before planning.',
      );
    } catch (err) {
      setImportError(err.message || 'Unable to import the saved snapshot.');
    } finally {
      setImportBusy(false);
    }
  }

  function updateRadio(id, patch) {
    setRadios(current => current.map(radio => radio.rowId === id ? { ...radio, ...patch } : radio));
    setResult(null);
  }
  function updateEdge(id, patch) {
    setEdges(current => current.map(edge => edge.rowId === id ? { ...edge, ...patch } : edge));
    setResult(null);
  }
  function changeBand(radio, band) {
    const width = Number(radio.width);
    const allowed = band === '2.4GHz' ? [20, 40] : band === '5GHz' ? [20, 40, 80, 160] : widths;
    updateRadio(radio.rowId, { band, width: String(allowed.includes(width) ? width : 20), options: '' });
  }

  async function execute(event) {
    event.preventDefault();
    setBusy(true);
    setError('');
    setResult(null);
    try {
      const payload = buildMultiApPlannerPayload(radios, edges, penalty);
      const response = await apiFetch(`${apiBase()}/api/features/multi_ap_channel_reuse_planner`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(20000),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || `Planner returned HTTP ${response.status}`);
      setResult(data.result || data);
    } catch (err) {
      setError(err.message || 'Channel planning failed.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{ display: 'grid', gap: 12 }}>
      <section style={{ ...panel, borderColor: '#24506a' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 9, marginBottom: 7 }}>
          <RadioTower size={17} color="#06d6f0"/>
          <strong style={{ color: '#e2e8f0', fontSize: 13 }}>Multi-AP channel planner</strong>
          <span style={{ marginLeft: 'auto', color: '#94a3b8', fontSize: 10 }}>F201 · READ-ONLY</span>
        </div>
        <p style={{ ...muted, margin: 0 }}>Define your AP radios, the channels each radio is permitted to use, and the interference relationships you have measured or assessed. The planner proposes a channel assignment; it never applies configuration.</p>
      </section>
      <form onSubmit={importSavedSnapshot} style={panel}>
        <div style={{ color: '#e2e8f0', fontSize: 12, fontWeight: 700, marginBottom: 7 }}>Import a saved site inventory</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(160px,240px) auto', gap: 8, alignItems: 'end' }}>
          <label><span style={label}>Saved snapshot ID</span><input type="number" min="1" step="1" value={snapshotId} onChange={event => setSnapshotId(event.target.value)} placeholder="e.g. 42" style={field}/></label>
          <button type="submit" disabled={importBusy || !snapshotId.trim()} style={{ ...secondary, opacity: importBusy || !snapshotId.trim() ? 0.5 : 1 }}>{importBusy ? 'Importing…' : 'Import AP radios'}</button>
        </div>
        {importError ? <div role="alert" style={{ ...muted, color: '#fca5a5', marginTop: 8 }}>{importError}</div> : null}
        {importMessage ? <div role="status" style={{ ...muted, color: '#a5f3fc', marginTop: 8 }}>{importMessage}</div> : null}
      </form>
      <form onSubmit={execute} style={{ display: 'grid', gap: 12 }}>
        <section style={panel}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8, marginBottom: 10, flexWrap: 'wrap' }}>
            <strong style={{ color: '#e2e8f0', fontSize: 12 }}>AP radio inventory</strong>
            <button type="button" onClick={() => { setRadios(current => [...current, blankRadio(radioSequence)]); setRadioSequence(value => value + 1); }} style={secondary}><Plus size={13}/>Add radio</button>
          </div>
          <div style={{ display: 'grid', gap: 9 }}>
            {radios.map((radio, index) => (
              <div key={radio.rowId} style={{ border: '1px solid #1e2d47', borderRadius: 8, padding: 10, display: 'grid', gap: 8 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <strong style={{ color: '#cbd5e1', fontSize: 11 }}>Radio {index + 1}</strong>
                  <button type="button" aria-label={`Remove radio ${index + 1}`} disabled={radios.length <= 1} onClick={() => {
                    const removedId = radio.radio_id;
                    setRadios(current => current.filter(item => item.rowId !== radio.rowId));
                    setEdges(current => current.map(edge => ({ ...edge, left: edge.left === removedId ? '' : edge.left, right: edge.right === removedId ? '' : edge.right })));
                    setResult(null);
                  }} style={{ ...secondary, padding: 6, color: '#fca5a5', opacity: radios.length <= 1 ? 0.4 : 1 }}><Trash2 size={12}/></button>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(140px,1fr))', gap: 8 }}>
                  <label><span style={label}>Radio ID</span><input required value={radio.radio_id} onChange={e => updateRadio(radio.rowId, { radio_id: e.target.value })} placeholder="ap-01-5g" style={field}/></label>
                  <label><span style={label}>Access point ID</span><input required value={radio.ap_id} onChange={e => updateRadio(radio.rowId, { ap_id: e.target.value })} placeholder="ap-01" style={field}/></label>
                  <label><span style={label}>Site ID</span><input required value={radio.site_id} onChange={e => updateRadio(radio.rowId, { site_id: e.target.value })} placeholder="head-office" style={field}/></label>
                  <label><span style={label}>Band</span><select value={radio.band} onChange={e => changeBand(radio, e.target.value)} style={field}>{bands.map(band => <option key={band} value={band}>{band}</option>)}</select></label>
                  <label><span style={label}>Channel width</span><select value={radio.width} onChange={e => updateRadio(radio.rowId, { width: e.target.value, options: '' })} style={field}>{widths.filter(width => radio.band === '2.4GHz' ? [20,40].includes(width) : radio.band === '5GHz' ? width !== 320 : true).map(width => <option key={width} value={width}>{width} MHz</option>)}</select></label>
                  <label><span style={label}>Current channel (optional)</span><input type="number" min="1" step="1" value={radio.current_channel} onChange={e => updateRadio(radio.rowId, { current_channel: e.target.value })} placeholder="36" style={field}/></label>
                </div>
                <label><span style={label}>Permitted channel options</span><input required value={radio.options} onChange={e => updateRadio(radio.rowId, { options: e.target.value })} placeholder={Number(radio.width) === 20 ? '1, 6, 11' : '36@5190, 44@5230'} style={field}/></label>
                <div style={muted}>{Number(radio.width) === 20 ? 'Enter channel numbers separated by commas.' : 'Enter channel@centre-frequency-MHz pairs. Obtain centre frequencies from the controller or an approved RF plan.'} Include only channels permitted for this radio and regulatory domain.</div>
              </div>
            ))}
          </div>
        </section>
        <section style={panel}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8, marginBottom: 8, flexWrap: 'wrap' }}>
            <strong style={{ color: '#e2e8f0', fontSize: 12 }}>RF interference evidence</strong>
            <button type="button" onClick={() => { setEdges(current => [...current, blankEdge(edgeSequence)]); setEdgeSequence(value => value + 1); }} style={secondary}><Plus size={13}/>Add relationship</button>
          </div>
          <p style={{ ...muted, marginTop: 0 }}>Each relationship connects two radios in the same site and band. Weight is a relative 0–1 planning input, not a dBm measurement or probability.</p>
          {edges.map((edge, index) => (
            <div key={edge.rowId} style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(135px,1fr))', gap: 8, borderTop: '1px solid #1e2d47', padding: '10px 0', alignItems: 'end' }}>
              <label><span style={label}>Radio A</span><select required value={edge.left} onChange={e => updateEdge(edge.rowId, { left: e.target.value })} style={field}><option value="">Select radio…</option>{choices.map(radio => <option key={radio.rowId} value={radio.radio_id}>{radio.radio_id}</option>)}</select></label>
              <label><span style={label}>Radio B</span><select required value={edge.right} onChange={e => updateEdge(edge.rowId, { right: e.target.value })} style={field}><option value="">Select radio…</option>{choices.map(radio => <option key={radio.rowId} value={radio.radio_id}>{radio.radio_id}</option>)}</select></label>
              <label><span style={label}>Relative weight (0–1)</span><input required type="number" min="0" max="1" step="0.01" value={edge.weight} onChange={e => updateEdge(edge.rowId, { weight: e.target.value })} placeholder="0.75" style={field}/></label>
              <label><span style={label}>Evidence source</span><select required value={edge.source} onChange={e => updateEdge(edge.rowId, { source: e.target.value })} style={field}><option value="">Select source…</option><option value="survey">RF survey</option><option value="controller">Controller telemetry</option><option value="operator">Operator assessment</option></select></label>
              <button type="button" onClick={() => { setEdges(current => current.filter(item => item.rowId !== edge.rowId)); setResult(null); }} style={{ ...secondary, width: 'fit-content', color: '#fca5a5' }}><Trash2 size={12}/>Remove</button>
            </div>
          ))}
        </section>
        <section style={{ ...panel, display: 'grid', gridTemplateColumns: 'minmax(170px,250px) 1fr', gap: 12, alignItems: 'end' }}>
          <label><span style={label}>Channel-change penalty</span><input type="number" min="0" max="0.5" step="0.01" value={penalty} onChange={e => setPenalty(e.target.value)} style={field}/></label>
          <p style={{ ...muted, margin: 0 }}>Balances reducing overlap against changing the current channel plan. Higher values favour operational stability.</p>
        </section>
        {error ? <div role="alert" style={{ ...panel, borderColor: '#ef4444', color: '#fca5a5', fontSize: 12 }}><AlertCircle size={14} style={{ verticalAlign: 'middle', marginRight: 6 }}/>{error}</div> : null}
        <div><button type="submit" disabled={busy} style={{ ...action, opacity: busy ? 0.6 : 1, cursor: busy ? 'wait' : 'pointer' }}><Play size={13}/>{busy ? 'Planning…' : 'Calculate channel plan'}</button></div>
      </form>
      {result ? (
        <section style={panel} aria-live="polite">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
            <ShieldCheck size={16} color="#22c55e"/>
            <strong style={{ color: '#e2e8f0', fontSize: 13 }}>Planning result</strong>
            <span style={{ marginLeft: 'auto', color: result.status === 'planned' ? '#86efac' : '#fbbf24', fontSize: 10, fontWeight: 700 }}>{result.status?.replaceAll('_', ' ').toUpperCase()}</span>
          </div>
          {result.status === 'planned' ? <>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(120px,1fr))', gap: 8, marginBottom: 12 }}>
              {[
                ['Radios', result.radio_count],
                ['Evidence links', result.evidence_edge_count],
                ['Remaining conflicts', result.conflict_count],
                ['Channel changes', result.channel_change_count],
                ['Baseline cost', result.baseline_interference_cost ?? 'n/a'],
                ['Planned cost', result.planned_interference_cost],
                ['Cost reduction', result.interference_cost_reduction_percent == null ? 'n/a' : `${result.interference_cost_reduction_percent}%`],
              ].map(([name, value]) => <div key={name} style={{ background: '#070b14', border: '1px solid #1e2d47', borderRadius: 7, padding: 9 }}><div style={muted}>{name}</div><div style={{ fontSize: 16, color: '#e2e8f0', fontWeight: 750, marginTop: 3 }}>{value ?? '—'}</div></div>)}
            </div>
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, textAlign: 'left' }}>
                <thead><tr>{['Site','AP','Radio','Band','Current','Recommended','Action','Weighted cost'].map(item => <th key={item} style={{ padding: 8, color: '#94a3b8', borderBottom: '1px solid #263956', whiteSpace: 'nowrap' }}>{item}</th>)}</tr></thead>
                <tbody>{result.assignments?.map(item => <tr key={item.radio_id}>{[item.site_id,item.ap_id,item.radio_id,item.band,item.current_channel ?? '—',item.recommended_channel ?? '—',item.status?.replaceAll('_',' '),item.weighted_interference_cost].map((value,index) => <td key={index} style={{ padding: 8, color: index === 6 && item.change_recommended ? '#fbbf24' : '#cbd5e1', borderBottom: '1px solid #1e2d47', whiteSpace: 'nowrap' }}>{value}</td>)}</tr>)}</tbody>
              </table>
            </div>
            {result.remaining_conflicts?.length ? <div style={{ marginTop: 12 }}><div style={{ fontSize: 11, color: '#fbbf24', fontWeight: 700, marginBottom: 5 }}>Residual RF overlap</div>{result.remaining_conflicts.map((item,index) => <div key={index} style={{ ...muted, padding: '6px 0', borderBottom: '1px solid #1e2d47' }}>{item.ap_ids.join(' ↔ ')} · {item.band} · channels {item.channels.join(' / ')} · overlap {Math.round(item.spectral_overlap_fraction * 100)}% · evidence {item.evidence_source}</div>)}</div> : null}
          </> : <p style={{ ...muted, margin: 0 }}>No channel assignment was generated because explicit interference evidence was not supplied.</p>}
          <div style={{ marginTop: 12, display: 'flex', gap: 7, color: '#94a3b8', fontSize: 10, lineHeight: 1.5 }}><Info size={14} style={{ flex: '0 0 auto' }}/>{result.note}</div>
        </section>
      ) : null}
    </div>
  );
}
