import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import {
  CartesianGrid, ResponsiveContainer, Scatter, ScatterChart, Tooltip, XAxis, YAxis,
} from 'recharts';
import {
  AlertCircle, Download, FileImage, FileUp, Info, MapPinned, Play, RefreshCw, ShieldCheck,
} from 'lucide-react';
import { apiBase, apiFetch } from '../lib/api.js';

const SERIES_COLORS = ['#06d6f0', '#a78bfa', '#34d399', '#fbbf24', '#fb7185', '#60a5fa', '#f97316'];
const MAX_JSON_BYTES = 900 * 1024;
const MAX_IMAGE_BYTES = 10 * 1024 * 1024;

function defaultSurveyPayload() {
  const now = Date.now();
  const observed = hours => new Date(now - hours * 60 * 60 * 1000).toISOString();
  return {
    site_id: "head-office",
    as_of: new Date(now).toISOString(),
    max_age_days: 7,
    floorplan: {
      floorplan_id: "head-office-level-1",
      floor_id: "level-1",
      width_px: 1600,
      height_px: 1000,
      scale_references: [
        { x1_px: 100, y1_px: 100, x2_px: 1100, y2_px: 100, distance_m: 20 },
        { x1_px: 100, y1_px: 100, x2_px: 100, y2_px: 600, distance_m: 10 }
      ]
    },
    access_points: [
      { ap_id: "ap-01", floor_id: "level-1", x_px: 300, y_px: 300 },
      { ap_id: "ap-02", floor_id: "level-1", x_px: 1250, y_px: 300 }
    ],
    survey_samples: [
      {
        sample_id: "survey-001", floor_id: "level-1", x_px: 400, y_px: 300,
        observed_at: observed(1), evidence_source: "survey",
        measurements: [
          { ap_id: "ap-01", rssi_dbm: -48, noise_dbm: -95 },
          { ap_id: "ap-02", rssi_dbm: -70, noise_dbm: -95 }
        ]
      },
      {
        sample_id: "survey-002", floor_id: "level-1", x_px: 650, y_px: 350,
        observed_at: observed(2), evidence_source: "survey",
        measurements: [
          { ap_id: "ap-01", rssi_dbm: -57, noise_dbm: -94 },
          { ap_id: "ap-02", rssi_dbm: -64, noise_dbm: -94 }
        ]
      },
      {
        sample_id: "survey-003", floor_id: "level-1", x_px: 900, y_px: 300,
        observed_at: observed(3), evidence_source: "controller",
        measurements: [
          { ap_id: "ap-01", rssi_dbm: -66 },
          { ap_id: "ap-02", rssi_dbm: -59 }
        ]
      }
    ]
  };
}

function signalColour(rssi) {
  if (!Number.isFinite(rssi)) return '#94a3b8';
  if (rssi >= -55) return '#34d399';
  if (rssi >= -67) return '#06d6f0';
  if (rssi >= -75) return '#fbbf24';
  return '#fb7185';
}

function MetricCard({ label, value, detail }) {
  return (
    <div className="glass rounded-xl p-3">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="text-2xl font-bold font-mono text-primary mt-1">{value}</div>
      <div className="text-xs text-muted-foreground mt-0.5">{detail}</div>
    </div>
  );
}

function downloadJson(filename, value) {
  const blob = new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function FloorplanEvidenceMap({ result, imageUrl }) {
  const width = Number(result?.floorplan?.width_px);
  const height = Number(result?.floorplan?.height_px);
  const accessPoints = Array.isArray(result?.access_points) ? result.access_points : [];
  const measurements = Array.isArray(result?.measurements) ? result.measurements : [];
  if (!(width > 0 && height > 0)) return null;

  return (
    <div className="rounded-xl overflow-hidden border border-border bg-slate-950">
      <div className="flex items-center justify-between gap-3 px-3 py-2 border-b border-border/70">
        <span className="text-xs font-semibold text-foreground">Floor-plan evidence overlay</span>
        <span className="text-[11px] text-muted-foreground">Coordinates: {width} × {height} px</span>
      </div>
      <div className="w-full" style={{ aspectRatio: width + ' / ' + height }}>
        <svg viewBox={`0 0 ${width} ${height}`} width="100%" height="100%" role="img"
          aria-label="Measured survey points and access point positions on the floor-plan coordinate map">
          <defs>
            <pattern id="rf-map-grid" width="50" height="50" patternUnits="userSpaceOnUse">
              <path d="M 50 0 L 0 0 0 50" fill="none" stroke="#334155" strokeWidth="1" opacity="0.45" />
            </pattern>
          </defs>
          <rect x="0" y="0" width={width} height={height} fill="#0f172a" />
          {imageUrl && <image href={imageUrl} x="0" y="0" width={width} height={height} preserveAspectRatio="none" opacity="0.82" />}
          {!imageUrl && <rect x="0" y="0" width={width} height={height} fill="url(#rf-map-grid)" />}
          {measurements.map((item, index) => {
            const ap = accessPoints.find(value => value.ap_id === item.ap_id);
            if (!ap) return null;
            return (
              <line key={'path-' + index} x1={item.survey_x_px} y1={item.survey_y_px}
                x2={ap.x_px} y2={ap.y_px} stroke={signalColour(item.rssi_dbm)}
                strokeWidth={Math.max(1.2, width / 1000)} strokeDasharray="7 6" opacity="0.38">
                <title>{item.ap_id}: {item.distance_m} m · {item.rssi_dbm} dBm · {item.evidence_source}</title>
              </line>
            );
          })}
          {measurements.map((item, index) => (
            <g key={'sample-' + index}>
              <circle cx={item.survey_x_px} cy={item.survey_y_px} r={Math.max(5, width / 220)}
                fill={signalColour(item.rssi_dbm)} stroke="#020617" strokeWidth={Math.max(1.5, width / 900)} opacity="0.95">
                <title>{item.ap_id} · {item.distance_m} m · {item.rssi_dbm} dBm · {item.observed_at}</title>
              </circle>
            </g>
          ))}
          {accessPoints.map(ap => (
            <g key={ap.ap_id}>
              <rect x={ap.x_px - width / 100} y={ap.y_px - width / 100} width={width / 50} height={width / 50}
                rx={width / 250} fill="#f8fafc" stroke="#0891b2" strokeWidth={Math.max(2, width / 500)} />
              <text x={ap.x_px} y={ap.y_px - width / 70} textAnchor="middle" fontSize={Math.max(12, width / 70)}
                fill="#f8fafc" stroke="#020617" strokeWidth="3" paintOrder="stroke">{ap.ap_id}</text>
            </g>
          ))}
        </svg>
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-2 px-3 py-2 border-t border-border/70 text-[11px] text-muted-foreground">
        <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-sm bg-white border border-cyan-500" /> Access point</span>
        <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-emerald-400" /> Stronger measured RSSI</span>
        <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-amber-400" /> Moderate measured RSSI</span>
        <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-rose-400" /> Weaker measured RSSI</span>
        <span>Dashed line: same-floor planar distance to AP</span>
      </div>
    </div>
  );
}

export default function FloorplanRfSurveyPanel() {
  const [payloadText, setPayloadText] = useState(() => JSON.stringify(defaultSurveyPayload(), null, 2));
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [fileName, setFileName] = useState('');
  const [samplePayload, setSamplePayload] = useState(true);
  const [floorplanImageUrl, setFloorplanImageUrl] = useState('');
  const [floorplanImageName, setFloorplanImageName] = useState('');

  useEffect(() => {
    if (!floorplanImageUrl) return undefined;
    return () => URL.revokeObjectURL(floorplanImageUrl);
  }, [floorplanImageUrl]);

  const measurements = Array.isArray(result?.measurements) ? result.measurements : [];
  const accessPoints = Array.isArray(result?.access_points) ? result.access_points : [];
  const chartData = useMemo(() => {
    const groups = new Map();
    for (const item of measurements) {
      if (!Number.isFinite(item?.distance_m) || !Number.isFinite(item?.rssi_dbm)) continue;
      if (!groups.has(item.ap_id)) groups.set(item.ap_id, []);
      groups.get(item.ap_id).push({ distance_m: item.distance_m, rssi_dbm: item.rssi_dbm });
    }
    return [...groups.entries()].sort((first, second) => first[0].localeCompare(second[0]));
  }, [measurements]);

  const execute = useCallback(async () => {
    setBusy(true);
    setError('');
    setResult(null);
    try {
      const payload = JSON.parse(payloadText);
      if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
        throw new Error('The survey input must be a JSON object.');
      }
      const response = await apiFetch(apiBase() + '/api/features/floorplan_rf_survey_analyzer', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(30000),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || 'The floor-plan RF survey analyzer failed.');
      const analysis = data.result || data;
      if (!analysis || !Array.isArray(analysis.access_points) || !Array.isArray(analysis.measurements)) {
        throw new Error('The analyzer returned an invalid result.');
      }
      setResult(analysis);
    } catch (runError) {
      setError(runError.message || 'Unable to analyse the supplied floor-plan RF survey.');
    } finally {
      setBusy(false);
    }
  }, [payloadText]);

  async function importJson(event) {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file) return;
    if (file.size > MAX_JSON_BYTES) {
      setError('Survey JSON files must not exceed 900 KiB so the API request stays below its 1 MiB limit.');
      return;
    }
    try {
      const content = await file.text();
      JSON.parse(content);
      setPayloadText(content);
      setFileName(file.name);
      setSamplePayload(false);
      setError('');
      setResult(null);
    } catch {
      setError('The selected survey file is not valid JSON.');
    }
  }

  function importFloorplanImage(event) {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file) return;
    if (!['image/png', 'image/jpeg', 'image/webp'].includes(file.type)) {
      setError('Floor plans must be PNG, JPEG or WebP images.');
      return;
    }
    if (file.size > MAX_IMAGE_BYTES) {
      setError('Floor-plan images must not exceed 10 MiB.');
      return;
    }
    setFloorplanImageUrl(URL.createObjectURL(file));
    setFloorplanImageName(file.name);
    setError('');
  }

  function loadSample() {
    setPayloadText(JSON.stringify(defaultSurveyPayload(), null, 2));
    setFileName('');
    setSamplePayload(true);
    setError('');
    setResult(null);
  }

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-4">
      <div className="glass rounded-xl p-4 flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-start gap-3 min-w-0">
          <div className="p-2 rounded-lg bg-primary/10 border border-primary/20"><MapPinned className="w-5 h-5 text-primary" /></div>
          <div>
            <div className="text-sm font-semibold text-foreground">Floor-plan aligned RF survey</div>
            <p className="text-xs text-muted-foreground mt-1 max-w-2xl">
              Align measured AP locations and timestamped RSSI readings with calibrated floor-plan coordinates. Outputs are observations and descriptive statistics, not a synthetic RF heatmap or coverage prediction.
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <label className="flex items-center gap-2 px-3 py-2 rounded-lg bg-secondary border border-border text-xs text-foreground cursor-pointer hover:bg-secondary/70">
            <FileUp className="w-3.5 h-3.5" /> Import survey JSON
            <input type="file" accept=".json,application/json" onChange={importJson} className="sr-only" />
          </label>
          <label className="flex items-center gap-2 px-3 py-2 rounded-lg bg-secondary border border-border text-xs text-foreground cursor-pointer hover:bg-secondary/70">
            <FileImage className="w-3.5 h-3.5" /> Floor-plan image
            <input type="file" accept="image/png,image/jpeg,image/webp" onChange={importFloorplanImage} className="sr-only" />
          </label>
          <button type="button" onClick={loadSample} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-secondary border border-border text-xs text-foreground">
            <RefreshCw className="w-3.5 h-3.5" /> Load sample
          </button>
          <button type="button" onClick={execute} disabled={busy}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-primary/10 border border-primary/30 text-primary text-xs font-semibold disabled:opacity-50">
            <Play className={`w-3.5 h-3.5 ${busy ? 'animate-pulse' : ''}`} /> {busy ? 'Analysing…' : 'Analyse survey'}
          </button>
        </div>
      </div>

      {samplePayload && <div className="glass rounded-lg p-3 text-xs text-amber-300/90 border border-amber-400/20">
        The loaded sample contains illustrative synthetic readings for testing the workflow. They are not measurements from your site.
      </div>}
      {fileName && <div className="text-xs text-muted-foreground">Survey data: {fileName}</div>}
      {floorplanImageName && <div className="text-xs text-muted-foreground">Floor-plan image: {floorplanImageName} · kept locally in this browser tab and not uploaded</div>}
      {error && <div role="alert" className="glass rounded-xl p-3 border border-red-400/30 text-xs text-red-400 flex gap-2"><AlertCircle className="w-4 h-4 flex-shrink-0" />{error}</div>}

      <section className="glass rounded-xl p-4 space-y-2">
        <div className="flex justify-between items-center gap-2">
          <div className="text-sm font-semibold text-foreground">Survey evidence JSON</div>
          <div className="text-xs text-muted-foreground">Maximum 900 KiB</div>
        </div>
        <textarea value={payloadText} onChange={event => { setPayloadText(event.target.value); setSamplePayload(false); }}
          spellCheck="false" rows={18} aria-label="Floor-plan RF survey JSON payload"
          className="w-full min-h-[320px] px-3 py-2 rounded-lg bg-background/70 border border-border text-xs font-mono text-foreground resize-y focus:outline-none focus:border-primary/50" />
        <p className="text-xs text-muted-foreground">
          Required evidence: floor-plan dimensions and known-distance scale references, same-floor AP and survey-point coordinates, UTC timestamps and measured per-AP RSSI. Noise is optional; SNR is calculated only when both RSSI and noise are supplied.
        </p>
      </section>

      {busy && <div className="glass rounded-xl p-6 text-center text-sm text-muted-foreground">Validating scale, timestamps, coordinates and measurements…</div>}

      {result && (
        <>
          <div className="flex items-center gap-2 text-xs">
            <ShieldCheck className="w-4 h-4 text-green-400" />
            <span className="text-foreground">{result.status === 'analysed' ? 'Measured RF observations aligned' : 'No fresh measurements available'}</span>
            <span className="text-muted-foreground">· supplied evidence · read-only analysis</span>
          </div>
          <div className="grid grid-cols-2 xl:grid-cols-4 gap-3">
            <MetricCard label="Access points" value={result.access_point_count} detail="On the selected floor" />
            <MetricCard label="Accepted samples" value={result.accepted_sample_count} detail={result.skipped_stale_sample_count + ' stale samples excluded'} />
            <MetricCard label="Measured AP readings" value={result.accepted_measurement_count} detail="Valid RSSI readings" />
            <MetricCard label="Scale" value={Number(result.scale?.metres_per_pixel).toFixed(4)} detail="Metres per pixel" />
          </div>

          <FloorplanEvidenceMap result={result} imageUrl={floorplanImageUrl} />

          <section className="glass rounded-xl p-4 space-y-3">
            <div className="text-sm font-semibold text-foreground">Measured RSSI by AP distance</div>
            <p className="text-xs text-muted-foreground">Every plotted point is an imported measurement. No propagation curve is fitted to predict unmeasured locations.</p>
            {measurements.length ? (
              <div style={{ height: 300 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <ScatterChart margin={{ top: 10, right: 20, bottom: 18, left: 4 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(148,163,184,0.14)" />
                    <XAxis type="number" dataKey="distance_m" name="AP distance" unit=" m" tick={{ fill: '#94a3b8', fontSize: 11 }} label={{ value: 'Measured planar distance (m)', position: 'insideBottom', offset: -8, fill: '#94a3b8', fontSize: 11 }} />
                    <YAxis type="number" dataKey="rssi_dbm" name="RSSI" unit=" dBm" domain={[-120, -10]} tick={{ fill: '#94a3b8', fontSize: 11 }} />
                    <Tooltip cursor={{ strokeDasharray: '3 3' }} formatter={(value, name) => [Number(value).toFixed(1), name]} />
                    {chartData.map(([apId, values], index) => (
                      <Scatter key={apId} name={apId} data={values} fill={SERIES_COLORS[index % SERIES_COLORS.length]} />
                    ))}
                  </ScatterChart>
                </ResponsiveContainer>
              </div>
            ) : <div className="text-xs text-muted-foreground">No measurements available in the selected freshness window.</div>}
          </section>

          <section className="glass rounded-xl p-4 space-y-3">
            <div className="text-sm font-semibold text-foreground">Per-access-point measured summaries</div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left">
                <thead className="text-muted-foreground border-b border-border">
                  <tr><th className="py-2 pr-3">AP ID</th><th className="py-2 pr-3">Samples</th><th className="py-2 pr-3">Mean RSSI</th><th className="py-2 pr-3">Range</th><th className="py-2 pr-3">Mean distance</th><th className="py-2">Distance trend</th></tr>
                </thead>
                <tbody>
                  {accessPoints.map(ap => (
                    <tr key={ap.ap_id} className="border-b border-border/50 last:border-0">
                      <td className="py-2 pr-3 font-mono text-foreground">{ap.ap_id}</td>
                      <td className="py-2 pr-3 text-muted-foreground">{ap.sample_count}</td>
                      <td className="py-2 pr-3 font-mono text-foreground">{ap.average_rssi_dbm == null ? '—' : ap.average_rssi_dbm.toFixed(1) + ' dBm'}</td>
                      <td className="py-2 pr-3 font-mono text-muted-foreground">{ap.minimum_rssi_dbm == null ? '—' : ap.minimum_rssi_dbm + ' to ' + ap.maximum_rssi_dbm + ' dBm'}</td>
                      <td className="py-2 pr-3 font-mono text-muted-foreground">{ap.average_distance_m == null ? '—' : ap.average_distance_m.toFixed(1) + ' m'}</td>
                      <td className="py-2 text-muted-foreground">{ap.rssi_distance_trend.status.replaceAll('_', ' ')}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <button type="button" onClick={() => downloadJson('floorplan-rf-survey-analysis.json', result)}
              className="flex items-center gap-2 px-3 py-2 rounded-lg bg-secondary border border-border text-xs text-foreground hover:bg-secondary/70">
              <Download className="w-3.5 h-3.5" /> Export analysis JSON
            </button>
          </section>

          <div className="glass rounded-xl p-3 flex items-start gap-2">
            <Info className="w-4 h-4 text-primary mt-0.5 flex-shrink-0" />
            <p className="text-xs text-muted-foreground">{result.limitations.join(' ')}</p>
          </div>
        </>
      )}
    </motion.div>
  );
}
