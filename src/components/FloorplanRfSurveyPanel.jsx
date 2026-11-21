import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import {
  CartesianGrid, ResponsiveContainer, Scatter, ScatterChart, Tooltip, XAxis, YAxis,
} from 'recharts';
import {
  Activity, AlertCircle, Download, FileImage, FileUp, History, Info, MapPinned, Play, RefreshCw, Save, ShieldCheck,
} from 'lucide-react';
import { apiBase, apiFetch } from '../lib/api.js';
import { buildMeasurementContext, measurementContextFormState } from '../lib/measurementContext.js';

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
  const [historySiteId, setHistorySiteId] = useState('head-office');
  const [historyReports, setHistoryReports] = useState([]);
  const [historyBusy, setHistoryBusy] = useState(false);
  const [historyError, setHistoryError] = useState('');
  const [historyCanManage, setHistoryCanManage] = useState(false);
  const [historyCanCompare, setHistoryCanCompare] = useState(false);
  const [comparison, setComparison] = useState(null);
  const [compareBusy, setCompareBusy] = useState(false);
  const [compareBaselineId, setCompareBaselineId] = useState('');
  const [compareCurrentId, setCompareCurrentId] = useState('');
  const [deleteTarget, setDeleteTarget] = useState('');
  const [activeReport, setActiveReport] = useState(null);
  const [reportLabel, setReportLabel] = useState('');
  const [measurementContext, setMeasurementContext] = useState(() => measurementContextFormState({}));
  function syncMeasurementContext(value) {
    setMeasurementContext(measurementContextFormState(value));
  }

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

  const loadHistory = useCallback(async () => {
    if (!historySiteId || historySiteId.length > 128) {
      setHistoryReports([]);
      return;
    }
    setHistoryBusy(true);
    setHistoryError('');
    try {
      const url = apiBase() + '/api/sites/rf-surveys?site_id=' + encodeURIComponent(historySiteId) + '&limit=50';
      const response = await apiFetch(url, { signal: AbortSignal.timeout(12000) });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || 'Unable to load saved RF surveys for this site.');
      if (!Array.isArray(data.reports)) throw new Error('The RF survey history response is invalid.');
      setHistoryReports(data.reports);
      setCompareBaselineId(current => data.reports.some(report => report.survey_id === current)
        ? current : (data.reports[1]?.survey_id || ''));
      setCompareCurrentId(current => data.reports.some(report => report.survey_id === current)
        ? current : (data.reports[0]?.survey_id || ''));
      setHistoryCanManage(data.can_manage === true);
      setHistoryCanCompare(data.can_compare === true);
    } catch (loadError) {
      setHistoryReports([]);
      setHistoryCanManage(false);
      setHistoryCanCompare(false);
      setHistoryError(loadError.message || 'Unable to load RF survey history.');
    } finally {
      setHistoryBusy(false);
    }
  }, [historySiteId]);

  useEffect(() => { void loadHistory(); }, [loadHistory]);

  async function openSavedReport(report) {
    if (!report?.survey_id || !historySiteId) return;
    setHistoryBusy(true);
    setHistoryError('');
    try {
      const url = apiBase() + '/api/sites/rf-surveys/' + encodeURIComponent(report.survey_id)
        + '?site_id=' + encodeURIComponent(historySiteId);
      const response = await apiFetch(url, { signal: AbortSignal.timeout(15000) });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || 'Unable to retrieve the saved RF survey.');
      if (!data.result || !Array.isArray(data.result.measurements) || !Array.isArray(data.result.access_points)) {
        throw new Error('The saved RF survey report is incomplete.');
      }
      setResult(data.result);
      setComparison(null);
      setActiveReport(data.report || report);
      setReportLabel(data.report?.label || report.label || '');
      syncMeasurementContext(data.result.measurement_context);
      // The original floor-plan image remains local and is not part of a saved report.
      setFloorplanImageUrl('');
      setFloorplanImageName('');
      setError('');
    } catch (loadError) {
      setHistoryError(loadError.message || 'Unable to retrieve the saved RF survey.');
    } finally {
      setHistoryBusy(false);
    }
  }

  async function compareSavedReports() {
    if (!historyCanCompare || historyReports.length < 2 || !historySiteId
      || !compareBaselineId || !compareCurrentId || compareBaselineId === compareCurrentId) return;
    const baseline = historyReports.find(report => report.survey_id === compareBaselineId);
    const current = historyReports.find(report => report.survey_id === compareCurrentId);
    if (!baseline || !current) {
      setHistoryError('Select two reports that are still present in this site history.');
      return;
    }
    if (Date.parse(baseline.created_at) >= Date.parse(current.created_at)) {
      setHistoryError('The baseline report must be older than the current report.');
      return;
    }
    setCompareBusy(true);
    setHistoryError('');
    setComparison(null);
    try {
      const response = await apiFetch(apiBase() + '/api/sites/rf-surveys/compare', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          site_id: historySiteId,
          baseline_report_id: baseline.survey_id,
          current_report_id: current.survey_id,
        }),
        signal: AbortSignal.timeout(30000),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || 'Unable to compare the latest saved surveys.');
      if (!data.result || !data.result.summary || !Array.isArray(data.result.access_points)) {
        throw new Error('The RF survey comparison response is invalid.');
      }
      setComparison(data.result);
      if (data.audit_status) setHistoryError(data.audit_status);
    } catch (compareError) {
      setHistoryError(compareError.message || 'Unable to compare saved RF surveys.');
    } finally {
      setCompareBusy(false);
    }
  }

  async function deleteSavedReport(report) {
    if (!report?.survey_id || !historySiteId) return;
    setHistoryBusy(true);
    setHistoryError('');
    try {
      const response = await apiFetch(apiBase() + '/api/sites/rf-surveys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          operation: 'delete',
          site_id: historySiteId,
          survey_id: report.survey_id,
        }),
        signal: AbortSignal.timeout(15000),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || 'Unable to delete the saved RF survey.');
      if (activeReport?.survey_id === report.survey_id) {
        setActiveReport(null);
        setResult(null);
      }
      setComparison(null);
      setDeleteTarget('');
      await loadHistory();
      if (data.audit_status) setHistoryError(data.audit_status);
    } catch (deleteError) {
      setHistoryError(deleteError.message || 'Unable to delete the saved RF survey.');
    } finally {
      setHistoryBusy(false);
    }
  }

  const execute = useCallback(async () => {
    setBusy(true);
    setError('');
    setResult(null);
    setActiveReport(null);
    setComparison(null);
    try {
      const payload = JSON.parse(payloadText);
      if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
        throw new Error('The survey input must be a JSON object.');
      }
      const context = buildMeasurementContext(measurementContext);
      if (Object.keys(context).length) payload.measurement_context = context;
      else delete payload.measurement_context;
      if (typeof payload.site_id !== 'string' || !payload.site_id.trim()) {
        throw new Error('A valid site_id is required before analysis.');
      }
      const saving = !samplePayload;
      const endpoint = saving ? '/api/sites/rf-surveys' : '/api/features/floorplan_rf_survey_analyzer';
      const requestBody = saving
        ? { site_id: payload.site_id, survey: payload, ...(reportLabel.trim() ? { label: reportLabel.trim() } : {}) }
        : payload;
      const response = await apiFetch(apiBase() + endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(requestBody),
        signal: AbortSignal.timeout(45000),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || 'The floor-plan RF survey analyzer failed.');
      const analysis = data.result || data;
      if (!analysis || !Array.isArray(analysis.access_points) || !Array.isArray(analysis.measurements)) {
        throw new Error('The analyzer returned an invalid result.');
      }
      setResult(analysis);
      if (saving) {
        setActiveReport(data.report || null);
        setReportLabel(data.report?.label || reportLabel);
        setHistorySiteId(payload.site_id);
        await loadHistory();
        if (data.audit_status) setHistoryError(data.audit_status);
      }
    } catch (runError) {
      setError(runError.message || 'Unable to analyse the supplied floor-plan RF survey.');
    } finally {
      setBusy(false);
    }
  }, [payloadText, samplePayload, reportLabel, loadHistory]);

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
      const parsed = JSON.parse(content);
      if (typeof parsed?.site_id === 'string') setHistorySiteId(parsed.site_id);
      syncMeasurementContext(parsed?.measurement_context);
      setPayloadText(content);
      setFileName(file.name);
      setSamplePayload(false);
      setError('');
      setResult(null);
      setActiveReport(null);
      setComparison(null);
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
    const payload = defaultSurveyPayload();
    setPayloadText(JSON.stringify(payload, null, 2));
    setHistorySiteId(payload.site_id);
    setReportLabel('');
    syncMeasurementContext({});
    setComparison(null);
    setFileName('');
    setSamplePayload(true);
    setError('');
    setResult(null);
    setActiveReport(null);
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
          <button type="button" onClick={execute} disabled={busy || Boolean(activeReport)}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-primary/10 border border-primary/30 text-primary text-xs font-semibold disabled:opacity-50">
            <Play className={`w-3.5 h-3.5 ${busy ? 'animate-pulse' : ''}`} />
            {busy ? 'Analysing…' : activeReport ? 'Saved report open' : samplePayload ? 'Analyse sample' : 'Analyse & save report'}
          </button>
        </div>
      </div>

      {samplePayload && <div className="glass rounded-lg p-3 text-xs text-amber-300/90 border border-amber-400/20">
        The loaded sample contains illustrative synthetic readings for testing the workflow. They are not measurements from your site.
      </div>}
      {fileName && <div className="text-xs text-muted-foreground">Survey data: {fileName}</div>}
      {floorplanImageName && <div className="text-xs text-muted-foreground">Floor-plan image: {floorplanImageName} · kept locally in this browser tab and not uploaded</div>}
      {error && <div role="alert" className="glass rounded-xl p-3 border border-red-400/30 text-xs text-red-400 flex gap-2"><AlertCircle className="w-4 h-4 flex-shrink-0" />{error}</div>}

      <section className="glass rounded-xl p-4 space-y-3">
        <div className="flex items-center justify-between gap-3">
          <div>
            <div className="text-sm font-semibold text-foreground flex items-center gap-2"><History className="w-4 h-4 text-primary" /> Saved site surveys</div>
            <div className="text-xs text-muted-foreground mt-0.5">Site: {historySiteId || 'not selected'} · site-scoped access</div>
          </div>
          <div className="flex items-center gap-2">
            {historyCanCompare && historyReports.length >= 2 && (
              <button type="button" onClick={() => void compareSavedReports()}
                disabled={historyBusy || compareBusy || !compareBaselineId || !compareCurrentId || compareBaselineId === compareCurrentId}
                className="flex items-center gap-2 px-3 py-2 rounded-lg bg-primary/10 border border-primary/30 text-primary text-xs disabled:opacity-50">
                <Activity className={`w-3.5 h-3.5 ${compareBusy ? 'animate-pulse' : ''}`} /> {compareBusy ? 'Comparing…' : 'Compare selected surveys'}
              </button>
            )}
            <button type="button" onClick={() => void loadHistory()} disabled={historyBusy || !historySiteId}
              className="flex items-center gap-2 px-3 py-2 rounded-lg bg-secondary border border-border text-xs text-foreground disabled:opacity-50">
              <RefreshCw className={`w-3.5 h-3.5 ${historyBusy ? 'animate-spin' : ''}`} /> Refresh
            </button>
          </div>
        </div>
        {historyError && <div role="alert" className="text-xs text-amber-400">{historyError}</div>}
        {historyBusy && <div className="text-xs text-muted-foreground">Loading site reports…</div>}
        {historyCanCompare && historyReports.length >= 2 && (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <label className="text-xs text-muted-foreground">
              Baseline (older report)
              <select value={compareBaselineId} onChange={event => { setCompareBaselineId(event.target.value); setComparison(null); }}
                disabled={historyBusy || compareBusy}
                className="mt-1 w-full rounded-lg border border-border bg-background/70 px-3 py-2 text-sm text-foreground">
                <option value="">Select baseline</option>
                {historyReports.map(report => (
                  <option key={report.survey_id} value={report.survey_id}>{report.label} · {new Date(report.created_at).toLocaleString()}</option>
                ))}
              </select>
            </label>
            <label className="text-xs text-muted-foreground">
              Current (newer report)
              <select value={compareCurrentId} onChange={event => { setCompareCurrentId(event.target.value); setComparison(null); }}
                disabled={historyBusy || compareBusy}
                className="mt-1 w-full rounded-lg border border-border bg-background/70 px-3 py-2 text-sm text-foreground">
                <option value="">Select current report</option>
                {historyReports.map(report => (
                  <option key={report.survey_id} value={report.survey_id}>{report.label} · {new Date(report.created_at).toLocaleString()}</option>
                ))}
              </select>
            </label>
          </div>
        )}
        {!historyBusy && historyReports.length === 0 && !historyError && <div className="text-xs text-muted-foreground">No saved reports for this site yet.</div>}
        {historyReports.length > 0 && (
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {historyReports.map(report => (
              <div key={report.survey_id} className="flex flex-wrap items-center justify-between gap-2 rounded-lg bg-secondary/40 border border-border/60 px-3 py-2">
                <div className="min-w-0">
                  <div className="text-xs font-semibold text-foreground truncate">{report.label}</div>
                  <div className="text-[11px] text-muted-foreground">
                    {report.floorplan_id} · {report.measurement_count} measurements · {new Date(report.created_at).toLocaleString()}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button type="button" onClick={() => void openSavedReport(report)} disabled={historyBusy}
                    className="px-3 py-1.5 rounded-lg bg-primary/10 border border-primary/30 text-primary text-xs disabled:opacity-50">
                    Open report
                  </button>
                  {historyCanManage && (
                    <button type="button" onClick={() => setDeleteTarget(current => current === report.survey_id ? '' : report.survey_id)}
                      disabled={historyBusy} className="px-3 py-1.5 rounded-lg border border-red-400/30 text-red-400 text-xs disabled:opacity-50">
                      Remove
                    </button>
                  )}
                </div>
                {historyCanManage && deleteTarget === report.survey_id && (
                  <div className="w-full rounded-lg border border-red-400/25 bg-red-400/5 p-2 flex flex-wrap items-center justify-between gap-2">
                    <span className="text-xs text-muted-foreground">Permanently remove this saved report from the site history?</span>
                    <div className="flex items-center gap-2">
                      <button type="button" onClick={() => void deleteSavedReport(report)} disabled={historyBusy}
                        className="px-3 py-1.5 rounded-lg bg-red-500/10 border border-red-400/30 text-red-400 text-xs disabled:opacity-50">Delete report</button>
                      <button type="button" onClick={() => setDeleteTarget('')} disabled={historyBusy}
                        className="px-3 py-1.5 rounded-lg bg-secondary border border-border text-xs text-foreground disabled:opacity-50">Cancel</button>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
        {comparison && (
          <div className="rounded-xl border border-border bg-secondary/20 p-3 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="text-sm font-semibold text-foreground">Longitudinal RF comparison</div>
              <span className={`text-xs ${comparison.status === 'compared' ? 'text-primary' : 'text-amber-400'}`}>
                {comparison.status.replaceAll('_', ' ')} · {comparison.comparability.status} comparability
              </span>
            </div>
            <div className="text-xs text-muted-foreground">
              {comparison.baseline_report.label} → {comparison.current_report.label}
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
              <div className="rounded-lg bg-background/50 p-2"><div className="text-[11px] text-muted-foreground">Matched points</div><div className="text-lg font-mono font-semibold text-foreground">{comparison.summary.matched_point_count}</div></div>
              <div className="rounded-lg bg-background/50 p-2"><div className="text-[11px] text-muted-foreground">Median RSSI delta</div><div className="text-lg font-mono font-semibold text-foreground">{comparison.summary.median_delta_rssi_db == null ? '—' : comparison.summary.median_delta_rssi_db + ' dB'}</div></div>
              <div className="rounded-lg bg-background/50 p-2"><div className="text-[11px] text-muted-foreground">Weaker points</div><div className="text-lg font-mono font-semibold text-rose-400">{comparison.summary.weaker_by_threshold_count}</div></div>
              <div className="rounded-lg bg-background/50 p-2"><div className="text-[11px] text-muted-foreground">Stronger points</div><div className="text-lg font-mono font-semibold text-emerald-400">{comparison.summary.stronger_by_threshold_count}</div></div>
            </div>
            {comparison.comparability.missing_context_fields.length > 0 && (
              <div className="text-xs text-amber-400">Missing comparison context: {comparison.comparability.missing_context_fields.join(', ')}</div>
            )}
            {comparison.comparability.mismatched_context_fields.length > 0 && (
              <div className="text-xs text-amber-400">Context differs between surveys: {comparison.comparability.mismatched_context_fields.join(', ')}</div>
            )}
            {(comparison.comparability.moved_or_repositioned_ap_ids.length > 0
              || comparison.comparability.added_ap_ids.length > 0
              || comparison.comparability.removed_ap_ids.length > 0) && (
              <div className="space-y-1 text-xs text-muted-foreground">
                {comparison.comparability.moved_or_repositioned_ap_ids.length > 0 && <div>Repositioned APs excluded: {comparison.comparability.moved_or_repositioned_ap_ids.join(', ')}</div>}
                {comparison.comparability.added_ap_ids.length > 0 && <div>New APs in current survey: {comparison.comparability.added_ap_ids.join(', ')}</div>}
                {comparison.comparability.removed_ap_ids.length > 0 && <div>APs absent from current survey: {comparison.comparability.removed_ap_ids.join(', ')}</div>}
              </div>
            )}
            {comparison.access_points.length > 0 && (
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left">
                  <thead className="text-muted-foreground border-b border-border">
                    <tr><th className="py-2 pr-3">AP</th><th className="py-2 pr-3">Matched points</th><th className="py-2 pr-3">Median Δ RSSI</th><th className="py-2">Weaker / stronger</th></tr>
                  </thead>
                  <tbody>
                    {comparison.access_points.map(ap => (
                      <tr key={ap.ap_id} className="border-b border-border/50 last:border-0">
                        <td className="py-2 pr-3 font-mono text-foreground">{ap.ap_id}</td>
                        <td className="py-2 pr-3 text-muted-foreground">{ap.matched_points}</td>
                        <td className="py-2 pr-3 font-mono text-foreground">{ap.median_delta_rssi_db == null ? '—' : ap.median_delta_rssi_db + ' dB'}</td>
                        <td className="py-2 text-muted-foreground">{ap.weaker_by_threshold_count} / {ap.stronger_by_threshold_count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <p className="text-[11px] text-muted-foreground">{comparison.comparability.limitations.join(' ')}</p>
          </div>
        )}
      </section>

      <section className="glass rounded-xl p-4 space-y-2">
        <div className="flex justify-between items-center gap-2">
          <div className="text-sm font-semibold text-foreground">Survey evidence JSON</div>
          <div className="text-xs text-muted-foreground">Maximum 900 KiB</div>
        </div>
        <textarea value={payloadText} onChange={event => {
          const value = event.target.value;
          setPayloadText(value);
          setSamplePayload(false);
          setActiveReport(null);
          try {
            const parsed = JSON.parse(value);
            if (typeof parsed?.site_id === 'string') setHistorySiteId(parsed.site_id);
            syncMeasurementContext(parsed?.measurement_context);
          } catch {
            // Keep the last valid site selection while the operator edits JSON.
          }
        }}
          spellCheck="false" rows={18} aria-label="Floor-plan RF survey JSON payload"
          className="w-full min-h-[320px] px-3 py-2 rounded-lg bg-background/70 border border-border text-xs font-mono text-foreground resize-y focus:outline-none focus:border-primary/50" />
        <p className="text-xs text-muted-foreground">
          Required evidence: floor-plan dimensions and known-distance scale references, same-floor AP and survey-point coordinates, UTC timestamps and measured per-AP RSSI. Noise is optional; SNR is calculated only when both RSSI and noise are supplied.
        </p>
        {!samplePayload && (
          <label className="block text-xs text-muted-foreground">
            Report name
            <input value={reportLabel} onChange={event => setReportLabel(event.target.value.slice(0, 128))}
              maxLength={128} placeholder="e.g. HQ Level 1 — November survey"
              className="mt-1 w-full px-3 py-2 rounded-lg bg-background/70 border border-border text-sm text-foreground" />
          </label>
        )}
        <div className="border-t border-border/60 pt-3 space-y-2">
          <div>
            <div className="text-sm font-semibold text-foreground">Measurement context</div>
            <p className="text-xs text-muted-foreground">Optional caller-declared collection metadata. Complete these fields consistently across repeat surveys to improve comparability; values are not independently attested.</p>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-2">
            <label className="text-xs text-muted-foreground">Survey device / model
              <input value={measurementContext.device_model} maxLength={128}
                onChange={event => setMeasurementContext(current => ({ ...current, device_model: event.target.value }))}
                placeholder="e.g. SurveyClient X"
                className="mt-1 w-full px-2.5 py-2 rounded-lg bg-background/70 border border-border text-sm text-foreground" />
            </label>
            <label className="text-xs text-muted-foreground">Radio band
              <select value={measurementContext.radio_band}
                onChange={event => setMeasurementContext(current => ({ ...current, radio_band: event.target.value }))}
                className="mt-1 w-full px-2.5 py-2 rounded-lg bg-background/70 border border-border text-sm text-foreground">
                <option value="">Not supplied</option>
                <option value="2.4GHz">2.4 GHz</option>
                <option value="5GHz">5 GHz</option>
                <option value="6GHz">6 GHz</option>
              </select>
            </label>
            <label className="text-xs text-muted-foreground">Channel
              <input type="number" min="1" max="233" step="1" value={measurementContext.channel}
                onChange={event => setMeasurementContext(current => ({ ...current, channel: event.target.value }))}
                placeholder="e.g. 36"
                className="mt-1 w-full px-2.5 py-2 rounded-lg bg-background/70 border border-border text-sm text-foreground" />
            </label>
            <label className="text-xs text-muted-foreground">Channel width (MHz)
              <input type="number" min="5" max="320" step="5" value={measurementContext.channel_width_mhz}
                onChange={event => setMeasurementContext(current => ({ ...current, channel_width_mhz: event.target.value }))}
                placeholder="e.g. 80"
                className="mt-1 w-full px-2.5 py-2 rounded-lg bg-background/70 border border-border text-sm text-foreground" />
            </label>
            <label className="text-xs text-muted-foreground">Antenna type
              <input value={measurementContext.antenna_type} maxLength={128}
                onChange={event => setMeasurementContext(current => ({ ...current, antenna_type: event.target.value }))}
                placeholder="e.g. integrated / omni"
                className="mt-1 w-full px-2.5 py-2 rounded-lg bg-background/70 border border-border text-sm text-foreground" />
            </label>
            <label className="text-xs text-muted-foreground">Antenna orientation (°)
              <input type="number" min="0" max="359.9" step="0.1" value={measurementContext.antenna_orientation_deg}
                onChange={event => setMeasurementContext(current => ({ ...current, antenna_orientation_deg: event.target.value }))}
                placeholder="0–359.9"
                className="mt-1 w-full px-2.5 py-2 rounded-lg bg-background/70 border border-border text-sm text-foreground" />
            </label>
            <label className="text-xs text-muted-foreground">Antenna height (m)
              <input type="number" min="0.1" max="20" step="0.1" value={measurementContext.antenna_height_m}
                onChange={event => setMeasurementContext(current => ({ ...current, antenna_height_m: event.target.value }))}
                placeholder="e.g. 1.2"
                className="mt-1 w-full px-2.5 py-2 rounded-lg bg-background/70 border border-border text-sm text-foreground" />
            </label>
            <label className="text-xs text-muted-foreground">Calibration ID
              <input value={measurementContext.calibration_id} maxLength={128}
                onChange={event => setMeasurementContext(current => ({ ...current, calibration_id: event.target.value }))}
                placeholder="Optional calibration reference"
                className="mt-1 w-full px-2.5 py-2 rounded-lg bg-background/70 border border-border text-sm text-foreground" />
            </label>
          </div>
        </div>
      </section>

      {busy && <div className="glass rounded-xl p-6 text-center text-sm text-muted-foreground">Validating scale, timestamps, coordinates and measurements…</div>}

      {result && (
        <>
          <div className="flex items-center gap-2 text-xs">
            <ShieldCheck className="w-4 h-4 text-green-400" />
            <span className="text-foreground">{result.status === 'analysed' ? 'Measured RF observations aligned' : 'No fresh measurements available'}</span>
            {activeReport
              ? <span className="text-muted-foreground">· saved report · {activeReport.label}</span>
              : <span className="text-muted-foreground">· {samplePayload ? 'illustrative sample' : 'saved to site history'}</span>}
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
            <div className="flex flex-wrap items-center gap-2">
              <button type="button" onClick={() => downloadJson('floorplan-rf-survey-analysis.json', result)}
                className="flex items-center gap-2 px-3 py-2 rounded-lg bg-secondary border border-border text-xs text-foreground hover:bg-secondary/70">
                <Download className="w-3.5 h-3.5" /> Export analysis JSON
              </button>
              {activeReport && <span className="text-xs text-muted-foreground flex items-center gap-1"><Save className="w-3.5 h-3.5" /> Retained in site history</span>}
            </div>
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
