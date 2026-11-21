import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { AlertCircle, CheckCircle2, ClipboardCheck, Play, ShieldAlert } from 'lucide-react';
import { apiBase, apiFetch } from '../lib/api.js';

function numeric(value, field, minimum, maximum, integer = false) {
  if (value === '') return undefined;
  const number = Number(value);
  if (!Number.isFinite(number) || number < minimum || number > maximum || (integer && !Number.isInteger(number))) {
    throw new RangeError(field + ' is outside its valid range.');
  }
  return number;
}

function statusClass(status) {
  if (status === 'accepted' || status === 'pass') return 'text-emerald-400';
  if (status === 'rejected' || status === 'fail') return 'text-rose-400';
  return 'text-amber-400';
}

export default function RfSurveyAcceptancePanel({ report, result }) {
  const [minimumRssi, setMinimumRssi] = useState('-67');
  const [minimumSnr, setMinimumSnr] = useState('');
  const [passingPercentage, setPassingPercentage] = useState('95');
  const [minimumPoints, setMinimumPoints] = useState('10');
  const [minimumAps, setMinimumAps] = useState('1');
  const [maximumAge, setMaximumAge] = useState('7');
  const [zonesText, setZonesText] = useState('');
  const [audit, setAudit] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  async function evaluate() {
    setBusy(true);
    setError('');
    setAudit(null);
    try {
      if (!report?.survey_id || !result || result.site_id !== report.site_id) {
        throw new Error('Open a retained survey report for this site before auditing acceptance.');
      }
      const policy = {
        minimum_rssi_dbm: numeric(minimumRssi, 'Minimum RSSI', -120, -10),
        minimum_passing_points_pct: numeric(passingPercentage, 'Passing-point percentage', 0, 100),
        minimum_sample_count: numeric(minimumPoints, 'Minimum sample count', 1, 20000, true),
        minimum_qualifying_aps: numeric(minimumAps, 'Minimum qualifying APs', 1, 16, true),
        maximum_sample_age_days: numeric(maximumAge, 'Maximum sample age', 1, 30, true),
      };
      if (minimumSnr !== '') policy.minimum_snr_db = numeric(minimumSnr, 'Minimum SNR', -20, 150);
      const zones = zonesText.trim() ? JSON.parse(zonesText) : [];
      if (!Array.isArray(zones)) throw new Error('Zones must be a JSON array of rectangles.');
      const response = await apiFetch(apiBase() + '/api/features/rf_survey_acceptance_auditor', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          site_id: report.site_id,
          report: { report, result },
          policy,
          zones,
          as_of: new Date().toISOString(),
        }),
        signal: AbortSignal.timeout(30000),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || 'RF survey acceptance audit failed.');
      if (!data.result || !data.result.summary || !Array.isArray(data.result.points)) {
        throw new Error('The acceptance auditor returned an invalid result.');
      }
      setAudit(data.result);
    } catch (auditError) {
      setError(auditError.message || 'Unable to run the acceptance audit.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <motion.section initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="glass rounded-xl p-4 space-y-3">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-start gap-2">
          <ClipboardCheck className="w-4 h-4 text-primary mt-0.5" />
          <div>
            <div className="text-sm font-semibold text-foreground">Customer RF acceptance audit</div>
            <p className="text-xs text-muted-foreground mt-1">
              Score only fresh measured survey points against explicit customer thresholds. Unsampled floor-plan areas remain unscored.
            </p>
          </div>
        </div>
        <button type="button" onClick={evaluate} disabled={busy}
          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-primary/10 border border-primary/30 text-primary text-xs font-semibold disabled:opacity-50">
          <Play className={`w-3.5 h-3.5 ${busy ? 'animate-pulse' : ''}`} /> {busy ? 'Auditing…' : 'Run acceptance audit'}
        </button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-2">
        <label className="text-xs text-muted-foreground">Minimum RSSI (dBm)
          <input type="number" min="-120" max="-10" step="1" value={minimumRssi} onChange={event => setMinimumRssi(event.target.value)}
            className="mt-1 w-full px-2.5 py-2 rounded-lg bg-background/70 border border-border text-sm text-foreground" />
        </label>
        <label className="text-xs text-muted-foreground">Minimum SNR (dB)
          <input type="number" min="-20" max="150" step="1" value={minimumSnr} onChange={event => setMinimumSnr(event.target.value)}
            placeholder="Not required"
            className="mt-1 w-full px-2.5 py-2 rounded-lg bg-background/70 border border-border text-sm text-foreground" />
        </label>
        <label className="text-xs text-muted-foreground">Passing points (%)
          <input type="number" min="0" max="100" step="1" value={passingPercentage} onChange={event => setPassingPercentage(event.target.value)}
            className="mt-1 w-full px-2.5 py-2 rounded-lg bg-background/70 border border-border text-sm text-foreground" />
        </label>
        <label className="text-xs text-muted-foreground">Minimum sample count
          <input type="number" min="1" max="20000" step="1" value={minimumPoints} onChange={event => setMinimumPoints(event.target.value)}
            className="mt-1 w-full px-2.5 py-2 rounded-lg bg-background/70 border border-border text-sm text-foreground" />
        </label>
        <label className="text-xs text-muted-foreground">Qualifying APs / point
          <input type="number" min="1" max="16" step="1" value={minimumAps} onChange={event => setMinimumAps(event.target.value)}
            className="mt-1 w-full px-2.5 py-2 rounded-lg bg-background/70 border border-border text-sm text-foreground" />
        </label>
        <label className="text-xs text-muted-foreground">Maximum age (days)
          <input type="number" min="1" max="30" step="1" value={maximumAge} onChange={event => setMaximumAge(event.target.value)}
            className="mt-1 w-full px-2.5 py-2 rounded-lg bg-background/70 border border-border text-sm text-foreground" />
        </label>
      </div>

      <details className="rounded-lg border border-border/60 p-3">
        <summary className="text-xs font-medium text-foreground cursor-pointer">Optional floor-plan zones (JSON rectangles)</summary>
        <p className="text-xs text-muted-foreground mt-2">Each rectangle uses zone_id, x1_px, y1_px, x2_px and y2_px. Zone scores use only measured points inside the rectangle.</p>
        <textarea value={zonesText} onChange={event => setZonesText(event.target.value)} rows={4} spellCheck="false"
          placeholder={'[{"zone_id":"west-wing","x1_px":0,"y1_px":0,"x2_px":500,"y2_px":400}]'}
          className="mt-2 w-full px-3 py-2 rounded-lg bg-background/70 border border-border text-xs font-mono text-foreground" />
      </details>

      {error && <div role="alert" className="text-xs text-rose-400 flex items-start gap-2"><AlertCircle className="w-4 h-4 flex-shrink-0" />{error}</div>}

      {audit && (
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            {audit.status === 'accepted'
              ? <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              : <ShieldAlert className="w-4 h-4 text-amber-400" />}
            <span className={`text-sm font-semibold ${statusClass(audit.status)}`}>{audit.status.replaceAll('_', ' ').toUpperCase()}</span>
            <span className="text-xs text-muted-foreground">· customer policy · measured evidence only</span>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
            <div className="rounded-lg bg-secondary/40 p-3"><div className="text-xs text-muted-foreground">Sampled points</div><div className="text-xl font-mono text-foreground">{audit.summary.sampled_point_count}</div></div>
            <div className="rounded-lg bg-secondary/40 p-3"><div className="text-xs text-muted-foreground">Passing points</div><div className="text-xl font-mono text-emerald-400">{audit.summary.passing_point_count}</div></div>
            <div className="rounded-lg bg-secondary/40 p-3"><div className="text-xs text-muted-foreground">Failing points</div><div className="text-xl font-mono text-rose-400">{audit.summary.failing_point_count}</div></div>
            <div className="rounded-lg bg-secondary/40 p-3"><div className="text-xs text-muted-foreground">Pass rate</div><div className="text-xl font-mono text-foreground">{audit.summary.passing_points_pct == null ? '—' : audit.summary.passing_points_pct + '%'}</div></div>
          </div>
          {audit.zones.length > 0 && (
            <div className="space-y-2">
              <div className="text-xs font-semibold text-foreground">Zone acceptance</div>
              {audit.zones.map(zone => (
                <div key={zone.zone_id} className="flex flex-wrap justify-between gap-2 rounded-lg bg-secondary/30 px-3 py-2 text-xs">
                  <span className="text-foreground">{zone.zone_id}</span>
                  <span className="text-muted-foreground">{zone.passing_point_count}/{zone.sampled_point_count} · {zone.passing_points_pct == null ? '—' : zone.passing_points_pct + '%'}</span>
                  <span className={statusClass(zone.status)}>{zone.status.replaceAll('_', ' ')}</span>
                </div>
              ))}
            </div>
          )}
          <div className="text-xs text-muted-foreground">
            {audit.summary.stale_measurement_count_excluded} stale measurement(s) excluded. {audit.limitations.join(' ')}
          </div>
        </div>
      )}
    </motion.section>
  );
}
