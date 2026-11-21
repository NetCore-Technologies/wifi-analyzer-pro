import React, { useState } from 'react';
import { motion } from 'framer-motion';
import {
  AlertCircle, CheckCircle2, Download, FileUp, Info, Play, Radio, RefreshCw, ShieldAlert, ShieldCheck,
} from 'lucide-react';
import { apiBase, apiFetch } from '../lib/api.js';

const MAX_IMPORT_BYTES = 900 * 1024;

function downloadJson(value) {
  const blob = new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = 'radio-capability-channel-preview.json';
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function StatusText({ status }) {
  const tone = status === 'eligible' ? 'text-emerald-400'
    : status === 'review_required' || status === 'partial' ? 'text-amber-400'
      : 'text-rose-400';
  return <span className={`text-xs font-semibold uppercase tracking-wide ${tone}`}>{String(status || 'unknown').replaceAll('_', ' ')}</span>;
}

export default function RadioCapabilityRegulatoryPlannerPanel() {
  const [payloadText, setPayloadText] = useState('');
  const [fileName, setFileName] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [registrySiteId, setRegistrySiteId] = useState("");
  const [registryDatasets, setRegistryDatasets] = useState([]);
  const [registryBusy, setRegistryBusy] = useState(false);
  const [registryError, setRegistryError] = useState("");

  async function loadRegistry() {
    const siteId = registrySiteId.trim();
    if (!siteId || siteId.length > 128) {
      setRegistryError("Enter a valid site ID before loading retained datasets.");
      return;
    }
    setRegistryBusy(true);
    setRegistryError("");
    try {
      const url = apiBase() + "/api/sites/regulatory-datasets?site_id=" + encodeURIComponent(siteId)
        + "&limit=100&include_revoked=false";
      const response = await apiFetch(url, { signal: AbortSignal.timeout(15000) });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || "Unable to load retained regulatory datasets.");
      if (!Array.isArray(data.datasets)) throw new Error("The regulatory dataset registry response is invalid.");
      setRegistryDatasets(data.datasets.filter(item => item && item.revoked !== true));
    } catch (loadError) {
      setRegistryDatasets([]);
      setRegistryError(loadError.message || "Unable to load the site regulatory dataset registry.");
    } finally {
      setRegistryBusy(false);
    }
  }

  function useRetainedDataset(record) {
    if (!record?.dataset_ref || record.revoked) return;
    try {
      const payload = payloadText.trim() ? JSON.parse(payloadText) : {};
      if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
        throw new Error("Planning input must be a JSON object.");
      }
      if (!Array.isArray(payload.radios) || payload.radios.length === 0) {
        throw new Error("Import or enter controller radio capability records before selecting a dataset.");
      }
      payload.site_id = registrySiteId.trim();
      payload.regulatory_dataset_ref = record.dataset_ref;
      delete payload.regulatory_dataset;
      delete payload.dataset_acknowledgement;
      setPayloadText(JSON.stringify(payload, null, 2));
      setError("");
      setResult(null);
    } catch (selectionError) {
      setError(selectionError.message || "Unable to select the retained regulatory dataset.");
    }
  }

  async function importFile(event) {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file) return;
    if (file.size > MAX_IMPORT_BYTES) {
      setError('Planning evidence JSON must not exceed 900 KiB.');
      return;
    }
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('JSON root must be an object.');
      }
      const hasRetainedReference = typeof parsed.regulatory_dataset_ref === 'string' && parsed.regulatory_dataset_ref.trim();
      const hasInlineDataset = parsed.regulatory_dataset && parsed.dataset_acknowledgement;
      if (!Array.isArray(parsed.radios) || (!hasRetainedReference && !hasInlineDataset)) {
        throw new Error('Import must contain radios and either a retained regulatory_dataset_ref or an F206 dataset plus acknowledgement.');
      }
      if (typeof parsed.site_id !== 'string' || !parsed.site_id.trim()) {
        throw new Error('Import must include the site_id assigned to these radios.');
      }
      setRegistrySiteId(parsed.site_id);
      setPayloadText(text);
      setFileName(file.name);
      setResult(null);
      setError('');
    } catch (importError) {
      setError(importError.message || 'The selected planning file is invalid.');
    }
  }

  async function plan() {
    setBusy(true);
    setError('');
    setResult(null);
    try {
      const payload = JSON.parse(payloadText);
      if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
        throw new Error('Planning input must be a JSON object.');
      }
      const response = await apiFetch(apiBase() + '/api/features/radio_capability_regulatory_channel_planner', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(45000),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || 'Radio capability planning failed.');
      const planning = data.result || data;
      if (!planning || !Array.isArray(planning.radios) || !planning.change_application) {
        throw new Error('The planner returned an invalid preview.');
      }
      setResult(planning);
    } catch (planError) {
      setError(planError.message || 'Unable to build a radio capability preview.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-4">
      <section className="glass rounded-xl p-4 flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-start gap-3 min-w-0">
          <div className="p-2 rounded-lg bg-primary/10 border border-primary/20"><Radio className="w-5 h-5 text-primary" /></div>
          <div>
            <div className="text-sm font-semibold text-foreground">Controller radio capability planner</div>
            <p className="text-xs text-muted-foreground mt-1 max-w-3xl">
              Cross-check controller/agent radio capability snapshots against an F206 dataset whose canonical fingerprint is verified and explicitly reviewed. The planner checks channel, width, device class, DFS/AFC, installation environment and EIRP constraints.
            </p>
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <label className="flex items-center gap-2 px-3 py-2 rounded-lg bg-secondary border border-border text-xs text-foreground cursor-pointer hover:bg-secondary/70">
            <FileUp className="w-3.5 h-3.5" /> Import planning JSON
            <input type="file" accept=".json,application/json" onChange={importFile} className="sr-only" />
          </label>
          <button type="button" onClick={plan} disabled={busy || !payloadText.trim()}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-primary/10 border border-primary/30 text-primary text-xs font-semibold disabled:opacity-50">
            <Play className={`w-3.5 h-3.5 ${busy ? 'animate-pulse' : ''}`} /> {busy ? 'Evaluating…' : 'Build channel preview'}
          </button>
        </div>
      </section>

      <section className="glass rounded-xl p-3 flex items-start gap-2">
        <ShieldAlert className="w-4 h-4 text-amber-400 mt-0.5 flex-shrink-0" />
        <p className="text-xs text-muted-foreground">
          Use current controller/agent exports, not guessed capability values. F206 source URLs and document digests are not independently authenticated; reviewer acknowledgement is caller-declared. An eligible result is not a legal authorization or an RF performance prediction. This feature never writes AP configuration.
        </p>
      </section>

      {fileName && <div className="text-xs text-muted-foreground">Loaded: {fileName}</div>}
      {error && <div role="alert" className="glass rounded-xl p-3 border border-red-400/30 text-xs text-red-400 flex gap-2"><AlertCircle className="w-4 h-4 flex-shrink-0" />{error}</div>}

      <section className="glass rounded-xl p-4 space-y-3">
        <div className="flex flex-wrap items-end gap-2">
          <label className="flex-1 min-w-[180px] text-xs text-muted-foreground">
            Registry site ID
            <input value={registrySiteId} onChange={event => setRegistrySiteId(event.target.value)}
              maxLength={128} placeholder="e.g. head-office"
              className="mt-1 w-full px-3 py-2 rounded-lg bg-background/70 border border-border text-sm text-foreground" />
          </label>
          <button type="button" onClick={() => void loadRegistry()} disabled={registryBusy || !registrySiteId.trim()}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-secondary border border-border text-xs text-foreground disabled:opacity-50">
            <RefreshCw className={`w-3.5 h-3.5 ${registryBusy ? 'animate-spin' : ''}`} />
            {registryBusy ? 'Loading…' : 'Load retained datasets'}
          </button>
        </div>
        {registryError && <div role="alert" className="text-xs text-amber-400">{registryError}</div>}
        {registryDatasets.length > 0 && (
          <div className="space-y-2 max-h-48 overflow-y-auto">
            {registryDatasets.map(item => (
              <div key={item.dataset_ref} className="flex flex-wrap items-center justify-between gap-2 rounded-lg bg-secondary/40 border border-border/60 px-3 py-2">
                <div className="min-w-0">
                  <div className="text-xs font-semibold text-foreground">{item.dataset_id} · {item.version} · {item.jurisdiction}</div>
                  <div className="text-[11px] text-muted-foreground">Reviewed {new Date(item.reviewed_at).toLocaleString()} · {item.reviewer_id} · {item.fingerprint_sha256.slice(0, 16)}…</div>
                </div>
                <button type="button" onClick={() => useRetainedDataset(item)}
                  className="px-3 py-1.5 rounded-lg bg-primary/10 border border-primary/30 text-primary text-xs">
                  Use version
                </button>
              </div>
            ))}
          </div>
        )}
        <div className="text-[11px] text-muted-foreground">
          Select a retained version to insert its immutable registry reference. Revoked versions are excluded and the server rechecks revocation at execution time.
        </div>
      </section>

      <section className="glass rounded-xl p-4 space-y-2">
        <div className="flex items-center justify-between gap-2">
          <div className="text-sm font-semibold text-foreground">Radio capability planning JSON</div>
          <span className="text-xs text-muted-foreground">Maximum 900 KiB</span>
        </div>
        <textarea value={payloadText} onChange={event => { setPayloadText(event.target.value); setResult(null); }}
          rows={20} spellCheck="false" aria-label="Controller radio capability and regulatory planning JSON"
          placeholder={JSON.stringify({
            site_id: 'your-site-id',
            regulatory_dataset: 'normalized F206 result object',
            dataset_acknowledgement: {
              dataset_fingerprint_sha256: 'exact F206 fingerprint',
              reviewer_id: 'reviewer identifier',
              reviewed_at: 'timezone-aware timestamp',
              review_reference: 'change ticket or review record',
            },
            radios: ['fresh controller/agent radio capability snapshots'],
          }, null, 2)}
          className="w-full min-h-[360px] px-3 py-2 rounded-lg bg-background/70 border border-border text-xs font-mono text-foreground resize-y" />
        <p className="text-xs text-muted-foreground">
          Each radio record must include its site/jurisdiction and installation reference, supported channels and widths, hardware device class, indoor/outdoor environment, DFS/AFC capabilities, maximum EIRP, current settings and capability observation timestamp. Use a retained dataset reference or include a normalized F206 dataset and matching reviewer acknowledgement.
        </p>
      </section>

      {busy && <div className="glass rounded-xl p-5 text-center text-sm text-muted-foreground">Verifying the F206 fingerprint, reviewer acknowledgement, controller snapshot freshness and per-channel restrictions…</div>}

      {result && (
        <>
          <section className="glass rounded-xl p-4 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                {result.status === 'eligible' ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <ShieldAlert className="w-4 h-4 text-amber-400" />}
                <StatusText status={result.status} />
              </div>
              <button type="button" onClick={() => downloadJson(result)}
                className="flex items-center gap-2 px-3 py-2 rounded-lg bg-secondary border border-border text-xs text-foreground">
                <Download className="w-3.5 h-3.5" /> Export preview JSON
              </button>
            </div>
            <div className="grid grid-cols-2 xl:grid-cols-4 gap-2">
              <div className="rounded-lg bg-secondary/40 p-3"><div className="text-xs text-muted-foreground">Radios</div><div className="text-2xl font-mono text-foreground">{result.radio_count}</div></div>
              <div className="rounded-lg bg-secondary/40 p-3"><div className="text-xs text-muted-foreground">Eligible radios</div><div className="text-2xl font-mono text-foreground">{result.eligible_radio_count}</div></div>
              <div className="rounded-lg bg-secondary/40 p-3"><div className="text-xs text-muted-foreground">Stale snapshots</div><div className="text-2xl font-mono text-foreground">{result.stale_capability_radio_count}</div></div>
              <div className="rounded-lg bg-secondary/40 p-3"><div className="text-xs text-muted-foreground">Rule evaluations</div><div className="text-2xl font-mono text-foreground">{result.rule_evaluation_count}</div></div>
            </div>
            <div className="text-xs text-muted-foreground">
              Dataset {result.dataset.dataset_id} · {result.dataset.jurisdiction} · version {result.dataset.version}
            </div>
            <div className="text-[11px] text-muted-foreground break-all">
              Verified normalized-content fingerprint: <span className="font-mono text-foreground">{result.dataset.fingerprint_sha256}</span>
            </div>
            <div className="text-xs text-amber-400 flex items-start gap-2">
              <Info className="w-4 h-4 flex-shrink-0" /> {result.change_application.note}
            </div>
          </section>

          <section className="glass rounded-xl p-4 space-y-3">
            <div className="text-sm font-semibold text-foreground">Per-radio eligibility and proposed configuration</div>
            <div className="space-y-3">
              {result.radios.map(radio => {
                const recommendation = radio.recommended_configuration;
                return (
                  <article key={radio.radio_id} className="rounded-lg bg-secondary/30 border border-border/60 p-3 space-y-2">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div>
                        <div className="text-sm font-semibold text-foreground">{radio.ap_id} · {radio.radio_id}</div>
                        <div className="text-xs text-muted-foreground">{radio.band} · observed {new Date(radio.capabilities_observed_at).toLocaleString()}</div>
                      </div>
                      <StatusText status={radio.status} />
                    </div>
                    {recommendation ? (
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                        <div className="rounded bg-background/50 p-2"><div className="text-[11px] text-muted-foreground">Channel</div><div className="text-lg font-mono text-foreground">{recommendation.channel}</div><div className="text-[11px] text-muted-foreground">{recommendation.centre_frequency_mhz} MHz</div></div>
                        <div className="rounded bg-background/50 p-2"><div className="text-[11px] text-muted-foreground">Width</div><div className="text-lg font-mono text-foreground">{recommendation.channel_width_mhz} MHz</div></div>
                        <div className="rounded bg-background/50 p-2"><div className="text-[11px] text-muted-foreground">EIRP ceiling</div><div className="text-lg font-mono text-foreground">{recommendation.eirp_ceiling_dbm} dBm</div></div>
                        <div className="rounded bg-background/50 p-2"><div className="text-[11px] text-muted-foreground">Proposed power</div><div className="text-lg font-mono text-foreground">{recommendation.proposed_eirp_dbm == null ? 'Review' : recommendation.proposed_eirp_dbm + ' dBm'}</div></div>
                      </div>
                    ) : (
                      <div className="text-xs text-muted-foreground">No channel can be previewed from this capability and rule snapshot.</div>
                    )}
                    {recommendation && (
                      <div className="flex flex-wrap gap-2 text-[11px] text-muted-foreground">
                        <span>Rule: {recommendation.rule_id}</span>
                        {recommendation.change_required && <span className="text-amber-400">Configuration change required</span>}
                        {radio.recommended_configuration && radio.eligible_candidates.find(item => item.channel === recommendation.channel && item.channel_width_mhz === recommendation.channel_width_mhz)?.six_ghz_psc && <span className="text-cyan-400">6 GHz PSC</span>}
                        {radio.eligible_candidates.find(item => item.channel === recommendation.channel && item.channel_width_mhz === recommendation.channel_width_mhz)?.requires_dfs_cac_before_activation && <span className="text-amber-400">DFS CAC required before activation</span>}
                      </div>
                    )}
                    {Object.keys(radio.rejected_reason_counts || {}).length > 0 && (
                      <details className="text-xs text-muted-foreground">
                        <summary className="cursor-pointer">Why other channel options were excluded</summary>
                        <div className="flex flex-wrap gap-x-3 gap-y-1 mt-2">
                          {Object.entries(radio.rejected_reason_counts).map(([reason, count]) => (
                            <span key={reason}>{reason.replaceAll('_', ' ')}: {count}</span>
                          ))}
                        </div>
                      </details>
                    )}
                  </article>
                );
              })}
            </div>
          </section>

          <div className="glass rounded-xl p-3 text-xs text-muted-foreground space-y-1">
            <div className="font-semibold text-foreground">Preview only · no configuration applied</div>
            {result.limitations.map((item, index) => <p key={index}>{item}</p>)}
          </div>
        </>
      )}
    </motion.div>
  );
}
