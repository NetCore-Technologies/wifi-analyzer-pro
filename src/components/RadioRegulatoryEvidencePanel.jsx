import React, { useState } from 'react';
import { motion } from 'framer-motion';
import { AlertCircle, CheckCircle2, Download, FileUp, Globe2, Play, RefreshCw, Save, ShieldAlert, Trash2 } from 'lucide-react';
import { apiBase, apiFetch } from '../lib/api.js';

const MAX_IMPORT_BYTES = 900 * 1024;

function downloadJson(value) {
  const blob = new Blob([JSON.stringify(value, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = 'radio-regulatory-evidence-validation.json';
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function resultTone(status) {
  if (status === 'validated' || status === 'in_effect') return 'text-emerald-400';
  if (status === 'review_required' || status === 'expired' || status === 'not_yet_effective') return 'text-amber-400';
  return 'text-rose-400';
}

export default function RadioRegulatoryEvidencePanel() {
  const [payloadText, setPayloadText] = useState(JSON.stringify({
    jurisdiction: "AU",
    dataset_id: "replace-with-stable-dataset-id",
    version: "publisher-revision-or-import-version",
    regulator: "Regulator name",
    retrieved_at: new Date().toISOString(),
    effective_from: "YYYY-MM-DD",
    sources: [],
    rules: []
  }, null, 2));
  const [fileName, setFileName] = useState('');
  const [result, setResult] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [siteId, setSiteId] = useState('head-office');
  const [reviewReference, setReviewReference] = useState('');
  const [acknowledged, setAcknowledged] = useState(false);
  const [retainBusy, setRetainBusy] = useState(false);
  const [registryRows, setRegistryRows] = useState([]);
  const [registryBusy, setRegistryBusy] = useState(false);
  const [registryError, setRegistryError] = useState('');
  const [registryCanManage, setRegistryCanManage] = useState(false);
  const [revokeReason, setRevokeReason] = useState('');
  const [revokeTarget, setRevokeTarget] = useState('');

  async function loadRegistry() {
    if (!siteId.trim() || siteId.length > 128) {
      setRegistryError('Enter a valid site ID to load retained regulatory datasets.');
      return;
    }
    setRegistryBusy(true);
    setRegistryError('');
    try {
      const url = apiBase() + '/api/sites/regulatory-datasets?site_id='
        + encodeURIComponent(siteId.trim()) + '&limit=100&include_revoked=true';
      const response = await apiFetch(url, { signal: AbortSignal.timeout(15000) });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || 'Unable to load the site regulatory dataset registry.');
      if (!Array.isArray(data.datasets)) throw new Error('The registry returned an invalid dataset list.');
      setRegistryRows(data.datasets);
      setRegistryCanManage(data.can_manage === true);
    } catch (loadError) {
      setRegistryRows([]);
      setRegistryCanManage(false);
      setRegistryError(loadError.message || 'Unable to load the regulatory dataset registry.');
    } finally {
      setRegistryBusy(false);
    }
  }

  async function retainDataset() {
    if (!result || result.status !== 'validated') {
      setRegistryError('Only a currently validated dataset can be retained.');
      return;
    }
    if (!acknowledged || !reviewReference.trim()) {
      setRegistryError('A review reference and explicit acknowledgement are required.');
      return;
    }
    if (!registryCanManage) {
      setRegistryError('Your account needs sites.manage permission for this site to retain regulatory datasets.');
      return;
    }
    setRetainBusy(true);
    setRegistryError('');
    try {
      const response = await apiFetch(apiBase() + '/api/sites/regulatory-datasets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          site_id: siteId.trim(),
          dataset: result,
          acknowledgement: {
            dataset_fingerprint_sha256: result.dataset_fingerprint_sha256,
            review_reference: reviewReference.trim(),
            acknowledged: true,
          },
        }),
        signal: AbortSignal.timeout(30000),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || 'Unable to retain the regulatory dataset.');
      setAcknowledged(false);
      await loadRegistry();
      if (data.audit_status) setRegistryError(data.audit_status);
    } catch (retainError) {
      setRegistryError(retainError.message || 'Unable to retain the regulatory dataset.');
    } finally {
      setRetainBusy(false);
    }
  }

  async function revokeDataset(record) {
    if (!record?.dataset_ref || record.revoked || !registryCanManage) return;
    if (revokeReason.trim().length < 12) {
      setRegistryError('Enter a revocation reason of at least 12 characters.');
      return;
    }
    setRegistryBusy(true);
    setRegistryError('');
    try {
      const response = await apiFetch(apiBase() + '/api/sites/regulatory-datasets', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          operation: 'revoke',
          site_id: siteId.trim(),
          dataset_ref: record.dataset_ref,
          reason: revokeReason.trim(),
        }),
        signal: AbortSignal.timeout(20000),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || 'Unable to revoke the regulatory dataset.');
      setRevokeReason('');
      setRevokeTarget('');
      await loadRegistry();
      if (data.audit_status) setRegistryError(data.audit_status);
    } catch (revokeError) {
      setRegistryError(revokeError.message || 'Unable to revoke the regulatory dataset.');
    } finally {
      setRegistryBusy(false);
    }
  }

  async function importFile(event) {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file) return;
    if (file.size > MAX_IMPORT_BYTES) {
      setError('Regulatory evidence JSON must not exceed 900 KiB.');
      return;
    }
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error('JSON root must be an object.');
      }
      setPayloadText(text);
      setFileName(file.name);
      setError('');
      setResult(null);
      setAcknowledged(false);
    } catch (importError) {
      setError(importError.message || 'The selected file is not valid JSON.');
    }
  }

  async function validate() {
    setBusy(true);
    setError('');
    setResult(null);
    try {
      const payload = JSON.parse(payloadText);
      if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
        throw new Error('Regulatory evidence input must be a JSON object.');
      }
      const response = await apiFetch(apiBase() + '/api/features/radio_regulatory_evidence_validator', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(30000),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || 'Regulatory evidence validation failed.');
      if (!data.result || !Array.isArray(data.result.sources) || !Array.isArray(data.result.rules)) {
        throw new Error('The validator returned an invalid evidence result.');
      }
      setResult(data.result);
      setAcknowledged(false);
      setRegistryError('');
    } catch (validationError) {
      setError(validationError.message || 'Unable to validate regulatory evidence.');
    } finally {
      setBusy(false);
    }
  }

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-4">
      <div className="glass rounded-xl p-4 flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-start gap-3 min-w-0">
          <div className="p-2 rounded-lg bg-primary/10 border border-primary/20"><Globe2 className="w-5 h-5 text-primary" /></div>
          <div>
            <div className="text-sm font-semibold text-foreground">Radio regulatory evidence</div>
            <p className="text-xs text-muted-foreground mt-1 max-w-3xl">
              Import a jurisdiction-specific rule dataset with official source URLs, revisions, dates, content digests and exact clause references. The tool validates provenance metadata and schema; it does not fetch or authenticate the source documents.
            </p>
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <label className="flex items-center gap-2 px-3 py-2 rounded-lg bg-secondary border border-border text-xs text-foreground cursor-pointer hover:bg-secondary/70">
            <FileUp className="w-3.5 h-3.5" /> Import JSON
            <input type="file" accept=".json,application/json" onChange={importFile} className="sr-only" />
          </label>
          <button type="button" onClick={validate} disabled={busy}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-primary/10 border border-primary/30 text-primary text-xs font-semibold disabled:opacity-50">
            <Play className={`w-3.5 h-3.5 ${busy ? 'animate-pulse' : ''}`} /> {busy ? 'Validating…' : 'Validate dataset'}
          </button>
        </div>
      </div>

      <section className="glass rounded-xl p-4 space-y-3">
        <div className="flex flex-wrap items-end gap-2">
          <label className="flex-1 min-w-[180px] text-xs text-muted-foreground">
            Site ID for retained regulatory version
            <input value={siteId} onChange={event => {
              setSiteId(event.target.value);
              setRegistryRows([]);
              setRegistryCanManage(false);
              setRegistryError('');
              setRevokeTarget('');
              setRevokeReason('');
            }}
              maxLength={128} placeholder="e.g. head-office"
              className="mt-1 w-full px-3 py-2 rounded-lg bg-background/70 border border-border text-sm text-foreground" />
          </label>
          <button type="button" onClick={() => void loadRegistry()} disabled={registryBusy || !siteId.trim()}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-secondary border border-border text-xs text-foreground disabled:opacity-50">
            <RefreshCw className={`w-3.5 h-3.5 ${registryBusy ? 'animate-spin' : ''}`} />
            {registryBusy ? 'Loading…' : 'Load site versions'}
          </button>
        </div>
        {registryError && <div role="alert" className="text-xs text-amber-400">{registryError}</div>}
        {registryRows.length > 0 && (
          <div className="space-y-2 max-h-64 overflow-y-auto">
            {registryRows.map(record => (
              <div key={record.dataset_ref} className="rounded-lg bg-secondary/30 border border-border/60 p-3 space-y-2">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div>
                    <div className="text-xs font-semibold text-foreground">{record.dataset_id} · {record.version} · {record.jurisdiction}</div>
                    <div className="text-[11px] text-muted-foreground">
                      {record.reviewer_id} · {record.review_reference} · {new Date(record.reviewed_at).toLocaleString()}
                    </div>
                    <div className="text-[11px] text-muted-foreground font-mono">{record.fingerprint_sha256}</div>
                  </div>
                  <span className={`text-xs font-semibold ${record.revoked ? 'text-rose-400' : 'text-emerald-400'}`}>
                    {record.revoked ? 'REVOKED' : 'ACTIVE'}
                  </span>
                </div>
                {record.revoked && <div className="text-xs text-rose-300">{record.revocation_reason} · {record.revoked_by} · {new Date(record.revoked_at).toLocaleString()}</div>}
                {registryCanManage && !record.revoked && (
                  <button type="button" onClick={() => setRevokeTarget(record.dataset_ref)} disabled={registryBusy}
                    className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-red-400/30 text-red-400 text-xs disabled:opacity-40">
                    <Trash2 className="w-3.5 h-3.5" /> Request revocation
                  </button>
                )}
                {registryCanManage && revokeTarget === record.dataset_ref && !record.revoked && (
                  <div className="rounded-lg border border-red-400/30 bg-red-500/5 p-3 space-y-2">
                    <div className="text-xs font-semibold text-red-300">Confirm permanent revocation</div>
                    <p className="text-xs text-muted-foreground">This version will remain in the audit history but cannot be retrieved or used for future F207 production planning.</p>
                    <div className="flex flex-wrap gap-2">
                      <button type="button" onClick={() => void revokeDataset(record)}
                        disabled={registryBusy || revokeReason.trim().length < 12}
                        className="px-3 py-1.5 rounded-lg bg-red-500/10 border border-red-400/30 text-red-300 text-xs disabled:opacity-40">
                        Confirm revoke
                      </button>
                      <button type="button" onClick={() => setRevokeTarget('')} disabled={registryBusy}
                        className="px-3 py-1.5 rounded-lg bg-secondary border border-border text-foreground text-xs">
                        Cancel
                      </button>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
        {registryCanManage && registryRows.some(record => !record.revoked) && (
          <label className="block text-xs text-muted-foreground">
            Mandatory revocation reason (12–512 characters)
            <input value={revokeReason} onChange={event => setRevokeReason(event.target.value.slice(0, 512))}
              maxLength={512} placeholder="Why this regulatory version must no longer be used"
              className="mt-1 w-full px-3 py-2 rounded-lg bg-background/70 border border-border text-sm text-foreground" />
          </label>
        )}
        {!registryBusy && registryRows.length === 0 && !registryError && (
          <div className="text-xs text-muted-foreground">No retained versions for this site, or load site versions to check.</div>
        )}
      </section>

      <div className="glass rounded-xl p-4 flex items-start gap-2">
        <ShieldAlert className="w-4 h-4 text-amber-400 mt-0.5 flex-shrink-0" />
        <p className="text-xs text-muted-foreground">
          A source domain on the built-in authority list is only a provenance hint. Document content, digital signatures, legal applicability and current regulatory status are not independently authenticated. Unknown domains return review_required; they are never promoted automatically.
        </p>
      </div>

      {fileName && <div className="text-xs text-muted-foreground">Loaded: {fileName}</div>}
      {error && <div role="alert" className="glass rounded-xl p-3 border border-red-400/30 text-xs text-red-400 flex gap-2"><AlertCircle className="w-4 h-4 flex-shrink-0" />{error}</div>}

      <section className="glass rounded-xl p-4 space-y-2">
        <div className="flex items-center justify-between gap-2">
          <div className="text-sm font-semibold text-foreground">Regulatory dataset JSON</div>
          <span className="text-xs text-muted-foreground">Maximum 900 KiB</span>
        </div>
        <textarea value={payloadText} onChange={event => { setPayloadText(event.target.value); setResult(null); }}
          rows={22} spellCheck="false" aria-label="Radio regulatory evidence JSON"
          className="w-full min-h-[360px] px-3 py-2 rounded-lg bg-background/70 border border-border text-xs font-mono text-foreground resize-y" />
        <p className="text-xs text-muted-foreground">
          Required top-level fields include jurisdiction, dataset_id, version, regulator, retrieved_at, effective dates, sources and rules. Each rule must cite exact source IDs and clause references.
        </p>
      </section>

      {busy && <div className="glass rounded-xl p-5 text-center text-sm text-muted-foreground">Validating source metadata, authority domains, effective dates and rule citations…</div>}

      {result && (
        <>
          <div className="glass rounded-xl p-4 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                {result.status === 'validated' ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <ShieldAlert className="w-4 h-4 text-amber-400" />}
                <span className={`text-sm font-semibold ${resultTone(result.status)}`}>{result.status.replaceAll('_', ' ').toUpperCase()}</span>
              </div>
              <button type="button" onClick={() => downloadJson(result)}
                className="flex items-center gap-2 px-3 py-2 rounded-lg bg-secondary border border-border text-xs text-foreground">
                <Download className="w-3.5 h-3.5" /> Export normalized result
              </button>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
              <div className="rounded-lg bg-secondary/40 p-3"><div className="text-xs text-muted-foreground">Jurisdiction</div><div className="text-xl font-mono text-foreground">{result.jurisdiction}</div></div>
              <div className="rounded-lg bg-secondary/40 p-3"><div className="text-xs text-muted-foreground">Rules</div><div className="text-xl font-mono text-foreground">{result.rule_count}</div></div>
              <div className="rounded-lg bg-secondary/40 p-3"><div className="text-xs text-muted-foreground">Allowlisted domains</div><div className="text-xl font-mono text-foreground">{result.allowlisted_source_domain_count}/{result.source_count}</div></div>
              <div className="rounded-lg bg-secondary/40 p-3"><div className="text-xs text-muted-foreground">Effective status</div><div className={`text-sm font-semibold mt-2 ${resultTone(result.effective_status)}`}>{result.effective_status.replaceAll('_', ' ')}</div></div>
            </div>
            <div className="text-xs text-muted-foreground break-all">Dataset fingerprint: <span className="font-mono text-foreground">{result.dataset_fingerprint_sha256}</span></div>
            {result.status === 'validated' && (
              <section className="rounded-lg border border-border bg-secondary/20 p-3 space-y-3">
                <div className="text-sm font-semibold text-foreground">Retain reviewed version for the site</div>
                <label className="block text-xs text-muted-foreground">
                  Review/change reference
                  <input value={reviewReference} onChange={event => setReviewReference(event.target.value.slice(0, 128))}
                    maxLength={128} placeholder="e.g. CHG-2026-1101"
                    className="mt-1 w-full px-3 py-2 rounded-lg bg-background/70 border border-border text-sm text-foreground" />
                </label>
                <label className="flex items-start gap-2 text-xs text-foreground">
                  <input type="checkbox" checked={acknowledged} onChange={event => setAcknowledged(event.target.checked)} className="mt-0.5" />
                  <span>I have reviewed the cited source clauses, effective dates, device classes and radio-rule limits for this version. I understand the source documents and supplied digests have not been independently authenticated.</span>
                </label>
                <div className="text-[11px] text-muted-foreground">The server records the authenticated account username and server UTC time as the reviewer; values entered in uploaded JSON cannot override them.</div>
                <button type="button" onClick={() => void retainDataset()}
                  disabled={retainBusy || !registryCanManage || !acknowledged || reviewReference.trim().length < 1}
                  className="flex items-center gap-2 px-3 py-2 rounded-lg bg-primary/10 border border-primary/30 text-primary text-xs font-semibold disabled:opacity-40">
                  <Save className={`w-3.5 h-3.5 ${retainBusy ? 'animate-pulse' : ''}`} />
                  {retainBusy ? 'Retaining…' : 'Retain immutable site version'}
                </button>
                {!registryCanManage && <div className="text-[11px] text-muted-foreground">Load site versions with an account that has sites.manage permission to retain or revoke versions.</div>}
              </section>
            )}
            {result.unverified_source_domains.length > 0 && (
              <div className="text-xs text-amber-400">Review domains: {result.unverified_source_domains.join(', ')}</div>
            )}
          </div>

          <section className="glass rounded-xl p-4 space-y-3">
            <div className="text-sm font-semibold text-foreground">Source documents and provenance</div>
            {result.sources.map(source => (
              <div key={source.source_id} className="rounded-lg bg-secondary/30 border border-border/60 p-3 space-y-1">
                <div className="flex flex-wrap justify-between gap-2">
                  <span className="text-xs font-semibold text-foreground">{source.title}</span>
                  <span className={source.source_domain_allowlisted ? 'text-xs text-emerald-400' : 'text-xs text-amber-400'}>
                    {source.source_domain_allowlisted ? 'Known authority domain' : 'Review required'}
                  </span>
                </div>
                <div className="text-xs text-muted-foreground">{source.authority} · {source.document_reference} · {source.revision}</div>
                <div className="text-xs text-muted-foreground break-all">{source.source_url}</div>
                <div className="text-[11px] text-muted-foreground">Published {source.published_at} · effective {source.effective_from}{source.effective_to ? ' to ' + source.effective_to : ' onward'} · retrieved {source.retrieved_at}</div>
                <div className="text-[11px] text-muted-foreground">Digest supplied but not independently verified · clauses: {source.clause_references.join(', ')}</div>
              </div>
            ))}
          </section>

          <section className="glass rounded-xl p-4 space-y-3">
            <div className="text-sm font-semibold text-foreground">Normalized radio-rule records</div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs text-left">
                <thead className="text-muted-foreground border-b border-border">
                  <tr><th className="py-2 pr-3">Rule</th><th className="py-2 pr-3">Band / MHz</th><th className="py-2 pr-3">Max EIRP</th><th className="py-2 pr-3">Widths</th><th className="py-2 pr-3">Classes</th><th className="py-2">Constraints</th></tr>
                </thead>
                <tbody>
                  {result.rules.map(rule => (
                    <tr key={rule.rule_id} className="border-b border-border/50 last:border-0">
                      <td className="py-2 pr-3 font-mono text-foreground">{rule.rule_id}</td>
                      <td className="py-2 pr-3">{rule.band} · {rule.lower_frequency_mhz}–{rule.upper_frequency_mhz}</td>
                      <td className="py-2 pr-3">{rule.maximum_eirp_dbm} dBm</td>
                      <td className="py-2 pr-3">{rule.channel_widths_mhz.join(', ')}</td>
                      <td className="py-2 pr-3">{rule.device_classes.join(', ')}</td>
                      <td className="py-2">{[rule.indoor_only && 'indoor', rule.dfs_required && 'DFS', rule.afc_required && 'AFC'].filter(Boolean).join(' · ') || 'none declared'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <div className="glass rounded-xl p-3 text-xs text-muted-foreground">{result.limitations.join(' ')}</div>
        </>
      )}
    </motion.div>
  );
}
