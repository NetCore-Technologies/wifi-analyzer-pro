import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import {
  AlertCircle, CheckCircle2, Clock3, FileCheck2, History, LockKeyhole,
  RefreshCw, ShieldAlert, ShieldCheck, XCircle,
} from 'lucide-react';
import { apiBase, apiFetch } from '../lib/api.js';

function when(value) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString();
}

function Badge({ status }) {
  const classes = {
    pending_approval: 'border-amber-400/30 text-amber-300 bg-amber-400/5',
    approved_not_applied: 'border-cyan-400/30 text-cyan-300 bg-cyan-400/5',
    rejected: 'border-red-400/30 text-red-300 bg-red-400/5',
    invalidated: 'border-red-400/30 text-red-300 bg-red-400/5',
    expired: 'border-slate-500/30 text-slate-300 bg-slate-400/5',
    cancelled: 'border-slate-500/30 text-slate-300 bg-slate-400/5',
  };
  return <span className={`inline-flex rounded-full border px-2 py-1 text-[10px] uppercase tracking-wide ${classes[status] || classes.cancelled}`}>{String(status || 'unknown').replaceAll('_', ' ')}</span>;
}

function Metric({ label, value }) {
  return <div className="rounded-lg border border-border bg-secondary/30 p-2 min-w-0">
    <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div>
    <div className="mt-1 text-xs font-mono text-foreground break-words">{value == null ? '—' : String(value)}</div>
  </div>;
}

export default function RfChangeApprovalPanel() {
  const base = useMemo(() => apiBase() + '/api/sites', []);
  const [siteId, setSiteId] = useState('');
  const [datasets, setDatasets] = useState([]);
  const [datasetRef, setDatasetRef] = useState('');
  const [adapterId, setAdapterId] = useState('openwrt');
  const [expiryMinutes, setExpiryMinutes] = useState('60');
  const [radiosText, setRadiosText] = useState('');
  const [requests, setRequests] = useState([]);
  const [selected, setSelected] = useState(null);
  const [canManage, setCanManage] = useState(false);
  const [busy, setBusy] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [comment, setComment] = useState('');

  const requestUrl = base + '/rf-change-requests';

  const refresh = useCallback(async () => {
    if (!siteId.trim()) {
      setDatasets([]);
      setRequests([]);
      setSelected(null);
      setCanManage(false);
      return;
    }
    setLoading(true);
    setError('');
    try {
      const [datasetResponse, requestResponse] = await Promise.all([
        apiFetch(base + '/regulatory-datasets?site_id=' + encodeURIComponent(siteId.trim()) + '&limit=100&include_revoked=false',
          { signal: AbortSignal.timeout(12000) }),
        apiFetch(requestUrl + '?site_id=' + encodeURIComponent(siteId.trim()) + '&limit=50',
          { signal: AbortSignal.timeout(12000) }),
      ]);
      const [datasetData, requestData] = await Promise.all([
        datasetResponse.json().catch(() => ({})),
        requestResponse.json().catch(() => ({})),
      ]);
      if (!datasetResponse.ok) throw new Error(datasetData.error || 'Unable to load retained F206 datasets.');
      if (!requestResponse.ok) throw new Error(requestData.error || 'Unable to load RF change requests.');
      const retained = Array.isArray(datasetData.datasets) ? datasetData.datasets : [];
      const history = Array.isArray(requestData.requests) ? requestData.requests : [];
      setDatasets(retained);
      setRequests(history);
      setCanManage(requestData.can_manage === true);
      if (datasetRef && !retained.some(item => item.dataset_ref === datasetRef)) setDatasetRef('');
      if (selected?.request_id && !history.some(item => item.request_id === selected.request_id)) {
        setSelected(null);
      }
    } catch (loadError) {
      setError(loadError.message || 'Unable to load RF change-management data.');
    } finally {
      setLoading(false);
    }
  }, [base, requestUrl, siteId, datasetRef, selected?.request_id]);

  useEffect(() => { void refresh(); }, [refresh]);

  async function openRequest(item) {
    setBusy('open');
    setError('');
    try {
      const url = requestUrl + '/' + encodeURIComponent(item.request_id)
        + '?site_id=' + encodeURIComponent(siteId.trim());
      const response = await apiFetch(url, { signal: AbortSignal.timeout(12000) });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || 'Unable to retrieve this approval packet.');
      setSelected(data);
      setComment('');
      setNotice('');
    } catch (openError) {
      setError(openError.message || 'Unable to retrieve this approval packet.');
    } finally {
      setBusy('');
    }
  }

  async function createRequest(event) {
    event.preventDefault();
    setBusy('create');
    setError('');
    setNotice('');
    try {
      if (!siteId.trim() || !datasetRef) throw new Error('Select a site and an active retained F206 dataset.');
      if (new TextEncoder().encode(radiosText).length > 900 * 1024) {
        throw new Error('Radio capability JSON must not exceed 900 KiB.');
      }
      const radios = JSON.parse(radiosText);
      if (!Array.isArray(radios) || radios.length === 0) throw new Error('Radio capability JSON must be a non-empty array.');
      const response = await apiFetch(requestUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          site_id: siteId.trim(),
          dataset_ref: datasetRef,
          adapter_id: adapterId,
          expiry_minutes: Number(expiryMinutes),
          radios,
        }),
        signal: AbortSignal.timeout(45000),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || 'The RF approval request could not be created.');
      setNotice(data.audit_status || 'Immutable approval packet created; two independent approvals are required.');
      setSelected({ request: data.request, packet: data.packet });
      setRadiosText('');
      await refresh();
    } catch (createError) {
      setError(createError.message || 'Unable to create the change request.');
    } finally {
      setBusy('');
    }
  }

  async function decision(value) {
    const requestId = selected?.request?.request_id || selected?.request_id;
    if (!requestId) return;
    setBusy(value);
    setError('');
    setNotice('');
    try {
      const response = await apiFetch(requestUrl + '/' + encodeURIComponent(requestId) + '/decision', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ site_id: siteId.trim(), decision: value, comment }),
        signal: AbortSignal.timeout(15000),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || 'The decision was not recorded.');
      setNotice(data.audit_status || (value === 'approve' ? 'Approval recorded.' : 'Request rejected.'));
      await refresh();
      await openRequest({ request_id: requestId });
    } catch (decisionError) {
      setError(decisionError.message || 'Unable to record this decision.');
    } finally {
      setBusy('');
    }
  }

  async function cancelRequest() {
    const requestId = selected?.request?.request_id || selected?.request_id;
    if (!requestId) return;
    setBusy('cancel');
    setError('');
    setNotice('');
    try {
      const response = await apiFetch(requestUrl + '/' + encodeURIComponent(requestId) + '/cancel', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ site_id: siteId.trim() }),
        signal: AbortSignal.timeout(15000),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || 'The request could not be cancelled.');
      setNotice('Pending request cancelled.');
      await refresh();
      await openRequest({ request_id: requestId });
    } catch (cancelError) {
      setError(cancelError.message || 'Unable to cancel the request.');
    } finally {
      setBusy('');
    }
  }

  async function checkExecutionGate() {
    const requestId = selected?.request?.request_id || selected?.request_id;
    if (!requestId) return;
    setBusy('execute');
    setError('');
    setNotice('');
    try {
      const response = await apiFetch(requestUrl + '/' + encodeURIComponent(requestId) + '/execute', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ site_id: siteId.trim() }),
        signal: AbortSignal.timeout(15000),
      });
      const data = await response.json().catch(() => ({}));
      if (data.request) setSelected(data.request);
      if (response.status === 409 && data.code === 'write_adapter_unavailable') {
        setNotice('Deployment is blocked: no write-capable adapter is registered. No router configuration was applied.');
        await openRequest({ request_id: requestId });
        return;
      }
      if (!response.ok) throw new Error(data.error || 'The deployment gate rejected this request.');
    } catch (gateError) {
      setError(gateError.message || 'Unable to check the deployment gate.');
    } finally {
      setBusy('');
    }
  }

  const record = selected?.request || selected;
  const packet = selected?.packet || record?.packet;
  const changes = Array.isArray(packet?.changes) ? packet.changes : [];

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-4">
      <section className="glass rounded-xl p-4 flex items-start gap-3">
        <div className="p-2 rounded-lg bg-primary/10 border border-primary/20"><ShieldCheck className="w-5 h-5 text-primary" /></div>
        <div>
          <div className="text-sm font-semibold text-foreground">RF controller change approvals</div>
          <p className="text-xs text-muted-foreground mt-1">
            Bind F207 proposals to retained F206 evidence. Two independent site managers must approve. Approval does not apply router configuration.
          </p>
        </div>
      </section>

      <section className="glass rounded-xl p-4 space-y-3">
        <div className="flex items-center justify-between gap-2">
          <div className="text-sm font-semibold text-foreground flex items-center gap-2"><History className="w-4 h-4 text-primary" /> Site approval history</div>
          <button type="button" onClick={() => void refresh()} disabled={loading || !siteId.trim()}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-secondary border border-border text-xs text-foreground disabled:opacity-50">
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} /> Refresh
          </button>
        </div>
        <label className="block text-xs text-muted-foreground">
          Assigned site ID
          <input value={siteId} onChange={event => { setSiteId(event.target.value); setSelected(null); }}
            maxLength={128} placeholder="Enter an assigned site ID"
            className="mt-1 w-full px-3 py-2 rounded-lg bg-background/70 border border-border text-sm text-foreground" />
        </label>
        {canManage
          ? <div className="text-[11px] text-muted-foreground">Site-management permission confirmed.</div>
          : siteId.trim() && <div className="text-[11px] text-muted-foreground">Read-only site access; sites.manage is required for changes.</div>}
        {requests.length ? <div className="space-y-2 max-h-64 overflow-y-auto">
          {requests.map(item => <button key={item.request_id} type="button" onClick={() => void openRequest(item)}
            className={`w-full text-left rounded-lg border px-3 py-2 flex flex-wrap justify-between items-center gap-2 ${record?.request_id === item.request_id ? 'border-primary/50 bg-primary/5' : 'border-border bg-secondary/30'}`}>
            <span className="min-w-0">
              <span className="block text-xs font-semibold font-mono text-foreground">{item.request_id}</span>
              <span className="block text-[11px] text-muted-foreground">{item.adapter_id} · {item.approval_count}/{item.required_approvals} approvals · {when(item.created_at)}</span>
            </span>
            <Badge status={item.status} />
          </button>)}
        </div> : <div className="text-xs text-muted-foreground">{siteId.trim() ? 'No retained requests for this site.' : 'Enter an assigned site ID to load approval history.'}</div>}
      </section>

      {canManage && <form onSubmit={createRequest} className="glass rounded-xl p-4 space-y-3">
        <div className="text-sm font-semibold text-foreground flex items-center gap-2"><FileCheck2 className="w-4 h-4 text-primary" /> Create two-person approval request</div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <label className="text-xs text-muted-foreground md:col-span-2">
            Active retained F206 dataset
            <select value={datasetRef} onChange={event => setDatasetRef(event.target.value)}
              className="mt-1 w-full px-3 py-2 rounded-lg bg-background/70 border border-border text-sm text-foreground">
              <option value="">Select reviewed dataset</option>
              {datasets.filter(item => !item.revoked).map(item => (
                <option key={item.dataset_ref} value={item.dataset_ref}>
                  {item.jurisdiction} · {item.dataset_id} · {item.version} · {item.reviewer_id}
                </option>
              ))}
            </select>
          </label>
          <label className="text-xs text-muted-foreground">
            Adapter
            <select value={adapterId} onChange={event => setAdapterId(event.target.value)}
              className="mt-1 w-full px-3 py-2 rounded-lg bg-background/70 border border-border text-sm text-foreground">
              <option value="openwrt">OpenWrt</option>
              <option value="unifi">UniFi</option>
              <option value="mikrotik">MikroTik</option>
            </select>
          </label>
          <label className="text-xs text-muted-foreground">
            Request expiry
            <select value={expiryMinutes} onChange={event => setExpiryMinutes(event.target.value)}
              className="mt-1 w-full px-3 py-2 rounded-lg bg-background/70 border border-border text-sm text-foreground">
              <option value="30">30 minutes</option>
              <option value="60">1 hour</option>
              <option value="240">4 hours</option>
              <option value="720">12 hours</option>
              <option value="1440">24 hours</option>
            </select>
          </label>
        </div>
        <label className="block text-xs text-muted-foreground">
          Exact F207 controller/agent radio capability JSON
          <textarea value={radiosText} onChange={event => setRadiosText(event.target.value)}
            rows={14} spellCheck="false"
            placeholder="Paste the exact radio capability array used for the F207 preview, including site, jurisdiction, installation, band, capability source/timestamp, channel/width support, DFS/AFC and EIRP limits."
            className="mt-1 w-full min-h-[220px] px-3 py-2 rounded-lg bg-background/70 border border-border text-xs font-mono text-foreground resize-y" />
        </label>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className="text-[11px] text-muted-foreground">900 KiB maximum · exactly two independent approvers · F207 must return fully eligible radios</span>
          <button type="submit" disabled={busy !== '' || !siteId.trim() || !datasetRef || !radiosText.trim()}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-primary/10 border border-primary/30 text-primary text-xs font-semibold disabled:opacity-50">
            <FileCheck2 className="w-3.5 h-3.5" /> {busy === 'create' ? 'Creating…' : 'Create approval request'}
          </button>
        </div>
      </form>}

      {error && <div role="alert" className="glass rounded-xl p-3 border border-red-400/30 text-xs text-red-400 flex gap-2"><AlertCircle className="w-4 h-4 shrink-0" />{error}</div>}
      {notice && <div role="status" className="glass rounded-xl p-3 border border-cyan-400/25 text-xs text-cyan-200">{notice}</div>}

      {record && <section className="glass rounded-xl p-4 space-y-4">
        <div className="flex flex-wrap items-start justify-between gap-2">
          <div>
            <div className="text-sm font-semibold text-foreground">Selected change request</div>
            <div className="mt-1 text-[11px] font-mono text-muted-foreground break-all">{record.request_id}</div>
          </div>
          <Badge status={record.status} />
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
          <Metric label="Adapter" value={record.adapter_id} />
          <Metric label="Requester" value={record.requested_by} />
          <Metric label="Approvals" value={`${record.approval_count || 0}/${record.required_approvals}`} />
          <Metric label="Expires" value={when(record.expires_at)} />
        </div>
        {packet && <>
          <div className="rounded-lg border border-border bg-secondary/25 p-3 space-y-2">
            <div className="text-xs font-semibold text-foreground">Regulatory evidence binding</div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              <Metric label="Dataset" value={packet.dataset?.dataset_id + ' · ' + packet.dataset?.version} />
              <Metric label="Jurisdiction" value={packet.dataset?.jurisdiction} />
              <Metric label="Reviewer" value={packet.dataset?.reviewer_id} />
              <Metric label="Review reference" value={packet.dataset?.review_reference} />
              <div className="md:col-span-2"><Metric label="Dataset SHA-256" value={packet.dataset?.fingerprint_sha256} /></div>
            </div>
          </div>
          <div className="space-y-2">
            <div className="text-xs font-semibold text-foreground">Exact proposed radio changes ({changes.length})</div>
            {changes.map(change => <div key={change.radio_id} className="rounded-lg border border-border bg-secondary/25 p-3 space-y-2">
              <div className="flex flex-wrap justify-between gap-2">
                <span className="text-xs font-semibold text-foreground">{change.ap_id} · {change.radio_id} · {change.band}</span>
                <span className="text-[10px] text-muted-foreground">Capabilities {when(change.capabilities_observed_at)}</span>
              </div>
              <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                <Metric label="Current channel / width" value={`${change.before.channel ?? '—'} / ${change.before.channel_width_mhz ?? '—'} MHz`} />
                <Metric label="Proposed channel / width" value={`${change.after.channel} / ${change.after.channel_width_mhz} MHz`} />
                <Metric label="EIRP dBm" value={`${change.before.eirp_dbm ?? '—'} → ${change.after.eirp_dbm ?? 'review required'}`} />
              </div>
              <div className="text-[10px] text-muted-foreground">Rule {change.rule_id} · DFS {change.dfs_required ? 'required' : 'not required'} · AFC {change.afc_required ? 'required' : 'not required'}</div>
            </div>)}
          </div>
        </>}
        <div className="space-y-2">
          <div className="text-xs font-semibold text-foreground">Independent approval history</div>
          {(record.approvals || []).map(item => <div key={item.actor} className="rounded-lg bg-secondary/30 px-3 py-2 flex flex-wrap justify-between gap-2 text-xs">
            <span className="font-medium text-foreground">{item.actor}</span>
            <span className="text-muted-foreground">{item.decision} · {when(item.occurred_at)}</span>
          </div>)}
          {(record.approvals || []).length === 0 && <div className="text-xs text-muted-foreground">No approvals recorded.</div>}
        </div>
        {canManage && record.status === 'pending_approval' && <div className="border-t border-border pt-3 space-y-2">
          <label className="block text-xs text-muted-foreground">Decision comment (optional)
            <input value={comment} onChange={event => setComment(event.target.value.slice(0, 1000))}
              maxLength={1000} className="mt-1 w-full px-3 py-2 rounded-lg bg-background/70 border border-border text-sm text-foreground" />
          </label>
          <div className="flex flex-wrap gap-2">
            <button type="button" onClick={() => void decision('approve')} disabled={busy !== ''}
              className="flex items-center gap-2 px-3 py-2 rounded-lg bg-emerald-400/10 border border-emerald-400/30 text-emerald-300 text-xs disabled:opacity-50">
              <CheckCircle2 className="w-3.5 h-3.5" /> Approve
            </button>
            <button type="button" onClick={() => void decision('reject')} disabled={busy !== ''}
              className="flex items-center gap-2 px-3 py-2 rounded-lg bg-red-400/10 border border-red-400/30 text-red-300 text-xs disabled:opacity-50">
              <XCircle className="w-3.5 h-3.5" /> Reject
            </button>
            <button type="button" onClick={cancelRequest} disabled={busy !== ''}
              className="px-3 py-2 rounded-lg bg-secondary border border-border text-xs text-muted-foreground disabled:opacity-50">Cancel request</button>
          </div>
          <p className="text-[11px] text-muted-foreground">The requester cannot approve their own request. Two separate site managers are mandatory.</p>
        </div>}
        {canManage && record.status === 'approved_not_applied' && <div className="rounded-lg border border-amber-400/25 bg-amber-400/5 p-3 space-y-2">
          <div className="flex items-center gap-2 text-xs font-semibold text-amber-200"><LockKeyhole className="w-4 h-4" /> Approved, not applied</div>
          <p className="text-xs text-muted-foreground">All installed adapters are read-only. The deployment gate remains closed.</p>
          <button type="button" onClick={checkExecutionGate} disabled={busy !== ''}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-secondary border border-border text-xs text-foreground disabled:opacity-50">
            <Clock3 className="w-3.5 h-3.5" /> {busy === 'execute' ? 'Checking…' : 'Check deployment gate'}
          </button>
        </div>}
        {record.status === 'invalidated' && <div className="text-xs text-red-300 flex items-center gap-2"><ShieldAlert className="w-4 h-4" /> Retained regulatory evidence was revoked or is missing.</div>}
        {record.status === 'expired' && <div className="text-xs text-muted-foreground">This request expired before receiving both approvals.</div>}
        <div className="text-[10px] text-muted-foreground break-all">Packet SHA-256: {record.packet_sha256}</div>
      </section>}
      <div className="glass rounded-xl p-3 flex items-start gap-2">
        <ShieldAlert className="w-4 h-4 text-amber-300 mt-0.5 shrink-0" />
        <p className="text-xs text-muted-foreground">This is a two-person approval register, not a controller write tool. Deployment is unavailable until an adapter provides authenticated least-privilege writes, live-state revalidation, rollback and post-change read-back verification.</p>
      </div>
    </motion.div>
  );
}
