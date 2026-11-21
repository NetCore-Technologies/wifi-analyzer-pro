import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import { ShieldAlert, ShieldCheck, Plus, Trash2, AlertTriangle, Info, RefreshCw, Building2 } from 'lucide-react';
import { apiBase, apiFetch } from '../../lib/api.js';
import {
  addTrustedBssid,
  assessTrustedAccessPoints,
  normalizeBssid,
  removeTrustedBssid,
  sanitizeTrustedMap,
} from '../../lib/trustedAccessPoints.js';

function recordsToTrustedMap(records, siteId) {
  const grouped = {};
  for (const record of Array.isArray(records) ? records : []) {
    if (record?.site_id !== siteId || typeof record?.ssid !== 'string' || typeof record?.bssid !== 'string') continue;
    if (!Object.hasOwn(grouped, record.ssid)) {
      Object.defineProperty(grouped, record.ssid, {
        value: [],
        enumerable: true,
        configurable: true,
        writable: true,
      });
    }
    grouped[record.ssid].push(record.bssid);
  }
  return sanitizeTrustedMap(grouped);
}

async function readJson(response) {
  return response.json().catch(() => ({}));
}

export default function RogueAPPanel({ networks = [] }) {
  const [siteIds, setSiteIds] = useState([]);
  const [siteId, setSiteId] = useState('');
  const [trusted, setTrusted] = useState({});
  const [canManage, setCanManage] = useState(false);
  const [loadingSites, setLoadingSites] = useState(true);
  const [loadingBaseline, setLoadingBaseline] = useState(false);
  const [mutating, setMutating] = useState(false);
  const [error, setError] = useState('');
  const [formError, setFormError] = useState('');
  const [notice, setNotice] = useState('');
  const [newSsid, setNewSsid] = useState('');
  const [newBssid, setNewBssid] = useState('');

  const trustedSsidCount = Object.keys(trusted).length;
  const trustedBssidCount = Object.values(trusted).reduce((total, items) => total + items.length, 0);
  const candidates = useMemo(() => assessTrustedAccessPoints(networks, trusted), [networks, trusted]);

  const loadSites = useCallback(async () => {
    setLoadingSites(true);
    setError('');
    try {
      const response = await apiFetch(apiBase() + '/api/sites', {
        signal: AbortSignal.timeout(12000),
      });
      const data = await readJson(response);
      if (!response.ok) throw new Error(data.error || 'Unable to load sites visible to this account.');
      if (!Array.isArray(data.site_ids)) throw new Error('The site directory returned an invalid response.');
      const visible = [...new Set(data.site_ids.filter(value => typeof value === 'string' && value.length > 0))].sort();
      setSiteIds(visible);
      setSiteId(current => visible.includes(current) ? current : visible[0] || '');
    } catch (requestError) {
      setSiteIds([]);
      setSiteId('');
      setTrusted({});
      setCanManage(false);
      setError(requestError.message || 'Unable to load the site directory.');
    } finally {
      setLoadingSites(false);
    }
  }, []);

  const refreshBaseline = useCallback(async () => {
    if (!siteId) {
      setTrusted({});
      setCanManage(false);
      return;
    }
    setLoadingBaseline(true);
    setError('');
    try {
      const response = await apiFetch(
        apiBase() + '/api/trusted-aps?site_id=' + encodeURIComponent(siteId),
        { signal: AbortSignal.timeout(12000) },
      );
      const data = await readJson(response);
      if (!response.ok) throw new Error(data.error || 'Unable to load the shared trusted AP baseline.');
      if (!Array.isArray(data.records)) throw new Error('The trusted AP service returned an invalid baseline.');
      setTrusted(recordsToTrustedMap(data.records, siteId));
      setCanManage(data.can_manage === true);
      setNotice(typeof data.privacy === 'string' ? data.privacy : 'Shared site baseline loaded.');
    } catch (requestError) {
      setTrusted({});
      setCanManage(false);
      setError(requestError.message || 'Unable to load the shared trusted AP baseline.');
    } finally {
      setLoadingBaseline(false);
    }
  }, [siteId]);

  useEffect(() => { void loadSites(); }, [loadSites]);
  useEffect(() => {
    let active = true;
    if (!siteId) {
      setTrusted({});
      setCanManage(false);
      setLoadingBaseline(false);
      return undefined;
    }
    const load = async () => {
      setLoadingBaseline(true);
      setError('');
      try {
        const response = await apiFetch(
          apiBase() + '/api/trusted-aps?site_id=' + encodeURIComponent(siteId),
          { signal: AbortSignal.timeout(12000) },
        );
        const data = await readJson(response);
        if (!response.ok) throw new Error(data.error || 'Unable to load the shared trusted AP baseline.');
        if (!Array.isArray(data.records)) throw new Error('The trusted AP service returned an invalid baseline.');
        if (!active) return;
        setTrusted(recordsToTrustedMap(data.records, siteId));
        setCanManage(data.can_manage === true);
        setNotice(typeof data.privacy === 'string' ? data.privacy : 'Shared site baseline loaded.');
      } catch (requestError) {
        if (!active) return;
        setTrusted({});
        setCanManage(false);
        setError(requestError.message || 'Unable to load the shared trusted AP baseline.');
      } finally {
        if (active) setLoadingBaseline(false);
      }
    };
    void load();
    return () => { active = false; };
  }, [siteId]);

  async function mutateBaseline(operation, ssid, bssid) {
    if (!siteId) {
      setFormError('Select a site before changing its trusted AP baseline.');
      return false;
    }
    if (!canManage) {
      setFormError('Your account has read-only access to this site baseline. A site administrator must make changes.');
      return false;
    }
    setMutating(true);
    setFormError('');
    setError('');
    try {
      const response = await apiFetch(apiBase() + '/api/trusted-aps', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ operation, site_id: siteId, ssid, bssid }),
        signal: AbortSignal.timeout(12000),
      });
      const data = await readJson(response);
      if (!response.ok) throw new Error(data.error || 'Trusted AP baseline update failed.');
      await refreshBaseline();
      setNotice(data.audit_status || (operation === 'add'
        ? (data.created ? 'Trusted BSSID added to the shared site baseline.' : 'This BSSID is already trusted for this site.')
        : (data.removed ? 'Trusted BSSID removed from the shared site baseline.' : 'The BSSID was not present in this site baseline.')));
      return true;
    } catch (requestError) {
      setFormError(requestError.message || 'Trusted AP baseline update failed.');
      return false;
    } finally {
      setMutating(false);
    }
  }

  async function addTrusted() {
    setFormError('');
    try {
      const proposed = addTrustedBssid(trusted, newSsid, newBssid);
      const normalised = normalizeBssid(newBssid);
      if (proposed[newSsid].length === (trusted[newSsid] || []).length) {
        setNotice('This BSSID is already trusted for the selected site.');
        return;
      }
      const saved = await mutateBaseline('add', newSsid, normalised);
      if (saved) {
        setNewSsid('');
        setNewBssid('');
      }
    } catch (validationError) {
      setFormError(validationError.message || 'Enter a valid SSID and BSSID.');
    }
  }

  async function trustObservedCandidate(candidate) {
    try {
      await mutateBaseline('add', candidate.ssid, candidate.bssid);
    } catch (validationError) {
      setFormError(validationError.message || 'Unable to trust this observed BSSID.');
    }
  }

  async function removeTrusted(ssid, bssid) {
    try {
      const proposed = removeTrustedBssid(trusted, ssid, bssid);
      if (proposed === trusted) return;
      await mutateBaseline('remove', ssid, bssid);
    } catch (validationError) {
      setFormError(validationError.message || 'Unable to remove this trusted BSSID.');
    }
  }

  const unavailable = loadingSites || loadingBaseline;
  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-4">
      <div className="glass rounded-xl p-4 flex flex-wrap items-end justify-between gap-3">
        <div className="min-w-[220px] flex-1">
          <label htmlFor="rogue-ap-site" className="text-xs text-muted-foreground block mb-1">Site inventory</label>
          <div className="flex items-center gap-2">
            <Building2 className="w-4 h-4 text-primary flex-shrink-0" />
            <select id="rogue-ap-site" value={siteId} onChange={event => setSiteId(event.target.value)}
              disabled={loadingSites || !siteIds.length}
              className="w-full px-3 py-2 rounded-lg bg-background/50 border border-border text-sm text-foreground disabled:opacity-50">
              {siteIds.length
                ? siteIds.map(id => <option key={id} value={id}>{id}</option>)
                : <option value="">No assigned sites</option>}
            </select>
          </div>
        </div>
        <button type="button" onClick={() => void refreshBaseline()} disabled={!siteId || loadingSites || loadingBaseline || mutating}
          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-primary/10 border border-primary/30 text-primary text-sm disabled:opacity-50">
          <RefreshCw className={`w-3.5 h-3.5 ${loadingBaseline ? 'animate-spin' : ''}`} /> Refresh baseline
        </button>
      </div>

      {error && <div role="alert" className="glass rounded-xl p-4 border border-red-400/30 text-xs text-red-400">{error}</div>}
      {!loadingSites && siteIds.length === 0 && (
        <div className="glass rounded-xl p-5 text-center space-y-2">
          <ShieldAlert className="w-6 h-6 text-muted-foreground mx-auto" />
          <div className="text-sm font-semibold text-foreground">No visible site assignments</div>
          <p className="text-xs text-muted-foreground">Ask a workspace administrator to assign a site to your account before managing or reviewing shared trusted AP baselines.</p>
        </div>
      )}

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="glass rounded-xl p-3 text-center"><div className="text-2xl font-bold font-mono text-primary">{trustedSsidCount}</div><div className="text-xs text-muted-foreground mt-0.5">Trusted SSIDs</div></div>
        <div className="glass rounded-xl p-3 text-center"><div className="text-2xl font-bold font-mono text-primary">{trustedBssidCount}</div><div className="text-xs text-muted-foreground mt-0.5">Trusted BSSIDs</div></div>
        <div className="glass rounded-xl p-3 text-center"><div className={`text-2xl font-bold font-mono ${trustedSsidCount && !unavailable ? (candidates.length ? 'text-yellow-400' : 'text-green-400') : 'text-muted-foreground'}`}>{trustedSsidCount ? candidates.length : '—'}</div><div className="text-xs text-muted-foreground mt-0.5">Untrusted candidates</div></div>
        <div className="glass rounded-xl p-3 text-center"><div className="text-2xl font-bold font-mono text-foreground">{(Array.isArray(networks) ? networks : []).length}</div><div className="text-xs text-muted-foreground mt-0.5">Scanned BSS records</div></div>
      </div>

      <div className="glass rounded-xl p-4 flex items-start gap-2">
        <Info className="w-4 h-4 text-primary mt-0.5 flex-shrink-0" />
        <p className="text-xs text-muted-foreground">
          An untrusted BSSID advertising a trusted SSID is a review candidate, not proof of an evil twin. Legitimate mesh systems, multi-AP WLANs, replacement APs and controller-managed BSSID rotation can produce the same observation. Confirm against controller inventory before escalating.
        </p>
      </div>

      {loadingSites || loadingBaseline ? (
        <div className="glass rounded-xl p-6 text-center text-sm text-muted-foreground">Loading the shared site baseline…</div>
      ) : trustedSsidCount === 0 && !error && siteId ? (
        <div className="glass rounded-xl p-5 text-center space-y-2">
          <ShieldAlert className="w-6 h-6 text-muted-foreground mx-auto" />
          <div className="text-sm font-semibold text-foreground">No trusted AP baseline configured for {siteId}</div>
          <p className="text-xs text-muted-foreground">Add approved SSID/BSSID pairs for the selected site. Candidate detection is limited to SSIDs with a saved trusted baseline.</p>
        </div>
      ) : candidates.length > 0 ? (
        <div className="glass rounded-xl p-4 border border-yellow-400/30 space-y-3">
          <div className="flex items-center gap-2 text-yellow-400 text-sm font-semibold"><AlertTriangle className="w-4 h-4" /> Untrusted BSSID candidates</div>
          {candidates.map(candidate => (
            <div key={candidate.ssid + candidate.bssid} className="bg-secondary/40 rounded-lg p-3 flex flex-wrap items-center justify-between gap-3">
              <div className="min-w-0">
                <div className="text-xs font-semibold text-foreground">{candidate.ssid}</div>
                <div className="text-xs font-mono text-muted-foreground mt-0.5">{candidate.bssid}</div>
                <div className="text-xs text-muted-foreground mt-1">
                  {candidate.band || 'Band unknown'} · {candidate.channel == null ? 'Channel unknown' : 'Ch ' + candidate.channel}
                  {candidate.rssi === null ? '' : ' · ' + candidate.rssi + ' dBm'}
                </div>
                <div className="text-[11px] text-muted-foreground mt-1">{candidate.reason}</div>
              </div>
              {canManage && <button type="button" disabled={mutating} onClick={() => void trustObservedCandidate(candidate)}
                className="px-3 py-2 rounded-lg bg-primary/10 border border-primary/30 text-primary text-xs hover:bg-primary/20 disabled:opacity-50">Trust this BSSID</button>}
            </div>
          ))}
        </div>
      ) : trustedSsidCount > 0 && !unavailable && !error ? (
        <div className="glass rounded-xl p-4 border border-green-400/30 flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-green-400" />
          <span className="text-sm text-green-400">No untrusted BSSIDs observed for configured trusted SSIDs in this scan.</span>
        </div>
      ) : null}

      {siteId && canManage && (
        <div className="glass rounded-xl p-4 space-y-3">
          <div className="text-sm font-semibold text-foreground">Add trusted access point to {siteId}</div>
          <div className="grid grid-cols-1 md:grid-cols-[minmax(0,1fr),minmax(0,1fr),auto] gap-2">
            <input value={newSsid} onChange={event => setNewSsid(event.target.value)} maxLength={32}
              aria-label="Trusted SSID" placeholder="Exact SSID" className="min-w-0 px-3 py-2 rounded-lg bg-background/50 border border-border text-sm text-foreground placeholder:text-muted-foreground" />
            <input value={newBssid} onChange={event => setNewBssid(event.target.value)} maxLength={17}
              aria-label="Trusted BSSID" placeholder="BSSID (AA:BB:CC:DD:EE:FF)" className="min-w-0 px-3 py-2 rounded-lg bg-background/50 border border-border text-sm text-foreground placeholder:text-muted-foreground font-mono" />
            <button type="button" onClick={() => void addTrusted()} disabled={mutating || !newSsid.trim() || !newBssid.trim()}
              className="flex items-center justify-center gap-2 px-3 py-2 rounded-lg bg-primary/10 border border-primary/30 text-primary hover:bg-primary/20 transition-all disabled:opacity-50">
              <Plus className="w-4 h-4" /> Add
            </button>
          </div>
          {formError && <div role="alert" className="text-xs text-red-400">{formError}</div>}
          <div className="text-xs text-muted-foreground">Changes are shared with users assigned to this site and recorded in the tamper-evident security audit ledger.</div>
        </div>
      )}

      {siteId && trustedSsidCount > 0 && Object.entries(trusted).map(([ssid, bssids]) => (
        <div key={ssid} className="glass rounded-xl p-4 space-y-2">
          <div className="text-sm font-medium text-foreground flex items-center gap-2"><ShieldCheck className="w-3.5 h-3.5 text-green-400" /> {ssid}</div>
          {bssids.map(bssid => (
            <div key={bssid} className="flex items-center justify-between text-xs font-mono text-muted-foreground gap-2">
              <span>{bssid}</span>
              {canManage && <button type="button" disabled={mutating} aria-label={'Remove trusted BSSID ' + bssid}
                onClick={() => void removeTrusted(ssid, bssid)} className="text-red-400 hover:text-red-300 disabled:opacity-50"><Trash2 className="w-3 h-3" /></button>}
            </div>
          ))}
        </div>
      ))}
      {notice && !error && <div role="status" className="text-xs text-muted-foreground">{notice}</div>}
      {siteId && !canManage && !loadingBaseline && !error && (
        <div className="text-xs text-muted-foreground">Read-only baseline access. A site administrator or network administrator must make changes.</div>
      )}
    </motion.div>
  );
}
