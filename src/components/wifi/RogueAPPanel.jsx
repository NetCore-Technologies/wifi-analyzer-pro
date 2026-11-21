import React, { useEffect, useMemo, useState } from 'react';
import { motion } from 'framer-motion';
import { ShieldAlert, ShieldCheck, Plus, Trash2, AlertTriangle, Info } from 'lucide-react';
import {
  addTrustedBssid,
  assessTrustedAccessPoints,
  removeTrustedBssid,
  sanitizeTrustedMap,
} from '../../lib/trustedAccessPoints.js';

const STORAGE_KEY = 'wifi-analyzer-pro.trusted-bssids.v1';

function loadTrustedBaseline() {
  try {
    const stored = window.localStorage.getItem(STORAGE_KEY);
    return stored ? sanitizeTrustedMap(JSON.parse(stored)) : {};
  } catch {
    return {};
  }
}

export default function RogueAPPanel({ networks = [] }) {
  const [trusted, setTrusted] = useState(loadTrustedBaseline);
  const [newSsid, setNewSsid] = useState('');
  const [newBssid, setNewBssid] = useState('');
  const [formError, setFormError] = useState('');
  const [savedNotice, setSavedNotice] = useState(false);

  useEffect(() => {
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(trusted));
      setSavedNotice(true);
    } catch {
      setSavedNotice(false);
    }
  }, [trusted]);

  const candidates = useMemo(
    () => assessTrustedAccessPoints(networks, trusted),
    [networks, trusted],
  );
  const trustedSsidCount = Object.keys(trusted).length;
  const trustedBssidCount = Object.values(trusted).reduce((total, items) => total + items.length, 0);

  function addTrusted() {
    setFormError('');
    try {
      setTrusted(current => addTrustedBssid(current, newSsid, newBssid));
      setNewSsid('');
      setNewBssid('');
    } catch (error) {
      setFormError(error.message || 'Unable to add this trusted access point.');
    }
  }

  function trustObservedCandidate(candidate) {
    setFormError('');
    try {
      setTrusted(current => addTrustedBssid(current, candidate.ssid, candidate.bssid));
    } catch (error) {
      setFormError(error.message || 'Unable to trust this observed BSSID.');
    }
  }

  function removeTrusted(ssid, bssid) {
    setTrusted(current => removeTrustedBssid(current, ssid, bssid));
  }

  return (
    <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="space-y-4">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="glass rounded-xl p-3 text-center">
          <div className="text-2xl font-bold font-mono text-primary">{trustedSsidCount}</div>
          <div className="text-xs text-muted-foreground mt-0.5">Trusted SSIDs</div>
        </div>
        <div className="glass rounded-xl p-3 text-center">
          <div className="text-2xl font-bold font-mono text-primary">{trustedBssidCount}</div>
          <div className="text-xs text-muted-foreground mt-0.5">Trusted BSSIDs</div>
        </div>
        <div className="glass rounded-xl p-3 text-center">
          <div className={`text-2xl font-bold font-mono ${candidates.length ? 'text-yellow-400' : trustedSsidCount ? 'text-green-400' : 'text-muted-foreground'}`}>
            {trustedSsidCount ? candidates.length : '—'}
          </div>
          <div className="text-xs text-muted-foreground mt-0.5">Untrusted candidates</div>
        </div>
        <div className="glass rounded-xl p-3 text-center">
          <div className="text-2xl font-bold font-mono text-foreground">{(Array.isArray(networks) ? networks : []).length}</div>
          <div className="text-xs text-muted-foreground mt-0.5">Scanned BSS records</div>
        </div>
      </div>

      <div className="glass rounded-xl p-4 flex items-start gap-2">
        <Info className="w-4 h-4 text-primary mt-0.5 flex-shrink-0" />
        <p className="text-xs text-muted-foreground">
          An untrusted BSSID advertising a trusted SSID is a review candidate, not proof of an evil twin. Legitimate mesh systems, multi-AP WLANs, replacement APs and controller-managed BSSID rotation can produce the same observation. Confirm against your controller inventory before escalating.
        </p>
      </div>

      {trustedSsidCount === 0 ? (
        <div className="glass rounded-xl p-5 text-center space-y-2">
          <ShieldAlert className="w-6 h-6 text-muted-foreground mx-auto" />
          <div className="text-sm font-semibold text-foreground">No trusted AP baseline configured</div>
          <p className="text-xs text-muted-foreground">Add the approved SSID/BSSID pairs for networks you manage. Untrusted candidates can only be assessed for SSIDs with a saved baseline.</p>
        </div>
      ) : candidates.length > 0 ? (
        <div className="glass rounded-xl p-4 border border-yellow-400/30 space-y-3">
          <div className="flex items-center gap-2 text-yellow-400 text-sm font-semibold">
            <AlertTriangle className="w-4 h-4" /> Untrusted BSSID candidates
          </div>
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
              <button type="button" onClick={() => trustObservedCandidate(candidate)}
                className="px-3 py-2 rounded-lg bg-primary/10 border border-primary/30 text-primary text-xs hover:bg-primary/20">
                Trust this BSSID
              </button>
            </div>
          ))}
        </div>
      ) : (
        <div className="glass rounded-xl p-4 border border-green-400/30 flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-green-400" />
          <span className="text-sm text-green-400">No untrusted BSSIDs observed for configured trusted SSIDs in this scan.</span>
        </div>
      )}

      <div className="glass rounded-xl p-4 space-y-3">
        <div className="text-sm font-semibold text-foreground">Add trusted access point</div>
        <div className="grid grid-cols-1 md:grid-cols-[minmax(0,1fr),minmax(0,1fr),auto] gap-2">
          <input value={newSsid} onChange={event => setNewSsid(event.target.value)} maxLength={32}
            aria-label="Trusted SSID" placeholder="Exact SSID" className="min-w-0 px-3 py-2 rounded-lg bg-background/50 border border-border text-sm text-foreground placeholder:text-muted-foreground" />
          <input value={newBssid} onChange={event => setNewBssid(event.target.value)} maxLength={17}
            aria-label="Trusted BSSID" placeholder="BSSID (AA:BB:CC:DD:EE:FF)" className="min-w-0 px-3 py-2 rounded-lg bg-background/50 border border-border text-sm text-foreground placeholder:text-muted-foreground font-mono" />
          <button type="button" onClick={addTrusted} className="flex items-center justify-center gap-2 px-3 py-2 rounded-lg bg-primary/10 border border-primary/30 text-primary hover:bg-primary/20 transition-all">
            <Plus className="w-4 h-4" /> Add
          </button>
        </div>
        {formError && <div role="alert" className="text-xs text-red-400">{formError}</div>}
        <div className="flex items-center justify-between gap-2 text-xs text-muted-foreground">
          <span>Exact SSID and a valid BSSID are required. Baseline is stored in this browser profile only.</span>
          {savedNotice && <span>Saved locally</span>}
        </div>
      </div>

      {Object.entries(trusted).map(([ssid, bssids]) => (
        <div key={ssid} className="glass rounded-xl p-4 space-y-2">
          <div className="text-sm font-medium text-foreground flex items-center gap-2">
            <ShieldCheck className="w-3.5 h-3.5 text-green-400" /> {ssid}
          </div>
          {bssids.map(bssid => (
            <div key={bssid} className="flex items-center justify-between text-xs font-mono text-muted-foreground gap-2">
              <span>{bssid}</span>
              <button type="button" aria-label={'Remove trusted BSSID ' + bssid} onClick={() => removeTrusted(ssid, bssid)} className="text-red-400 hover:text-red-300">
                <Trash2 className="w-3 h-3" />
              </button>
            </div>
          ))}
        </div>
      ))}
    </motion.div>
  );
}
