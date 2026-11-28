import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity, AlertCircle, CheckCircle2, Copy, KeyRound, RefreshCw,
  RotateCcw, Server, ShieldCheck, Trash2,
} from "lucide-react";
import { apiFetch } from "../lib/api.js";

const API_BASE = `${window.location.protocol}//${window.location.hostname}:199`;
const DEFAULT_CAPABILITIES = [
  "system.board",
  "system.health",
  "network.interfaces",
  "network.routes",
  "wireless.radios",
  "wireless.associations",
  "inventory.snapshot",
];

const COLORS = {
  card: "#111624",
  cardAlt: "#182235",
  border: "#29374d",
  text: "#f1f5fb",
  secondary: "#a8b6ca",
  muted: "#71829a",
  cyan: "#ff8359",
  green: "#56d6ae",
  yellow: "#f2c36b",
  red: "#ff7185",
  purple: "#a78bfa",
};

async function requestJSON(path, options = {}) {
  const response = await apiFetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(options.headers || {}),
    },
  });
  let data = {};
  try {
    data = await response.json();
  } catch {
    data = {};
  }
  if (!response.ok) {
    throw new Error(typeof data.error === "string" ? data.error : `Request failed (HTTP ${response.status})`);
  }
  return data;
}

function Panel({ title, subtitle, action, children, style }) {
  return (
    <section style={{ background: COLORS.card, border: `1px solid ${COLORS.border}`, borderRadius: 12, minWidth: 0, ...style }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, padding: "14px 16px", borderBottom: `1px solid ${COLORS.border}` }}>
        <div>
          <div style={{ color: COLORS.text, fontSize: 13, fontWeight: 700 }}>{title}</div>
          {subtitle && <div style={{ color: COLORS.muted, fontSize: 11, marginTop: 3 }}>{subtitle}</div>}
        </div>
        {action}
      </div>
      <div style={{ padding: 16 }}>{children}</div>
    </section>
  );
}

function StatusPill({ value }) {
  const status = String(value || "unknown").toLowerCase();
  const good = ["healthy", "active", "online"].includes(status);
  const bad = ["unhealthy", "revoked", "expired"].includes(status);
  const color = good ? COLORS.green : bad ? COLORS.red : status === "degraded" || status === "stale" ? COLORS.yellow : COLORS.muted;
  return <span style={{ display: "inline-flex", alignItems: "center", gap: 5, padding: "3px 7px", borderRadius: 20, fontSize: 10, fontWeight: 700, color, background: `${color}18`, border: `1px solid ${color}44`, whiteSpace: "nowrap" }}>{status}</span>;
}

function Metric({ label, value, note }) {
  return (
    <div style={{ background: COLORS.cardAlt, border: `1px solid ${COLORS.border}`, borderRadius: 9, padding: "11px 13px", minWidth: 0 }}>
      <div style={{ color: COLORS.muted, fontSize: 10, textTransform: "uppercase", letterSpacing: .7, fontWeight: 700 }}>{label}</div>
      <div style={{ color: COLORS.cyan, fontSize: 21, fontWeight: 750, marginTop: 5, overflowWrap: "anywhere" }}>{value}</div>
      {note && <div style={{ color: COLORS.muted, fontSize: 10, marginTop: 4 }}>{note}</div>}
    </div>
  );
}

function timestamp(value) {
  if (!value) return "Never";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleString();
}

function bytes(value) {
  if (!Number.isFinite(Number(value))) return "—";
  const n = Number(value);
  if (n < 1024) return `${n} B`;
  const units = ["KiB", "MiB", "GiB", "TiB"];
  let size = n;
  let unit = -1;
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(size >= 100 ? 0 : 1)} ${units[unit]}`;
}


export default function RouterAgentConsole() {
  const [health, setHealth] = useState(null);
  const [credentials, setCredentials] = useState([]);
  const [snapshots, setSnapshots] = useState([]);
  const [negotiations, setNegotiations] = useState([]);
  const [adapters, setAdapters] = useState([]);
  const [selectedAgentId, setSelectedAgentId] = useState("");
  const [selectedSnapshot, setSelectedSnapshot] = useState(null);
  const [selectedDiff, setSelectedDiff] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [agentId, setAgentId] = useState("");
  const [siteId, setSiteId] = useState("");
  const [knownSiteIds, setKnownSiteIds] = useState([]);
  const [agentVersion, setAgentVersion] = useState("1.0.0");
  const [ttlDays, setTtlDays] = useState(90);
  const [selectedCapabilities, setSelectedCapabilities] = useState(DEFAULT_CAPABILITIES);
  const [issuedCredential, setIssuedCredential] = useState(null);

  const load = useCallback(async (quiet = false) => {
    if (quiet) setRefreshing(true);
    else setLoading(true);
    setError("");
    try {
      const [healthData, credentialData, snapshotData, negotiationData, adapterData, siteData] = await Promise.all([
        requestJSON("/api/agents/health"),
        requestJSON("/api/agents/credentials"),
        requestJSON("/api/agents/snapshots"),
        requestJSON("/api/agents/negotiations"),
        requestJSON("/api/adapters"),
        requestJSON("/api/sites"),
      ]);
      const healthReport = healthData?.result || healthData;
      setHealth(healthReport);
      setCredentials(Array.isArray(credentialData?.credentials) ? credentialData.credentials : []);
      setSnapshots(Array.isArray(snapshotData?.snapshots) ? snapshotData.snapshots : []);
      setNegotiations(Array.isArray(negotiationData?.negotiations) ? negotiationData.negotiations : []);
      setAdapters(Array.isArray(adapterData?.adapters) ? adapterData.adapters : []);
      setKnownSiteIds(Array.isArray(siteData?.site_ids) ? siteData.site_ids : []);
      setSelectedAgentId((current) => {
        if (current) return current;
        const first = healthReport?.agents?.[0]?.agent_id
          || credentialData?.credentials?.[0]?.agent_id
          || snapshotData?.snapshots?.[0]?.agent_id;
        return first || "";
      });
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Could not load router-agent data");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    load();
    const timer = window.setInterval(() => load(true), 30000);
    return () => window.clearInterval(timer);
  }, [load]);

  useEffect(() => {
    if (!selectedAgentId) {
      setSelectedSnapshot(null);
      setSelectedDiff(null);
      return undefined;
    }
    let disposed = false;
    const encodedId = encodeURIComponent(selectedAgentId);
    Promise.all([
      requestJSON(`/api/agents/snapshots/${encodedId}`).catch(() => null),
      requestJSON(`/api/agents/snapshots/${encodedId}/diff`).catch(() => null),
    ]).then(([snapshotData, diffData]) => {
      if (disposed) return;
      setSelectedSnapshot(snapshotData?.snapshot || null);
      setSelectedDiff(diffData?.result || null);
    });
    return () => { disposed = true; };
  }, [selectedAgentId, snapshots]);

  const agents = useMemo(() => {
    const byId = new Map();
    for (const agent of health?.agents || []) byId.set(agent.agent_id, { ...agent });
    for (const credential of credentials) {
      byId.set(credential.agent_id, { ...(byId.get(credential.agent_id) || {}), credential });
    }
    for (const snapshot of snapshots) {
      byId.set(snapshot.agent_id, { ...(byId.get(snapshot.agent_id) || {}), latest_snapshot: snapshot });
    }
    for (const negotiation of negotiations) {
      byId.set(negotiation.agent_id, { ...(byId.get(negotiation.agent_id) || {}), latest_negotiation: negotiation });
    }
    return [...byId.values()].sort((a, b) => String(a.agent_id).localeCompare(String(b.agent_id)));
  }, [health, credentials, snapshots, negotiations]);

  const openwrtManifest = adapters.find((adapter) => adapter.adapter_id === "openwrt");
  const supportedCapabilities = openwrtManifest?.capabilities || DEFAULT_CAPABILITIES;
  const summary = health?.summary || {};
  const statusCounts = summary.status_counts || {};

  const toggleCapability = (capability) => {
    setSelectedCapabilities((current) => current.includes(capability)
      ? current.filter((item) => item !== capability)
      : [...current, capability]);
  };

  const showIssuedToken = (credential, action) => {
    if (!credential?.token) return;
    setIssuedCredential({
      agent_id: credential.agent_id,
      action,
      token: credential.token,
      expires_at: credential.expires_at,
    });
    setNotice(`${action} complete for ${credential.agent_id}. Copy the token now; it will not be shown again.`);
  };

  const enroll = async (event) => {
    event.preventDefault();
    setSaving(true);
    setError("");
    setNotice("");
    setIssuedCredential(null);
    try {
      const capabilities = [...new Set(selectedCapabilities)];
      if (!agentId.trim()) throw new Error("Enter an agent ID.");
      if (!siteId.trim()) throw new Error("Assign this router agent to a site.");
      if (!capabilities.includes("system.board") || !capabilities.includes("inventory.snapshot")) {
        throw new Error("Enrolment requires system.board and inventory.snapshot.");
      }
      const response = await requestJSON("/api/agents/enroll", {
        method: "POST",
        body: JSON.stringify({
          agent_id: agentId.trim(),
          site_id: siteId.trim(),
          adapter_id: "openwrt",
          agent_version: agentVersion,
          advertised_capabilities: capabilities,
          requested_capabilities: capabilities,
          requested_permissions: ["read"],
          ttl_days: Number(ttlDays),
        }),
      });
      showIssuedToken(response.credential, "Enrolment");
      setAgentId("");
      setSiteId("");
      await load(true);
      setSelectedAgentId(response.credential?.agent_id || "");
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Agent enrolment failed");
    } finally {
      setSaving(false);
    }
  };

  const rotate = async (id) => {
    if (!window.confirm(`Rotate the credential for ${id}? The current token stops working immediately.`)) return;
    setSaving(true);
    setError("");
    setNotice("");
    setIssuedCredential(null);
    try {
      const response = await requestJSON(`/api/agents/${encodeURIComponent(id)}/credentials/rotate`, {
        method: "POST", body: JSON.stringify({ ttl_days: Number(ttlDays) }),
      });
      showIssuedToken(response.credential, "Credential rotation");
      await load(true);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Credential rotation failed");
    } finally {
      setSaving(false);
    }
  };

  const revoke = async (id) => {
    if (!window.confirm(`Revoke the credential for ${id}? This agent will stop authenticating immediately.`)) return;
    setSaving(true);
    setError("");
    setNotice("");
    setIssuedCredential(null);
    try {
      await requestJSON(`/api/agents/${encodeURIComponent(id)}/credentials/revoke`, {
        method: "POST", body: JSON.stringify({}),
      });
      setNotice(`Credential revoked for ${id}.`);
      await load(true);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Credential revocation failed");
    } finally {
      setSaving(false);
    }
  };

  const assignSite = async (id) => {
    if (!id || !siteId.trim() || saving) return;
    setSaving(true);
    setError("");
    setNotice("");
    try {
      const response = await requestJSON("/api/agents/" + encodeURIComponent(id) + "/site", {
        method: "POST",
        body: JSON.stringify({ site_id: siteId.trim() }),
      });
      setNotice("Assigned " + id + " to " + response.assignment.site_id + ".");
      await load(true);
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Could not update the site assignment.");
    } finally {
      setSaving(false);
    }
  };

  const copyToken = async () => {
    if (!issuedCredential?.token) return;
    try {
      await navigator.clipboard.writeText(issuedCredential.token);
      setNotice("The one-time agent token was copied to the clipboard.");
    } catch {
      setError("Clipboard access was blocked. Select and copy the token from the field.");
    }
  };

  const activeAgent = agents.find((agent) => agent.agent_id === selectedAgentId);
  const healthReport = selectedSnapshot?.snapshot?.system_health;
  const diffSummary = selectedDiff?.summary;

  return (
    <div style={{ color: COLORS.text, display: "flex", flexDirection: "column", gap: 16 }}>
      <style>{`
        .agent-console-grid { display:grid; grid-template-columns:minmax(260px, .9fr) minmax(0, 1.5fr); gap:14px; align-items:start; }
        .agent-console-capabilities { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:7px 12px; }
        .agent-console-button { border:1px solid ${COLORS.border}; background:${COLORS.cardAlt}; color:${COLORS.text}; padding:7px 10px; border-radius:7px; font-size:11px; cursor:pointer; display:inline-flex; align-items:center; justify-content:center; gap:6px; }
        .agent-console-button:disabled { opacity:.5; cursor:not-allowed; }
        .agent-console-input { width:100%; min-width:0; box-sizing:border-box; background:${COLORS.cardAlt}; border:1px solid ${COLORS.border}; color:${COLORS.text}; border-radius:7px; padding:9px 10px; font-size:12px; outline:none; }
        .agent-console-input:focus { border-color:${COLORS.cyan}; }
        @media(max-width:850px) { .agent-console-grid { grid-template-columns:1fr; } }
        @media(max-width:520px) { .agent-console-capabilities { grid-template-columns:1fr; } }
      `}</style>

      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 10 }}>
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: 9, fontWeight: 800, fontSize: 16 }}>
            <Server size={18} color={COLORS.cyan} /> Router Agent Console
          </div>
          <div style={{ color: COLORS.muted, fontSize: 11, marginTop: 4 }}>
            OpenWrt agent health, scoped credentials, inventory history and drift
          </div>
        </div>
        <button className="agent-console-button" onClick={() => load(true)} disabled={refreshing || loading}>
          <RefreshCw size={12} style={{ animation: refreshing ? "spin .7s linear infinite" : "none" }} />
          {refreshing ? "Refreshing" : "Refresh"}
        </button>
      </div>

      {error && <div role="alert" style={{ padding: "10px 12px", borderRadius: 8, background: "#ff718518", border: "1px solid #ff718555", color: "#fca5a5", fontSize: 12, display: "flex", alignItems: "center", gap: 8 }}><AlertCircle size={14} />{error}</div>}
      {notice && <div role="status" style={{ padding: "10px 12px", borderRadius: 8, background: "#56d6ae14", border: "1px solid #56d6ae44", color: "#86efac", fontSize: 12, display: "flex", alignItems: "center", gap: 8 }}><CheckCircle2 size={14} />{notice}</div>}

      {issuedCredential && (
        <Panel title="One-time agent credential" subtitle={`${issuedCredential.action} · ${issuedCredential.agent_id} · expires ${timestamp(issuedCredential.expires_at)}`}>
          <div style={{ display: "flex", gap: 8, alignItems: "stretch" }}>
            <input className="agent-console-input" readOnly value={issuedCredential.token} aria-label="One-time agent token" />
            <button className="agent-console-button" onClick={copyToken}><Copy size={13} />Copy token</button>
          </div>
          <div style={{ color: COLORS.yellow, fontSize: 10, marginTop: 8 }}>This secret is shown only in this page session. Save it directly into the router's protected agent configuration. It is not stored in browser storage.</div>
        </Panel>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "repeat(4,minmax(0,1fr))", gap: 10 }}>
        <Metric label="Registered agents" value={summary.agent_count ?? health?.agents?.length ?? 0} note="Known agent identities" />
        <Metric label="Healthy" value={statusCounts.healthy ?? "—"} note="Latest heartbeat status" />
        <Metric label="Stale" value={statusCounts.stale ?? "—"} note="No recent heartbeat" />
        <Metric label="Stored snapshots" value={snapshots.length} note="Latest per agent" />
      </div>

      <div className="agent-console-grid">
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          <Panel title="Agents" subtitle="Select an agent to inspect its most recent inventory">
            {loading && !agents.length ? <div style={{ color: COLORS.muted, fontSize: 12 }}>Loading agent registry…</div>
              : !agents.length ? <div style={{ color: COLORS.muted, fontSize: 12 }}>No router agents enrolled yet.</div>
              : <div style={{ display: "flex", flexDirection: "column", gap: 7 }}>
                {agents.map((agent) => {
                  const status = agent.health_status || agent.status || agent.credential?.status || "unknown";
                  const selected = selectedAgentId === agent.agent_id;
                  return (
                    <button key={agent.agent_id} onClick={() => setSelectedAgentId(agent.agent_id)}
                      style={{ width: "100%", textAlign: "left", cursor: "pointer", background: selected ? "#ff835918" : COLORS.cardAlt, border: `1px solid ${selected ? COLORS.cyan + "77" : COLORS.border}`, borderRadius: 8, padding: "10px 11px", color: COLORS.text }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8 }}>
                        <span style={{ fontWeight: 700, fontSize: 12 }}>{agent.agent_id}</span>
                        <StatusPill value={status} />
                      </div>
                      <div style={{ color: COLORS.muted, fontSize: 10, marginTop: 5 }}>
                        {agent.adapter_id || agent.credential?.adapter_id || "unknown adapter"} · v{agent.agent_version || agent.credential?.agent_version || "—"}
                      </div>
                      <div style={{ color: COLORS.muted, fontSize: 10, marginTop: 3 }}>Last seen: {timestamp(agent.last_seen_at)}</div>
                    </button>
                  );
                })}
              </div>}
          </Panel>

          <Panel title="Enrol an OpenWrt agent" subtitle="Create a read-only credential with an explicit capability scope">
            <form onSubmit={enroll} style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              <label style={{ color: COLORS.secondary, fontSize: 10, display: "flex", flexDirection: "column", gap: 5 }}>
                Agent ID
                <input className="agent-console-input" value={agentId} onChange={(event) => setAgentId(event.target.value)} placeholder="openwrt-home" maxLength={64} required />
              </label>
              <label style={{ color: COLORS.secondary, fontSize: 10, display: "flex", flexDirection: "column", gap: 5 }}>
                Assigned site ID
                <input className="agent-console-input" list="wpa-known-sites-enrol" value={siteId} onChange={(event) => setSiteId(event.target.value)} placeholder="e.g. head-office" maxLength={64} pattern="[A-Za-z0-9][A-Za-z0-9._:-]{0,63}" required />
                <datalist id="wpa-known-sites-enrol">{knownSiteIds.map(site => <option key={site} value={site}/>)}</datalist>
                <span style={{ color: COLORS.muted }}>Health, credentials and inventory from this agent are tied to this site.</span>
              </label>
              <div style={{ display: "grid", gridTemplateColumns: "1fr 100px", gap: 8 }}>
                <label style={{ color: COLORS.secondary, fontSize: 10, display: "flex", flexDirection: "column", gap: 5 }}>
                  Agent version
                  <input className="agent-console-input" value={agentVersion} onChange={(event) => setAgentVersion(event.target.value)} required />
                </label>
                <label style={{ color: COLORS.secondary, fontSize: 10, display: "flex", flexDirection: "column", gap: 5 }}>
                  Token days
                  <select className="agent-console-input" value={ttlDays} onChange={(event) => setTtlDays(Number(event.target.value))}>
                    {[30, 90, 180, 365].map((days) => <option key={days} value={days}>{days}</option>)}
                  </select>
                </label>
              </div>
              <div style={{ color: COLORS.secondary, fontSize: 10, fontWeight: 700 }}>READ-ONLY CAPABILITIES</div>
              <div className="agent-console-capabilities">
                {supportedCapabilities.map((capability) => (
                  <label key={capability} style={{ display: "flex", alignItems: "center", gap: 7, color: COLORS.secondary, fontSize: 10 }}>
                    <input type="checkbox" checked={selectedCapabilities.includes(capability)} onChange={() => toggleCapability(capability)} />
                    {capability}
                  </label>
                ))}
              </div>
              <button className="agent-console-button" type="submit" disabled={saving || !selectedCapabilities.includes("system.board") || !selectedCapabilities.includes("inventory.snapshot")} style={{ background: "#ff83591b", borderColor: "#ff835966", color: COLORS.cyan, marginTop: 3 }}>
                <KeyRound size={13} />{saving ? "Enrolling…" : "Enrol agent"}
              </button>
              <div style={{ color: COLORS.muted, fontSize: 10 }}>Only read permission is available. The token is returned once and is never listed again.</div>
            </form>
          </Panel>
        </div>

        <div style={{ display: "flex", flexDirection: "column", gap: 14, minWidth: 0 }}>
          <Panel title={selectedAgentId ? `Agent details · ${selectedAgentId}` : "Agent details"} subtitle="Credential state and negotiated permissions"
            action={activeAgent?.credential && activeAgent.credential.status !== "revoked" ? <div style={{ display: "flex", gap: 6 }}>
              <button className="agent-console-button" disabled={saving} onClick={() => rotate(selectedAgentId)}><RotateCcw size={11} />Rotate</button>
              <button className="agent-console-button" disabled={saving} onClick={() => revoke(selectedAgentId)} style={{ color: "#fca5a5" }}><Trash2 size={11} />Revoke</button>
            </div> : null}>
            {!activeAgent ? <div style={{ color: COLORS.muted, fontSize: 12 }}>Choose an agent from the list.</div> : <>
              <div style={{ display: "flex", flexWrap: "wrap", alignItems: "center", gap: 8, marginBottom: 10 }}>
                <StatusPill value={activeAgent.health_status || activeAgent.status || "unknown"} />
                <StatusPill value={activeAgent.credential?.status || "no credential"} />
                <span style={{ color: COLORS.muted, fontSize: 10 }}>Last heartbeat: {timestamp(activeAgent.last_seen_at)}</span>
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                {(activeAgent.capabilities || activeAgent.credential?.allowed_capabilities || []).map((capability) => (
                  <span key={capability} style={{ padding: "4px 7px", borderRadius: 6, background: "#ff835912", border: "1px solid #ff835933", color: COLORS.cyan, fontSize: 10 }}>{capability}</span>
                ))}
              </div>
              {activeAgent.credential && <div style={{ color: COLORS.muted, fontSize: 10, marginTop: 11 }}>
                Credential expires {timestamp(activeAgent.credential.expires_at)} · created {timestamp(activeAgent.credential.created_at)}
              </div>}
              {activeAgent.credential && <div style={{ display: "grid", gap: 7, marginTop: 12, paddingTop: 10, borderTop: "1px solid " + COLORS.border }}>
                <div style={{ color: COLORS.secondary, fontSize: 10 }}>Assigned site: <strong style={{ color: COLORS.cyan }}>{activeAgent.credential.site_id || "Unassigned"}</strong></div>
                <div style={{ display: "grid", gridTemplateColumns: "minmax(120px,1fr) auto", gap: 7 }}>
                  <input className="agent-console-input" list="wpa-known-sites-assign" value={siteId} onChange={(event) => setSiteId(event.target.value)} placeholder="New site ID" maxLength={64}/>
                  <button className="agent-console-button" disabled={saving || !siteId.trim()} onClick={() => assignSite(selectedAgentId)}>Assign site</button>
                </div>
                <datalist id="wpa-known-sites-assign">{knownSiteIds.map(site => <option key={site} value={site}/>)}</datalist>
              </div>}
            </>}
          </Panel>

          <Panel title="Latest system health" subtitle="Only present when system.health was granted and collected">
            {!healthReport ? <div style={{ color: COLORS.muted, fontSize: 12 }}>No system health sample is available for this agent.</div> : <>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(4,minmax(0,1fr))", gap: 8 }}>
                <Metric label="Uptime" value={`${Math.floor(healthReport.uptime_seconds / 3600)}h ${Math.floor((healthReport.uptime_seconds % 3600) / 60)}m`} />
                <Metric label="Load · 1m" value={healthReport.load_average?.["1m"] ?? "—"} />
                <Metric label="Load · 5m" value={healthReport.load_average?.["5m"] ?? "—"} />
                <Metric label="Load · 15m" value={healthReport.load_average?.["15m"] ?? "—"} />
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(2,minmax(0,1fr))", gap: 8, marginTop: 9 }}>
                <div style={{ background: COLORS.cardAlt, border: `1px solid ${COLORS.border}`, borderRadius: 8, padding: 11 }}>
                  <div style={{ color: COLORS.secondary, fontSize: 11, fontWeight: 700 }}>Memory (bytes)</div>
                  <div style={{ color: COLORS.text, fontSize: 11, marginTop: 7 }}>Total: {bytes(healthReport.memory_bytes?.total)}</div>
                  <div style={{ color: COLORS.text, fontSize: 11, marginTop: 4 }}>Free: {bytes(healthReport.memory_bytes?.free)}</div>
                  <div style={{ color: COLORS.text, fontSize: 11, marginTop: 4 }}>Available: {bytes(healthReport.memory_bytes?.available)}</div>
                  <div style={{ color: COLORS.muted, fontSize: 9, marginTop: 6 }}>No estimated memory-use percentage is inferred.</div>
                </div>
                <div style={{ background: COLORS.cardAlt, border: `1px solid ${COLORS.border}`, borderRadius: 8, padding: 11 }}>
                  <div style={{ color: COLORS.secondary, fontSize: 11, fontWeight: 700 }}>Swap (bytes)</div>
                  <div style={{ color: COLORS.text, fontSize: 11, marginTop: 7 }}>Total: {bytes(healthReport.swap_bytes?.total)}</div>
                  <div style={{ color: COLORS.text, fontSize: 11, marginTop: 4 }}>Free: {bytes(healthReport.swap_bytes?.free)}</div>
                </div>
              </div>
            </>}
          </Panel>

          <Panel title="Latest inventory and drift" subtitle="Most recent retained OpenWrt snapshot and comparison with its predecessor">
            {!selectedSnapshot ? <div style={{ color: COLORS.muted, fontSize: 12 }}>No snapshot has been received for the selected agent.</div> : <>
              <div style={{ color: COLORS.muted, fontSize: 10, marginBottom: 9 }}>Captured {timestamp(selectedSnapshot.captured_at)} · received {timestamp(selectedSnapshot.received_at)}</div>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(4,minmax(0,1fr))", gap: 8 }}>
                <Metric label="Interfaces" value={selectedSnapshot.snapshot?.summary?.interface_count ?? 0} />
                <Metric label="Radios" value={selectedSnapshot.snapshot?.summary?.wireless_radio_count ?? 0} />
                <Metric label="Clients" value={selectedSnapshot.snapshot?.summary?.association_count ?? 0} />
                <Metric label="Routes" value={selectedSnapshot.snapshot?.summary?.route_count ?? 0} />
              </div>
              {diffSummary && <div style={{ marginTop: 11, padding: 11, background: COLORS.cardAlt, border: `1px solid ${COLORS.border}`, borderRadius: 8 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 7, color: COLORS.secondary, fontSize: 11, fontWeight: 700 }}><Activity size={12} />Snapshot drift · {selectedDiff.status}</div>
                <div style={{ display: "flex", gap: 12, flexWrap: "wrap", marginTop: 8, color: COLORS.text, fontSize: 10 }}>
                  <span>Changes: <b style={{ color: COLORS.cyan }}>{diffSummary.total_changes ?? 0}</b></span>
                  <span>Interfaces: {diffSummary.interface_added ?? 0}+ / {diffSummary.interface_removed ?? 0}− / {diffSummary.interface_changed ?? 0}Δ</span>
                  <span>Radios: {diffSummary.radio_added ?? 0}+ / {diffSummary.radio_removed ?? 0}− / {diffSummary.radio_changed ?? 0}Δ</span>
                  <span>Clients: {diffSummary.association_added ?? 0}+ / {diffSummary.association_removed ?? 0}−</span>
                  <span>Routes: {diffSummary.route_added ?? 0}+ / {diffSummary.route_removed ?? 0}− / {diffSummary.route_changed ?? 0}Δ</span>
                </div>
              </div>}
            </>}
          </Panel>
        </div>
      </div>

      <Panel title="Credential inventory" subtitle="Metadata only · token values and hashes are never returned by the server">
        {!credentials.length ? <div style={{ color: COLORS.muted, fontSize: 12 }}>No agent credentials have been issued.</div> : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
              <thead><tr style={{ color: COLORS.muted, textAlign: "left" }}>
                {["Agent","Adapter","Scope","Expires","State"].map((label) => <th key={label} style={{ padding: "7px 8px", borderBottom: `1px solid ${COLORS.border}` }}>{label}</th>)}
              </tr></thead>
              <tbody>
                {credentials.map((credential) => <tr key={credential.agent_id} style={{ borderBottom: `1px solid ${COLORS.border}` }}>
                  <td style={{ padding: "9px 8px", color: COLORS.text }}>{credential.agent_id}</td>
                  <td style={{ padding: "9px 8px", color: COLORS.secondary }}>{credential.adapter_id}</td>
                  <td style={{ padding: "9px 8px", color: COLORS.secondary }}>{(credential.allowed_capabilities || []).join(", ")}</td>
                  <td style={{ padding: "9px 8px", color: COLORS.secondary, whiteSpace: "nowrap" }}>{timestamp(credential.expires_at)}</td>
                  <td style={{ padding: "9px 8px" }}><StatusPill value={credential.status} /></td>
                </tr>)}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Panel title="Negotiation audit" subtitle="Latest read-only capability decisions recorded by the server">
        {!negotiations.length ? <div style={{ color: COLORS.muted, fontSize: 12 }}>No capability negotiations recorded.</div> : (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {negotiations.slice(0, 8).map((entry, index) => {
              const record = entry.negotiation || {};
              return (
              <div key={entry.id || `${entry.agent_id}-${index}`} style={{ display: "flex", flexWrap: "wrap", justifyContent: "space-between", gap: 8, padding: 9, borderRadius: 7, background: COLORS.cardAlt, border: `1px solid ${COLORS.border}` }}>
                <div>
                  <div style={{ color: COLORS.text, fontWeight: 700, fontSize: 11 }}>{entry.agent_id || record.agent_id || "Unknown agent"} · {entry.adapter_id || record.adapter_id || "OpenWrt"}</div>
                  <div style={{ color: COLORS.muted, fontSize: 10, marginTop: 3 }}>Adapter {record.adapter_version || "—"} · schema {record.capability_schema_version || "—"} · {timestamp(entry.negotiated_at)}</div>
                </div>
                <div style={{ display: "flex", gap: 5, alignItems: "center" }}>
                  <StatusPill value={record.permission === "read" ? "read-only" : record.permission || "recorded"} />
                  <span style={{ color: COLORS.muted, fontSize: 10 }}>{(record.negotiated_capabilities || []).length} capabilities</span>
                </div>
              </div>
              );
            })}
          </div>
        )}
      </Panel>
      <div style={{ color: COLORS.muted, fontSize: 10, display: "flex", alignItems: "center", gap: 7 }}>
        <ShieldCheck size={12} /> Admin actions use the existing authenticated session. Agent bearer secrets are only displayed once after enrolment or rotation.
      </div>
    </div>
  );
}
