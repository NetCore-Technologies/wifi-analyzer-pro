import { useCallback, useEffect, useMemo, useState } from "react";
import { apiBase, apiFetch } from "../lib/api.js";
import { Activity, AlertTriangle, Clock3, RadioTower, RefreshCw, Router, Wifi, WifiOff } from "lucide-react";

const panel = { background:"#0c1120", border:"1px solid #1e2d47", borderRadius:10, padding:15 };
const muted = "#94a3b8";
const sitePattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const MAX_AGE_SECONDS = 300;

function formatAge(value) {
  if (!Number.isFinite(value) || value < 0) return "Unknown";
  if (value < 60) return Math.round(value) + "s ago";
  if (value < 3600) return Math.floor(value / 60) + "m ago";
  if (value < 86400) return (value / 3600).toFixed(1) + "h ago";
  return (value / 86400).toFixed(1) + "d ago";
}

function ageSeconds(value, now) {
  if (typeof value !== "string") return null;
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) return null;
  return Math.max(0, (now - timestamp) / 1000);
}

function count(value) {
  return Number.isInteger(value) && value >= 0 ? value.toLocaleString() : "—";
}

function metric(value, suffix = "") {
  return typeof value === "number" && Number.isFinite(value)
    ? value.toFixed(1) + suffix
    : "—";
}

function Status({ tone, children }) {
  const colors = {
    green: ["#86efac", "rgba(34,197,94,0.10)", "rgba(34,197,94,0.28)"],
    cyan: ["#67e8f9", "rgba(6,214,240,0.10)", "rgba(6,214,240,0.28)"],
    amber: ["#fcd34d", "rgba(245,158,11,0.10)", "rgba(245,158,11,0.28)"],
    red: ["#fca5a5", "rgba(239,68,68,0.10)", "rgba(239,68,68,0.28)"],
    grey: [muted, "rgba(148,163,184,0.08)", "rgba(148,163,184,0.18)"],
  };
  const [color, background, border] = colors[tone] || colors.grey;
  return (
    <span style={{ display:"inline-flex", alignItems:"center", gap:5, border:"1px solid " + border, borderRadius:5, padding:"3px 6px", color, background, fontSize:9, fontWeight:800, letterSpacing:0.45, whiteSpace:"nowrap" }}>
      <span style={{ width:5, height:5, borderRadius:"50%", background:color }}/>
      {children}
    </span>
  );
}

async function getJson(path, signal) {
  const response = await apiFetch(apiBase() + path, { signal });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(typeof data.error === "string" ? data.error : "Request failed (HTTP " + response.status + ")");
    error.status = response.status;
    throw error;
  }
  return data;
}

export default function FleetOverviewPanel() {
  const [sites, setSites] = useState([]);
  const [rollups, setRollups] = useState([]);
  const [agents, setAgents] = useState([]);
  const [snapshots, setSnapshots] = useState([]);
  const [allSites, setAllSites] = useState(false);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState(null);
  const [errors, setErrors] = useState([]);
  const [refreshing, setRefreshing] = useState(false);

  const refresh = useCallback(async ({ quiet = false } = {}) => {
    if (quiet) setRefreshing(true);
    else setLoading(true);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15000);
    const tasks = [
      ["sites", "/api/sites"],
      ["telemetry", "/api/telemetry/latest?days=1&limit=100"],
      ["agents", "/api/agents/health"],
      ["snapshots", "/api/agents/snapshots"],
    ];
    try {
      const results = await Promise.all(tasks.map(async ([key, path]) => {
        try {
          return { key, data: await getJson(path, controller.signal) };
        } catch (error) {
          return { key, error };
        }
      }));
      const nextErrors = [];
      for (const result of results) {
        if (result.error) {
          nextErrors.push({
            source: result.key,
            message: result.error?.message || "Data source is unavailable",
            status: result.error?.status || null,
          });
          continue;
        }
        if (result.key === "sites") {
          const ids = Array.isArray(result.data.site_ids)
            ? result.data.site_ids.filter((value) => typeof value === "string" && sitePattern.test(value))
            : [];
          setSites([...new Set(ids)].sort());
          setAllSites(result.data.all_sites === true);
        } else if (result.key === "telemetry") {
          setRollups(Array.isArray(result.data.rollups) ? result.data.rollups : []);
        } else if (result.key === "agents") {
          const data = result.data.result || result.data;
          setAgents(Array.isArray(data.agents) ? data.agents : []);
        } else if (result.key === "snapshots") {
          setSnapshots(Array.isArray(result.data.snapshots) ? result.data.snapshots : []);
        }
      }
      setErrors(nextErrors);
      setLastRefresh(Date.now());
    } finally {
      clearTimeout(timeout);
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    refresh();
    const timer = setInterval(() => refresh({ quiet:true }), 30000);
    return () => clearInterval(timer);
  }, [refresh]);

  const now = Date.now();
  const telemetryBySite = useMemo(
    () => new Map(rollups.map((row) => [row.site_id, row])),
    [rollups],
  );
  const snapshotByAgent = useMemo(() => {
    const map = new Map();
    for (const item of snapshots) {
      if (!item || typeof item.agent_id !== "string") continue;
      const old = map.get(item.agent_id);
      if (!old || String(item.received_at || item.captured_at || "") > String(old.received_at || old.captured_at || "")) {
        map.set(item.agent_id, item);
      }
    }
    return map;
  }, [snapshots]);

  const agentRows = useMemo(() => agents.map((agent) => {
    const snapshot = snapshotByAgent.get(agent.agent_id);
    return {
      ...agent,
      site_id: snapshot?.site_id || null,
      snapshot,
    };
  }), [agents, snapshotByAgent]);

  const siteStats = useMemo(() => {
    return sites.map((siteId) => {
      const row = telemetryBySite.get(siteId);
      const age = row ? ageSeconds(row.minute_utc, now) : null;
      const fresh = age !== null && age <= MAX_AGE_SECONDS;
      const siteAgents = agentRows.filter((agent) => agent.site_id === siteId);
      const activeAgents = siteAgents.filter((agent) => ["healthy", "degraded", "unhealthy"].includes(agent.health_status));
      return {
        siteId,
        row,
        age,
        fresh,
        siteAgents,
        activeAgents,
      };
    });
  }, [sites, telemetryBySite, agentRows, now]);

  const freshSites = siteStats.filter((site) => site.fresh).length;
  const staleSites = siteStats.filter((site) => site.row && !site.fresh).length;
  const missingSites = siteStats.filter((site) => !site.row).length;
  const healthyAgents = agents.filter((agent) => agent.health_status === "healthy").length;
  const staleAgents = agents.filter((agent) => agent.health_status === "stale").length;
  const unhealthyAgents = agents.filter((agent) => ["unhealthy", "future_timestamp"].includes(agent.health_status)).length;

  return (
    <div style={{ display:"grid", gap:14 }}>
      <section style={panel}>
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", gap:12, flexWrap:"wrap" }}>
          <div style={{ display:"flex", gap:10, alignItems:"center" }}>
            <div style={{ width:36, height:36, borderRadius:9, display:"grid", placeItems:"center", color:"#67e8f9", background:"rgba(6,214,240,0.10)" }}>
              <RadioTower size={19}/>
            </div>
            <div>
              <div style={{ color:"#e2e8f0", fontSize:15, fontWeight:800 }}>Multi-site fleet overview</div>
              <div style={{ color:muted, fontSize:11, marginTop:3 }}>
                Latest measured telemetry and registered router-agent health
                {allSites ? " · all-site administrator" : " · assigned sites only"}
              </div>
            </div>
          </div>
          <button
            type="button"
            onClick={() => refresh({ quiet:true })}
            disabled={refreshing}
            style={{ display:"inline-flex", alignItems:"center", gap:6, border:"1px solid #29405f", background:"#111827", color:"#cbd5e1", borderRadius:7, padding:"7px 10px", fontSize:11, fontWeight:700, cursor:"pointer", opacity:refreshing ? 0.6 : 1 }}
          >
            <RefreshCw size={13}/> Refresh
          </button>
        </div>

        <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fit,minmax(125px,1fr))", gap:8, marginTop:16 }}>
          {[
            ["Assigned sites", sites.length, "#e2e8f0", "map"],
            ["Fresh telemetry", freshSites, "#86efac", "fresh"],
            ["Stale telemetry", staleSites, "#fcd34d", "stale"],
            ["No telemetry", missingSites, "#94a3b8", "missing"],
            ["Healthy agents", healthyAgents, "#67e8f9", "healthy"],
            ["Stale agents", staleAgents, "#fcd34d", "agent-stale"],
            ["Unhealthy agents", unhealthyAgents, "#fca5a5", "agent-unhealthy"],
          ].map(([label, value, color, key]) => (
            <div key={key} style={{ border:"1px solid #263956", background:"#080d18", borderRadius:8, padding:"9px 10px" }}>
              <div style={{ color:muted, fontSize:9, textTransform:"uppercase", letterSpacing:0.5 }}>{label}</div>
              <div style={{ color, fontSize:22, fontWeight:800, marginTop:3 }}>{value}</div>
            </div>
          ))}
        </div>
        <div style={{ display:"flex", flexWrap:"wrap", gap:8, alignItems:"center", marginTop:12, color:muted, fontSize:10 }}>
          <span>Telemetry freshness threshold: 5 minutes</span>
          {lastRefresh && <span>· Refreshed {formatAge((Date.now() - lastRefresh) / 1000)}</span>}
          {loading && <Status tone="cyan">LOADING</Status>}
        </div>
      </section>

      {errors.length > 0 && (
        <section role="status" style={{ ...panel, borderColor:"rgba(245,158,11,0.35)", background:"rgba(245,158,11,0.04)" }}>
          <div style={{ display:"flex", alignItems:"center", gap:8, color:"#fcd34d", fontSize:11, fontWeight:800 }}>
            <AlertTriangle size={14}/> PARTIAL FLEET DATA
          </div>
          <div style={{ display:"grid", gap:5, marginTop:9 }}>
            {errors.map((item) => (
              <div key={item.source} style={{ color:"#cbd5e1", fontSize:11 }}>
                {item.source}: {item.message}
              </div>
            ))}
          </div>
        </section>
      )}

      <section style={panel}>
        <div style={{ display:"flex", alignItems:"center", gap:8, color:"#e2e8f0", fontWeight:800, fontSize:13, marginBottom:12 }}>
          <Wifi size={15} color="#67e8f9"/> Site telemetry
        </div>
        {loading && sites.length === 0 ? (
          <div style={{ color:muted, fontSize:12 }}>Loading assigned sites…</div>
        ) : sites.length === 0 ? (
          <div style={{ color:muted, fontSize:12 }}>No sites are assigned to this account.</div>
        ) : (
          <div style={{ overflowX:"auto" }}>
            <table style={{ width:"100%", borderCollapse:"collapse", minWidth:760 }}>
              <thead>
                <tr>
                  {["Site","Freshness","Latest scan","APs / scan","Avg RSSI","Gateway","Download","Agents"].map((label) => (
                    <th key={label} style={{ textAlign:"left", padding:"8px 9px", borderBottom:"1px solid #263956", color:muted, fontSize:9, textTransform:"uppercase", letterSpacing:0.5, whiteSpace:"nowrap" }}>{label}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {siteStats.map(({ siteId, row, age, fresh, activeAgents: siteAgentList }) => (
                  <tr key={siteId}>
                    <td style={{ padding:"10px 9px", borderBottom:"1px solid #1b2940", color:"#e2e8f0", fontSize:11, fontWeight:700 }}>{siteId}</td>
                    <td style={{ padding:"10px 9px", borderBottom:"1px solid #1b2940" }}>
                      {!row ? <Status tone="grey">NO DATA</Status> : fresh ? <Status tone="green">FRESH</Status> : <Status tone="amber">STALE</Status>}
                      {row && <div style={{ color:muted, fontSize:9, marginTop:4 }}>{formatAge(age)}</div>}
                    </td>
                    <td style={{ padding:"10px 9px", borderBottom:"1px solid #1b2940", color:"#cbd5e1", fontSize:10, whiteSpace:"nowrap" }}>
                      {row?.minute_utc ? new Date(row.minute_utc).toLocaleString() : "—"}
                    </td>
                    <td style={{ padding:"10px 9px", borderBottom:"1px solid #1b2940", color:"#e2e8f0", fontSize:11 }}>{metric(row?.average_network_count)}</td>
                    <td style={{ padding:"10px 9px", borderBottom:"1px solid #1b2940", color:"#e2e8f0", fontSize:11 }}>{metric(row?.average_rssi_dbm, " dBm")}</td>
                    <td style={{ padding:"10px 9px", borderBottom:"1px solid #1b2940", color:"#e2e8f0", fontSize:11 }}>{metric(row?.average_latency_ms, " ms")}</td>
                    <td style={{ padding:"10px 9px", borderBottom:"1px solid #1b2940", color:"#e2e8f0", fontSize:11 }}>{metric(row?.average_speedtest_download_mbps, " Mb/s")}</td>
                    <td style={{ padding:"10px 9px", borderBottom:"1px solid #1b2940", color:"#e2e8f0", fontSize:11 }}>{count(siteAgentList.length)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <div style={{ color:muted, fontSize:10, lineHeight:1.6, marginTop:10 }}>
          Each site shows its latest persisted minute-level aggregate. Missing measurements remain unavailable rather than being shown as zero.
        </div>
      </section>

      <section style={panel}>
        <div style={{ display:"flex", alignItems:"center", gap:8, color:"#e2e8f0", fontWeight:800, fontSize:13, marginBottom:12 }}>
          <Router size={15} color="#67e8f9"/> Router agents
        </div>
        {agents.length === 0 ? (
          <div style={{ color:muted, fontSize:12 }}>No visible agent heartbeat records were returned.</div>
        ) : (
          <div style={{ display:"grid", gap:7 }}>
            {agentRows.map((agent) => {
              const tone = agent.health_status === "healthy" ? "green"
                : agent.health_status === "degraded" ? "amber"
                : ["unhealthy", "future_timestamp"].includes(agent.health_status) ? "red" : "grey";
              const snapshot = agent.snapshot;
              return (
                <div key={agent.agent_id} style={{ display:"grid", gridTemplateColumns:"minmax(120px,1.3fr) minmax(90px,1fr) minmax(100px,1fr) minmax(100px,1fr)", alignItems:"center", gap:10, border:"1px solid #1b2940", background:"#080d18", borderRadius:8, padding:"9px 10px" }}>
                  <div style={{ minWidth:0 }}>
                    <div style={{ color:"#e2e8f0", fontSize:11, fontWeight:800, overflowWrap:"anywhere" }}>{agent.agent_id}</div>
                    <div style={{ color:muted, fontSize:9, marginTop:3 }}>{agent.adapter_id || "Unknown adapter"}{agent.site_id ? " · " + agent.site_id : " · unassigned site"}</div>
                  </div>
                  <div><Status tone={tone}>{String(agent.health_status || "unknown").toUpperCase()}</Status></div>
                  <div style={{ color:"#cbd5e1", fontSize:10 }}>
                    {agent.age_seconds != null ? formatAge(agent.age_seconds) : "No heartbeat time"}
                    <div style={{ color:muted, fontSize:9, marginTop:3 }}>{agent.agent_version || "Version unavailable"}</div>
                  </div>
                  <div style={{ color:"#cbd5e1", fontSize:10 }}>
                    {snapshot ? count(snapshot.wireless_radio_count) + " radios · " + count(snapshot.association_count) + " associations" : "No snapshot"}
                    <div style={{ color:muted, fontSize:9, marginTop:3 }}>{snapshot?.received_at ? "Snapshot " + formatAge(ageSeconds(snapshot.received_at, now)) : ""}</div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
        <div style={{ color:muted, fontSize:10, lineHeight:1.6, marginTop:10 }}>
          Agent state is classified using server-recorded heartbeat times. A stale heartbeat does not identify whether a device is powered off, disconnected or blocked.
        </div>
      </section>

      <section style={{ display:"flex", alignItems:"center", gap:8, color:muted, fontSize:10, padding:"0 2px" }}>
        <Clock3 size={12}/>
        Fleet metrics refresh every 30 seconds. Access is limited by the current account's site assignments and agent visibility.
      </section>
    </div>
  );
}
