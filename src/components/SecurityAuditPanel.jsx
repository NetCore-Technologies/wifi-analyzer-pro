import { useCallback, useEffect, useRef, useState } from "react";
import { apiFetch } from "../lib/api.js";

const API_BASE = window.location.protocol + "//" + window.location.hostname + ":199";
const colours = {
  success: { color: "#4ade80", border: "rgba(74,222,128,.35)", background: "rgba(74,222,128,.08)" },
  denied: { color: "#fbbf24", border: "rgba(251,191,36,.35)", background: "rgba(251,191,36,.08)" },
  failure: { color: "#f87171", border: "rgba(248,113,113,.35)", background: "rgba(248,113,113,.08)" },
};
const styles = {
  panel: { color: "#e2e8f0", display: "grid", gap: 14 },
  card: { background: "#0c1120", border: "1px solid #1e2d47", borderRadius: 10, padding: 16 },
  muted: { color: "#94a3b8", fontSize: 11 },
  button: { border: "1px solid #06d6f0", borderRadius: 7, background: "rgba(6,214,240,.1)", color: "#06d6f0", padding: "8px 11px", fontWeight: 700, fontSize: 11, cursor: "pointer" },
  select: { background: "#070b14", color: "#e2e8f0", border: "1px solid #2a3f65", borderRadius: 7, padding: "8px 10px", fontSize: 11 },
};
async function readResponse(response) {
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `Request failed (HTTP ${response.status})`);
  return data;
}
function formatTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export default function SecurityAuditPanel() {
  const [events, setEvents] = useState([]);
  const [summary, setSummary] = useState(null);
  const [verification, setVerification] = useState(null);
  const [outcome, setOutcome] = useState("");
  const [action, setAction] = useState("");
  const [beforeId, setBeforeId] = useState(null);
  const [nextBeforeId, setNextBeforeId] = useState(null);
  const [loading, setLoading] = useState(true);
  const [verifying, setVerifying] = useState(false);
  const [error, setError] = useState("");
  const initialLoadStarted = useRef(false);

  const loadEvents = useCallback(async ({ older = false } = {}) => {
    setLoading(true);
    setError("");
    try {
      const params = new URLSearchParams({ limit: "50" });
      if (outcome) params.set("outcome", outcome);
      if (action.trim()) params.set("action", action.trim());
      const cursor = older ? nextBeforeId : null;
      if (cursor) params.set("before_id", String(cursor));
      const response = await apiFetch(`${API_BASE}/api/security/audit?${params.toString()}`, {
        signal: AbortSignal.timeout(10000),
      });
      const data = await readResponse(response);
      setEvents(current => older ? [...current, ...(data.events || [])] : (data.events || []));
      setSummary(data.summary || null);
      setNextBeforeId(data.next_before_id || null);
    } catch (loadError) {
      setError(loadError.message || "Could not load the security audit trail.");
    } finally {
      setLoading(false);
    }
  }, [action, outcome, nextBeforeId]);

  const verify = async () => {
    setVerifying(true);
    setError("");
    try {
      const response = await apiFetch(`${API_BASE}/api/security/audit/verify`, {
        signal: AbortSignal.timeout(15000),
      });
      const data = await readResponse(response);
      setVerification(data.verification || null);
    } catch (verifyError) {
      setError(verifyError.message || "Could not verify the local audit chain.");
    } finally {
      setVerifying(false);
    }
  };

  useEffect(() => {
    if (!initialLoadStarted.current) {
      initialLoadStarted.current = true;
      loadEvents();
    }
  }, [loadEvents]); // Filter changes require explicit Apply.

  const outcomeStyle = value => colours[value] || { color: "#94a3b8", border: "#334155", background: "transparent" };

  return (
    <div style={styles.panel}>
      <section style={styles.card}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12, flexWrap: "wrap" }}>
          <div>
            <div style={{ fontSize: 16, fontWeight: 750 }}>Security audit trail</div>
            <p style={{ ...styles.muted, margin: "5px 0 0", lineHeight: 1.6 }}>
              Account, authorisation, team and router-agent credential events. Sensitive request content and credentials are excluded.
            </p>
          </div>
          <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
            <button type="button" style={styles.button} disabled={loading} onClick={() => loadEvents()}>Refresh</button>
            <button type="button" style={styles.button} disabled={verifying} onClick={verify}>{verifying ? "Verifying…" : "Verify hash chain"}</button>
          </div>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(130px,1fr))", gap: 9, marginTop: 16 }}>
          <div style={{ background: "#070b14", border: "1px solid #1e2d47", borderRadius: 8, padding: 11 }}>
            <div style={styles.muted}>Stored events</div>
            <div style={{ fontSize: 22, fontWeight: 750, marginTop: 4 }}>{summary?.event_count ?? "—"}</div>
          </div>
          <div style={{ background: "#070b14", border: "1px solid #1e2d47", borderRadius: 8, padding: 11 }}>
            <div style={styles.muted}>Successful actions</div>
            <div style={{ fontSize: 22, fontWeight: 750, color: "#4ade80", marginTop: 4 }}>{summary?.counts_by_outcome?.success ?? 0}</div>
          </div>
          <div style={{ background: "#070b14", border: "1px solid #1e2d47", borderRadius: 8, padding: 11 }}>
            <div style={styles.muted}>Denied / failed</div>
            <div style={{ fontSize: 22, fontWeight: 750, color: "#fbbf24", marginTop: 4 }}>{(summary?.counts_by_outcome?.denied ?? 0) + (summary?.counts_by_outcome?.failure ?? 0)}</div>
          </div>
        </div>
        {verification ? (
          <div role="status" style={{ marginTop: 12, padding: 10, borderRadius: 8, border: `1px solid ${verification.valid ? "rgba(74,222,128,.35)" : "rgba(248,113,113,.35)"}`, background: verification.valid ? "rgba(74,222,128,.07)" : "rgba(248,113,113,.07)", color: verification.valid ? "#4ade80" : "#f87171", fontSize: 11 }}>
            {verification.valid ? "Hash chain verified" : "Hash-chain verification failed"} · {verification.verified_count}/{verification.event_count} records checked
          </div>
        ) : null}
      </section>

      <section style={styles.card}>
        <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
          <label style={{ display: "flex", gap: 6, alignItems: "center", color: "#94a3b8", fontSize: 11 }}>
            Outcome
            <select aria-label="Filter audit outcome" style={styles.select} value={outcome} onChange={event => setOutcome(event.target.value)}>
              <option value="">All outcomes</option>
              <option value="success">Success</option>
              <option value="denied">Denied</option>
              <option value="failure">Failure</option>
            </select>
          </label>
          <label style={{ display: "flex", gap: 6, alignItems: "center", color: "#94a3b8", fontSize: 11 }}>
            Action
            <input aria-label="Filter audit action" style={{ ...styles.select, width: 190 }} value={action} maxLength={96} onChange={event => setAction(event.target.value)} placeholder="e.g. user.created"/>
          </label>
          <button type="button" style={styles.button} disabled={loading} onClick={() => { setNextBeforeId(null); loadEvents(); }}>Apply filters</button>
          {loading ? <span style={styles.muted}>Loading…</span> : null}
        </div>
        {error ? <div role="alert" style={{ color: "#f87171", fontSize: 12, marginTop: 10 }}>{error}</div> : null}
        <div style={{ display: "grid", gap: 0, marginTop: 14 }}>
          {events.map(event => (
            <article key={event.event_id} style={{ display: "grid", gridTemplateColumns: "minmax(130px,1.3fr) minmax(130px,1fr) auto", gap: 12, alignItems: "start", borderTop: "1px solid #1e2d47", padding: "12px 0" }}>
              <div style={{ minWidth: 0 }}>
                <div style={{ fontSize: 12, fontWeight: 700, overflowWrap: "anywhere" }}>{event.action}</div>
                <div style={{ ...styles.muted, marginTop: 4 }}>{formatTime(event.occurred_at)}</div>
                <div style={{ ...styles.muted, marginTop: 4 }}>{event.actor?.username || "System / unauthenticated"}{event.actor?.role ? ` · ${event.actor.role}` : ""}</div>
              </div>
              <div style={{ minWidth: 0 }}>
                <div style={{ fontSize: 11, color: "#cbd5e1", overflowWrap: "anywhere" }}>
                  {event.target_type ? `${event.target_type}${event.target_id ? ` · ${event.target_id}` : ""}` : "Workspace"}
                </div>
                <div style={{ ...styles.muted, overflowWrap: "anywhere", marginTop: 4 }}>{Object.keys(event.metadata || {}).length ? JSON.stringify(event.metadata) : "No additional metadata"}</div>
              </div>
              <span style={{ ...outcomeStyle(event.outcome), border: `1px solid ${outcomeStyle(event.outcome).border}`, background: outcomeStyle(event.outcome).background, color: outcomeStyle(event.outcome).color, borderRadius: 999, padding: "4px 8px", fontSize: 10, fontWeight: 750, whiteSpace: "nowrap" }}>{event.outcome}</span>
            </article>
          ))}
          {!loading && events.length === 0 ? <div style={{ ...styles.muted, padding: 15, textAlign: "center" }}>No matching audit events.</div> : null}
        </div>
        {nextBeforeId ? <div style={{ display: "flex", justifyContent: "center", marginTop: 12 }}>
          <button type="button" style={styles.button} disabled={loading} onClick={() => loadEvents({ older: true })}>Load older events</button>
        </div> : null}
      </section>
      <p style={{ ...styles.muted, margin: 0, lineHeight: 1.6 }}>
        The database rejects ordinary row updates and deletions and links each event to the previous digest. This detects local edits and gaps, but it is not a tamper-proof external archive: a host administrator can replace the database and rewrite the chain. Export signed checkpoints to an independently administered log platform for stronger retention.
      </p>
    </div>
  );
}
