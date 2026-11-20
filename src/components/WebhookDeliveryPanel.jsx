import { useState } from "react";
import { apiFetch } from "../lib/api.js";

const API_BASE = window.location.protocol + "//" + window.location.hostname + ":199";
const panel = { background: "#0c1120", border: "1px solid #1e2d47", borderRadius: 10, padding: 15, minWidth: 0 };
const muted = { color: "#94a3b8", fontSize: 11, lineHeight: 1.6 };
const input = { boxSizing: "border-box", width: "100%", minWidth: 0, resize: "vertical", background: "#070b14", color: "#e2e8f0", border: "1px solid #2a3f65", borderRadius: 7, padding: 10, fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: 10, lineHeight: 1.55 };
const button = { border: "1px solid #06d6f0", borderRadius: 7, background: "rgba(6,214,240,.1)", color: "#06d6f0", padding: "9px 12px", fontWeight: 700, fontSize: 11, cursor: "pointer" };

function createExample() {
  const now = new Date();
  const connectedAt = now.toISOString();
  const resolutionAt = new Date(now.getTime() - 5000).toISOString();
  return {
    now: connectedAt,
    subscriptions: [{
      subscription_id: "home-alerts",
      endpoint: "https://hooks.example.net/router/events",
      allowed_hosts: ["hooks.example.net"],
      key_id: "home-key-v1",
      event_types: ["router.health"],
      minimum_severity: "warning",
      site_allowlist: ["home"],
      maximum_events_per_batch: 100,
      maximum_batches: 10
    }],
    events: [{
      event_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      event_type: "router.health",
      severity: "warning",
      occurred_at: connectedAt,
      site_id: "home",
      router_id: "openwrt-home",
      summary: "Router health warning",
      attributes: { finding_count: 1, threshold: 85, password: "this-unknown-field-is-removed" }
    }],
    signing_keys: { "home-key-v1": "sample-signing-key-material-minimum-32-bytes" },
    egress_evidence: [{
      subscription_id: "home-alerts",
      endpoint: "https://hooks.example.net/router/events",
      allowed_hosts: ["hooks.example.net"],
      resolution_at: resolutionAt,
      connected_at: connectedAt,
      resolved_addresses: ["1.1.1.1"],
      peer_ip: "1.1.1.1",
      connected_port: 443,
      tls_version: "TLSv1.3",
      tls_verified: true,
      hostname_verified: true,
      redirect_location: null
    }]
  };
}
async function readResponse(response) {
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || "Request failed (HTTP " + response.status + ")");
  return data;
}
export default function WebhookDeliveryPanel() {
  const [payloadText, setPayloadText] = useState("");
  const [result, setResult] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const prepare = async event => {
    event.preventDefault();
    if (busy) return;
    setBusy(true); setError(""); setNotice(""); setResult(null);
    try {
      let payload;
      try { payload = JSON.parse(payloadText); }
      catch { throw new Error("The delivery input must be valid JSON."); }
      if (!payload || Array.isArray(payload) || typeof payload !== "object") {
        throw new Error("The delivery input must be a JSON object.");
      }
      const response = await apiFetch(API_BASE + "/api/features/router_webhook_delivery_orchestrator", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(30000)
      });
      const data = await readResponse(response);
      setResult(data.result);
      // Retain the operator's draft but clear secrets immediately after a successful request.
      if (payload.signing_keys) {
        payload.signing_keys = {};
        setPayloadText(JSON.stringify(payload, null, 2));
      }
      setNotice("Preparation completed. Signing keys were cleared from the editor.");
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "Webhook delivery preparation failed.");
    } finally { setBusy(false); }
  };

  const copyPrepared = async () => {
    if (!result || !result.prepared_deliveries || !result.prepared_deliveries.length) return;
    try {
      await navigator.clipboard.writeText(JSON.stringify(result.prepared_deliveries, null, 2));
      setNotice("Prepared envelopes copied. They are not sent; the dispatcher must re-verify egress before transmission.");
    } catch {
      setError("Clipboard access was blocked. The prepared envelopes remain visible below.");
    }
  };

  const prepared = result && Array.isArray(result.prepared_deliveries) ? result.prepared_deliveries : [];
  const blocked = result && Array.isArray(result.blocked_deliveries) ? result.blocked_deliveries : [];
  const metric = (label, value, hint, color) => (
    <div key={label} style={{ background: "#070b14", border: "1px solid #1e2d47", borderRadius: 8, padding: 12 }}>
      <div style={{ color: "#94a3b8", fontSize: 10 }}>{label}</div>
      <div style={{ color: color || "#e2e8f0", fontSize: 22, fontWeight: 800, marginTop: 4, fontVariantNumeric: "tabular-nums" }}>{value}</div>
      <div style={{ color: "#64748b", fontSize: 9, marginTop: 3 }}>{hint}</div>
    </div>
  );

  return (
    <div style={{ color: "#e2e8f0", display: "grid", gap: 14, minWidth: 0 }}>
      <style>{".webhook-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.webhook-table{width:100%;border-collapse:collapse;font-size:10px}.webhook-table th,.webhook-table td{padding:9px 8px;text-align:left;vertical-align:top;border-bottom:1px solid #1e2d47;overflow-wrap:anywhere}.webhook-table th{color:#94a3b8;font-weight:700}@media(max-width:760px){.webhook-grid{grid-template-columns:1fr}}"}</style>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
        <div>
          <div style={{ fontSize: 16, fontWeight: 800 }}>Webhook Delivery Center</div>
          <div style={{ ...muted, marginTop: 4 }}>Prepare independently signed deliveries for multiple router-event subscriptions.</div>
        </div>
        <span style={{ color: "#06d6f0", background: "rgba(6,214,240,.07)", border: "1px solid rgba(6,214,240,.35)", borderRadius: 99, padding: "5px 9px", fontSize: 9, fontWeight: 800 }}>F190 + F185 + F187 + F192</span>
      </div>

      <section style={{ ...panel, borderColor: "rgba(245,158,11,.35)" }}>
        <div style={{ display: "flex", gap: 9, alignItems: "flex-start" }}>
          <span style={{ color: "#fbbf24", fontSize: 15, fontWeight: 900 }}>!</span>
          <div style={muted}>
            <strong style={{ color: "#fbbf24" }}>Preparation only — this screen does not send webhooks.</strong>
            Signing keys are submitted to the local API for this request and cleared from the editor after a successful run. They are not stored in browser storage, audit events or the result. The sample uses placeholder DNS proof, not real connectivity. A dispatcher must re-resolve DNS, pin the actual peer IP, validate TLS and re-run the egress policy immediately before every attempt.
          </div>
        </div>
      </section>

      {error ? <div role="alert" style={{ color: "#fca5a5", border: "1px solid rgba(248,113,113,.35)", background: "rgba(248,113,113,.07)", borderRadius: 8, padding: 10, fontSize: 11 }}>{error}</div> : null}
      {notice ? <div role="status" style={{ color: "#86efac", border: "1px solid rgba(74,222,128,.3)", background: "rgba(74,222,128,.06)", borderRadius: 8, padding: 10, fontSize: 11 }}>{notice}</div> : null}

      <section style={panel}>
        <div style={{ display: "flex", justifyContent: "space-between", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <div style={{ fontSize: 13, fontWeight: 750 }}>Orchestration request</div>
          <button type="button" style={{ ...button, background: "transparent", borderColor: "#475569", color: "#cbd5e1" }} onClick={() => { setPayloadText(JSON.stringify(createExample(), null, 2)); setResult(null); setError(""); setNotice("Example loaded. Replace the sample key and placeholder peer evidence with your actual secret and trusted connection evidence."); }}>Load example</button>
        </div>
        <p style={{ ...muted, margin: "6px 0 12px" }}>Provide subscriptions, events, signing_keys and egress_evidence in one JSON object. Each subscription is matched by event type, severity and site; each approved batch receives a deterministic idempotency key and HMAC signature.</p>
        <form onSubmit={prepare} style={{ display: "grid", gap: 10 }}>
          <label style={{ ...muted, display: "grid", gap: 6 }}>
            Multi-subscription payload · JSON
            <textarea value={payloadText} onChange={event => setPayloadText(event.target.value)} spellCheck={false} rows={18} style={{ ...input, minHeight: 300 }} placeholder={'{\n  "now": "2026-11-21T10:00:00Z",\n  "subscriptions": [],\n  "events": [],\n  "signing_keys": {},\n  "egress_evidence": []\n}'}/>
          </label>
          <div style={{ display: "flex", justifyContent: "flex-end", gap: 8, flexWrap: "wrap" }}>
            <button type="button" style={{ ...button, background: "transparent", borderColor: "#475569", color: "#cbd5e1" }} onClick={() => { setPayloadText(""); setResult(null); setError(""); setNotice(""); }}>Clear</button>
            <button type="submit" style={button} disabled={busy || !payloadText.trim()}>{busy ? "Preparing…" : "Validate and prepare deliveries"}</button>
          </div>
        </form>
      </section>

      {result ? <>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          <div style={{ fontSize: 13, fontWeight: 750 }}>Result · {result.status}</div>
          <button type="button" style={button} onClick={copyPrepared} disabled={!prepared.length}>Copy prepared envelopes</button>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(130px,1fr))", gap: 9 }}>
          {metric("Subscriptions", result.summary.subscription_count, "configured")}
          {metric("Planned batches", result.summary.planned_batch_count, "F190 matched batches")}
          {metric("Prepared", result.summary.prepared_delivery_count, "signed and egress-approved", "#4ade80")}
          {metric("Blocked", result.summary.blocked_delivery_count, "not eligible for dispatch", blocked.length ? "#fbbf24" : "#e2e8f0")}
        </div>

        {prepared.length ? <section style={panel}>
          <div style={{ fontSize: 12, fontWeight: 750 }}>Prepared deliveries</div>
          <div style={{ overflowX: "auto" }}>
            <table className="webhook-table">
              <thead><tr><th>Subscription</th><th>Batch</th><th>Events</th><th>Endpoint</th><th>Verified peer</th></tr></thead>
              <tbody>{prepared.map(item => (
                <tr key={item.batch_id}>
                  <td style={{ fontWeight: 700 }}>{item.subscription_id}<div style={{ color: "#4ade80", marginTop: 3 }}>Prepared</div></td>
                  <td style={{ fontFamily: "monospace", color: "#94a3b8" }}>{item.batch_id.slice(0, 16)}…</td>
                  <td>{item.event_count}</td>
                  <td>{item.endpoint}</td>
                  <td>{(item.egress && item.egress.connected_peer_ip) || "—"} · {(item.egress && item.egress.tls_version) || "—"}</td>
                </tr>
              ))}</tbody>
            </table>
          </div>
        </section> : null}

        {blocked.length ? <section style={panel}>
          <div style={{ fontSize: 12, fontWeight: 750 }}>Blocked deliveries</div>
          <div style={{ display: "grid", gap: 8 }}>
            {blocked.map(item => (
              <div key={item.batch_id} style={{ border: "1px solid rgba(245,158,11,.3)", borderRadius: 7, padding: 10, background: "rgba(245,158,11,.04)" }}>
                <div style={{ fontSize: 11, fontWeight: 700 }}>{item.subscription_id} · {item.event_count} event(s)</div>
                <div style={{ color: "#fbbf24", fontSize: 10, marginTop: 5 }}>{item.reasons.join(" · ")}</div>
              </div>
            ))}
          </div>
        </section> : null}

        <section style={panel}>
          <div style={{ fontSize: 11, fontWeight: 700 }}>Dispatcher hand-off</div>
          <p style={muted}>{result.note}</p>
        </section>
      </> : null}
    </div>
  );
}
