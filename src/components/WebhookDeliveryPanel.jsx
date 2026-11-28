import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "../lib/api.js";

const API_BASE = window.location.protocol + "//" + window.location.hostname + ":199";
const panel = { background: "#111624", border: "1px solid #29374d", borderRadius: 10, padding: 15, minWidth: 0 };
const muted = { color: "#a8b6ca", fontSize: 11, lineHeight: 1.6 };
const input = { boxSizing: "border-box", width: "100%", minWidth: 0, resize: "vertical", background: "#090c15", color: "#f1f5fb", border: "1px solid #435775", borderRadius: 7, padding: 10, fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace", fontSize: 10, lineHeight: 1.55 };
const button = { border: "1px solid #ff8359", borderRadius: 7, background: "rgba(255,131,89,.1)", color: "#ff8359", padding: "9px 12px", fontWeight: 700, fontSize: 11, cursor: "pointer" };

function emptySubscriptionDraft() {
  return {
    subscription_id: "",
    endpoint: "",
    allowed_hosts: "",
    key_id: "",
    event_types: "router.health",
    minimum_severity: "warning",
    site_allowlist: "",
    maximum_events_per_batch: "100",
    maximum_batches: "10",
    enabled: true,
  };
}

function csvValues(value) {
  return String(value || "").split(",").map(item => item.trim()).filter(Boolean);
}

function createExample() {
  const now = new Date().toISOString();
  return {
    now,
    subscriptions: [],
    events: [{
      event_id: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      event_type: "router.health",
      severity: "warning",
      occurred_at: now,
      site_id: "office",
      router_id: "router-office-01",
      summary: "Example router health warning",
      attributes: { finding_count: 1 }
    }],
    signing_keys: {},
    egress_evidence: []
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
  const [queue, setQueue] = useState([]);
  const [queueSummary, setQueueSummary] = useState(null);
  const [queueBusy, setQueueBusy] = useState(false);
  const [enqueueBusy, setEnqueueBusy] = useState(false);
  const [queueError, setQueueError] = useState("");
  const [queueNotice, setQueueNotice] = useState("");
  const [subscriptions, setSubscriptions] = useState([]);
  const [subscriptionsBusy, setSubscriptionsBusy] = useState(false);
  const [subscriptionSaving, setSubscriptionSaving] = useState(false);
  const [subscriptionError, setSubscriptionError] = useState("");
  const [subscriptionNotice, setSubscriptionNotice] = useState("");
  const [subscriptionDraft, setSubscriptionDraft] = useState(emptySubscriptionDraft);
  const [editingSubscriptionId, setEditingSubscriptionId] = useState("");
  const [confirmDeleteId, setConfirmDeleteId] = useState("");
  const [signingKeyDrafts, setSigningKeyDrafts] = useState({});
  const [probeEvidence, setProbeEvidence] = useState({});
  const [probeResults, setProbeResults] = useState({});
  const [probingSubscriptionId, setProbingSubscriptionId] = useState("");

  const loadQueue = useCallback(async () => {
    setQueueBusy(true);
    setQueueError("");
    try {
      const response = await apiFetch(API_BASE + "/api/webhooks/deliveries", {
        signal: AbortSignal.timeout(10000),
      });
      const data = await readResponse(response);
      setQueue(Array.isArray(data.deliveries) ? data.deliveries : []);
      setQueueSummary(data.summary || null);
    } catch (requestError) {
      setQueueError(requestError instanceof Error ? requestError.message : "Could not load the webhook delivery queue.");
    } finally {
      setQueueBusy(false);
    }
  }, []);

  useEffect(() => {
    loadQueue();
  }, [loadQueue]);

  const loadSubscriptions = useCallback(async () => {
    setSubscriptionsBusy(true);
    setSubscriptionError("");
    try {
      const response = await apiFetch(API_BASE + "/api/webhooks/subscriptions", {
        signal: AbortSignal.timeout(10000),
      });
      const data = await readResponse(response);
      setSubscriptions(Array.isArray(data.subscriptions) ? data.subscriptions : []);
    } catch (requestError) {
      setSubscriptionError(
        requestError instanceof Error ? requestError.message : "Could not load saved webhook subscriptions."
      );
    } finally {
      setSubscriptionsBusy(false);
    }
  }, []);

  useEffect(() => {
    loadSubscriptions();
  }, [loadSubscriptions]);

  const saveSubscription = async event => {
    event.preventDefault();
    if (subscriptionSaving) return;
    setSubscriptionSaving(true);
    setSubscriptionError("");
    setSubscriptionNotice("");
    const configuration = {
      subscription_id: subscriptionDraft.subscription_id.trim(),
      endpoint: subscriptionDraft.endpoint.trim(),
      allowed_hosts: csvValues(subscriptionDraft.allowed_hosts),
      key_id: subscriptionDraft.key_id.trim(),
      event_types: csvValues(subscriptionDraft.event_types),
      minimum_severity: subscriptionDraft.minimum_severity,
      site_allowlist: csvValues(subscriptionDraft.site_allowlist),
      maximum_events_per_batch: Number(subscriptionDraft.maximum_events_per_batch),
      maximum_batches: Number(subscriptionDraft.maximum_batches),
      enabled: Boolean(subscriptionDraft.enabled),
    };
    const target = editingSubscriptionId
      ? "/api/webhooks/subscriptions/" + encodeURIComponent(editingSubscriptionId) + "/update"
      : "/api/webhooks/subscriptions";
    try {
      const response = await apiFetch(API_BASE + target, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ subscription: configuration }),
        signal: AbortSignal.timeout(12000),
      });
      const data = await readResponse(response);
      setSubscriptionNotice(
        (editingSubscriptionId ? "Updated " : "Saved ") +
        data.subscription.subscription_id + ". Signing secrets are not part of saved subscription metadata."
      );
      setSubscriptionDraft(emptySubscriptionDraft());
      setEditingSubscriptionId("");
      setProbeEvidence({});
      setProbeResults({});
      await loadSubscriptions();
    } catch (requestError) {
      setSubscriptionError(
        requestError instanceof Error ? requestError.message : "Could not save the webhook subscription."
      );
    } finally {
      setSubscriptionSaving(false);
    }
  };

  const editSubscription = item => {
    setEditingSubscriptionId(item.subscription_id);
    setSubscriptionDraft({
      subscription_id: item.subscription_id,
      endpoint: item.endpoint,
      allowed_hosts: (item.allowed_hosts || []).join(", "),
      key_id: item.key_id,
      event_types: (item.event_types || []).join(", "),
      minimum_severity: item.minimum_severity,
      site_allowlist: (item.site_allowlist || []).join(", "),
      maximum_events_per_batch: String(item.maximum_events_per_batch),
      maximum_batches: String(item.maximum_batches),
      enabled: Boolean(item.enabled),
    });
    setSubscriptionError("");
    setSubscriptionNotice("Editing " + item.subscription_id + ".");
  };

  const changeSubscriptionState = async item => {
    setSubscriptionError("");
    setSubscriptionNotice("");
    try {
      const configuration = {
        subscription_id: item.subscription_id,
        endpoint: item.endpoint,
        allowed_hosts: item.allowed_hosts || [],
        key_id: item.key_id,
        event_types: item.event_types || [],
        minimum_severity: item.minimum_severity,
        site_allowlist: item.site_allowlist || [],
        maximum_events_per_batch: item.maximum_events_per_batch,
        maximum_batches: item.maximum_batches,
        enabled: !item.enabled,
      };
      const response = await apiFetch(
        API_BASE + "/api/webhooks/subscriptions/" + encodeURIComponent(item.subscription_id) + "/update",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ subscription: configuration }),
          signal: AbortSignal.timeout(10000),
        }
      );
      await readResponse(response);
      setProbeEvidence(current => {
        const next = { ...current };
        delete next[item.subscription_id];
        return next;
      });
      setProbeResults(current => {
        const next = { ...current };
        delete next[item.subscription_id];
        return next;
      });
      setSubscriptionNotice(item.subscription_id + (item.enabled ? " disabled." : " enabled."));
      await loadSubscriptions();
    } catch (requestError) {
      setSubscriptionError(requestError instanceof Error ? requestError.message : "Could not update subscription state.");
    }
  };

  const deleteSubscription = async item => {
    if (confirmDeleteId !== item.subscription_id) {
      setConfirmDeleteId(item.subscription_id);
      setSubscriptionNotice("Press Delete again to remove " + item.subscription_id + ".");
      return;
    }
    setSubscriptionError("");
    setSubscriptionNotice("");
    try {
      const response = await apiFetch(
        API_BASE + "/api/webhooks/subscriptions/" + encodeURIComponent(item.subscription_id) + "/delete",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({}),
          signal: AbortSignal.timeout(10000),
        }
      );
      await readResponse(response);
      if (editingSubscriptionId === item.subscription_id) {
        setEditingSubscriptionId("");
        setSubscriptionDraft(emptySubscriptionDraft());
      }
      setConfirmDeleteId("");
      setProbeEvidence(current => {
        const next = { ...current };
        delete next[item.subscription_id];
        return next;
      });
      setProbeResults(current => {
        const next = { ...current };
        delete next[item.subscription_id];
        return next;
      });
      setSubscriptionNotice("Deleted " + item.subscription_id + ".");
      await loadSubscriptions();
    } catch (requestError) {
      setSubscriptionError(requestError instanceof Error ? requestError.message : "Could not delete subscription.");
    }
  };

  const probeSubscription = async item => {
    setProbingSubscriptionId(item.subscription_id);
    setSubscriptionError("");
    setSubscriptionNotice("");
    setProbeResults(current => ({
      ...current,
      [item.subscription_id]: { status: "checking", message: "Resolving DNS and verifying TLS…" },
    }));
    try {
      const response = await apiFetch(
        API_BASE + "/api/webhooks/subscriptions/" + encodeURIComponent(item.subscription_id) + "/probe",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({}),
          signal: AbortSignal.timeout(15000),
        }
      );
      const data = await readResponse(response);
      setProbeResults(current => ({
        ...current,
        [item.subscription_id]: {
          status: data.approved ? "approved" : "blocked",
          message: data.approved
            ? "Fresh DNS and TLS evidence approved."
            : (data.verification?.reasons || ["Endpoint egress policy blocked"]).join(", "),
        },
      }));
      if (data.approved && data.evidence) {
        setProbeEvidence(current => ({ ...current, [item.subscription_id]: data.evidence }));
        setSubscriptionNotice(
          "Endpoint verified for " + item.subscription_id + ". Evidence is short-lived and will be cleared after preparation."
        );
      } else {
        setProbeEvidence(current => {
          const next = { ...current };
          delete next[item.subscription_id];
          return next;
        });
        setSubscriptionError("The endpoint did not pass the egress policy. Review the reported reasons before preparing.");
      }
    } catch (requestError) {
      setProbeResults(current => ({
        ...current,
        [item.subscription_id]: {
          status: "failed",
          message: requestError instanceof Error ? requestError.message : "Endpoint probe failed.",
        },
      }));
      setProbeEvidence(current => {
        const next = { ...current };
        delete next[item.subscription_id];
        return next;
      });
      setSubscriptionError(
        requestError instanceof Error ? requestError.message : "Could not probe the saved webhook endpoint."
      );
    } finally {
      setProbingSubscriptionId("");
    }
  };

  const useSavedSubscriptions = () => {
    const enabled = subscriptions.filter(item => item.enabled);
    if (!enabled.length) {
      setSubscriptionError("Save and enable at least one subscription before building a request.");
      return;
    }
    let request = {};
    if (payloadText.trim()) {
      try {
        request = JSON.parse(payloadText);
      } catch {
        setSubscriptionError("Fix the current JSON request before inserting saved subscriptions.");
        return;
      }
    }
    if (!request || Array.isArray(request) || typeof request !== "object") {
      setSubscriptionError("The current request must be a JSON object.");
      return;
    }
    const subscriptionsForRequest = enabled.map(item => ({
      subscription_id: item.subscription_id,
      endpoint: item.endpoint,
      allowed_hosts: item.allowed_hosts,
      key_id: item.key_id,
      event_types: item.event_types,
      minimum_severity: item.minimum_severity,
      site_allowlist: item.site_allowlist,
      maximum_events_per_batch: item.maximum_events_per_batch,
      maximum_batches: item.maximum_batches,
      enabled: true,
    }));
    const missingKeys = enabled.filter(item => !signingKeyDrafts[item.key_id] || !signingKeyDrafts[item.key_id].trim());
    if (missingKeys.length) {
      setSubscriptionError(
        "Enter the one-time HMAC signing secret for: " + missingKeys.map(item => item.key_id).join(", ")
      );
      return;
    }
    const signingKeys = { ...(request.signing_keys || {}) };
    for (const item of enabled) {
      const draftKey = signingKeyDrafts[item.key_id];
      if (typeof draftKey === "string" && draftKey.length) signingKeys[item.key_id] = draftKey;
    }
    request.now = request.now || new Date().toISOString();
    request.subscriptions = subscriptionsForRequest;
    request.signing_keys = signingKeys;
    request.events = Array.isArray(request.events) ? request.events : [];
    const freshEvidence = enabled
      .map(item => probeEvidence[item.subscription_id])
      .filter(Boolean);
    request.egress_evidence = freshEvidence.length
      ? freshEvidence
      : (Array.isArray(request.egress_evidence) ? request.egress_evidence : []);
    setPayloadText(JSON.stringify(request, null, 2));
    const evidenceCount = enabled.filter(item => probeEvidence[item.subscription_id]).length;
    setSubscriptionNotice(
      "Inserted " + enabled.length + " enabled subscription(s) and " + evidenceCount +
      " fresh endpoint probe(s). Add event data and probe any remaining endpoints before preparation."
    );
    setSubscriptionError("");
  };

  const enqueuePrepared = async () => {
    if (!prepared.length || enqueueBusy) return;
    setEnqueueBusy(true);
    setQueueError("");
    setQueueNotice("");
    try {
      const response = await apiFetch(API_BASE + "/api/webhooks/deliveries/enqueue", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ deliveries: prepared }),
        signal: AbortSignal.timeout(20000),
      });
      const data = await readResponse(response);
      setQueueNotice(
        (data.created_count || 0) + " delivery batch(es) queued; " +
        (data.duplicate_count || 0) + " idempotent duplicate(s) already existed."
      );
      await loadQueue();
    } catch (requestError) {
      setQueueError(requestError instanceof Error ? requestError.message : "Could not enqueue prepared deliveries.");
    } finally {
      setEnqueueBusy(false);
    }
  };

  const updateDelivery = async (deliveryId, action) => {
    setQueueError("");
    setQueueNotice("");
    try {
      const response = await apiFetch(
        API_BASE + "/api/webhooks/deliveries/" + encodeURIComponent(deliveryId) + "/" + action,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({}),
          signal: AbortSignal.timeout(10000),
        }
      );
      const data = await readResponse(response);
      setQueueNotice("Delivery #" + deliveryId + " is now " + data.delivery.status + ".");
      await loadQueue();
    } catch (requestError) {
      setQueueError(requestError instanceof Error ? requestError.message : "Could not update the selected delivery.");
    }
  };

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
      setSigningKeyDrafts({});
      setProbeEvidence({});
      setProbeResults({});
      setNotice("Preparation completed. Signing keys and short-lived endpoint evidence were cleared; saved subscription definitions were unchanged.");
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
    <div key={label} style={{ background: "#090c15", border: "1px solid #29374d", borderRadius: 8, padding: 12 }}>
      <div style={{ color: "#a8b6ca", fontSize: 10 }}>{label}</div>
      <div style={{ color: color || "#f1f5fb", fontSize: 22, fontWeight: 800, marginTop: 4, fontVariantNumeric: "tabular-nums" }}>{value}</div>
      <div style={{ color: "#71829a", fontSize: 9, marginTop: 3 }}>{hint}</div>
    </div>
  );

  return (
    <div style={{ color: "#f1f5fb", display: "grid", gap: 14, minWidth: 0 }}>
      <style>{".webhook-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.webhook-table{width:100%;border-collapse:collapse;font-size:10px}.webhook-table th,.webhook-table td{padding:9px 8px;text-align:left;vertical-align:top;border-bottom:1px solid #29374d;overflow-wrap:anywhere}.webhook-table th{color:#a8b6ca;font-weight:700}@media(max-width:760px){.webhook-grid{grid-template-columns:1fr}}"}</style>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
        <div>
          <div style={{ fontSize: 16, fontWeight: 800 }}>Webhook Delivery Center</div>
          <div style={{ ...muted, marginTop: 4 }}>Prepare independently signed deliveries for multiple router-event subscriptions.</div>
        </div>
        <span style={{ color: "#ff8359", background: "rgba(255,131,89,.07)", border: "1px solid rgba(255,131,89,.35)", borderRadius: 99, padding: "5px 9px", fontSize: 9, fontWeight: 800 }}>F190 + F185 + F187 + F192</span>
      </div>

      <section style={{ ...panel, borderColor: "rgba(242,195,107,.35)" }}>
        <div style={{ display: "flex", gap: 9, alignItems: "flex-start" }}>
          <span style={{ color: "#fbbf24", fontSize: 15, fontWeight: 900 }}>!</span>
          <div style={muted}>
            <strong style={{ color: "#fbbf24" }}>Preparation and queue management — network sends run in a separate worker.</strong>
            Signing keys are submitted only for this preparation request, cleared from the editor after success and never stored in the outbox. The sample uses placeholder DNS proof, not real connectivity. The worker independently resolves DNS, pins the actual peer IP, verifies TLS and re-runs the egress policy immediately before every attempt.
          </div>
        </div>
      </section>

      {error ? <div role="alert" style={{ color: "#fca5a5", border: "1px solid rgba(248,113,113,.35)", background: "rgba(248,113,113,.07)", borderRadius: 8, padding: 10, fontSize: 11 }}>{error}</div> : null}
      {notice ? <div role="status" style={{ color: "#86efac", border: "1px solid rgba(74,222,128,.3)", background: "rgba(74,222,128,.06)", borderRadius: 8, padding: 10, fontSize: 11 }}>{notice}</div> : null}


      <section style={panel}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          <div>
            <div style={{ fontSize: 13, fontWeight: 750 }}>Saved subscription directory</div>
            <div style={muted}>Up to 100 definitions · site-scoped · HMAC secrets are never saved</div>
          </div>
          <div style={{ display: "flex", gap: 7, flexWrap: "wrap" }}>
            <button type="button" style={{ ...button, background: "transparent", borderColor: "#475569", color: "#cbd5e1" }}
              onClick={loadSubscriptions} disabled={subscriptionsBusy}>{subscriptionsBusy ? "Refreshing…" : "Refresh"}</button>
            <button type="button" style={button} onClick={useSavedSubscriptions} disabled={!subscriptions.some(item => item.enabled)}>
              Use enabled subscriptions in request
            </button>
          </div>
        </div>
        {subscriptionError ? <div role="alert" style={{ color: "#fca5a5", fontSize: 11, marginTop: 9 }}>{subscriptionError}</div> : null}
        {subscriptionNotice ? <div role="status" style={{ color: "#86efac", fontSize: 11, marginTop: 9 }}>{subscriptionNotice}</div> : null}
        <form onSubmit={saveSubscription} style={{ display: "grid", gap: 10, marginTop: 12 }}>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(180px,1fr))", gap: 9 }}>
            <label style={{ ...muted, display: "grid", gap: 5 }}>
              Subscription ID
              <input style={input} value={subscriptionDraft.subscription_id} maxLength={64} required
                disabled={Boolean(editingSubscriptionId)}
                onChange={event => setSubscriptionDraft(current => ({ ...current, subscription_id: event.target.value }))}
                placeholder="office-alerts"/>
            </label>
            <label style={{ ...muted, display: "grid", gap: 5 }}>
              Key ID
              <input style={input} value={subscriptionDraft.key_id} maxLength={64} required
                onChange={event => setSubscriptionDraft(current => ({ ...current, key_id: event.target.value }))}
                placeholder="office-key-v1"/>
            </label>
            <label style={{ ...muted, display: "grid", gap: 5, gridColumn: "1 / -1" }}>
              HTTPS endpoint
              <input style={input} value={subscriptionDraft.endpoint} maxLength={2048} type="url" required
                onChange={event => setSubscriptionDraft(current => ({ ...current, endpoint: event.target.value }))}
                placeholder="https://hooks.example.net/router/events"/>
            </label>
            <label style={{ ...muted, display: "grid", gap: 5 }}>
              Exact DNS host allowlist (comma-separated)
              <input style={input} value={subscriptionDraft.allowed_hosts} required
                onChange={event => setSubscriptionDraft(current => ({ ...current, allowed_hosts: event.target.value }))}
                placeholder="hooks.example.net"/>
            </label>
            <label style={{ ...muted, display: "grid", gap: 5 }}>
              Event types (comma-separated)
              <input style={input} value={subscriptionDraft.event_types} required
                onChange={event => setSubscriptionDraft(current => ({ ...current, event_types: event.target.value }))}
                placeholder="router.health, radio.down"/>
            </label>
            <label style={{ ...muted, display: "grid", gap: 5 }}>
              Minimum severity
              <select style={input} value={subscriptionDraft.minimum_severity}
                onChange={event => setSubscriptionDraft(current => ({ ...current, minimum_severity: event.target.value }))}>
                <option value="critical">Critical</option>
                <option value="warning">Warning</option>
                <option value="info">Info</option>
              </select>
            </label>
            <label style={{ ...muted, display: "grid", gap: 5 }}>
              Site allowlist (comma-separated, empty = all sites; owner only)
              <input style={input} value={subscriptionDraft.site_allowlist}
                onChange={event => setSubscriptionDraft(current => ({ ...current, site_allowlist: event.target.value }))}
                placeholder="office, floor-2"/>
            </label>
            <label style={{ ...muted, display: "grid", gap: 5 }}>
              Events per batch (1–500)
              <input style={input} type="number" min="1" max="500" value={subscriptionDraft.maximum_events_per_batch}
                onChange={event => setSubscriptionDraft(current => ({ ...current, maximum_events_per_batch: event.target.value }))}/>
            </label>
            <label style={{ ...muted, display: "grid", gap: 5 }}>
              Maximum batches (1–100)
              <input style={input} type="number" min="1" max="100" value={subscriptionDraft.maximum_batches}
                onChange={event => setSubscriptionDraft(current => ({ ...current, maximum_batches: event.target.value }))}/>
            </label>
          </div>
          <label style={{ display: "flex", alignItems: "center", gap: 8, color: "#cbd5e1", fontSize: 11 }}>
            <input type="checkbox" checked={subscriptionDraft.enabled}
              onChange={event => setSubscriptionDraft(current => ({ ...current, enabled: event.target.checked }))}/>
            Subscription enabled
          </label>
          <div style={{ display: "flex", gap: 8, justifyContent: "flex-end", flexWrap: "wrap" }}>
            {editingSubscriptionId ? (
              <button type="button" style={{ ...button, background: "transparent", borderColor: "#475569", color: "#cbd5e1" }}
                onClick={() => { setEditingSubscriptionId(""); setSubscriptionDraft(emptySubscriptionDraft()); }}>
                Cancel edit
              </button>
            ) : null}
            <button type="submit" style={button} disabled={subscriptionSaving}>
              {subscriptionSaving ? "Saving…" : editingSubscriptionId ? "Update subscription" : "Save subscription"}
            </button>
          </div>
        </form>
        <div style={{ marginTop: 13, borderTop: "1px solid #29374d", paddingTop: 12 }}>
          <div style={{ fontSize: 11, fontWeight: 750, marginBottom: 8 }}>Saved subscriptions ({subscriptions.length}/100)</div>
          {!subscriptions.length ? (
            <div style={muted}>{subscriptionsBusy ? "Loading…" : "No saved subscriptions. Add one above; signing secrets are entered separately for each preparation run."}</div>
          ) : (
            <div style={{ display: "grid", gap: 8 }}>
              {subscriptions.map(item => (
                <div key={item.subscription_id} style={{ border: "1px solid #29374d", borderRadius: 8, background: "#090c15", padding: 10, display: "grid", gap: 9 }}>
                  <div style={{ display: "flex", justifyContent: "space-between", gap: 10, alignItems: "flex-start", flexWrap: "wrap" }}>
                    <div style={{ minWidth: 0 }}>
                      <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                        <strong style={{ fontSize: 11 }}>{item.subscription_id}</strong>
                        <span style={{ color: item.enabled ? "#4ade80" : "#fbbf24", fontSize: 9, fontWeight: 800 }}>{item.enabled ? "ENABLED" : "DISABLED"}</span>
                      </div>
                      <div style={{ ...muted, overflowWrap: "anywhere", marginTop: 3 }}>{item.endpoint}</div>
                      <div style={{ ...muted, marginTop: 3 }}>
                        {item.key_id} · {(item.event_types || []).join(", ")} · {item.minimum_severity} · {(item.site_allowlist || []).join(", ") || "All sites"}
                      </div>
                    </div>
                    <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                      <button type="button" style={{ ...button, padding: "6px 8px" }} onClick={() => editSubscription(item)}>Edit</button>
                      <button type="button" style={{ ...button, padding: "6px 8px", background: "rgba(255,131,89,.08)" }}
                        disabled={!item.enabled || probingSubscriptionId === item.subscription_id}
                        onClick={() => probeSubscription(item)}>
                        {probingSubscriptionId === item.subscription_id ? "Testing…" : "Test TLS"}
                      </button>
                      <button type="button" style={{ ...button, padding: "6px 8px", background: "transparent", borderColor: "#475569", color: "#cbd5e1" }}
                        onClick={() => changeSubscriptionState(item)}>{item.enabled ? "Disable" : "Enable"}</button>
                      <button type="button" style={{ ...button, padding: "6px 8px", background: "transparent", borderColor: confirmDeleteId === item.subscription_id ? "#f87171" : "#475569", color: "#fca5a5" }}
                        onClick={() => deleteSubscription(item)}>{confirmDeleteId === item.subscription_id ? "Confirm delete" : "Delete"}</button>
                    </div>
                  </div>
                  {probeResults[item.subscription_id] ? (
                    <div role="status" style={{
                      color: probeResults[item.subscription_id].status === "approved" ? "#4ade80" :
                        probeResults[item.subscription_id].status === "checking" ? "#ff8359" : "#fbbf24",
                      fontSize: 10,
                    }}>
                      Endpoint probe · {probeResults[item.subscription_id].message}
                    </div>
                  ) : null}
                  <label style={{ ...muted, display: "grid", gap: 5 }}>
                    One-time HMAC signing secret for {item.key_id}
                    <input
                      type="password"
                      autoComplete="off"
                      value={signingKeyDrafts[item.key_id] || ""}
                      onChange={event => setSigningKeyDrafts(current => ({ ...current, [item.key_id]: event.target.value }))}
                      style={input}
                      placeholder="Enter for this preparation only; never saved"
                    />
                  </label>
                </div>
              ))}
            </div>
          )}
        </div>
        <p style={{ ...muted, margin: "10px 0 0" }}>
          Subscription records contain routing metadata only. Signing secrets remain transient in this page and are cleared after a successful preparation. Test TLS performs a DNS lookup and TLS handshake only; it sends no HTTP payload. The resulting F187 evidence is short-lived and automatically inserted into the next request.
        </p>
      </section>
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
          <div style={{ display: "flex", gap: 7, flexWrap: "wrap" }}>
            <button type="button" style={{ ...button, background: "transparent", borderColor: "#475569", color: "#cbd5e1" }} onClick={copyPrepared} disabled={!prepared.length}>Copy envelopes</button>
            <button type="button" style={button} onClick={enqueuePrepared} disabled={!prepared.length || enqueueBusy}>
              {enqueueBusy ? "Queueing…" : "Queue prepared deliveries"}
            </button>
          </div>
        </div>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(130px,1fr))", gap: 9 }}>
          {metric("Subscriptions", result.summary.subscription_count, "configured")}
          {metric("Planned batches", result.summary.planned_batch_count, "F190 matched batches")}
          {metric("Prepared", result.summary.prepared_delivery_count, "signed and egress-approved", "#4ade80")}
          {metric("Blocked", result.summary.blocked_delivery_count, "not eligible for dispatch", blocked.length ? "#fbbf24" : "#f1f5fb")}
        </div>

        {prepared.length ? <section style={panel}>
          <div style={{ fontSize: 12, fontWeight: 750 }}>Prepared deliveries</div>
          <div style={{ overflowX: "auto" }}>
            <table className="webhook-table">
              <thead><tr><th>Subscription</th><th>Batch</th><th>Events</th><th>Endpoint</th><th>Verified peer</th></tr></thead>
              <tbody>{prepared.map(item => (
                <tr key={item.batch_id}>
                  <td style={{ fontWeight: 700 }}>{item.subscription_id}<div style={{ color: "#4ade80", marginTop: 3 }}>Prepared</div></td>
                  <td style={{ fontFamily: "monospace", color: "#a8b6ca" }}>{item.batch_id.slice(0, 16)}…</td>
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
              <div key={item.batch_id} style={{ border: "1px solid rgba(242,195,107,.3)", borderRadius: 7, padding: 10, background: "rgba(242,195,107,.04)" }}>
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

      <section style={panel}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          <div>
            <div style={{ fontSize: 13, fontWeight: 750 }}>Durable delivery queue</div>
            <div style={muted}>Site-scoped outbox · safe state metadata only · no signing secrets</div>
          </div>
          <button type="button" style={{ ...button, background: "transparent", borderColor: "#475569", color: "#cbd5e1" }}
            onClick={loadQueue} disabled={queueBusy}>{queueBusy ? "Refreshing…" : "Refresh queue"}</button>
        </div>
        {queueError ? <div role="alert" style={{ color: "#fca5a5", fontSize: 11, marginTop: 9 }}>{queueError}</div> : null}
        {queueNotice ? <div role="status" style={{ color: "#86efac", fontSize: 11, marginTop: 9 }}>{queueNotice}</div> : null}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(110px,1fr))", gap: 8, marginTop: 12 }}>
          {metric("Pending", queueSummary?.counts_by_status?.pending ?? 0, "awaiting worker")}
          {metric("Sending", queueSummary?.counts_by_status?.sending ?? 0, "leased")}
          {metric("Retry wait", queueSummary?.counts_by_status?.retry_wait ?? 0, "backoff scheduled", "#fbbf24")}
          {metric("Delivered", queueSummary?.counts_by_status?.delivered ?? 0, "2xx confirmed", "#4ade80")}
          {metric("Dead letter", queueSummary?.counts_by_status?.dead_letter ?? 0, "manual recovery", queueSummary?.counts_by_status?.dead_letter ? "#f87171" : "#f1f5fb")}
        </div>
        {!queue.length ? (
          <div style={{ ...muted, marginTop: 12 }}>{queueBusy ? "Loading delivery state…" : "No visible webhook deliveries are queued."}</div>
        ) : (
          <div style={{ overflowX: "auto", marginTop: 12 }}>
            <table className="webhook-table">
              <thead><tr><th>Delivery</th><th>Subscription</th><th>Sites</th><th>Events</th><th>State</th><th>Attempts</th><th>Last error</th><th>Action</th></tr></thead>
              <tbody>
                {queue.map(item => (
                  <tr key={item.id}>
                    <td style={{ fontFamily: "monospace" }}>#{item.id}<div style={{ color: "#71829a", marginTop: 3 }}>{item.batch_id.slice(0, 12)}…</div></td>
                    <td>{item.subscription_id}<div style={{ color: "#71829a", marginTop: 3 }}>{item.endpoint}</div></td>
                    <td>{item.has_unscoped_events ? "Unscoped" : (item.site_ids || []).join(", ") || "—"}</td>
                    <td>{item.event_count}</td>
                    <td style={{
                      color: item.status === "delivered" ? "#4ade80" :
                        item.status === "dead_letter" ? "#f87171" :
                        item.status === "retry_wait" ? "#fbbf24" :
                        item.status === "sending" ? "#ff8359" : "#cbd5e1",
                      fontWeight: 750,
                    }}>{item.status.replace("_", " ")}</td>
                    <td>{item.attempts}/{item.max_attempts}</td>
                    <td style={{ color: item.last_error_code ? "#fbbf24" : "#71829a" }}>{item.last_error_code || "—"}</td>
                    <td>
                      {item.status === "dead_letter" || item.status === "cancelled" ? (
                        <button type="button" style={button} disabled={queueBusy} onClick={() => updateDelivery(item.id, "retry")}>Retry</button>
                      ) : item.status === "pending" || item.status === "retry_wait" ? (
                        <button type="button" style={{ ...button, background: "transparent", borderColor: "#475569", color: "#cbd5e1" }} disabled={queueBusy} onClick={() => updateDelivery(item.id, "cancel")}>Cancel</button>
                      ) : <span style={muted}>—</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <p style={{ ...muted, marginBottom: 0, marginTop: 12 }}>
          Enqueue stores signed envelopes but does not transmit them. Start the separate webhook_dispatch_worker.py process to send pending items. A delivery is marked successful only after a verified 2xx response; exhausted retries move to dead letter.
        </p>
      </section>
    </div>
  );
}
