import { useEffect, useState } from "react";
import { apiFetch } from "../lib/api.js";
import { CreditCard, RefreshCw, ExternalLink, ShieldCheck, AlertCircle } from "lucide-react";

const API_BASE = `${window.location.protocol}//${window.location.hostname}:199`;
const panel = {
  background: "#0c1120", border: "1px solid #1e2d47", borderRadius: 10,
  padding: 16, color: "#e2e8f0",
};
const button = {
  display: "inline-flex", alignItems: "center", justifyContent: "center", gap: 7,
  border: "1px solid #06d6f0", borderRadius: 7, padding: "9px 13px",
  background: "rgba(6,214,240,.12)", color: "#06d6f0",
  fontSize: 12, fontWeight: 700, cursor: "pointer",
};
const quietButton = {
  ...button, border: "1px solid #263956", background: "#111827",
  color: "#cbd5e1",
};
const formatDate = value => {
  if (!value) return "Not available";
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "Not available" : parsed.toLocaleString();
};

export default function BillingPanel() {
  const [billing, setBilling] = useState(null);
  const [plans, setPlans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const response = await apiFetch(`${API_BASE}/api/billing/status`, {
        signal: AbortSignal.timeout(10000),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || `Billing status returned HTTP ${response.status}`);
      setBilling(data.billing);
      setPlans(Array.isArray(data.plans) ? data.plans : []);
    } catch (err) {
      setError(err.message || "Unable to load subscription status.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const openStripeUrl = url => {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:" ||
        !["checkout.stripe.com", "billing.stripe.com"].includes(parsed.hostname)) {
      throw new Error("The server returned an untrusted Stripe URL.");
    }
    window.location.assign(parsed.href);
  };

  const startCheckout = async planId => {
    setBusy(planId);
    setError("");
    try {
      const response = await apiFetch(`${API_BASE}/api/billing/checkout`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ plan_id: planId }),
        signal: AbortSignal.timeout(15000),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || `Checkout returned HTTP ${response.status}`);
      openStripeUrl(data.checkout?.url);
    } catch (err) {
      setError(err.message || "Could not start Stripe Checkout.");
    } finally {
      setBusy("");
    }
  };

  const openPortal = async () => {
    setBusy("portal");
    setError("");
    try {
      const response = await apiFetch(`${API_BASE}/api/billing/portal`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{}",
        signal: AbortSignal.timeout(15000),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || `Billing portal returned HTTP ${response.status}`);
      openStripeUrl(data.portal?.url);
    } catch (err) {
      setError(err.message || "Could not open the Stripe billing portal.");
    } finally {
      setBusy("");
    }
  };

  const limits = billing?.limits || {};
  const usage = billing?.usage || {};
  const activePlan = billing?.plan_id || "free";
  const active = billing?.active === true;

  return (
    <div style={{ display: "grid", gap: 14, maxWidth: 1100 }}>
      <section style={panel}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{ width: 38, height: 38, borderRadius: 9, display: "grid", placeItems: "center", background: "rgba(6,214,240,.10)", border: "1px solid rgba(6,214,240,.28)" }}>
              <CreditCard size={18} color="#06d6f0"/>
            </div>
            <div>
              <div style={{ fontSize: 16, fontWeight: 750 }}>Subscription & billing</div>
              <div style={{ color: "#64748b", fontSize: 11 }}>Workspace plan, service limits and payment management</div>
            </div>
          </div>
          <button type="button" onClick={load} disabled={loading || !!busy} style={quietButton}>
            <RefreshCw size={13}/>{loading ? "Refreshing…" : "Refresh"}
          </button>
        </div>
        {error ? <div role="alert" style={{ marginTop: 13, color: "#fca5a5", fontSize: 12, display: "flex", gap: 7 }}><AlertCircle size={14}/>{error}</div> : null}
        </section>

      {loading && !billing ? <section style={panel}>Loading billing status…</section> : null}
      {billing ? (
        <>
          <section style={{ ...panel, display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 14 }}>
            <div>
              <div style={{ color: "#64748b", fontSize: 10, letterSpacing: 1 }}>CURRENT PLAN</div>
              <div style={{ fontSize: 22, fontWeight: 800, marginTop: 5 }}>{billing.plan_label}</div>
              <div style={{ color: active ? "#86efac" : "#fbbf24", fontSize: 11, marginTop: 4 }}>
                {active ? (billing.grace_period ? "Payment grace period" : billing.subscription_status) : "Free plan"}
              </div>
            </div>
            <div>
              <div style={{ color: "#64748b", fontSize: 10, letterSpacing: 1 }}>NEXT BILLING DATE / ACCESS END</div>
              <div style={{ fontSize: 13, fontWeight: 650, marginTop: 9 }}>{formatDate(billing.current_period_end)}</div>
              <div style={{ color: "#64748b", fontSize: 10, marginTop: 4 }}>
                {billing.cancel_at_period_end ? "Cancellation is scheduled at period end" : billing.grace_period ? `Grace ends ${formatDate(billing.grace_period_ends_at)}` : "Subscription status is synchronized by Stripe"}
              </div>
            </div>
            <div>
              <div style={{ color: "#64748b", fontSize: 10, letterSpacing: 1 }}>BILLING CONNECTION</div>
              <div style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 9, fontSize: 12 }}>
                <ShieldCheck size={15} color={billing.billing_configured && billing.webhook_configured ? "#86efac" : "#fbbf24"}/>
                {billing.billing_configured && billing.webhook_configured ? "Stripe connected" : "Stripe setup required"}
              </div>
              <div style={{ color: "#64748b", fontSize: 10, marginTop: 4 }}>Payment secrets remain on the server</div>
            </div>
          </section>

          <section style={panel}>
            <div style={{ fontSize: 13, fontWeight: 750, marginBottom: 10 }}>Plan usage</div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 10 }}>
              {[
                ["Users", "users"],
                ["Managed router agents", "agents"],
                ["Webhook subscriptions", "webhook_subscriptions"],
              ].map(([label, key]) => {
                const used = Number(usage[key] || 0);
                const limit = Number(limits[key] || 0);
                const pct = limit > 0 ? Math.min(100, used / limit * 100) : 0;
                return (
                  <div key={key} style={{ background: "#080d18", border: "1px solid #1e2d47", borderRadius: 8, padding: 11 }}>
                    <div style={{ color: "#94a3b8", fontSize: 11 }}>{label}</div>
                    <div style={{ fontSize: 18, fontWeight: 750, marginTop: 5 }}>{used} <span style={{ color: "#64748b", fontSize: 11, fontWeight: 500 }}>/ {limit}</span></div>
                    <div style={{ height: 4, background: "#1e2d47", borderRadius: 5, marginTop: 9, overflow: "hidden" }}>
                      <div style={{ width: `${pct}%`, height: "100%", background: pct >= 100 ? "#f59e0b" : "#06d6f0" }}/>
                    </div>
                  </div>
                );
              })}
            </div>
          </section>

          <section style={panel}>
            <div style={{ display: "flex", justifyContent: "space-between", gap: 10, alignItems: "center", flexWrap: "wrap", marginBottom: 12 }}>
              <div>
                <div style={{ fontSize: 13, fontWeight: 750 }}>Choose a plan</div>
                <div style={{ fontSize: 10, color: "#64748b", marginTop: 3 }}>Prices, billing intervals and currency are configured in your Stripe account.</div>
              </div>
              {billing.portal_available ? (
                <button type="button" disabled={!!busy} onClick={openPortal} style={quietButton}>
                  <ExternalLink size={13}/>{busy === "portal" ? "Opening…" : "Manage subscription"}
                </button>
              ) : null}
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))", gap: 10 }}>
              {plans.filter(plan => plan.plan_id !== "free").map(plan => {
                const current = activePlan === plan.plan_id && active;
                return (
                  <div key={plan.plan_id} style={{ background: "#080d18", border: `1px solid ${current ? "#06d6f0" : "#1e2d47"}`, borderRadius: 9, padding: 13 }}>
                    <div style={{ fontSize: 14, fontWeight: 750 }}>{plan.label}</div>
                    <div style={{ color: "#64748b", fontSize: 10, margin: "5px 0 10px" }}>Workspace subscription</div>
                    {Object.entries(plan.limits).map(([key, value]) => (
                      <div key={key} style={{ display: "flex", justifyContent: "space-between", gap: 8, fontSize: 10, color: "#94a3b8", padding: "4px 0", borderBottom: "1px solid #1e2d47" }}>
                        <span>{{ users: "Users", agents: "Router agents", webhook_subscriptions: "Webhook subscriptions" }[key]}</span><strong style={{ color: "#e2e8f0" }}>{value}</strong>
                      </div>
                    ))}
                    <button type="button" disabled={!!busy || current || !plan.available_for_checkout || !billing.billing_configured}
                      onClick={() => startCheckout(plan.plan_id)}
                      style={{ ...button, width: "100%", marginTop: 12, opacity: current || !plan.available_for_checkout || !billing.billing_configured ? .45 : 1, cursor: current || !plan.available_for_checkout || !billing.billing_configured ? "not-allowed" : "pointer" }}>
                      {current ? "Current plan" : busy === plan.plan_id ? "Opening checkout…" : plan.available_for_checkout ? `Choose ${plan.label}` : "Price not configured"}
                    </button>
                  </div>
                );
              })}
            </div>
            {(!billing.billing_configured || !billing.webhook_configured) ? (
              <p style={{ fontSize: 10, color: "#fbbf24", margin: "12px 0 0" }}>
                Checkout stays disabled until the Stripe secret key, webhook signing secret, public HTTPS URL and at least one Stripe price are configured on the server.
              </p>
            ) : null}
          </section>
        </>
      ) : null}
    </div>
  );
}
