import { useEffect, useState } from "react";
import { apiFetch } from "../lib/api.js";
import { useAuth } from "../auth/AuthContext.jsx";

const API_BASE = window.location.protocol + "//" + window.location.hostname + ":199";
const styles = {
  panel: { color: "#e2e8f0", display: "grid", gap: 14 },
  card: { background: "#0c1120", border: "1px solid #1e2d47", borderRadius: 10, padding: 16 },
  muted: { color: "#94a3b8", fontSize: 11, lineHeight: 1.6 },
  input: { boxSizing: "border-box", width: "100%", minWidth: 0, background: "#070b14", color: "#e2e8f0", border: "1px solid #2a3f65", borderRadius: 7, padding: "10px 11px", fontSize: 12 },
  button: { border: "1px solid #06d6f0", borderRadius: 7, background: "rgba(6,214,240,.1)", color: "#06d6f0", padding: "9px 12px", fontWeight: 700, fontSize: 11, cursor: "pointer" },
};
async function readResponse(response) {
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `Request failed (HTTP ${response.status})`);
  return data;
}
export default function AccountSecurityPanel() {
  const { identity } = useAuth();
  const [mfaEnabled, setMfaEnabled] = useState(Boolean(identity?.mfa_enabled));
  const [recoveryRemaining, setRecoveryRemaining] = useState(identity?.recovery_codes_remaining ?? 0);
  const [setupPassword, setSetupPassword] = useState("");
  const [setupSecret, setSetupSecret] = useState("");
  const [setupUri, setSetupUri] = useState("");
  const [confirmCode, setConfirmCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState([]);
  const [disablePassword, setDisablePassword] = useState("");
  const [disableCode, setDisableCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  useEffect(() => {
    let active = true;
    apiFetch(`${API_BASE}/api/auth/status`, { signal: AbortSignal.timeout(8000) })
      .then(readResponse)
      .then(data => {
        if (!active) return;
        setMfaEnabled(Boolean(data.identity?.mfa_enabled));
        setRecoveryRemaining(data.identity?.recovery_codes_remaining ?? 0);
      })
      .catch(() => {
        // Keep the already authenticated identity's MFA status if the refresh fails.
      });
    return () => { active = false; };
  }, []);

  const beginSetup = async event => {
    event.preventDefault();
    if (busy) return;
    setBusy(true); setError(""); setNotice("");
    try {
      const response = await apiFetch(`${API_BASE}/api/auth/mfa/setup`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: setupPassword }), signal: AbortSignal.timeout(10000),
      });
      const data = await readResponse(response);
      setSetupSecret(data.setup.secret); setSetupUri(data.setup.otpauth_uri); setConfirmCode("");
      setNotice("Add the secret to your authenticator app, then enter its current six-digit code.");
    } catch (requestError) {
      setError(requestError.message || "Could not start MFA enrolment.");
    } finally { setBusy(false); }
  };

  const confirmSetup = async event => {
    event.preventDefault();
    if (busy) return;
    setBusy(true); setError(""); setNotice("");
    try {
      const response = await apiFetch(`${API_BASE}/api/auth/mfa/confirm`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: setupPassword, code: confirmCode.trim() }), signal: AbortSignal.timeout(10000),
      });
      const data = await readResponse(response);
      setMfaEnabled(true); setRecoveryRemaining(data.mfa.recovery_codes_remaining);
      setRecoveryCodes(data.mfa.recovery_codes || []);
      setSetupSecret(""); setSetupUri(""); setSetupPassword(""); setConfirmCode("");
      setNotice("MFA is enabled. Save the recovery codes now; they are shown only once.");
    } catch (requestError) {
      setError(requestError.message || "Could not confirm MFA enrolment.");
    } finally { setBusy(false); }
  };

  const disableMfa = async event => {
    event.preventDefault();
    if (busy) return;
    setBusy(true); setError(""); setNotice("");
    try {
      const response = await apiFetch(`${API_BASE}/api/auth/mfa/disable`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ password: disablePassword, code: disableCode.trim() }), signal: AbortSignal.timeout(10000),
      });
      await readResponse(response);
      setMfaEnabled(false); setRecoveryRemaining(0); setDisablePassword(""); setDisableCode(""); setRecoveryCodes([]);
      setNotice("Multi-factor authentication has been disabled for this account.");
    } catch (requestError) {
      setError(requestError.message || "Could not disable MFA.");
    } finally { setBusy(false); }
  };

  const copyRecoveryCodes = async () => {
    try {
      await navigator.clipboard.writeText(recoveryCodes.join("\n"));
      setNotice("Recovery codes copied. Store them separately from this device.");
    } catch {
      setError("Clipboard access was blocked. Select and copy the displayed recovery codes.");
    }
  };

  return (
    <div style={styles.panel}>
      <section style={styles.card}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
          <div>
            <div style={{ fontSize: 16, fontWeight: 750 }}>Account security</div>
            <p style={{ ...styles.muted, margin: "5px 0 0" }}>Protect this account with an authenticator app and one-time recovery codes.</p>
          </div>
          <span style={{ border: `1px solid ${mfaEnabled ? "rgba(74,222,128,.45)" : "#334155"}`, background: mfaEnabled ? "rgba(74,222,128,.08)" : "transparent", color: mfaEnabled ? "#4ade80" : "#94a3b8", borderRadius: 999, padding: "5px 9px", fontSize: 10, fontWeight: 750 }}>
            {mfaEnabled ? "MFA ENABLED" : "MFA NOT ENABLED"}
          </span>
        </div>
        <div style={{ ...styles.muted, marginTop: 12 }}>Signed in as <strong style={{ color: "#e2e8f0" }}>{identity?.username || "current user"}</strong>. {mfaEnabled ? `${recoveryRemaining} unused recovery code(s) remain.` : "Password-only sign-in is active."}</div>
      </section>

      {error ? <div role="alert" style={{ color: "#f87171", border: "1px solid rgba(248,113,113,.3)", padding: 10, borderRadius: 8, fontSize: 12 }}>{error}</div> : null}
      {notice ? <div role="status" style={{ color: "#4ade80", border: "1px solid rgba(74,222,128,.3)", padding: 10, borderRadius: 8, fontSize: 12 }}>{notice}</div> : null}

      {!mfaEnabled ? <section style={styles.card}>
        <div style={{ fontSize: 13, fontWeight: 700 }}>Enable authenticator-app MFA</div>
        <p style={styles.muted}>Use a TOTP-compatible authenticator. The secret is encrypted at rest. A valid six-digit code is required before MFA becomes active.</p>
        {!setupSecret ? (
          <form onSubmit={beginSetup} style={{ display: "grid", gap: 9, marginTop: 12 }}>
            <label style={styles.muted} htmlFor="account-mfa-password">Confirm your account password</label>
            <input id="account-mfa-password" type="password" autoComplete="current-password" minLength={12} required style={styles.input} value={setupPassword} onChange={event => setSetupPassword(event.target.value)} />
            <button type="submit" disabled={busy} style={styles.button}>{busy ? "Preparing…" : "Set up authenticator"}</button>
          </form>
        ) : (
          <form onSubmit={confirmSetup} style={{ display: "grid", gap: 9, marginTop: 12 }}>
            <div style={styles.muted}>Add this account using the URI or enter the manual key in your authenticator application.</div>
            <a href={setupUri} style={{ color: "#06d6f0", fontSize: 11, overflowWrap: "anywhere" }}>Open authenticator setup link</a>
            <div style={{ padding: 12, borderRadius: 8, border: "1px solid #2a3f65", background: "#070b14" }}>
              <div style={{ color: "#94a3b8", fontSize: 10, marginBottom: 6 }}>MANUAL SECRET · BASE32</div>
              <div style={{ fontFamily: "monospace", fontSize: 13, color: "#e2e8f0", overflowWrap: "anywhere", letterSpacing: 1 }}>{setupSecret}</div>
            </div>
            <label style={styles.muted} htmlFor="account-mfa-confirm-code">Current six-digit authenticator code</label>
            <input id="account-mfa-confirm-code" inputMode="numeric" autoComplete="one-time-code" pattern="[0-9]{6}" maxLength={6} required style={styles.input} value={confirmCode} onChange={event => setConfirmCode(event.target.value.replace(/\D/g, "").slice(0, 6))} />
            <button type="submit" disabled={busy || confirmCode.length !== 6} style={styles.button}>{busy ? "Verifying…" : "Verify and enable MFA"}</button>
          </form>
        )}
      </section> : (
        <section style={styles.card}>
          <div style={{ fontSize: 13, fontWeight: 700 }}>Disable authenticator-app MFA</div>
          <p style={styles.muted}>Disabling MFA requires your account password and a valid authenticator or unused recovery code.</p>
          <form onSubmit={disableMfa} style={{ display: "grid", gap: 9, marginTop: 12 }}>
            <label style={styles.muted} htmlFor="account-mfa-disable-password">Account password</label>
            <input id="account-mfa-disable-password" type="password" autoComplete="current-password" required style={styles.input} value={disablePassword} onChange={event => setDisablePassword(event.target.value)} />
            <label style={styles.muted} htmlFor="account-mfa-disable-code">Authenticator or recovery code</label>
            <input id="account-mfa-disable-code" autoComplete="one-time-code" required maxLength={24} style={styles.input} value={disableCode} onChange={event => setDisableCode(event.target.value)} />
            <button type="submit" disabled={busy} style={{ ...styles.button, borderColor: "#f87171", color: "#fca5a5" }}>{busy ? "Updating…" : "Disable MFA"}</button>
          </form>
        </section>
      )}

      {recoveryCodes.length ? <section style={styles.card}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          <div style={{ fontSize: 13, fontWeight: 700 }}>One-time recovery codes</div>
          <button type="button" style={styles.button} onClick={copyRecoveryCodes}>Copy codes</button>
        </div>
        <p style={styles.muted}>Each code works once. Save these separately from your authenticator device; they cannot be displayed again after leaving this page.</p>
        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(145px,1fr))", gap: 7, marginTop: 10 }}>
          {recoveryCodes.map(code => <code key={code} style={{ background: "#070b14", border: "1px solid #1e2d47", borderRadius: 6, padding: 9, fontSize: 12, letterSpacing: 1, textAlign: "center" }}>{code}</code>)}
        </div>
      </section> : null}
      <p style={styles.muted}>TOTP uses a 30-second SHA-1 time step with a one-step clock-skew window. MFA secrets are encrypted at rest using password-derived AES-256-GCM key material. Password resets clear MFA and recovery codes, requiring fresh enrolment.</p>
    </div>
  );
}
