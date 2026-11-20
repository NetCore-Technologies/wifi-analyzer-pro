import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "../lib/api.js";
import { useAuth } from "../auth/AuthContext.jsx";

const API_BASE = window.location.protocol + "//" + window.location.hostname + ":199";
const ROLES = [
  { value: "admin", label: "Administrator" },
  { value: "network_admin", label: "Network administrator" },
  { value: "analyst", label: "Analyst" },
  { value: "viewer", label: "Read-only viewer" },
];

const styles = {
  panel: { color: "#e2e8f0", display: "grid", gap: 16 },
  card: { background: "#0c1120", border: "1px solid #1e2d47", borderRadius: 10, padding: 16 },
  muted: { color: "#94a3b8", fontSize: 12 },
  input: { boxSizing: "border-box", width: "100%", minWidth: 0, background: "#070b14", color: "#e2e8f0", border: "1px solid #2a3f65", borderRadius: 7, padding: "9px 10px", fontSize: 12 },
  button: { border: "1px solid #06d6f0", borderRadius: 7, background: "rgba(6,214,240,.12)", color: "#06d6f0", padding: "9px 12px", fontWeight: 700, fontSize: 12, cursor: "pointer" },
};

async function readResponse(response) {
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `Request failed (HTTP ${response.status})`);
  return data;
}

export default function TeamAccessPanel() {
  const { identity } = useAuth();
  const availableRoles = identity?.role === "owner" ? ROLES : ROLES.filter(item => item.value !== "admin");
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("analyst");

  const loadUsers = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const response = await apiFetch(`${API_BASE}/api/users`, { signal: AbortSignal.timeout(8000) });
      const data = await readResponse(response);
      setUsers(Array.isArray(data.users) ? data.users : []);
    } catch (loadError) {
      setError(loadError.message || "Could not load the user directory.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadUsers(); }, [loadUsers]);

  const createUser = async event => {
    event.preventDefault();
    if (saving) return;
    setSaving(true);
    setError("");
    setNotice("");
    try {
      const response = await apiFetch(`${API_BASE}/api/users`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password, role }),
        signal: AbortSignal.timeout(10000),
      });
      const data = await readResponse(response);
      setUsers(current => [...current, data.user].sort((a, b) => a.username.localeCompare(b.username)));
      setUsername("");
      setPassword("");
      setNotice(`Created account for ${data.user.username}.`);
    } catch (createError) {
      setError(createError.message || "Could not create this account.");
    } finally {
      setSaving(false);
    }
  };

  const updateUser = async (user, updates) => {
    if (saving) return;
    setSaving(true);
    setError("");
    setNotice("");
    try {
      const response = await apiFetch(`${API_BASE}/api/users/${user.id}/update`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(updates),
        signal: AbortSignal.timeout(10000),
      });
      const data = await readResponse(response);
      setUsers(current => current.map(item => item.id === user.id ? data.user : item));
      setNotice(`Updated ${user.username}.`);
    } catch (updateError) {
      setError(updateError.message || "Could not update this account.");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div style={styles.panel}>
      <section style={styles.card}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
          <div>
            <div style={{ fontSize: 16, fontWeight: 750 }}>Team access</div>
            <p style={{ ...styles.muted, margin: "5px 0 0" }}>Create named local accounts and assign least-privilege network roles.</p>
          </div>
          <button type="button" onClick={loadUsers} disabled={loading} style={styles.button}>Refresh directory</button>
        </div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginTop: 15 }}>
          {[
            ["Owner", "Full workspace control"],
            ["Administrator", "Manage team and operations"],
            ["Network admin", "Manage agents, sites and reports"],
            ["Analyst", "Run diagnostics and review results"],
            ["Viewer", "Read-only access"],
          ].map(([name, description]) => (
            <div key={name} style={{ flex: "1 1 145px", minWidth: 130, border: "1px solid #1e2d47", borderRadius: 8, padding: 10, background: "#070b14" }}>
              <div style={{ color: "#06d6f0", fontSize: 11, fontWeight: 750 }}>{name}</div>
              <div style={{ color: "#94a3b8", fontSize: 10, marginTop: 4 }}>{description}</div>
            </div>
          ))}
        </div>
      </section>

      <section style={styles.card}>
        <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 4 }}>Add a team member</div>
        <p style={{ ...styles.muted, margin: "0 0 14px" }}>Each person has their own username, password verifier and revocable session.</p>
        <form onSubmit={createUser} style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(150px,1fr))", gap: 10, alignItems: "end" }}>
          <label style={{ display: "grid", gap: 5, color: "#94a3b8", fontSize: 11 }}>
            Username
            <input style={styles.input} value={username} onChange={event => setUsername(event.target.value)} minLength={3} maxLength={64} pattern="[A-Za-z0-9][A-Za-z0-9._-]{2,63}" autoComplete="off" required placeholder="e.g. alex.network"/>
          </label>
          <label style={{ display: "grid", gap: 5, color: "#94a3b8", fontSize: 11 }}>
            Temporary password
            <input style={styles.input} value={password} onChange={event => setPassword(event.target.value)} minLength={12} maxLength={1024} autoComplete="new-password" type="password" required placeholder="At least 12 characters"/>
          </label>
          <label style={{ display: "grid", gap: 5, color: "#94a3b8", fontSize: 11 }}>
            Role
            <select style={styles.input} value={role} onChange={event => setRole(event.target.value)}>
              {availableRoles.map(item => <option key={item.value} value={item.value}>{item.label}</option>)}
            </select>
          </label>
          <button type="submit" disabled={saving} style={{ ...styles.button, opacity: saving ? .6 : 1 }}>Create account</button>
        </form>
      </section>

      <section style={styles.card}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, marginBottom: 12 }}>
          <div>
            <div style={{ fontSize: 14, fontWeight: 700 }}>User directory</div>
            <div style={styles.muted}>{users.length} account(s) · maximum 100 local users</div>
          </div>
          {loading ? <span style={styles.muted}>Loading…</span> : null}
        </div>
        {error ? <div role="alert" style={{ color: "#f87171", fontSize: 12, marginBottom: 10 }}>{error}</div> : null}
        {notice ? <div role="status" style={{ color: "#4ade80", fontSize: 12, marginBottom: 10 }}>{notice}</div> : null}
        <div style={{ display: "grid", gap: 8 }}>
          {users.map(user => (
            <div key={user.id} style={{ display: "grid", gridTemplateColumns: "minmax(110px,1fr) minmax(140px,1fr) auto", alignItems: "center", gap: 10, borderTop: "1px solid #1e2d47", padding: "11px 0" }}>
              <div style={{ minWidth: 0 }}>
                <div style={{ fontWeight: 650, fontSize: 12, overflowWrap: "anywhere" }}>{user.username}</div>
                <div style={{ ...styles.muted, fontSize: 10 }}>{user.role === "owner" ? "Workspace owner · protected" : user.enabled ? "Enabled" : "Disabled"}</div>
              </div>
              <div>
                {user.role === "owner" || (identity?.role !== "owner" && user.role === "admin") ? (
                  <span style={{ color: "#06d6f0", fontSize: 11, fontWeight: 700 }}>
                    {user.role === "owner" ? "Owner" : "Administrator · owner-managed"}
                  </span>
                ) : (
                  <select aria-label={`Role for ${user.username}`} style={styles.input} value={user.role} disabled={saving || !user.enabled || (identity?.role !== "owner" && user.role === "admin")} onChange={event => updateUser(user, { role: event.target.value })}>
                    {availableRoles.map(item => <option key={item.value} value={item.value}>{item.label}</option>)}
                  </select>
                )}
              </div>
              <button type="button" disabled={saving || user.role === "owner" || (identity?.role !== "owner" && user.role === "admin")} onClick={() => updateUser(user, { enabled: !user.enabled })}
                style={{ ...styles.button, borderColor: user.enabled ? "#f59e0b" : "#22c55e", color: user.enabled ? "#f59e0b" : "#22c55e", background: "transparent", whiteSpace: "nowrap" }}>
                {user.enabled ? "Disable" : "Enable"}
              </button>
            </div>
          ))}
          {!loading && users.length === 0 ? <div style={styles.muted}>No accounts found.</div> : null}
        </div>
      </section>
      <p style={{ ...styles.muted, margin: 0, lineHeight: 1.6 }}>This local directory does not yet provide per-site isolation, SSO, MFA or centralised identity federation. Keep remote access behind a VPN and do not expose the local API directly to the public internet.</p>
    </div>
  );
}
