import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "../lib/api.js";
import { useAuth } from "../auth/AuthContext.jsx";

const API_BASE = `${window.location.protocol}//${window.location.hostname}:199`;

const PANEL = {
  background: "#0d1725",
  border: "1px solid #23364e",
  borderRadius: 10,
  padding: 13,
};
const MUTED = { color: "#94a3b8", fontSize: 10 };
const CONTROL = {
  width: "100%",
  minWidth: 0,
  boxSizing: "border-box",
  background: "#07111d",
  color: "#e2e8f0",
  border: "1px solid #2b405b",
  borderRadius: 7,
  padding: "8px 9px",
  fontSize: 11,
};
const BUTTON = {
  border: "1px solid #2b405b",
  borderRadius: 7,
  color: "#d6e2ee",
  background: "#172539",
  padding: "7px 10px",
  fontSize: 10,
  fontWeight: 700,
  cursor: "pointer",
};
const ROLE_COLOURS = { admin: "#50e3d2", viewer: "#9bb4d1" };

async function request(path, payload) {
  const response = await apiFetch(`${API_BASE}${path}`, {
    method: payload === undefined ? "GET" : "POST",
    headers: payload === undefined ? undefined : { "Content-Type": "application/json" },
    body: payload === undefined ? undefined : JSON.stringify(payload),
    signal: AbortSignal.timeout(10000),
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(result.error || `Request failed with HTTP ${response.status}`);
  return result;
}

function splitSites(value) {
  return [...new Set(String(value || "").split(",").map(site => site.trim()).filter(Boolean))];
}

export default function UserManagement() {
  const { user, refreshUser } = useAuth();
  const [users, setUsers] = useState([]);
  const [drafts, setDrafts] = useState({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("viewer");
  const [sites, setSites] = useState("");
  const [resetTarget, setResetTarget] = useState("");
  const [resetPassword, setResetPassword] = useState("");

  const loadUsers = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const response = await request("/api/auth/users");
      setUsers(response.users || []);
      setDrafts(Object.fromEntries((response.users || []).map(item => [
        item.username,
        {
          role: item.role,
          sites: item.site_ids?.includes("*") ? "" : (item.site_ids || []).join(", "),
        },
      ])));
    } catch (caught) {
      setError(caught.message || "Unable to load local accounts.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadUsers(); }, [loadUsers]);

  const perform = async (key, action, successMessage) => {
    setSaving(key);
    setError("");
    setNotice("");
    try {
      await action();
      await loadUsers();
      await refreshUser?.();
      setNotice(successMessage);
    } catch (caught) {
      setError(caught.message || "The account operation failed.");
    } finally {
      setSaving("");
    }
  };

  const createUser = async event => {
    event.preventDefault();
    await perform("create", async () => {
      await request("/api/auth/users", {
        username: username.trim(),
        password,
        role,
        site_ids: role === "admin" ? ["*"] : splitSites(sites),
      });
      setUsername("");
      setPassword("");
      setSites("");
      setRole("viewer");
    }, `Account ${username.trim()} created.`);
  };

  const saveUser = async item => {
    const draft = drafts[item.username] || { role: item.role, sites: "" };
    await perform(item.username, async () => {
      await request(`/api/auth/users/${encodeURIComponent(item.username)}/role`, {
        role: draft.role,
        site_ids: draft.role === "admin" ? ["*"] : splitSites(draft.sites),
      });
    }, `Updated ${item.username}.`);
  };

  const toggleEnabled = item => perform(item.username, async () => {
    const action = item.enabled ? "disable" : "enable";
    await request(`/api/auth/users/${encodeURIComponent(item.username)}/${action}`, {});
  }, `${item.username} ${item.enabled ? "disabled" : "enabled"}.`);

  const removeUser = item => {
    if (!window.confirm(`Delete local account "${item.username}"? Existing sessions will be revoked.`)) return;
    perform(item.username, async () => {
      await request(`/api/auth/users/${encodeURIComponent(item.username)}/delete`, {});
    }, `Deleted ${item.username}.`);
  };

  const resetUserPassword = async event => {
    event.preventDefault();
    if (!resetTarget) return;
    await perform("reset-password", async () => {
      await request(`/api/auth/users/${encodeURIComponent(resetTarget)}/password`, {
        password: resetPassword,
      });
      setResetPassword("");
    }, `Password reset for ${resetTarget}. Their existing sessions were revoked.`);
  };

  if (user?.role !== "admin") {
    return (
      <section style={PANEL}>
        <div style={{ color: "#e2e8f0", fontSize: 12, fontWeight: 750 }}>Local account</div>
        <div style={{ marginTop: 8, color: "#d3e1ed", fontSize: 11 }}>{user?.username || "Signed-in user"}</div>
        <div style={{ ...MUTED, marginTop: 3 }}>Role: {user?.role || "viewer"}</div>
        <div style={{ ...MUTED, marginTop: 7 }}>
          Accessible sites: {user?.site_ids?.join(", ") || "No site access assigned"}
        </div>
        <div style={{ ...MUTED, marginTop: 8 }}>Account administration is available to administrators only.</div>
      </section>
    );
  }

  return (
    <div style={{ display: "grid", gap: 12 }}>
      <section style={PANEL}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10 }}>
          <div>
            <div style={{ color: "#e2e8f0", fontSize: 12, fontWeight: 750 }}>Local accounts</div>
            <div style={{ ...MUTED, marginTop: 3 }}>Scrypt-protected credentials · revocable sessions · site-scoped viewer access</div>
          </div>
          <button type="button" onClick={loadUsers} disabled={loading} style={BUTTON}>Refresh</button>
        </div>
        {error && <div role="alert" style={{ color: "#ff9aa6", fontSize: 11, marginTop: 10 }}>{error}</div>}
        {notice && <div role="status" style={{ color: "#50e3d2", fontSize: 11, marginTop: 10 }}>{notice}</div>}
      </section>

      <section style={PANEL}>
        <div style={{ color: "#e2e8f0", fontSize: 11, fontWeight: 750, marginBottom: 10 }}>Create account</div>
        <form onSubmit={createUser} style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(135px,1fr))", gap: 8 }}>
          <label style={MUTED}>
            Username
            <input required minLength={2} maxLength={32} autoComplete="off" value={username}
              onChange={event => setUsername(event.target.value)} placeholder="e.g. office.viewer" style={CONTROL}/>
          </label>
          <label style={MUTED}>
            Temporary password
            <input required minLength={12} maxLength={1024} type="password" autoComplete="new-password"
              value={password} onChange={event => setPassword(event.target.value)}
              placeholder="At least 12 characters" style={CONTROL}/>
          </label>
          <label style={MUTED}>
            Role
            <select value={role} onChange={event => setRole(event.target.value)} style={CONTROL}>
              <option value="viewer">Viewer</option>
              <option value="admin">Administrator</option>
            </select>
          </label>
          <label style={MUTED}>
            Site access
            <input value={sites} disabled={role === "admin"}
              onChange={event => setSites(event.target.value)}
              placeholder="home, branch-1, office-2" style={CONTROL}/>
          </label>
          <div style={{ display: "flex", alignItems: "end" }}>
            <button disabled={saving === "create" || !username.trim() || password.length < 12}
              style={{ ...BUTTON, width: "100%", borderColor: "#367a83", color: "#50e3d2" }}>
              {saving === "create" ? "Creating…" : "Create account"}
            </button>
          </div>
        </form>
        <div style={{ ...MUTED, marginTop: 7 }}>Administrators can access all sites. Viewers can access only the comma-separated site IDs assigned to them.</div>
      </section>

      <section style={PANEL}>
        <div style={{ color: "#e2e8f0", fontSize: 11, fontWeight: 750, marginBottom: 10 }}>
          Accounts {loading ? "· Loading…" : `· ${users.length}`}
        </div>
        {users.map(item => {
          const draft = drafts[item.username] || { role: item.role, sites: "" };
          const ownAccount = item.username === user?.username;
          return (
            <div key={item.username} style={{ padding: "11px 0", borderTop: "1px solid #23364e", display: "grid", gap: 8 }}>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 10, flexWrap: "wrap" }}>
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: 7 }}>
                    <span style={{ color: "#e2e8f0", fontSize: 11, fontWeight: 750 }}>{item.username}</span>
                    {ownAccount && <span style={{ color: "#50e3d2", fontSize: 9 }}>YOU</span>}
                    <span style={{ color: ROLE_COLOURS[item.role] || "#94a3b8", fontSize: 9, fontWeight: 750 }}>{item.role.toUpperCase()}</span>
                  </div>
                  <div style={{ ...MUTED, marginTop: 3 }}>
                    {item.enabled ? "Enabled" : "Disabled"} · {item.active_sessions} active session(s)
                    · Created {new Date(item.created_at * 1000).toLocaleDateString()}
                  </div>
                </div>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                  <button type="button" disabled={saving === item.username || ownAccount}
                    onClick={() => toggleEnabled(item)} style={BUTTON}>
                    {item.enabled ? "Disable" : "Enable"}
                  </button>
                  <button type="button" disabled={saving === item.username || ownAccount}
                    onClick={() => removeUser(item)} style={{ ...BUTTON, color: "#ff9aa6" }}>Delete</button>
                </div>
              </div>
              <div style={{ display: "grid", gridTemplateColumns: "minmax(100px,140px) minmax(150px,1fr) auto", gap: 7, alignItems: "end" }}>
                <label style={MUTED}>
                  Role
                  <select value={draft.role} disabled={ownAccount}
                    onChange={event => setDrafts(current => ({
                      ...current,
                      [item.username]: { ...draft, role: event.target.value },
                    }))} style={CONTROL}>
                    <option value="viewer">Viewer</option>
                    <option value="admin">Administrator</option>
                  </select>
                </label>
                <label style={MUTED}>
                  Site IDs {draft.role === "admin" ? "(all sites)" : "(comma-separated)"}
                  <input value={draft.role === "admin" ? "*" : draft.sites} disabled={ownAccount || draft.role === "admin"}
                    onChange={event => setDrafts(current => ({
                      ...current,
                      [item.username]: { ...draft, sites: event.target.value },
                    }))} style={CONTROL}/>
                </label>
                <button type="button" disabled={saving === item.username || ownAccount}
                  onClick={() => saveUser(item)} style={{ ...BUTTON, color: "#50e3d2" }}>Save role / scope</button>
              </div>
            </div>
          );
        })}
        {!loading && users.length === 0 && <div style={MUTED}>No local accounts found.</div>}
      </section>

      <section style={PANEL}>
        <div style={{ color: "#e2e8f0", fontSize: 11, fontWeight: 750, marginBottom: 8 }}>Reset a password</div>
        <form onSubmit={resetUserPassword} style={{ display: "grid", gridTemplateColumns: "minmax(110px,1fr) minmax(160px,1.4fr) auto", gap: 8 }}>
          <label style={MUTED}>
            Account
            <select required value={resetTarget} onChange={event => setResetTarget(event.target.value)} style={CONTROL}>
              <option value="">Select account…</option>
              {users.map(item => <option value={item.username} key={item.username}>{item.username}</option>)}
            </select>
          </label>
          <label style={MUTED}>
            New password
            <input required minLength={12} maxLength={1024} type="password" autoComplete="new-password"
              value={resetPassword} onChange={event => setResetPassword(event.target.value)} style={CONTROL}/>
          </label>
          <div style={{ display: "flex", alignItems: "end" }}>
            <button disabled={!resetTarget || resetPassword.length < 12 || saving === "reset-password"}
              style={{ ...BUTTON, color: "#50e3d2" }}>
              {saving === "reset-password" ? "Saving…" : "Reset password"}
            </button>
          </div>
        </form>
        <div style={{ ...MUTED, marginTop: 7 }}>Password resets and role/site changes revoke the affected account’s existing sessions.</div>
      </section>
    </div>
  );
}
