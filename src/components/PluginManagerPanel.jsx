import { useCallback, useEffect, useState } from "react";
import { apiBase, apiFetch } from "../lib/api.js";
import { CheckCircle2, CircleAlert, Package, RefreshCw, ShieldCheck, ShieldX, ToggleLeft, ToggleRight } from "lucide-react";

const panel = { background:"#111624", border:"1px solid #29374d", borderRadius:10, padding:16 };
const button = { border:"1px solid #29405f", borderRadius:7, padding:"7px 10px", fontSize:11, fontWeight:700, cursor:"pointer", display:"inline-flex", alignItems:"center", gap:6 };
const muted = "#a8b6ca";

export default function PluginManagerPanel() {
  const [plugins, setPlugins] = useState([]);
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const load = useCallback(async ({ quiet = false } = {}) => {
    if (!quiet) setLoading(true);
    setError("");
    try {
      const response = await apiFetch(apiBase() + "/api/plugins", {
        signal: AbortSignal.timeout(10000),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(typeof data.error === "string" ? data.error : "Plugin directory returned HTTP " + response.status);
      }
      setPlugins(Array.isArray(data.plugins) ? data.plugins : []);
      setSummary(data);
    } catch (failure) {
      setError(failure?.message || "Could not load the plugin directory");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const perform = async (plugin, operation) => {
    setBusyId(plugin.plugin_id);
    setError("");
    setNotice("");
    try {
      const response = await apiFetch(
        apiBase() + "/api/plugins/" + encodeURIComponent(plugin.plugin_id) + "/" + operation,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: "{}",
          signal: AbortSignal.timeout(20000),
        },
      );
      const data = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(typeof data.error === "string" ? data.error : "Plugin " + operation + " returned HTTP " + response.status);
      }
      const label = operation === "enable" ? "enabled" : operation === "disable" ? "disabled" : "reloaded";
      setNotice((plugin.name || plugin.plugin_id) + " " + label + ".");
      await load({ quiet:true });
    } catch (failure) {
      setError(failure?.message || "Plugin " + operation + " failed");
    } finally {
      setBusyId("");
    }
  };

  return (
    <div style={{ display:"grid", gap:14 }}>
      <section style={panel}>
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", gap:12, flexWrap:"wrap" }}>
          <div style={{ display:"flex", alignItems:"center", gap:10 }}>
            <div style={{ width:36, height:36, borderRadius:9, background:"rgba(255,131,89,0.10)", color:"#ff8359", display:"grid", placeItems:"center" }}>
              <Package size={19}/>
            </div>
            <div>
              <div style={{ color:"#f1f5fb", fontWeight:800, fontSize:15 }}>Third-party feature plugins</div>
              <div style={{ color:muted, fontSize:11, marginTop:3 }}>Publisher-signed extensions installed on this host</div>
            </div>
          </div>
          <button type="button" onClick={() => load()} disabled={loading || !!busyId} style={{ ...button, color:"#cbd5e1", background:"#182235", opacity:loading ? 0.6 : 1 }}>
            <RefreshCw size={13}/> Refresh
          </button>
        </div>

        {summary && (
          <div style={{ display:"flex", flexWrap:"wrap", gap:8, marginTop:16 }}>
            {[
              ["Verified", summary.plugin_count ?? 0, "#56d6ae"],
              ["Enabled", summary.enabled_count ?? 0, "#ff8359"],
              ["Rejected", summary.rejected_count ?? 0, "#f2c36b"],
            ].map(([label, value, color]) => (
              <div key={label} style={{ border:"1px solid #263956", background:"#080d18", borderRadius:8, padding:"8px 11px", minWidth:88 }}>
                <div style={{ color:muted, fontSize:10, textTransform:"uppercase", letterSpacing:0.6 }}>{label}</div>
                <div style={{ color, fontSize:20, fontWeight:800, marginTop:2 }}>{value}</div>
              </div>
            ))}
          </div>
        )}
        {error && <div role="alert" style={{ display:"flex", gap:8, color:"#fca5a5", background:"rgba(255,113,133,0.08)", border:"1px solid rgba(255,113,133,0.3)", borderRadius:8, padding:10, fontSize:12, marginTop:14 }}><CircleAlert size={15}/>{error}</div>}
        {notice && <div role="status" style={{ display:"flex", gap:8, color:"#86efac", background:"rgba(86,214,174,0.08)", border:"1px solid rgba(86,214,174,0.25)", borderRadius:8, padding:10, fontSize:12, marginTop:14 }}><CheckCircle2 size={15}/>{notice}</div>}
      </section>

      {loading ? (
        <div style={{ ...panel, color:muted, fontSize:12 }}>Loading the local signed-plugin directory…</div>
      ) : plugins.length === 0 ? (
        <div style={{ ...panel, textAlign:"center", padding:28 }}>
          <Package size={30} color="#71829a"/>
          <div style={{ color:"#f1f5fb", fontWeight:700, marginTop:10 }}>No third-party plugins installed</div>
          <div style={{ color:muted, fontSize:12, lineHeight:1.65, maxWidth:540, margin:"7px auto 0" }}>
            Install a reviewed, publisher-signed package on the host and add its publisher public key to the local trust store. The API intentionally does not accept plugin uploads.
          </div>
        </div>
      ) : (
        <div style={{ display:"grid", gap:10 }}>
          {plugins.map((plugin, index) => {
            const verified = plugin.signature_verified === true;
            const enabled = plugin.enabled === true;
            const rejected = plugin.status === "rejected" || !verified;
            return (
              <section key={plugin.plugin_id || ("rejected-" + index)} style={{ ...panel, borderColor:rejected ? "rgba(242,195,107,0.35)" : "#29374d" }}>
                <div style={{ display:"flex", alignItems:"flex-start", justifyContent:"space-between", gap:12, flexWrap:"wrap" }}>
                  <div style={{ minWidth:0, flex:"1 1 280px" }}>
                    <div style={{ display:"flex", alignItems:"center", gap:8, flexWrap:"wrap" }}>
                      <div style={{ color:"#f1f5fb", fontWeight:800, fontSize:13 }}>{plugin.name || plugin.plugin_id || "Unidentified package"}</div>
                      {verified ? (
                        <span style={{ display:"inline-flex", alignItems:"center", gap:4, padding:"3px 6px", borderRadius:5, color:"#86efac", background:"rgba(86,214,174,0.10)", fontSize:9, fontWeight:800, letterSpacing:0.5 }}>
                          <ShieldCheck size={11}/> SIGNATURE VERIFIED
                        </span>
                      ) : (
                        <span style={{ display:"inline-flex", alignItems:"center", gap:4, padding:"3px 6px", borderRadius:5, color:"#fbbf24", background:"rgba(242,195,107,0.10)", fontSize:9, fontWeight:800, letterSpacing:0.5 }}>
                          <ShieldX size={11}/> REJECTED
                        </span>
                      )}
                      {verified && <span style={{ padding:"3px 6px", borderRadius:5, color:enabled ? "#67e8f9" : muted, background:enabled ? "rgba(255,131,89,0.09)" : "rgba(148,163,184,0.08)", fontSize:9, fontWeight:800 }}>{enabled ? "ENABLED" : "DISABLED"}</span>}
                    </div>
                    <div style={{ color:muted, fontSize:10, marginTop:6, overflowWrap:"anywhere" }}>
                      {plugin.plugin_id || "Invalid package"}{plugin.version ? " · v" + plugin.version : ""}{plugin.publisher ? " · " + plugin.publisher : ""}
                    </div>
                    <div style={{ color:"#cbd5e1", fontSize:11, lineHeight:1.55, marginTop:9 }}>
                      {plugin.description || plugin.error_code || "Package verification failed. Review the package and local publisher trust store."}
                    </div>
                    {verified && <div style={{ color:muted, fontSize:10, marginTop:8 }}>Required permissions: {plugin.permissions?.length ? plugin.permissions.join(", ") : "none declared"}</div>}
                    {rejected && plugin.error_code && <div style={{ color:"#fbbf24", fontSize:10, marginTop:7 }}>Validation code: {plugin.error_code}</div>}
                  </div>
                  {verified && (
                    <div style={{ display:"flex", gap:7, flexWrap:"wrap" }}>
                      {!enabled ? (
                        <button type="button" disabled={!!busyId} onClick={() => perform(plugin, "enable")} style={{ ...button, background:"rgba(86,214,174,0.10)", borderColor:"rgba(86,214,174,0.35)", color:"#86efac" }}>
                          <ToggleRight size={13}/> Enable
                        </button>
                      ) : (
                        <>
                          <button type="button" disabled={!!busyId} onClick={() => perform(plugin, "reload")} style={{ ...button, background:"#182235", color:"#cbd5e1" }}>
                            <RefreshCw size={13} style={busyId === plugin.plugin_id ? { animation:"spin 1s linear infinite" } : {}}/> Reload
                          </button>
                          <button type="button" disabled={!!busyId} onClick={() => perform(plugin, "disable")} style={{ ...button, background:"rgba(255,113,133,0.08)", borderColor:"rgba(255,113,133,0.3)", color:"#fca5a5" }}>
                            <ToggleLeft size={13}/> Disable
                          </button>
                        </>
                      )}
                    </div>
                  )}
                </div>
              </section>
            );
          })}
        </div>
      )}

      <section style={{ ...panel, borderColor:"rgba(242,195,107,0.3)", background:"rgba(242,195,107,0.035)" }}>
        <div style={{ display:"flex", alignItems:"center", gap:8, color:"#fbbf24", fontSize:11, fontWeight:800 }}>
          <ShieldCheck size={14}/> TRUST BOUNDARY
        </div>
        <p style={{ color:"#cbd5e1", fontSize:11, lineHeight:1.65, margin:"8px 0 0" }}>
          A valid signature proves publisher identity and package integrity; it does not sandbox Python. Enabled plugins run inside the API process with the service account's operating-system permissions. Enable only code you have reviewed and trust.
        </p>
        <a href="https://github.com/NetCore-Technologies/wifi-analyzer-pro/blob/main/wifi_analyzer_backend/PLUGIN_SDK.md" target="_blank" rel="noreferrer" style={{ display:"inline-flex", alignItems:"center", gap:6, color:"#67e8f9", fontSize:11, marginTop:10, textDecoration:"none" }}>
          <ShieldCheck size={12}/> Developer SDK and installation guide
        </a>
      </section>
    </div>
  );
}
