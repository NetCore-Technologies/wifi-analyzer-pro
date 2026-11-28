import { useEffect, useRef, useState } from "react";
import {
  Activity, AlertTriangle, CheckCircle2, Clock3, Download, FileSearch,
  Radio, ShieldCheck, Upload, X,
} from "lucide-react";
import { apiFetch } from "../lib/api.js";

const API_BASE = `${window.location.protocol}//${window.location.hostname}:199`;
const MAX_CAPTURE_BYTES = 512 * 1024;
const PANEL = {
  background: "#111624",
  border: "1px solid #29374d",
  borderRadius: 12,
  padding: 16,
};
const MUTED = { color: "#a8b6ca", fontSize: 11 };
const TITLE = { color: "#f1f5fb", fontSize: 12, fontWeight: 700 };
const number = value => new Intl.NumberFormat().format(Number(value) || 0);
const bytes = value => {
  const amount = Number(value) || 0;
  if (amount < 1024) return `${amount} B`;
  if (amount < 1024 * 1024) return `${(amount / 1024).toFixed(1)} KiB`;
  return `${(amount / (1024 * 1024)).toFixed(2)} MiB`;
};

function safeCaptureName(name) {
  const stem = String(name || "capture").replace(/\.[^.]*$/, "");
  return stem.replace(/[^a-zA-Z0-9._-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 48) || "capture";
}

function downloadReport(content, mimeType, filename) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.style.display = "none";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function captureReportCsv(analysis) {
  const rows = [["section", "metric", "value"]];
  const summary = analysis.summary || {};
  const capture = analysis.capture || {};
  for (const [key, value] of Object.entries({
    format: capture.format,
    link_type: capture.link_type_name,
    byte_order: capture.byte_order,
    interface_count: capture.interface_count ?? 1,
    section_count: capture.section_count ?? "",
    timestamp_resolution: capture.timestamp_resolution,
    packet_count: summary.packet_count,
    captured_bytes: summary.captured_bytes,
    wire_bytes: summary.wire_bytes,
    ipv4_packet_count: summary.ipv4_packet_count,
    ipv6_packet_count: summary.ipv6_packet_count,
    arp_packet_count: summary.arp_packet_count,
    truncated_packet_count: summary.truncated_packet_count,
    malformed_frame_count: summary.malformed_frame_count,
    first_packet_at: summary.first_packet_at,
    last_packet_at: summary.last_packet_at,
    average_signal_dbm: analysis.radiotap_observations?.signal?.average_dbm,
    average_noise_dbm: analysis.radiotap_observations?.noise?.average_dbm,
    capture_sha256: capture.capture_sha256,
  })) {
    rows.push(["summary", key, value ?? ""]);
  }
  for (const section of [
    "ether_type_counts",
    "ip_protocol_counts",
    "dscp_counts",
    "wireless_frame_type_counts",
    "wireless_subtype_counts",
    "radiotap_channel_frequency_mhz",
  ]) {
    const values = section === "radiotap_channel_frequency_mhz"
      ? analysis.radiotap_observations?.channel_frequency_mhz_counts || {}
      : analysis[section] || {};
    for (const [key, value] of Object.entries(values)) rows.push([section, key, value]);
  }
  for (const item of analysis.top_destination_ports || []) {
    rows.push(["destination_ports", item.port, item.count]);
  }
  const escape = value => {
    const text = String(value ?? "");
    return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  };
  return rows.map(row => row.map(escape).join(",")).join("\r\n") + "\r\n";
}

function Metric({ label, value, detail }) {
  return (
    <div style={{ ...PANEL, padding: 13 }}>
      <div style={{ ...MUTED, marginBottom: 7 }}>{label}</div>
      <div style={{ color: "#f1f5fb", fontSize: 21, fontWeight: 750, fontVariantNumeric: "tabular-nums" }}>{value}</div>
      {detail && <div style={{ ...MUTED, marginTop: 4 }}>{detail}</div>}
    </div>
  );
}

function CountList({ title, rows, emptyLabel }) {
  const entries = Object.entries(rows || {});
  return (
    <section style={PANEL}>
      <div style={{ ...TITLE, marginBottom: 12 }}>{title}</div>
      {entries.length === 0 ? (
        <div style={MUTED}>{emptyLabel || "No matching packets in this capture."}</div>
      ) : (
        <div style={{ display: "grid", gap: 8 }}>
          {entries.map(([name, count]) => (
            <div key={name} style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12 }}>
              <span style={{ ...MUTED, color: "#a8b6ca" }}>{name}</span>
              <strong style={{ color: "#ff8359", fontSize: 12, fontVariantNumeric: "tabular-nums" }}>{number(count)}</strong>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

export default function PcapAnalyzer() {
  const inputRef = useRef(null);
  const [file, setFile] = useState(null);
  const [maximumPackets, setMaximumPackets] = useState(5000);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [analysis, setAnalysis] = useState(null);
  const [captureInventory, setCaptureInventory] = useState({ available: false, interfaces: [], reason: "Checking local capture support…" });
  const [selectedInterface, setSelectedInterface] = useState("");
  const [filterProfile, setFilterProfile] = useState("all");
  const [durationSeconds, setDurationSeconds] = useState(15);
  const [packetLimit, setPacketLimit] = useState(250);
  const [captureConsent, setCaptureConsent] = useState(false);
  const [startingCapture, setStartingCapture] = useState(false);
  const [liveCapture, setLiveCapture] = useState(null);

  useEffect(() => {
    let disposed = false;
    apiFetch(`${API_BASE}/api/capture/interfaces`, { signal: AbortSignal.timeout(8000) })
      .then(response => response.json().then(data => ({ response, data })))
      .then(({ response, data }) => {
        if (disposed) return;
        if (!response.ok) throw new Error(data.error || `Capture inventory failed (HTTP ${response.status})`);
        setCaptureInventory(data);
        if (data.interfaces?.length) setSelectedInterface(data.interfaces[0].name);
      })
      .catch(caught => {
        if (!disposed) setCaptureInventory({ available: false, interfaces: [], reason: caught.message || "Could not inspect packet-capture support." });
      });
    return () => { disposed = true; };
  }, []);

  useEffect(() => {
    if (liveCapture?.state !== "running") return undefined;
    let disposed = false;
    const refresh = async () => {
      try {
        const response = await apiFetch(`${API_BASE}/api/capture/status`, { signal: AbortSignal.timeout(5000) });
        const data = await response.json().catch(() => ({}));
        if (!disposed && response.ok && data.capture) setLiveCapture(data.capture);
      } catch {
        // Keep the last known capture state; the operator can still stop it manually.
      }
    };
    refresh();
    const timer = window.setInterval(refresh, 1200);
    return () => { disposed = true; window.clearInterval(timer); };
  }, [liveCapture?.capture_id, liveCapture?.state]);

  const chooseFile = event => {
    const selected = event.target.files?.[0] || null;
    setError("");
    setAnalysis(null);
    if (selected && selected.size > MAX_CAPTURE_BYTES) {
      setFile(null);
      setError(`The selected file is ${bytes(selected.size)}. The maximum is ${bytes(MAX_CAPTURE_BYTES)}.`);
      event.target.value = "";
      return;
    }
    setFile(selected);
  };

  const clearFile = () => {
    setFile(null);
    setAnalysis(null);
    setError("");
    if (inputRef.current) inputRef.current.value = "";
  };

  const analyze = async (targetFile = file) => {
    if (!targetFile || busy) return;
    if (targetFile.size === 0) {
      setError("The selected capture file is empty.");
      return;
    }
    setBusy(true);
    setError("");
    setAnalysis(null);
    try {
      const data = new Uint8Array(await targetFile.arrayBuffer());
      let binary = "";
      const chunkSize = 0x8000;
      for (let offset = 0; offset < data.length; offset += chunkSize) {
        binary += String.fromCharCode(...data.subarray(offset, offset + chunkSize));
      }
      const captureBase64 = window.btoa(binary);
      const response = await apiFetch(`${API_BASE}/api/features/pcap_capture_analyzer`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          capture_base64: captureBase64,
          maximum_packets: maximumPackets,
        }),
        signal: AbortSignal.timeout(30000),
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        throw new Error(payload.error || `PCAP analysis failed with HTTP ${response.status}`);
      }
      setAnalysis(payload.result || null);
    } catch (caught) {
      setError(caught?.message || "The capture could not be analysed.");
    } finally {
      setBusy(false);
    }
  };

  const startLiveCapture = async () => {
    if (!captureConsent || !selectedInterface || startingCapture) return;
    setStartingCapture(true);
    setError("");
    try {
      const response = await apiFetch(`${API_BASE}/api/capture/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          interface: selectedInterface,
          duration_seconds: durationSeconds,
          packet_limit: packetLimit,
          filter_profile: filterProfile,
        }),
        signal: AbortSignal.timeout(12000),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || `Capture start failed (HTTP ${response.status})`);
      setLiveCapture(data.capture || null);
    } catch (caught) {
      setError(caught.message || "Could not start the local packet capture.");
    } finally {
      setStartingCapture(false);
    }
  };

  const stopLiveCapture = async () => {
    if (!liveCapture?.capture_id) return;
    setError("");
    try {
      const response = await apiFetch(`${API_BASE}/api/capture/stop`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ capture_id: liveCapture.capture_id }),
        signal: AbortSignal.timeout(8000),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || `Capture stop failed (HTTP ${response.status})`);
      setLiveCapture(data.capture || null);
    } catch (caught) {
      setError(caught.message || "Could not stop the local packet capture.");
    }
  };

  const loadLiveCaptureForAnalysis = async () => {
    if (!liveCapture?.capture_id || liveCapture.state !== "completed" || busy) return;
    setError("");
    try {
      const response = await apiFetch(`${API_BASE}/api/capture/${liveCapture.capture_id}/download`, {
        signal: AbortSignal.timeout(12000),
      });
      if (!response.ok) {
        const data = await response.json().catch(() => ({}));
        throw new Error(data.error || `PCAP download failed (HTTP ${response.status})`);
      }
      const blob = await response.blob();
      if (blob.size === 0 || blob.size > MAX_CAPTURE_BYTES) {
        throw new Error("The captured file is empty or exceeds the 512 KiB analysis limit.");
      }
      const capturedFile = new File([blob], `live-${liveCapture.interface}-${liveCapture.capture_id.slice(0, 8)}.pcap`, {
        type: "application/vnd.tcpdump.pcap",
      });
      setFile(capturedFile);
      setAnalysis(null);
      await analyze(capturedFile);
    } catch (caught) {
      setError(caught.message || "Could not load the live capture into the analyzer.");
    }
  };

  const summary = analysis?.summary || {};
  const capture = analysis?.capture || {};
  const radio = analysis?.radiotap_observations || {};

  return (
    <div style={{ display: "grid", gap: 16, maxWidth: 1120, margin: "0 auto" }}>
      <section style={{
        ...PANEL, padding: 20,
        background: "linear-gradient(145deg, #29374d, #111624)",
        borderColor: "#2a596b",
      }}>
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 16, flexWrap: "wrap" }}>
          <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
            <div style={{
              width: 42, height: 42, borderRadius: 12, display: "grid", placeItems: "center",
              background: "rgba(80,227,210,.12)", border: "1px solid rgba(80,227,210,.25)",
            }}>
              <FileSearch size={20} color="#ff8359"/>
            </div>
            <div>
              <div style={{ color: "#f1f5fb", fontSize: 16, fontWeight: 800 }}>Packet capture analysis</div>
              <div style={MUTED}>Offline PCAP / PCAPNG inspection · F191</div>
            </div>
          </div>
          <span style={{
            border: "1px solid rgba(80,227,210,.3)", borderRadius: 99,
            padding: "5px 9px", color: "#ff8359", fontSize: 10, fontWeight: 700,
          }}>LOCAL ANALYSIS</span>
        </div>

        <div style={{
          marginTop: 16, padding: 15, border: "1px solid #2a596b", borderRadius: 10,
          background: "rgba(4,14,24,.45)", display: "grid", gap: 12,
        }}>
          <div style={{ display: "flex", justifyContent: "space-between", gap: 12, flexWrap: "wrap", alignItems: "center" }}>
            <div>
              <div style={{ color: "#f1f5fb", fontSize: 12, fontWeight: 750 }}>Live interface capture</div>
              <div style={{ ...MUTED, marginTop: 4 }}>Explicit, local capture via tcpdump / libpcap · no monitor-mode changes</div>
            </div>
            <span style={{ color: captureInventory.available ? "#56d6ae" : "#f2c36b", fontSize: 10, fontWeight: 750 }}>
              {captureInventory.available ? "CAPTURE SUPPORT AVAILABLE" : "CAPTURE SUPPORT UNAVAILABLE"}
            </span>
          </div>
          {captureInventory.available ? (
            <>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(150px,1fr))", gap: 9 }}>
                <label style={{ ...MUTED, display: "grid", gap: 5 }}>
                  Interface
                  <select aria-label="Capture network interface" value={selectedInterface} onChange={event => setSelectedInterface(event.target.value)}
                    disabled={startingCapture || liveCapture?.state === "running"}
                    style={{ background: "#090c15", color: "#f1f5fb", border: "1px solid #435775", borderRadius: 7, padding: "8px 9px", fontSize: 11 }}>
                    {captureInventory.interfaces.map(item => <option key={item.name} value={item.name}>{item.description}</option>)}
                  </select>
                </label>
                <label style={{ ...MUTED, display: "grid", gap: 5 }}>
                  Capture filter
                  <select aria-label="Capture filter profile" value={filterProfile} onChange={event => setFilterProfile(event.target.value)}
                    disabled={startingCapture || liveCapture?.state === "running"}
                    style={{ background: "#090c15", color: "#f1f5fb", border: "1px solid #435775", borderRadius: 7, padding: "8px 9px", fontSize: 11 }}>
                    <option value="all">All traffic</option>
                    <option value="dns">DNS</option>
                    <option value="dhcp">DHCP</option>
                    <option value="arp">ARP</option>
                    <option value="tcp">TCP</option>
                    <option value="udp">UDP</option>
                    <option value="icmp">ICMP / ICMPv6</option>
                  </select>
                </label>
                <label style={{ ...MUTED, display: "grid", gap: 5 }}>
                  Duration
                  <select aria-label="Capture duration" value={durationSeconds} onChange={event => setDurationSeconds(Number(event.target.value))}
                    disabled={startingCapture || liveCapture?.state === "running"}
                    style={{ background: "#090c15", color: "#f1f5fb", border: "1px solid #435775", borderRadius: 7, padding: "8px 9px", fontSize: 11 }}>
                    <option value={5}>5 seconds</option>
                    <option value={15}>15 seconds</option>
                    <option value={30}>30 seconds</option>
                    <option value={60}>60 seconds (max)</option>
                  </select>
                </label>
                <label style={{ ...MUTED, display: "grid", gap: 5 }}>
                  Packet limit
                  <select aria-label="Capture packet limit" value={packetLimit} onChange={event => setPacketLimit(Number(event.target.value))}
                    disabled={startingCapture || liveCapture?.state === "running"}
                    style={{ background: "#090c15", color: "#f1f5fb", border: "1px solid #435775", borderRadius: 7, padding: "8px 9px", fontSize: 11 }}>
                    <option value={100}>100 packets</option>
                    <option value={250}>250 packets</option>
                    <option value={500}>500 packets</option>
                    <option value={1000}>1,000 packets (max)</option>
                  </select>
                </label>
              </div>
              <label style={{ display: "flex", gap: 8, alignItems: "flex-start", color: "#f2c36b", fontSize: 10, lineHeight: 1.55 }}>
                <input type="checkbox" checked={captureConsent} onChange={event => setCaptureConsent(event.target.checked)} disabled={liveCapture?.state === "running"} style={{ marginTop: 2 }}/>
                I am authorised to capture traffic on this interface and network. Captures can contain sensitive data.
              </label>
              <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                {liveCapture?.state === "running" ? (
                  <button type="button" onClick={stopLiveCapture} style={{ border: "1px solid #f2c36b", borderRadius: 8, padding: "8px 11px", background: "rgba(245,158,11,.12)", color: "#f2c36b", fontSize: 11, fontWeight: 750, cursor: "pointer" }}>
                    Stop capture
                  </button>
                ) : (
                  <button type="button" onClick={startLiveCapture} disabled={!captureConsent || !selectedInterface || startingCapture}
                    style={{ border: "1px solid #ff8359", borderRadius: 8, padding: "8px 11px", background: captureConsent && selectedInterface && !startingCapture ? "#ff8359" : "#29374d", color: captureConsent && selectedInterface && !startingCapture ? "#090c15" : "#a8b6ca", fontSize: 11, fontWeight: 800, cursor: captureConsent && !startingCapture ? "pointer" : "not-allowed" }}>
                    {startingCapture ? "Starting…" : liveCapture?.state === "completed" ? "Start another capture" : "Start live capture"}
                  </button>
                )}
                {liveCapture?.state === "completed" ? (
                  <button type="button" onClick={loadLiveCaptureForAnalysis} disabled={busy}
                    style={{ border: "1px solid #435775", borderRadius: 8, padding: "8px 11px", background: "#182235", color: "#a8b6ca", fontSize: 11, fontWeight: 750, cursor: "pointer" }}>
                    {busy ? "Analysing…" : "Load & analyse PCAP"}
                  </button>
                ) : null}
                {liveCapture ? <span style={{ ...MUTED, color: liveCapture.state === "failed" ? "#ff7185" : liveCapture.state === "running" ? "#ff8359" : "#a8b6ca" }}>
                  {liveCapture.state.toUpperCase()} · {liveCapture.interface} · {bytes(liveCapture.captured_bytes || 0)}
                </span> : null}
              </div>
              {liveCapture?.error ? <div role="alert" style={{ color: "#ff7185", fontSize: 10 }}>{liveCapture.error}</div> : null}
              <div style={MUTED}>Hard limits: 60 seconds · 1,000 packets · 256-byte snap length · 512 KiB file. Only one capture runs at a time.</div>
            </>
          ) : (
            <div style={{ ...MUTED, lineHeight: 1.6 }}>
              {captureInventory.reason || "No supported packet-capture interface is available."}
              {" "}Install tcpdump/libpcap and grant this service account capture permissions, then reload this page. WiFi Analyzer Pro will not elevate privileges or change monitor mode automatically.
            </div>
          )}
        </div>

        <div style={{
          marginTop: 18, padding: 16, border: "1px dashed #435775", borderRadius: 10,
          background: "rgba(4,14,24,.35)",
        }}>
          <input
            ref={inputRef}
            type="file"
            accept=".pcap,.pcapng,.cap,application/vnd.tcpdump.pcap,application/octet-stream"
            onChange={chooseFile}
            aria-label="Choose a PCAP or PCAPNG capture file"
            style={{ display: "none" }}
          />
          {!file ? (
            <button type="button" onClick={() => inputRef.current?.click()} style={{
              display: "flex", alignItems: "center", gap: 10, cursor: "pointer",
              border: "1px solid #435775", borderRadius: 9, padding: "10px 13px",
              color: "#f1f5fb", background: "#182235", fontSize: 12, fontWeight: 700,
            }}>
              <Upload size={15} color="#ff8359"/> Choose PCAP / PCAPNG file
            </button>
          ) : (
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10, minWidth: 0 }}>
                <Radio size={18} color="#ff8359"/>
                <div style={{ minWidth: 0 }}>
                  <div style={{ color: "#f1f5fb", fontSize: 12, fontWeight: 700, overflowWrap: "anywhere" }}>{file.name}</div>
                  <div style={MUTED}>{bytes(file.size)} · ready for analysis</div>
                </div>
              </div>
              <button type="button" onClick={clearFile} aria-label="Remove selected capture" style={{
                background: "transparent", border: "1px solid #435775", borderRadius: 7,
                color: "#a8b6ca", padding: 7, cursor: "pointer",
              }}><X size={14}/></button>
            </div>
          )}
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap", marginTop: 14 }}>
          <label style={{ ...MUTED, display: "flex", alignItems: "center", gap: 8 }}>
            Maximum packets
            <select value={maximumPackets} onChange={event => setMaximumPackets(Number(event.target.value))}
              style={{
                background: "#090c15", color: "#f1f5fb", border: "1px solid #435775",
                borderRadius: 7, padding: "7px 9px", fontSize: 11,
              }}>
              <option value={250}>250</option>
              <option value={1000}>1,000</option>
              <option value={2500}>2,500</option>
              <option value={5000}>5,000</option>
            </select>
          </label>
          <button type="button" onClick={analyze} disabled={!file || busy} style={{
            display: "inline-flex", alignItems: "center", gap: 8, cursor: file && !busy ? "pointer" : "not-allowed",
            border: "1px solid #ff8359", borderRadius: 8, padding: "9px 13px",
            background: file && !busy ? "#ff8359" : "#29374d",
            color: file && !busy ? "#090c15" : "#a8b6ca",
            fontSize: 12, fontWeight: 800,
          }}>
            <Activity size={14}/>{busy ? "Analysing…" : "Analyse capture"}
          </button>
        </div>
        <div style={{ ...MUTED, marginTop: 12, lineHeight: 1.6 }}>
          PCAP / PCAPNG · 512 KiB maximum · Multi-interface captures · Ethernet, Linux cooked, 802.11 and radiotap
        </div>
      </section>

      {error && (
        <div role="alert" style={{
          display: "flex", alignItems: "center", gap: 9, padding: 12,
          borderRadius: 9, border: "1px solid rgba(255,115,132,.35)",
          background: "rgba(255,115,132,.08)", color: "#ff9eac", fontSize: 12,
        }}>
          <AlertTriangle size={15}/>{error}
        </div>
      )}

      {analysis && (
        <>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
            <div>
              <div style={{ color: "#f1f5fb", fontSize: 14, fontWeight: 800 }}>Capture summary</div>
              <div style={MUTED}>{String(capture.format || "pcap").toUpperCase()} · {capture.link_type_name} · {capture.byte_order}-endian · {capture.timestamp_resolution} timestamps · {number(capture.interface_count || 1)} interface{capture.interface_count === 1 || !capture.interface_count ? "" : "s"}{capture.section_count ? ` · ${number(capture.section_count)} sections` : ""}</div>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
              <div style={{ ...MUTED, display: "flex", alignItems: "center", gap: 6 }}>
                <CheckCircle2 size={14} color="#ff8359"/> Analysis complete
              </div>
              <button type="button" onClick={() => downloadReport(
                JSON.stringify({ schema_version: "1.0", generated_at: new Date().toISOString(), analysis }, null, 2),
                "application/json;charset=utf-8",
                `${safeCaptureName(file?.name)}-analysis.json`,
              )} style={{
                display: "inline-flex", alignItems: "center", gap: 6, cursor: "pointer",
                border: "1px solid #435775", borderRadius: 7, padding: "6px 9px",
                color: "#a8b6ca", background: "#182235", fontSize: 10, fontWeight: 700,
              }}>
                <Download size={12}/> JSON
              </button>
              <button type="button" onClick={() => downloadReport(
                captureReportCsv(analysis),
                "text/csv;charset=utf-8",
                `${safeCaptureName(file?.name)}-analysis.csv`,
              )} style={{
                display: "inline-flex", alignItems: "center", gap: 6, cursor: "pointer",
                border: "1px solid #435775", borderRadius: 7, padding: "6px 9px",
                color: "#a8b6ca", background: "#182235", fontSize: 10, fontWeight: 700,
              }}>
                <Download size={12}/> CSV
              </button>
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(150px,1fr))", gap: 10 }}>
            <Metric label="Packets" value={number(summary.packet_count)} detail="Records analysed"/>
            <Metric label="Captured bytes" value={bytes(summary.captured_bytes)} detail={`${bytes(summary.wire_bytes)} on wire`}/>
            <Metric label="IPv4 / IPv6" value={`${number(summary.ipv4_packet_count)} / ${number(summary.ipv6_packet_count)}`} detail={`${number(summary.arp_packet_count)} ARP frames`}/>
            <Metric label="Truncated / malformed" value={`${number(summary.truncated_packet_count)} / ${number(summary.malformed_frame_count)}`} detail="Capture quality"/>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(150px,1fr))", gap: 10 }}>
            <Metric label="Average antenna signal" value={radio.signal?.average_dbm == null ? "—" : `${radio.signal.average_dbm} dBm`} detail={`${number(radio.signal?.sample_count)} radiotap samples`}/>
            <Metric label="Average noise" value={radio.noise?.average_dbm == null ? "—" : `${radio.noise.average_dbm} dBm`} detail={`${number(radio.noise?.sample_count)} radiotap samples`}/>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(230px,1fr))", gap: 12 }}>
            <CountList title="Radiotap channel frequencies (MHz)" rows={radio.channel_frequency_mhz_counts}/>
            <CountList title="IP protocol distribution" rows={analysis.ip_protocol_counts}/>
            <CountList title="EtherType distribution" rows={analysis.ether_type_counts}/>
            <CountList title="DSCP distribution" rows={analysis.dscp_counts}/>
            <CountList title="802.11 frame types" rows={analysis.wireless_frame_type_counts}/>
            <CountList title="802.11 subtypes" rows={analysis.wireless_subtype_counts}/>
          </div>

          <section style={PANEL}>
            <div style={{ ...TITLE, marginBottom: 12 }}>Top destination ports</div>
            {analysis.top_destination_ports?.length ? (
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit,minmax(110px,1fr))", gap: 9 }}>
                {analysis.top_destination_ports.map(item => (
                  <div key={item.port} style={{ background: "#182235", border: "1px solid #29374d", borderRadius: 8, padding: 10 }}>
                    <div style={{ ...MUTED }}>Port {item.port}</div>
                    <div style={{ color: "#ff8359", fontWeight: 800, fontSize: 16 }}>{number(item.count)}</div>
                  </div>
                ))}
              </div>
            ) : <div style={MUTED}>No TCP or UDP destination ports were observed.</div>}
          </section>

          <section style={{ ...PANEL, display: "grid", gap: 8 }}>
            <div style={{ ...TITLE, display: "flex", alignItems: "center", gap: 7 }}>
              <Clock3 size={14} color="#ff8359"/> Capture time range
            </div>
            <div style={MUTED}>First packet: {summary.first_packet_at || "—"}</div>
            <div style={MUTED}>Last packet: {summary.last_packet_at || "—"}</div>
            <div style={MUTED}>SHA-256: <span style={{ color: "#a8b6ca", overflowWrap: "anywhere" }}>{capture.capture_sha256}</span></div>
          </section>

          <div style={{
            ...PANEL, display: "flex", alignItems: "flex-start", gap: 10,
            borderColor: "rgba(80,227,210,.25)", background: "rgba(80,227,210,.05)",
          }}>
            <ShieldCheck size={17} color="#ff8359" style={{ flexShrink: 0, marginTop: 1 }}/>
            <div style={{ ...MUTED, lineHeight: 1.65, color: "#b6c8d0" }}>
              Privacy-preserving output: packet payloads, source and destination addresses, SSIDs and BSSIDs are not returned. The capture is processed by your authenticated local analyzer.
            </div>
          </div>
        </>
      )}
    </div>
  );
}
