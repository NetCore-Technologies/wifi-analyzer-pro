import { useRef, useState } from "react";
import {
  Activity, AlertTriangle, CheckCircle2, Clock3, Download, FileSearch,
  Radio, ShieldCheck, Upload, X,
} from "lucide-react";
import { apiFetch } from "../lib/api.js";

const API_BASE = `${window.location.protocol}//${window.location.hostname}:199`;
const MAX_CAPTURE_BYTES = 512 * 1024;
const PANEL = {
  background: "#0c1120",
  border: "1px solid #1e2d47",
  borderRadius: 12,
  padding: 16,
};
const MUTED = { color: "#94a3b8", fontSize: 11 };
const TITLE = { color: "#e2e8f0", fontSize: 12, fontWeight: 700 };
const number = value => new Intl.NumberFormat().format(Number(value) || 0);
const bytes = value => {
  const amount = Number(value) || 0;
  if (amount < 1024) return `${amount} B`;
  if (amount < 1024 * 1024) return `${(amount / 1024).toFixed(1)} KiB`;
  return `${(amount / (1024 * 1024)).toFixed(2)} MiB`;
};

function safeCaptureName(name) {
  const stem = String(name || "capture").replace(/\\.[^.]*$/, "");
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
    return /[",\\r\\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  };
  return rows.map(row => row.map(escape).join(",")).join("\\r\\n") + "\\r\\n";
}

function Metric({ label, value, detail }) {
  return (
    <div style={{ ...PANEL, padding: 13 }}>
      <div style={{ ...MUTED, marginBottom: 7 }}>{label}</div>
      <div style={{ color: "#e2e8f0", fontSize: 21, fontWeight: 750, fontVariantNumeric: "tabular-nums" }}>{value}</div>
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
              <span style={{ ...MUTED, color: "#cbd5e1" }}>{name}</span>
              <strong style={{ color: "#50e3d2", fontSize: 12, fontVariantNumeric: "tabular-nums" }}>{number(count)}</strong>
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

  const analyze = async () => {
    if (!file || busy) return;
    if (file.size === 0) {
      setError("The selected capture file is empty.");
      return;
    }
    setBusy(true);
    setError("");
    setAnalysis(null);
    try {
      const data = new Uint8Array(await file.arrayBuffer());
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

  const summary = analysis?.summary || {};
  const capture = analysis?.capture || {};
  const radio = analysis?.radiotap_observations || {};

  return (
    <div style={{ display: "grid", gap: 16, maxWidth: 1120, margin: "0 auto" }}>
      <section style={{
        ...PANEL, padding: 20,
        background: "linear-gradient(145deg, #102d3d, #0c1120)",
        borderColor: "#2a596b",
      }}>
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 16, flexWrap: "wrap" }}>
          <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
            <div style={{
              width: 42, height: 42, borderRadius: 12, display: "grid", placeItems: "center",
              background: "rgba(80,227,210,.12)", border: "1px solid rgba(80,227,210,.25)",
            }}>
              <FileSearch size={20} color="#50e3d2"/>
            </div>
            <div>
              <div style={{ color: "#e2e8f0", fontSize: 16, fontWeight: 800 }}>Packet capture analysis</div>
              <div style={MUTED}>Offline PCAP inspection · F191</div>
            </div>
          </div>
          <span style={{
            border: "1px solid rgba(80,227,210,.3)", borderRadius: 99,
            padding: "5px 9px", color: "#50e3d2", fontSize: 10, fontWeight: 700,
          }}>LOCAL ANALYSIS</span>
        </div>

        <div style={{
          marginTop: 18, padding: 16, border: "1px dashed #3b6677", borderRadius: 10,
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
              border: "1px solid #2a3f65", borderRadius: 9, padding: "10px 13px",
              color: "#e2e8f0", background: "#111827", fontSize: 12, fontWeight: 700,
            }}>
              <Upload size={15} color="#50e3d2"/> Choose PCAP file
            </button>
          ) : (
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, flexWrap: "wrap" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 10, minWidth: 0 }}>
                <Radio size={18} color="#50e3d2"/>
                <div style={{ minWidth: 0 }}>
                  <div style={{ color: "#e2e8f0", fontSize: 12, fontWeight: 700, overflowWrap: "anywhere" }}>{file.name}</div>
                  <div style={MUTED}>{bytes(file.size)} · ready for analysis</div>
                </div>
              </div>
              <button type="button" onClick={clearFile} aria-label="Remove selected capture" style={{
                background: "transparent", border: "1px solid #2a3f65", borderRadius: 7,
                color: "#94a3b8", padding: 7, cursor: "pointer",
              }}><X size={14}/></button>
            </div>
          )}
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap", marginTop: 14 }}>
          <label style={{ ...MUTED, display: "flex", alignItems: "center", gap: 8 }}>
            Maximum packets
            <select value={maximumPackets} onChange={event => setMaximumPackets(Number(event.target.value))}
              style={{
                background: "#070b14", color: "#e2e8f0", border: "1px solid #2a3f65",
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
            border: "1px solid #50e3d2", borderRadius: 8, padding: "9px 13px",
            background: file && !busy ? "#50e3d2" : "#24404a",
            color: file && !busy ? "#07111d" : "#94a3b8",
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
          background: "rgba(255,115,132,.08)", color: "#ff9aa6", fontSize: 12,
        }}>
          <AlertTriangle size={15}/>{error}
        </div>
      )}

      {analysis && (
        <>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 12, flexWrap: "wrap" }}>
            <div>
              <div style={{ color: "#e2e8f0", fontSize: 14, fontWeight: 800 }}>Capture summary</div>
              <div style={MUTED}>{String(capture.format || "pcap").toUpperCase()} · {capture.link_type_name} · {capture.byte_order}-endian · {capture.timestamp_resolution} timestamps · {number(capture.interface_count || 1)} interface{capture.interface_count === 1 || !capture.interface_count ? "" : "s"}{capture.section_count ? ` · ${number(capture.section_count)} sections` : ""}</div>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" }}>
              <div style={{ ...MUTED, display: "flex", alignItems: "center", gap: 6 }}>
                <CheckCircle2 size={14} color="#50e3d2"/> Analysis complete
              </div>
              <button type="button" onClick={() => downloadReport(
                JSON.stringify({ schema_version: "1.0", generated_at: new Date().toISOString(), analysis }, null, 2),
                "application/json;charset=utf-8",
                `${safeCaptureName(file?.name)}-analysis.json`,
              )} style={{
                display: "inline-flex", alignItems: "center", gap: 6, cursor: "pointer",
                border: "1px solid #2a3f65", borderRadius: 7, padding: "6px 9px",
                color: "#cbd5e1", background: "#111827", fontSize: 10, fontWeight: 700,
              }}>
                <Download size={12}/> JSON
              </button>
              <button type="button" onClick={() => downloadReport(
                captureReportCsv(analysis),
                "text/csv;charset=utf-8",
                `${safeCaptureName(file?.name)}-analysis.csv`,
              )} style={{
                display: "inline-flex", alignItems: "center", gap: 6, cursor: "pointer",
                border: "1px solid #2a3f65", borderRadius: 7, padding: "6px 9px",
                color: "#cbd5e1", background: "#111827", fontSize: 10, fontWeight: 700,
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
                  <div key={item.port} style={{ background: "#111827", border: "1px solid #1e2d47", borderRadius: 8, padding: 10 }}>
                    <div style={{ ...MUTED }}>Port {item.port}</div>
                    <div style={{ color: "#50e3d2", fontWeight: 800, fontSize: 16 }}>{number(item.count)}</div>
                  </div>
                ))}
              </div>
            ) : <div style={MUTED}>No TCP or UDP destination ports were observed.</div>}
          </section>

          <section style={{ ...PANEL, display: "grid", gap: 8 }}>
            <div style={{ ...TITLE, display: "flex", alignItems: "center", gap: 7 }}>
              <Clock3 size={14} color="#50e3d2"/> Capture time range
            </div>
            <div style={MUTED}>First packet: {summary.first_packet_at || "—"}</div>
            <div style={MUTED}>Last packet: {summary.last_packet_at || "—"}</div>
            <div style={MUTED}>SHA-256: <span style={{ color: "#cbd5e1", overflowWrap: "anywhere" }}>{capture.capture_sha256}</span></div>
          </section>

          <div style={{
            ...PANEL, display: "flex", alignItems: "flex-start", gap: 10,
            borderColor: "rgba(80,227,210,.25)", background: "rgba(80,227,210,.05)",
          }}>
            <ShieldCheck size={17} color="#50e3d2" style={{ flexShrink: 0, marginTop: 1 }}/>
            <div style={{ ...MUTED, lineHeight: 1.65, color: "#b6c8d0" }}>
              Privacy-preserving output: packet payloads, source and destination addresses, SSIDs and BSSIDs are not returned. The capture is processed by your authenticated local analyzer.
            </div>
          </div>
        </>
      )}
    </div>
  );
}
