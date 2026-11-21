import React from "react";
import { Activity, Antenna, ArrowDownToLine, ArrowUpFromLine, Radio, Signal, Waves } from "lucide-react";

function finite(value) {
  return value !== null && value !== undefined && value !== "" && Number.isFinite(Number(value));
}

function number(value, digits = 0) {
  return finite(value) ? Number(value).toLocaleString(undefined, { maximumFractionDigits: digits }) : "—";
}

function bytes(value) {
  if (!finite(value)) return "—";
  const amount = Math.max(0, Number(value));
  if (amount < 1024) return `${number(amount)} B`;
  const units = ["KB", "MB", "GB", "TB", "PB"];
  let scaled = amount;
  let unit = -1;
  do {
    scaled /= 1024;
    unit += 1;
  } while (scaled >= 1024 && unit < units.length - 1);
  return `${number(scaled, 2)} ${units[unit]}`;
}

function frequency(value) {
  if (!finite(value)) return "—";
  const mhz = Number(value);
  return mhz >= 1000 ? `${number(mhz / 1000, 3)} GHz` : `${number(mhz)} MHz`;
}

function Field({ label, value, mono = false }) {
  return (
    <div className="live-data-field">
      <span className="live-data-label">{label}</span>
      <strong className={mono ? "live-data-value mono" : "live-data-value"}>{value ?? "—"}</strong>
    </div>
  );
}

function PanelHeader({ icon: Icon, title, description, interfaceName }) {
  return (
    <div className="live-panel-header">
      <div className="live-panel-icon"><Icon size={17} /></div>
      <div className="live-panel-title">
        <h2>{title}</h2>
        <p>{description}</p>
      </div>
      <span className="live-panel-interface">{interfaceName || "Interface not reported"}</span>
    </div>
  );
}

function EmptyTelemetry({ children }) {
  return (
    <div className="live-telemetry-empty" role="status">
      <Activity size={18} />
      <span>{children}</span>
    </div>
  );
}

export function PhyTelemetryPanel({ data, interfaceName }) {
  const phy = data && typeof data === "object" ? data : {};
  const hasMeasurements = Object.keys(phy).length > 0;
  const capabilities = [
    ["802.11n / HT", phy.ht_support],
    ["802.11ac / VHT", phy.vht_support],
    ["802.11ax / HE", phy.he_support],
    ["DFS support", phy.dfs_support],
  ].filter(([, supported]) => typeof supported === "boolean");

  return (
    <section className="live-telemetry-panel">
      <PanelHeader
        icon={Antenna}
        title="Radio & PHY telemetry"
        description="Values reported by the host wireless driver; unavailable fields are left blank."
        interfaceName={interfaceName}
      />
      {!hasMeasurements ? (
        <EmptyTelemetry>
          No PHY telemetry was returned. Check adapter support, driver permissions and the local API.
        </EmptyTelemetry>
      ) : (
        <>
          <div className="live-metric-grid">
            <div className="live-metric-card">
              <span>Connected signal</span>
              <strong>{finite(phy.signal_dbm) ? `${number(phy.signal_dbm)} dBm` : "—"}</strong>
              <small>Current station link</small>
            </div>
            <div className="live-metric-card">
              <span>Transmit PHY rate</span>
              <strong>{finite(phy.tx_bitrate_mbps) ? `${number(phy.tx_bitrate_mbps, 1)} Mbps` : "—"}</strong>
              <small>Driver-reported TX bitrate</small>
            </div>
            <div className="live-metric-card">
              <span>Receive PHY rate</span>
              <strong>{finite(phy.rx_bitrate_mbps) ? `${number(phy.rx_bitrate_mbps, 1)} Mbps` : "—"}</strong>
              <small>Driver-reported RX bitrate</small>
            </div>
            <div className="live-metric-card">
              <span>Operating frequency</span>
              <strong>{frequency(phy.frequency_mhz)}</strong>
              <small>Current association</small>
            </div>
          </div>
          <div className="live-data-grid">
            <Field label="Connected SSID" value={phy.connected_ssid || "Not associated / unavailable"} />
            <Field label="Connected BSSID" value={phy.connected_bssid || "—"} mono />
            <Field label="MCS index" value={number(phy.mcs_index)} />
            <Field label="Supported bands" value={Array.isArray(phy.supported_bands) && phy.supported_bands.length ? phy.supported_bands.join(", ") : "Not reported"} />
          </div>
          {capabilities.length > 0 && (
            <div className="live-capabilities">
              <span className="live-data-label">Driver capability evidence</span>
              <div className="live-capability-list">
                {capabilities.map(([label, supported]) => (
                  <span key={label} className={supported ? "live-capability supported" : "live-capability"}>
                    <span aria-hidden="true">{supported ? "●" : "○"}</span>{label}: {supported ? "detected" : "not detected"}
                  </span>
                ))}
              </div>
            </div>
          )}
        </>
      )}
    </section>
  );
}

export function InterfaceTelemetryPanel({ data, rates, interfaceName }) {
  const link = data && typeof data === "object" ? data : {};
  const hasCounters = Object.keys(link).length > 0;
  const rxRate = finite(rates?.rxMbps) ? `${number(rates.rxMbps, 2)} Mbps` : "—";
  const txRate = finite(rates?.txMbps) ? `${number(rates.txMbps, 2)} Mbps` : "—";
  const errors = (finite(link.rx_errors) ? Number(link.rx_errors) : 0)
    + (finite(link.tx_errors) ? Number(link.tx_errors) : 0);
  const drops = (finite(link.rx_dropped) ? Number(link.rx_dropped) : 0)
    + (finite(link.tx_dropped) ? Number(link.tx_dropped) : 0);

  return (
    <section className="live-telemetry-panel">
      <PanelHeader
        icon={Activity}
        title="Interface performance"
        description="Counter deltas are calculated from successive local API samples; rates appear after two valid samples."
        interfaceName={interfaceName}
      />
      {!hasCounters ? (
        <EmptyTelemetry>
          No interface counters were returned for this adapter. Confirm that the operating system exposes per-interface statistics.
        </EmptyTelemetry>
      ) : (
        <>
          <div className="live-metric-grid">
            <div className="live-metric-card throughput">
              <span><ArrowDownToLine size={13} /> Receive throughput</span>
              <strong>{rxRate}</strong>
              <small>{bytes(link.rx_bytes)} received in total</small>
            </div>
            <div className="live-metric-card throughput">
              <span><ArrowUpFromLine size={13} /> Transmit throughput</span>
              <strong>{txRate}</strong>
              <small>{bytes(link.tx_bytes)} transmitted in total</small>
            </div>
            <div className="live-metric-card">
              <span>Packet errors</span>
              <strong>{number(errors)}</strong>
              <small>RX + TX cumulative errors</small>
            </div>
            <div className="live-metric-card">
              <span>Packet drops</span>
              <strong>{number(drops)}</strong>
              <small>RX + TX cumulative drops</small>
            </div>
          </div>
          {!rates && (
            <div className="live-sampling-note">
              <Radio size={14} />
              <span>Collecting a second counter sample to calculate measured throughput.</span>
            </div>
          )}
          <div className="live-data-grid">
            <Field label="RX packets" value={number(link.rx_packets)} />
            <Field label="TX packets" value={number(link.tx_packets)} />
            <Field label="TX retries" value={number(link.tx_retries)} />
            <Field label="TX failed" value={number(link.tx_failed)} />
            <Field label="Missed beacons" value={number(link.missed_beacons)} />
            <Field label="RX invalid NWID" value={number(link.invalid_misc)} />
          </div>
        </>
      )}
      <div className="live-telemetry-footnote">
        <Waves size={13} />
        <span>Rates are derived from byte-counter deltas, not estimated link speed. Counter resets and unavailable samples are not plotted.</span>
      </div>
    </section>
  );
}
