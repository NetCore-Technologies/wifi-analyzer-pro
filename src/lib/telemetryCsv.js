export const TELEMETRY_CSV_COLUMNS = Object.freeze([
  "site_id",
  "minute_utc",
  "scan_count",
  "sample_count",
  "average_network_count",
  "network_count_min",
  "network_count_max",
  "average_open_network_count",
  "average_2_4ghz_network_count",
  "average_5ghz_network_count",
  "average_6ghz_network_count",
  "average_rssi_dbm",
  "rssi_min",
  "rssi_max",
  "diagnostic_sample_count",
  "average_latency_ms",
  "latency_min",
  "latency_max",
  "average_jitter_ms",
  "jitter_min",
  "jitter_max",
  "average_packet_loss_pct",
  "packet_loss_min",
  "packet_loss_max",
  "speedtest_sample_count",
  "average_speedtest_download_mbps",
  "speedtest_download_min",
  "speedtest_download_max",
  "average_speedtest_upload_mbps",
  "speedtest_upload_min",
  "speedtest_upload_max",
  "average_speedtest_ping_ms",
  "speedtest_ping_min",
  "speedtest_ping_max",
  "updated_at",
]);

function csvCell(value) {
  if (value === null || value === undefined) return "";
  const text = String(value);
  return /[",\r\n]/.test(text) ? '"' + text.replace(/"/g, '""') + '"' : text;
}

/** Serialise aggregate-only rows through a fixed allowlist. */
export function buildTelemetryCsv(rows) {
  const records = Array.isArray(rows)
    ? rows.filter(row => row && typeof row === "object" && !Array.isArray(row))
    : [];
  const header = TELEMETRY_CSV_COLUMNS.map(csvCell).join(",");
  const lines = records.map(row =>
    TELEMETRY_CSV_COLUMNS.map(column => csvCell(row[column])).join(",")
  );
  return [header, ...lines].join("\r\n") + "\r\n";
}
