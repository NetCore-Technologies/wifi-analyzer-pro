const FORMULA_PREFIX = /^[=+@-]/;

function csvValue(value) {
  if (value === null || value === undefined) return "";
  if (typeof value === "object") value = JSON.stringify(value);
  let text = String(value);
  const numeric = /^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$/.test(text);
  const firstMeaningfulCharacter = text.replace(/^[\s\uFEFF]+/, "");
  if ((!numeric && FORMULA_PREFIX.test(firstMeaningfulCharacter)) || /^[\t\r]/.test(text)) {
    text = "'" + text;
  }
  return '"' + text.replace(/"/g, '""') + '"';
}

export function buildScanExport({
  networks = [],
  devices = [],
  diagnostics = null,
  systemInfo = null,
  source = "unknown",
  stale = false,
  lastScan = null,
  exportedAt = new Date().toISOString(),
} = {}) {
  return {
    schema_version: 1,
    exported_at: exportedAt,
    observation: {
      source,
      stale: Boolean(stale),
      last_scan_at: lastScan instanceof Date ? lastScan.toISOString() : lastScan || null,
      system: systemInfo,
    },
    networks: Array.isArray(networks) ? networks : [],
    devices: Array.isArray(devices) ? devices : [],
    latest_diagnostics: diagnostics,
  };
}

export function buildScanCsv(payload) {
  const data = payload && typeof payload === "object" ? payload : {};
  const records = [
    ...(Array.isArray(data.networks) ? data.networks.map(item => ({ ...item, record_type: "network" })) : []),
    ...(Array.isArray(data.devices) ? data.devices.map(item => ({ ...item, record_type: "device" })) : []),
  ];
  const metadata = data.observation || {};
  const columns = [...new Set([
    "record_type",
    "observation_source",
    "data_stale",
    "exported_at",
    "last_scan_at",
    ...records.flatMap(record => Object.keys(record)),
  ])];
  const rows = [
    columns,
    ...records.map(record => columns.map(column => {
      if (column === "observation_source") return metadata.source ?? "unknown";
      if (column === "data_stale") return metadata.stale === true;
      if (column === "exported_at") return data.exported_at ?? "";
      if (column === "last_scan_at") return metadata.last_scan_at ?? "";
      return record[column] ?? "";
    })),
  ];
  return rows.map(row => row.map(csvValue).join(",")).join("\r\n") + "\r\n";
}
