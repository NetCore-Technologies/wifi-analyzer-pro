const MAX_SIGNAL_HISTORY = 60;
const MAX_SPEED_HISTORY = 24;

function finiteTimestamp(value) {
  const timestamp = Number(value);
  return Number.isFinite(timestamp) && timestamp > 0 && timestamp <= Date.now() + 5 * 60 * 1000
    ? timestamp
    : null;
}

function boundedMetric(value, minimum, maximum) {
  if (value === null || value === undefined || value === "" || typeof value === "boolean") return null;
  const number = Number(value);
  return Number.isFinite(number) && number >= minimum && number <= maximum ? number : null;
}

function average(values) {
  return values.length ? Number((values.reduce((sum, value) => sum + value, 0) / values.length).toFixed(2)) : null;
}

/**
 * Append an aggregate derived only from a successful live scan response.
 * Raw SSIDs and BSSIDs are deliberately excluded from this in-memory history.
 */
export function appendLiveSignalSample(history, networks, {
  source,
  timestamp = Date.now(),
} = {}) {
  const current = Array.isArray(history) ? history : [];
  if (source !== "live" || !Array.isArray(networks)) return current;
  const sampledAt = finiteTimestamp(timestamp);
  if (sampledAt === null) return current;

  const measuredRecords = networks
    .map(network => ({
      rssi: boundedMetric(network?.rssi, -127, 0),
      snr: boundedMetric(network?.snr, -20, 150),
    }))
    .filter(record => record.rssi !== null);
  if (!measuredRecords.length) return current;

  const rssiValues = measuredRecords.map(record => record.rssi);
  const snrValues = measuredRecords
    .map(record => record.snr)
    .filter(value => value !== null);

  const entry = {
    t: sampledAt,
    label: new Date(sampledAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    rssi: average(rssiValues),
    snr: average(snrValues),
    bssCount: rssiValues.length,
    snrCount: snrValues.length,
  };

  return [...current.slice(-(MAX_SIGNAL_HISTORY - 1)), entry];
}

/** Append one completed, validated throughput measurement; no sample data is generated. */
export function appendSpeedTestSample(history, measurement, timestamp = Date.now()) {
  const current = Array.isArray(history) ? history : [];
  if (!measurement || typeof measurement !== "object") return current;
  const sampledAt = finiteTimestamp(timestamp);
  const download = boundedMetric(measurement.download, 0, 1_000_000);
  const upload = boundedMetric(measurement.upload, 0, 1_000_000);
  const ping = boundedMetric(measurement.ping, 0, 3_600_000);
  if (sampledAt === null || download === null || upload === null || ping === null) return current;

  const entry = {
    t: sampledAt,
    label: new Date(sampledAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    dl: download,
    ul: upload,
    ping,
  };
  return [...current.slice(-(MAX_SPEED_HISTORY - 1)), entry];
}
