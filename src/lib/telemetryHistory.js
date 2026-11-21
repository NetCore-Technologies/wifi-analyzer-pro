const BSSID_PATTERN = /^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$/i;

function boundedNumber(value, minimum, maximum) {
  if (value === null || value === undefined || value === "") return null;
  const number = typeof value === "number" ? value : Number(value);
  return Number.isFinite(number) && number >= minimum && number <= maximum ? number : null;
}

function boundedLimit(value, fallback) {
  return Number.isInteger(value) && value > 0 ? Math.min(value, 120) : fallback;
}

export function appendSignalHistory(history, networks, sampledAt = Date.now(), limit = 30) {
  if (!Number.isFinite(sampledAt) || !Array.isArray(networks)) return history || {};
  const next = { ...(history && typeof history === "object" ? history : {}) };
  const maxSamples = boundedLimit(limit, 30);

  for (const network of networks) {
    const bssid = typeof network?.bssid === "string" ? network.bssid.trim().toUpperCase() : "";
    const rssi = boundedNumber(network?.rssi, -127, 0);
    if (!BSSID_PATTERN.test(bssid) || rssi === null) continue;

    const existing = Array.isArray(next[bssid])
      ? next[bssid].filter(sample => Number.isFinite(sample?.t) && boundedNumber(sample?.rssi, -127, 0) !== null)
      : [];
    const sample = { t: sampledAt, rssi };
    if (existing.at(-1)?.t === sampledAt) existing[existing.length - 1] = sample;
    else existing.push(sample);
    next[bssid] = existing.slice(-maxSamples);
  }
  return next;
}

export function appendDiagnosticSample(history, diagnostics, sampledAt = Date.now(), limit = 60) {
  if (!diagnostics || typeof diagnostics !== "object" || !Number.isFinite(sampledAt)) return history || [];
  const sample = {
    sampled_at: sampledAt,
    packet_loss_pct: boundedNumber(diagnostics.packet_loss_pct, 0, 100),
    latency_ms: boundedNumber(diagnostics.latency_ms, 0, 600000),
    jitter_ms: boundedNumber(diagnostics.jitter_ms, 0, 600000),
  };
  if (sample.packet_loss_pct === null && sample.latency_ms === null && sample.jitter_ms === null) return history || [];
  const previous = Array.isArray(history) ? history.filter(item => Number.isFinite(item?.sampled_at)) : [];
  if (previous.at(-1)?.sampled_at === sampledAt) previous[previous.length - 1] = sample;
  else previous.push(sample);
  return previous.slice(-boundedLimit(limit, 60));
}

export function summariseMetric(samples, key) {
  const maximum = key === "packet_loss_pct" || key === "loss" ? 100 : 600000;
  const values = (Array.isArray(samples) ? samples : [])
    .map(sample => boundedNumber(sample?.[key], 0, maximum))
    .filter(value => value !== null);
  if (!values.length) return { count: 0, last: null, mean: null, max: null };
  return {
    count: values.length,
    last: values[values.length - 1],
    mean: values.reduce((sum, value) => sum + value, 0) / values.length,
    max: Math.max(...values),
  };
}
