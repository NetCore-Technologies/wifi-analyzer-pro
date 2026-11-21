const METRIC_RANGES = {
  average_network_count: [0, 10000],
  average_rssi_dbm: [-127, 0],
  average_latency_ms: [0, 600000],
  average_jitter_ms: [0, 600000],
  average_packet_loss_pct: [0, 100],
};

export function buildTelemetryChartData(rollups, metric) {
  if (!Object.hasOwn(METRIC_RANGES, metric)) {
    throw new RangeError("Unsupported telemetry chart metric");
  }
  const [minimum, maximum] = METRIC_RANGES[metric];
  const byMinute = new Map();
  const sites = new Set();
  let measuredValueCount = 0;

  for (const row of Array.isArray(rollups) ? rollups : []) {
    if (typeof row?.site_id !== "string" || !row.site_id
      || typeof row?.minute_utc !== "string" || !Number.isFinite(Date.parse(row.minute_utc))) continue;
    const value = row[metric];
    if (value === null || value === undefined || value === "") continue;
    const number = Number(value);
    if (!Number.isFinite(number) || number < minimum || number > maximum) continue;

    const siteKey = `site:${row.site_id}`;
    if (!byMinute.has(row.minute_utc)) byMinute.set(row.minute_utc, { minute_utc: row.minute_utc });
    const point = byMinute.get(row.minute_utc);
    point[siteKey] = number;
    sites.add(row.site_id);
    measuredValueCount += 1;
  }

  return {
    data: [...byMinute.values()].sort((first, second) => first.minute_utc.localeCompare(second.minute_utc)),
    sites: [...sites].sort(),
    measuredValueCount,
  };
}

export function summariseTelemetry(rollups) {
  const rows = Array.isArray(rollups) ? rollups : [];
  const scanSamples = rows.reduce((sum, row) => sum + (Number.isSafeInteger(row?.sample_count) && row.sample_count > 0 ? row.sample_count : 0), 0);
  const diagnosticSamples = rows.reduce((sum, row) => sum + (Number.isSafeInteger(row?.diagnostic_sample_count) && row.diagnostic_sample_count > 0 ? row.diagnostic_sample_count : 0), 0);
  const sites = new Set(rows.filter(row => typeof row?.site_id === "string").map(row => row.site_id));
  return { buckets: rows.length, scanSamples, diagnosticSamples, siteCount: sites.size };
}
