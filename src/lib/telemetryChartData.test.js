import test from "node:test";
import assert from "node:assert/strict";
import { buildTelemetryChartData, summariseTelemetry } from "./telemetryChartData.js";

test("chart data groups independent site measurements by UTC minute", () => {
  const result = buildTelemetryChartData([
    { site_id: "branch", minute_utc: "2026-11-21T10:02:00+00:00", average_latency_ms: 20 },
    { site_id: "hq", minute_utc: "2026-11-21T10:01:00+00:00", average_latency_ms: 10 },
    { site_id: "branch", minute_utc: "2026-11-21T10:01:00+00:00", average_latency_ms: 15 },
  ], "average_latency_ms");
  assert.deepEqual(result.sites, ["branch", "hq"]);
  assert.deepEqual(result.data, [
    { minute_utc: "2026-11-21T10:01:00+00:00", "site:branch": 15, "site:hq": 10 },
    { minute_utc: "2026-11-21T10:02:00+00:00", "site:branch": 20 },
  ]);
  assert.equal(result.measuredValueCount, 3);
});

test("missing, malformed and out-of-range values are not converted into zeroes", () => {
  const result = buildTelemetryChartData([
    { site_id: "hq", minute_utc: "2026-11-21T10:00:00Z", average_rssi_dbm: null },
    { site_id: "hq", minute_utc: "2026-11-21T10:01:00Z", average_rssi_dbm: "missing" },
    { site_id: "hq", minute_utc: "2026-11-21T10:02:00Z", average_rssi_dbm: 1 },
    { site_id: "hq", minute_utc: "2026-11-21T10:03:00Z", average_rssi_dbm: -65 },
    { site_id: "hq", minute_utc: "invalid", average_rssi_dbm: -60 },
  ], "average_rssi_dbm");
  assert.deepEqual(result.data, [{ minute_utc: "2026-11-21T10:03:00Z", "site:hq": -65 }]);
  assert.equal(result.measuredValueCount, 1);
});

test("unsupported metrics fail rather than silently showing an empty chart", () => {
  assert.throws(() => buildTelemetryChartData([], "secret"), RangeError);
});

test("summary counts are non-negative and site-aware", () => {
  assert.deepEqual(summariseTelemetry([
    { site_id: "hq", sample_count: 3, diagnostic_sample_count: 2 },
    { site_id: "branch", sample_count: 4, diagnostic_sample_count: 1 },
    { site_id: "branch", sample_count: -1, diagnostic_sample_count: 0 },
  ]), { buckets: 3, scanSamples: 7, diagnosticSamples: 3, siteCount: 2 });
});
