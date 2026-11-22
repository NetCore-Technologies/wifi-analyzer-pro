import test from "node:test";
import assert from "node:assert/strict";
import { buildTelemetryCsv, TELEMETRY_CSV_COLUMNS } from "./telemetryCsv.js";

test("exports only the documented aggregate telemetry allowlist", () => {
  const csv = buildTelemetryCsv([{
    site_id: "head-office",
    minute_utc: "2026-11-22T00:00:00+00:00",
    average_rssi_dbm: -61.5,
    sample_count: 4,
    ssid: "Secret-SSID",
    bssid: "AA:BB:CC:DD:EE:FF",
    client_mac: "00:11:22:33:44:55",
    station_identity: "private-client",
  }]);
  assert.ok(csv.includes("site_id,minute_utc"));
  assert.ok(csv.includes("head-office"));
  assert.ok(csv.includes("-61.5"));
  assert.equal(csv.includes("Secret-SSID"), false);
  assert.equal(csv.includes("AA:BB:CC:DD:EE:FF"), false);
  assert.equal(csv.includes("private-client"), false);
  assert.equal(csv.split("\r\n").length, 3);
  assert.equal(TELEMETRY_CSV_COLUMNS.includes("ssid"), false);
});

test("quotes CSV fields containing commas, quotes and line breaks", () => {
  const csv = buildTelemetryCsv([{
    site_id: 'site,"north"',
    minute_utc: "2026-11-22T00:00:00Z\ncontinued",
    average_network_count: 5,
  }]);
  assert.ok(csv.includes('"site,""north"""'));
  assert.ok(csv.includes('"2026-11-22T00:00:00Z\ncontinued"'));
  assert.ok(csv.endsWith("\r\n"));
});

test("null metrics are exported as empty values and malformed rows are skipped", () => {
  const csv = buildTelemetryCsv([
    { site_id: "branch", average_rssi_dbm: null, average_latency_ms: undefined },
    null,
    "not-a-row",
    [],
  ]);
  const lines = csv.trimEnd().split("\r\n");
  assert.equal(lines.length, 2);
  assert.ok(lines[1].startsWith("branch,"));
  assert.ok(lines[1].includes("branch,,,,"));
});

test("empty history returns just the header row", () => {
  const csv = buildTelemetryCsv([]);
  assert.equal(csv.trimEnd().split("\r\n").length, 1);
  assert.ok(csv.endsWith("\r\n"));
});
