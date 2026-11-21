import test from "node:test";
import assert from "node:assert/strict";
import { buildScanCsv, buildScanExport } from "./telemetryExport.js";

test("export payload carries provenance, staleness, scan time and complete record groups", () => {
  const lastScan = new Date("2026-11-21T08:00:00.000Z");
  const payload = buildScanExport({
    networks: [{ ssid: "Office", rssi: -52 }],
    devices: [{ ip: "192.0.2.10" }],
    diagnostics: { packet_loss_pct: null },
    systemInfo: { os: "Linux" },
    source: "live",
    stale: true,
    lastScan,
    exportedAt: "2026-11-21T08:01:00.000Z",
  });
  assert.equal(payload.schema_version, 1);
  assert.equal(payload.observation.source, "live");
  assert.equal(payload.observation.stale, true);
  assert.equal(payload.observation.last_scan_at, lastScan.toISOString());
  assert.deepEqual(payload.networks, [{ ssid: "Office", rssi: -52 }]);
  assert.deepEqual(payload.devices, [{ ip: "192.0.2.10" }]);
  assert.deepEqual(payload.latest_diagnostics, { packet_loss_pct: null });
});

test("CSV quotes delimiters, quotes and newlines and includes both record types", () => {
  const csv = buildScanCsv(buildScanExport({
    networks: [{ ssid: 'Office, "East"', rssi: -52 }],
    devices: [{ hostname: "desk\nunit", ip: "192.0.2.4" }],
    source: "demo",
    exportedAt: "2026-11-21T08:01:00.000Z",
  }));
  assert.match(csv, /"network"/);
  assert.match(csv, /"device"/);
  assert.match(csv, /"Office, ""East"""/);
  assert.match(csv, /"desk\nunit"/);
  assert.match(csv, /"demo"/);
});

test("CSV neutralises spreadsheet formulas but preserves negative numeric measurements", () => {
  const csv = buildScanCsv(buildScanExport({
    networks: [{ ssid: "=HYPERLINK(\"https://attacker.invalid\")", rssi: -73 }],
  }));
  assert.match(csv, /"'=HYPERLINK/);
  assert.match(csv, /"-73"/);

  const leadingWhitespace = buildScanCsv(buildScanExport({
    networks: [{ ssid: "  =HYPERLINK(\"https://attacker.invalid\")" }],
  }));
  assert.match(leadingWhitespace, /"'  =HYPERLINK/);
});

test("empty exports remain valid CSV with the metadata contract", () => {
  const csv = buildScanCsv(buildScanExport({ networks: [], devices: [], source: "demo" }));
  assert.match(csv, /^"record_type","observation_source","data_stale"/);
  assert.equal(csv.trim().split("\r\n").length, 1);
});
