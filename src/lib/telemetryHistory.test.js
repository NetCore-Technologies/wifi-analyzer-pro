import test from "node:test";
import assert from "node:assert/strict";
import { appendDiagnosticSample, appendSignalHistory, summariseMetric } from "./telemetryHistory.js";

test("signal history stores only valid measured BSSID and RSSI observations", () => {
  assert.deepEqual(appendSignalHistory({}, [
    { bssid: "aa:bb:cc:dd:ee:ff", rssi: -57 },
    { bssid: "not-a-bssid", rssi: -40 },
    { bssid: "00:11:22:33:44:55", rssi: null },
    { bssid: "00:11:22:33:44:66", rssi: 4 },
  ], 1000), { "AA:BB:CC:DD:EE:FF": [{ t: 1000, rssi: -57 }] });
});

test("signal history deduplicates timestamps and caps retained samples", () => {
  let history = {};
  for (let t = 1; t <= 35; t += 1) {
    history = appendSignalHistory(history, [{ bssid: "00:11:22:33:44:55", rssi: -60 }], t, 3);
  }
  history = appendSignalHistory(history, [{ bssid: "00:11:22:33:44:55", rssi: -52 }], 35, 3);
  assert.deepEqual(history["00:11:22:33:44:55"], [
    { t: 33, rssi: -60 }, { t: 34, rssi: -60 }, { t: 35, rssi: -52 },
  ]);
});

test("diagnostic samples preserve absent metrics as null", () => {
  assert.deepEqual(appendDiagnosticSample([], { packet_loss_pct: 0, latency_ms: null }, 1000), [{
    sampled_at: 1000, packet_loss_pct: 0, latency_ms: null, jitter_ms: null,
  }]);
});

test("diagnostic objects without any measured metric are not recorded", () => {
  assert.deepEqual(appendDiagnosticSample([], { packet_loss_pct: null, latency_ms: null, jitter_ms: null }, 1000), []);
});

test("diagnostic history is immutable and caps retention", () => {
  const original = [];
  const first = appendDiagnosticSample(original, { packet_loss_pct: 2 }, 1000, 2);
  const second = appendDiagnosticSample(first, { packet_loss_pct: 3 }, 2000, 2);
  const third = appendDiagnosticSample(second, { packet_loss_pct: 4 }, 3000, 2);
  assert.equal(original.length, 0);
  assert.deepEqual(third.map(sample => sample.packet_loss_pct), [3, 4]);
});

test("summaries exclude missing and invalid measurements", () => {
  assert.deepEqual(summariseMetric([
    { latency_ms: null }, { latency_ms: 12 }, { latency_ms: "invalid" }, { latency_ms: 18 },
  ], "latency_ms"), { count: 2, last: 18, mean: 15, max: 18 });
  assert.deepEqual(summariseMetric([{ latency_ms: null }], "latency_ms"), {
    count: 0, last: null, mean: null, max: null,
  });
});
