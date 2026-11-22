import test from "node:test";
import assert from "node:assert/strict";
import { appendLiveSignalSample, appendSpeedTestSample } from "./measurementHistory.js";

test("signal history accepts only live scans and aggregates measured values", () => {
  const networks = [
    { ssid: "private-name-a", bssid: "AA:BB:CC:DD:EE:01", rssi: -50, snr: 40 },
    { ssid: "private-name-b", bssid: "AA:BB:CC:DD:EE:02", rssi: -70, snr: null },
    { ssid: "missing-rssi", rssi: null, snr: 30 },
    { ssid: "invalid-rssi", rssi: "not-measured", snr: 20 },
  ];
  const result = appendLiveSignalSample([], networks, { source: "live", timestamp: Date.now() });
  assert.equal(result.length, 1);
  assert.equal(result[0].rssi, -60);
  assert.equal(result[0].snr, 40);
  assert.equal(result[0].bssCount, 2);
  assert.equal(result[0].snrCount, 1);
  assert.equal(Object.hasOwn(result[0], "ssid"), false);
  assert.equal(Object.hasOwn(result[0], "bssid"), false);
});

test("demo, unknown, empty and invalid scans do not contaminate live history", () => {
  const previous = [{ t: 100, rssi: -55, snr: null, bssCount: 1, snrCount: 0 }];
  assert.equal(appendLiveSignalSample(previous, [{ rssi: -30 }], { source: "demo" }), previous);
  assert.equal(appendLiveSignalSample(previous, [{ rssi: -30 }], { source: "unknown" }), previous);
  assert.equal(appendLiveSignalSample(previous, [], { source: "live" }), previous);
  assert.equal(appendLiveSignalSample(previous, [{ rssi: 4 }], { source: "live" }), previous);
  assert.equal(appendLiveSignalSample(previous, [{ rssi: -30 }], { source: "live", timestamp: NaN }), previous);
});

test("signal history is bounded to the latest 60 scans without mutating prior state", () => {
  const initial = [];
  let history = initial;
  for (let index = 1; index <= 75; index += 1) {
    history = appendLiveSignalSample(history, [{ rssi: -50 - (index % 10) }], {
      source: "live",
      timestamp: Date.now() + index,
    });
  }
  assert.equal(history.length, 60);
  assert.equal(history[0].rssi, -56);
  assert.deepEqual(initial, []);
});

test("speed history contains only completed finite measurements and is bounded", () => {
  let history = [];
  for (let index = 1; index <= 30; index += 1) {
    history = appendSpeedTestSample(history, {
      download: 800 + index,
      upload: 350 + index,
      ping: 10 + index / 10,
    }, Date.now() + index);
  }
  assert.equal(history.length, 24);
  assert.equal(history[0].dl, 807);
  assert.equal(history.at(-1).dl, 830);
  const unchanged = appendSpeedTestSample(history, { download: 900, upload: -1, ping: 10 });
  assert.equal(unchanged, history);
});
