import test from "node:test";
import assert from "node:assert/strict";
import { summariseBandPresence } from "./bandObservation.js";

test("multi-band presence groups by exact visible SSID and strongest measured BSS per band", () => {
  const result = summariseBandPresence([
    { ssid: "Corp", bssid: "24:00:00:00:00:01", band: "2.4GHz", rssi: -65, channel: 6 },
    { ssid: "Corp", bssid: "24:00:00:00:00:02", band: "2.4GHz", rssi: -48, channel: 1 },
    { ssid: "Corp", bssid: "50:00:00:00:00:01", band: "5GHz", rssi: -58, channel: 36 },
  ]);
  assert.equal(result.multiBand.length, 1);
  assert.deepEqual(result.multiBand[0].present_bands, ["2.4GHz", "5GHz"]);
  assert.equal(result.multiBand[0].bands["2.4GHz"].bss_count, 2);
  assert.equal(result.multiBand[0].bands["2.4GHz"].strongest.bssid, "24:00:00:00:00:02");
  assert.equal(result.multiBand[0].bands["2.4GHz"].strongest.rssi, -48);
  assert.equal(result.multiBand[0].bands["5GHz"].strongest.channel, 36);
});

test("hidden SSIDs are counted separately and are not incorrectly correlated", () => {
  const result = summariseBandPresence([
    { ssid: "", band: "2.4GHz", bssid: "00:00:00:00:00:01" },
    { ssid: "", band: "5GHz", bssid: "00:00:00:00:00:02" },
  ]);
  assert.equal(result.hiddenBssCount, 2);
  assert.equal(result.multiBand.length, 0);
  assert.equal(result.singleOrUnknownBand.length, 0);
});

test("missing band and invalid RSSI remain unknown instead of being scored", () => {
  const result = summariseBandPresence([
    { ssid: "Branch", band: null, bssid: "00:00:00:00:00:03", rssi: -50 },
    { ssid: "Branch", band: "5GHz", bssid: "00:00:00:00:00:04", rssi: null },
    { ssid: "Branch", band: "2.4GHz", bssid: "00:00:00:00:00:05", rssi: 4 },
  ]);
  const summary = result.multiBand[0];
  assert.equal(summary.unknown_band_count, 1);
  assert.equal(summary.bands["5GHz"].strongest, null);
  assert.equal(summary.bands["2.4GHz"].strongest, null);
});
