import test from "node:test";
import assert from "node:assert/strict";
import {
  addTrustedBssid,
  assessTrustedAccessPoints,
  normalizeBssid,
  removeTrustedBssid,
  sanitizeTrustedMap,
  validateSsid,
} from "./trustedAccessPoints.js";

test("normalises standard and hyphen-separated BSSIDs", () => {
  assert.equal(normalizeBssid("aa:bb:cc:dd:ee:ff"), "AA:BB:CC:DD:EE:FF");
  assert.equal(normalizeBssid("aa-bb-cc-dd-ee-ff"), "AA:BB:CC:DD:EE:FF");
  assert.equal(normalizeBssid("not a mac"), null);
  assert.equal(normalizeBssid("AA:BB:CC:DD:EE"), null);
  assert.equal(normalizeBssid("FF:FF:FF:FF:FF:FF"), null);
  assert.equal(normalizeBssid("01:00:5E:00:00:01"), null);
  assert.equal(normalizeBssid("00:00:00:00:00:00"), null);
});

test("validates SSID length using UTF-8 bytes", () => {
  assert.equal(validateSsid("Enterprise"), true);
  assert.equal(validateSsid("é".repeat(16)), true);
  assert.equal(validateSsid("é".repeat(17)), false);
  assert.equal(validateSsid("bad\nssid"), false);
  assert.equal(validateSsid(""), false);
});

test("adds trusted BSSIDs immutably and deduplicates case variants", () => {
  const empty = {};
  const first = addTrustedBssid(empty, "CorpWiFi", "aa:bb:cc:dd:ee:ff");
  const second = addTrustedBssid(first, "CorpWiFi", "AA-BB-CC-DD-EE-FF");
  assert.deepEqual(empty, {});
  assert.deepEqual(first, { CorpWiFi: ["AA:BB:CC:DD:EE:FF"] });
  assert.deepEqual(second, first);
});

test("rejects invalid trusted identities and enforces input validation", () => {
  assert.throws(() => addTrustedBssid({}, "", "AA:BB:CC:DD:EE:FF"), /SSID/);
  assert.throws(() => addTrustedBssid({}, "CorpWiFi", "invalid"), /BSSID/);
});

test("removes one BSSID and removes an empty SSID group", () => {
  const trusted = {
    CorpWiFi: ["AA:BB:CC:DD:EE:FF", "00:11:22:33:44:55"],
    Guest: ["10:20:30:40:50:60"],
  };
  assert.deepEqual(removeTrustedBssid(trusted, "CorpWiFi", "aa:bb:cc:dd:ee:ff"), {
    CorpWiFi: ["00:11:22:33:44:55"],
    Guest: ["10:20:30:40:50:60"],
  });
  assert.deepEqual(removeTrustedBssid(trusted, "Guest", "10:20:30:40:50:60"), {
    CorpWiFi: ["AA:BB:CC:DD:EE:FF", "00:11:22:33:44:55"],
  });
});

test("assesses only SSIDs with a configured baseline and compares BSSIDs canonically", () => {
  const candidates = assessTrustedAccessPoints([
    { ssid: "CorpWiFi", bssid: "AA:BB:CC:DD:EE:FF", rssi: -50 },
    { ssid: "CorpWiFi", bssid: "aa:bb:cc:dd:ee:01", rssi: -72, channel: 36, band: "5GHz" },
    { ssid: "CorpWiFi", bssid: "AA-BB-CC-DD-EE-01", rssi: -72, channel: 36, band: "5GHz" },
    { ssid: "Guest", bssid: "00:11:22:33:44:55", rssi: -40 },
    { ssid: "", bssid: "00:11:22:33:44:66" },
  ], { CorpWiFi: ["aa:bb:cc:dd:ee:ff"] });
  assert.deepEqual(candidates, [{
    ssid: "CorpWiFi",
    bssid: "AA:BB:CC:DD:EE:01",
    rssi: -72,
    channel: 36,
    band: "5GHz",
    reason: "The SSID matches a trusted profile, but this BSSID is not in its allowlist.",
  }]);
});

test("missing or out-of-range signal readings remain unavailable", () => {
  const candidates = assessTrustedAccessPoints([
    { ssid: "CorpWiFi", bssid: "AA:BB:CC:DD:EE:01", rssi: null },
    { ssid: "CorpWiFi", bssid: "AA:BB:CC:DD:EE:02", rssi: 9 },
  ], { CorpWiFi: ["AA:BB:CC:DD:EE:FF"] });
  assert.deepEqual(candidates.map(candidate => candidate.rssi), [null, null]);
});

test("prototype-like SSID values are stored as data and cannot affect object inheritance", () => {
  const withProto = addTrustedBssid({}, "__proto__", "AA:BB:CC:DD:EE:FF");
  assert.equal(Object.hasOwn(withProto, "__proto__"), true);
  assert.deepEqual(withProto["__proto__"], ["AA:BB:CC:DD:EE:FF"]);
  assert.equal(Object.getPrototypeOf(withProto), Object.prototype);

  const withConstructor = addTrustedBssid(withProto, "constructor", "00:11:22:33:44:55");
  assert.deepEqual(withConstructor.constructor, ["00:11:22:33:44:55"]);
  assert.equal(Object.getPrototypeOf(withConstructor), Object.prototype);
});

test("sanitises corrupted local storage and rejects oversized identity sets", () => {
  assert.deepEqual(sanitizeTrustedMap({
    CorpWiFi: ["aa:bb:cc:dd:ee:ff", "invalid"],
    "bad\nssid": ["00:11:22:33:44:55"],
    Other: "not-an-array",
  }), { CorpWiFi: ["AA:BB:CC:DD:EE:FF"] });
  assert.throws(() => addTrustedBssid({}, "x".repeat(33), "AA:BB:CC:DD:EE:FF"), /SSID/);
});
