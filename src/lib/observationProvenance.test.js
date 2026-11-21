import test from "node:test";
import assert from "node:assert/strict";
import { getScanSource } from "./observationProvenance.js";

test("classifies a backend live scan as live", () => {
  assert.equal(getScanSource({ source: "live", networks: [] }), "live");
});

test("classifies an explicitly enabled backend demo scan as demo", () => {
  assert.equal(getScanSource({ source: "demo", networks: [] }), "demo");
});

test("fails closed when scan provenance is absent", () => {
  assert.equal(getScanSource({ networks: [] }), "unknown");
  assert.equal(getScanSource(null), "unknown");
  assert.equal(getScanSource(undefined), "unknown");
});

test("does not accept ambiguous or case-variant source labels", () => {
  assert.equal(getScanSource({ source: "LIVE" }), "unknown");
  assert.equal(getScanSource({ source: "sample" }), "unknown");
});
