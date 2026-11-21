import test from "node:test";
import assert from "node:assert/strict";
import { countObservedChannels, rankObservedChannels } from "./rfPlanningEvidence.js";

test("channel counts include only valid records for the requested band", () => {
  const networks = [
    { band: "2.4GHz", channel: 1 },
    { band: "2.4GHz", channel: "1" },
    { band: "5GHz", channel: 1 },
    { band: "2.4GHz", channel: null },
    { band: "2.4GHz", channel: 234 },
    { band: "6GHz", channel: 5 },
  ];
  assert.deepEqual([...countObservedChannels(networks, "2.4GHz")], [[1, 2]]);
  assert.deepEqual([...countObservedChannels(networks, "6GHz")], [[5, 1]]);
});

test("candidate ranking contains observed channels only and resolves ties by channel", () => {
  const networks = [
    { band: "5GHz", channel: 100 },
    { band: "5GHz", channel: 36 },
    { band: "5GHz", channel: 100 },
    { band: "5GHz", channel: 149 },
    { band: "5GHz", channel: 36 },
  ];
  assert.deepEqual(rankObservedChannels(networks, "5GHz"), [
    { channel: 149, count: 1 },
    { channel: 36, count: 2 },
    { channel: 100, count: 2 },
  ]);
  assert.deepEqual(rankObservedChannels([], "6GHz"), []);
});

test("invalid channel strings and fractional channel numbers are ignored", () => {
  const counts = countObservedChannels([
    { band: "6GHz", channel: "unknown" },
    { band: "6GHz", channel: 5.5 },
    { band: "6GHz", channel: 233 },
  ], "6GHz");
  assert.deepEqual([...counts], [[233, 1]]);
});
