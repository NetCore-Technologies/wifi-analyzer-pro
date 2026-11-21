import test from "node:test";
import assert from "node:assert/strict";
import { calculateInterfaceRates } from "./telemetryMath.js";

test("calculates Mbps from actual byte-counter deltas and elapsed time", () => {
  const result = calculateInterfaceRates(
    { sampledAt: 1000, rxBytes: 1000, txBytes: 4000 },
    { sampledAt: 2000, rxBytes: 126000, txBytes: 254000 },
  );
  assert.deepEqual(result, { rxMbps: 1, txMbps: 2, sampledAt: 2000 });
});

test("returns no rate before the second sample", () => {
  assert.equal(calculateInterfaceRates(null, { sampledAt: 2000, rxBytes: 10, txBytes: 20 }), null);
});

test("rejects a zero or negative sampling interval", () => {
  const previous = { sampledAt: 2000, rxBytes: 100, txBytes: 200 };
  assert.equal(calculateInterfaceRates(previous, { ...previous }), null);
  assert.equal(calculateInterfaceRates(previous, { sampledAt: 1000, rxBytes: 200, txBytes: 300 }), null);
});

test("rejects counters that reset instead of reporting a negative rate", () => {
  assert.equal(
    calculateInterfaceRates(
      { sampledAt: 1000, rxBytes: 5000, txBytes: 8000 },
      { sampledAt: 2000, rxBytes: 120, txBytes: 9000 },
    ),
    null,
  );
});

test("rejects missing, non-finite and negative counters", () => {
  assert.equal(calculateInterfaceRates(
    { sampledAt: 1000, rxBytes: 1, txBytes: 1 },
    { sampledAt: 2000, rxBytes: null, txBytes: 2 },
  ), null);
  assert.equal(calculateInterfaceRates(
    { sampledAt: 1000, rxBytes: 1, txBytes: 1 },
    { sampledAt: 2000, rxBytes: 2, txBytes: Number.NaN },
  ), null);
  assert.equal(calculateInterfaceRates(
    { sampledAt: 1000, rxBytes: 1, txBytes: 1 },
    { sampledAt: 2000, rxBytes: -1, txBytes: 2 },
  ), null);
});
