import test from "node:test";
import assert from "node:assert/strict";
import { selectObservationRows } from "./observationRows.js";

const fixtures = [{ id: "demo-only" }];

test("live source never falls back to demo fixtures when records are missing", () => {
  assert.deepEqual(selectObservationRows({
    source: "live",
    rows: null,
    demoRows: fixtures,
  }), []);
  assert.deepEqual(selectObservationRows({
    source: "live",
    rows: undefined,
    demoRows: fixtures,
  }), []);
});

test("live source preserves an explicitly empty live result", () => {
  assert.deepEqual(selectObservationRows({
    source: "live",
    rows: [],
    demoRows: fixtures,
  }), []);
});

test("demo source uses explicit demo API rows or fixture rows", () => {
  const apiDemo = [{ id: "demo-api" }];
  assert.deepEqual(selectObservationRows({
    source: "demo",
    rows: apiDemo,
    demoRows: fixtures,
  }), apiDemo);
  assert.deepEqual(selectObservationRows({
    source: "demo",
    rows: null,
    demoRows: fixtures,
  }), fixtures);
});

test("hide demo preference suppresses both demo API rows and fixtures", () => {
  assert.deepEqual(selectObservationRows({
    source: "demo",
    rows: [{ id: "demo-api" }],
    demoRows: fixtures,
    hideDemoData: true,
  }), []);
  assert.deepEqual(selectObservationRows({
    source: "demo",
    rows: null,
    demoRows: fixtures,
    hideDemoData: true,
  }), []);
});
