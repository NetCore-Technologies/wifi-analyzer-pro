import assert from "node:assert/strict";
import test from "node:test";

import {
  buildFeaturePayloadTemplate,
  filterFeatureCatalog,
} from "./featureWorkbench.js";

const catalogue = [
  { id: "F001", slug: "wifi_scan", name: "Wi-Fi scan", category: "Discovery", description: "Collect nearby access points" },
  { id: "F030", slug: "recommend_channel", name: "Recommend channel", category: "RF planning", description: "Rank usable channels" },
  { id: "F070", slug: "security_rank", name: "Security ranking", category: "Security", description: "Rank advertised link security" },
];

test("feature catalogue filters by exact categories and retains stable ordering", () => {
  const rows = filterFeatureCatalog(catalogue, { categoryTerms: ["RF planning", "Security"] });
  assert.deepEqual(rows.map(row => row.slug), ["recommend_channel", "security_rank"]);
});

test("feature catalogue search covers names, slugs, IDs, categories and descriptions", () => {
  assert.deepEqual(filterFeatureCatalog(catalogue, { query: "f030" }).map(row => row.slug), ["recommend_channel"]);
  assert.deepEqual(filterFeatureCatalog(catalogue, { query: "nearby access points" }).map(row => row.slug), ["wifi_scan"]);
  assert.deepEqual(filterFeatureCatalog(catalogue, { query: "security" }).map(row => row.slug), ["security_rank"]);
});

test("feature catalogue safely ignores malformed entries and invalid input", () => {
  assert.deepEqual(filterFeatureCatalog(null), []);
  assert.deepEqual(filterFeatureCatalog([null, "bad", ...catalogue]), catalogue);
});

test("payload templates derive arrays, booleans, objects, enums, numbers and strings", () => {
  assert.deepEqual(buildFeaturePayloadTemplate({
    networks: "optional network[]",
    enabled: "boolean",
    settings: "object",
    band: "2.4GHz|5GHz|6GHz",
    channel: "integer",
    note: "string",
  }), {
    networks: [],
    enabled: false,
    settings: {},
    band: "2.4GHz",
    channel: 0,
    note: "",
  });
});

test("payload template builder accepts empty or invalid parameter metadata", () => {
  assert.deepEqual(buildFeaturePayloadTemplate(), {});
  assert.deepEqual(buildFeaturePayloadTemplate([]), {});
});
