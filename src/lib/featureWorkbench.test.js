import assert from "node:assert/strict";
import test from "node:test";
import {
  buildFeaturePayloadTemplate,
  filterFeatureCatalog,
  getFeatureParameterChoices,
  getFeatureParameterKind,
  parseFeatureParameterValue,
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
test("parameter metadata recognises primitive types, enums and structured payloads", () => {
  assert.equal(getFeatureParameterKind("integer"), "integer");
  assert.equal(getFeatureParameterKind("number"), "number");
  assert.equal(getFeatureParameterKind("boolean"), "boolean");
  assert.equal(getFeatureParameterKind("string"), "text");
  assert.equal(getFeatureParameterKind("2.4GHz|5GHz|6GHz"), "enum");
  assert.equal(getFeatureParameterKind("number[]"), "array");
  assert.equal(getFeatureParameterKind("object[]"), "array");
  assert.equal(getFeatureParameterKind("object"), "object");
  assert.equal(getFeatureParameterKind("Up to 2048 AP records with BSSID and site evidence"), "array");
  assert.equal(getFeatureParameterKind("One to six F194-F199 audit result objects"), "array");
  assert.equal(getFeatureParameterKind("Between two and eight profile records"), "array");
  assert.equal(getFeatureParameterKind("Up to 5000 sanitized webhook delivery metadata records"), "array");
  assert.equal(getFeatureParameterKind("number of active alerts"), "number");
  assert.equal(getFeatureParameterKind("Baseline window object with timestamped samples"), "object");
  assert.equal(getFeatureParameterKind("system_profiler JSON", "text"), "text");
  assert.equal(getFeatureParameterKind("opaque vendor-specific structure"), "json");
});
test("enum choices are trimmed, stable and duplicate-free", () => {
  assert.deepEqual(getFeatureParameterChoices("2.4GHz | 5GHz | 6GHz | 5GHz"), ["2.4GHz", "5GHz", "6GHz"]);
  assert.deepEqual(getFeatureParameterChoices("string"), []);
});
test("payload templates are driven by declared field types without discarding complex inputs", () => {
  assert.deepEqual(buildFeaturePayloadTemplate({
    networks: "optional network[]", enabled: "boolean", settings: "object",
    band: "2.4GHz|5GHz|6GHz", channel: "integer", frequency: "number",
    note: "string", source: "opaque vendor-specific structure",
  }), {
    networks: [], enabled: false, settings: {}, band: "2.4GHz",
    channel: 0, frequency: 0, note: "", source: {},
  });
});
test("JSON field parsing enforces the declared array and object shapes", () => {
  assert.deepEqual(parseFeatureParameterValue("[1,2]", "array"), [1, 2]);
  assert.deepEqual(parseFeatureParameterValue('{"site":"office"}', "object"), { site: "office" });
  assert.throws(() => parseFeatureParameterValue('{"wrong":"shape"}', "array"), /requires a JSON array/);
  assert.throws(() => parseFeatureParameterValue("[]", "object"), /requires a JSON object/);
  assert.throws(() => parseFeatureParameterValue("{broken", "object"), /Enter valid JSON/);
});
test("payload template builder accepts empty or invalid parameter metadata", () => {
  assert.deepEqual(buildFeaturePayloadTemplate(), {});
  assert.deepEqual(buildFeaturePayloadTemplate([]), {});
});
