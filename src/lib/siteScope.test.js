import test from "node:test";
import assert from "node:assert/strict";
import { normaliseVisibleSiteIds } from "./siteScope.js";

test("site picker accepts only bounded, visible string identifiers", () => {
  assert.deepEqual(normaliseVisibleSiteIds({
    site_ids: [' head-office ', '', null, 4, '../bad', 'branch/other', 'branch', 'branch'],
  }), ['branch', 'head-office']);
});

test("malformed site-directory responses fail closed to an empty list", () => {
  for (const response of [null, {}, { site_ids: 'head-office' }, { site_ids: null }, ['']]) {
    assert.deepEqual(normaliseVisibleSiteIds(response), []);
  }
});

test("site directory output is deduplicated, sorted and bounded to the API maximum", () => {
  const values = Array.from({ length: 110 }, (_, index) => `site-${String(index).padStart(3, '0')}`);
  const result = normaliseVisibleSiteIds({ site_ids: [...values, values[0]] });
  assert.equal(result.length, 100);
  assert.deepEqual(result, values.slice(0, 100));
});
