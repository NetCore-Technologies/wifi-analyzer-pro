/**
 * Select rows without ever substituting demo fixtures for a missing live result.
 * A demo source may use its explicit API payload or the local demo fixture.
 */
export function selectObservationRows({
  source,
  rows,
  demoRows = [],
  hideDemoData = false,
} = {}) {
  if (source === "live") return Array.isArray(rows) ? rows : [];
  if (hideDemoData) return [];
  if (Array.isArray(rows)) return rows;
  return Array.isArray(demoRows) ? demoRows : [];
}
