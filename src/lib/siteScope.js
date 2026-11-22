/**
 * Normalise the authenticated site-directory response before it reaches a selector.
 * Server-side access checks remain authoritative for every site operation.
 */
const SITE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export function normaliseVisibleSiteIds(response) {
  const values = Array.isArray(response)
    ? response
    : Array.isArray(response?.site_ids) ? response.site_ids : [];
  const visible = values
    .filter(value => typeof value === 'string')
    .map(value => value.trim())
    .filter(value => SITE_ID_PATTERN.test(value));
  return [...new Set(visible)].sort().slice(0, 100);
}
