/**
 * Classify the provenance explicitly supplied by the local scan API.
 * Unknown or missing provenance must never be presented as a live observation.
 */
export function getScanSource(scanData) {
  if (scanData?.source === "live" || scanData?.source === "demo") {
    return scanData.source;
  }
  return "unknown";
}
