/**
 * Calculate actual interface throughput from successive byte-counter samples.
 * A reset, missing counter or non-positive sample interval produces no rate.
 */
export function calculateInterfaceRates(previous, current) {
  if (!previous || !current) return null;

  const fields = ["sampledAt", "rxBytes", "txBytes"];
  for (const sample of [previous, current]) {
    for (const field of fields) {
      if (typeof sample[field] !== "number" || !Number.isFinite(sample[field])) {
        return null;
      }
    }
    if (sample.rxBytes < 0 || sample.txBytes < 0) return null;
  }

  const elapsedMs = current.sampledAt - previous.sampledAt;
  if (
    elapsedMs <= 0
    || current.rxBytes < previous.rxBytes
    || current.txBytes < previous.txBytes
  ) {
    return null;
  }

  const rxMbps = ((current.rxBytes - previous.rxBytes) * 8) / (elapsedMs * 1000);
  const txMbps = ((current.txBytes - previous.txBytes) * 8) / (elapsedMs * 1000);
  if (!Number.isFinite(rxMbps) || !Number.isFinite(txMbps)) return null;

  return { rxMbps, txMbps, sampledAt: current.sampledAt };
}
