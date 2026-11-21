const KNOWN_BANDS = ["2.4GHz", "5GHz", "6GHz"];

function measuredRssi(value) {
  if (value === null || value === undefined || value === "") return null;
  const number = Number(value);
  return Number.isFinite(number) && number >= -127 && number <= 0 ? number : null;
}

export function summariseBandPresence(networks) {
  const groups = new Map();
  let hiddenBssCount = 0;

  for (const network of Array.isArray(networks) ? networks : []) {
    const ssid = typeof network?.ssid === "string" ? network.ssid : "";
    if (!ssid) {
      hiddenBssCount += 1;
      continue;
    }
    if (!groups.has(ssid)) {
      groups.set(ssid, { ssid, bands: Object.fromEntries(KNOWN_BANDS.map(band => [band, []])), unknownBandCount: 0 });
    }
    const group = groups.get(ssid);
    const band = network?.band;
    if (!KNOWN_BANDS.includes(band)) {
      group.unknownBandCount += 1;
      continue;
    }
    group.bands[band].push({
      bssid: typeof network?.bssid === "string" ? network.bssid : null,
      channel: network?.channel === null || network?.channel === undefined || network.channel === "" ? null : Number.isInteger(Number(network.channel)) ? Number(network.channel) : null,
      rssi: measuredRssi(network?.rssi),
    });
  }

  const summaries = [...groups.values()].map(group => {
    const bands = {};
    for (const band of KNOWN_BANDS) {
      const observations = group.bands[band];
      const measured = observations.filter(observation => observation.rssi !== null)
        .sort((first, second) => second.rssi - first.rssi);
      bands[band] = {
        bss_count: observations.length,
        strongest: measured[0] || null,
      };
    }
    const presentBands = KNOWN_BANDS.filter(band => bands[band].bss_count > 0);
    return {
      ssid: group.ssid,
      bands,
      present_bands: presentBands,
      multi_band_observed: presentBands.length > 1,
      total_bss_count: KNOWN_BANDS.reduce((sum, band) => sum + bands[band].bss_count, 0) + group.unknownBandCount,
      unknown_band_count: group.unknownBandCount,
    };
  }).sort((first, second) => first.ssid.localeCompare(second.ssid));

  return {
    multiBand: summaries.filter(summary => summary.multi_band_observed),
    singleOrUnknownBand: summaries.filter(summary => !summary.multi_band_observed),
    hiddenBssCount,
  };
}
