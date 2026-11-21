export const WIFI_BANDS = ['2.4GHz', '5GHz', '6GHz'];

export function countObservedChannels(networks, band) {
  const counts = new Map();
  for (const network of Array.isArray(networks) ? networks : []) {
    if (network?.band !== band || network.channel === null || network.channel === undefined || network.channel === '') continue;
    const channel = Number(network.channel);
    if (!Number.isInteger(channel) || channel < 1 || channel > 233) continue;
    counts.set(channel, (counts.get(channel) || 0) + 1);
  }
  return counts;
}

/** Rank only channels actually present in the scan; never invent unobserved candidates. */
export function rankObservedChannels(networks, band) {
  return [...countObservedChannels(networks, band).entries()]
    .map(([channel, count]) => ({ channel, count }))
    .sort((first, second) => first.count - second.count || first.channel - second.channel);
}
