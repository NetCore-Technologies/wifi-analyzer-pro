const BSSID_PATTERN = /^(?:[0-9A-F]{2}:){5}[0-9A-F]{2}$/;
const MAX_TRUSTED_SSIDS = 256;
const MAX_BSSIDS_PER_SSID = 64;
const MAX_TRUSTED_BSSIDS = 1024;

export function normalizeBssid(value) {
  if (typeof value !== "string") return null;
  const normalized = value.trim().replace(/-/g, ":").toUpperCase();
  if (!BSSID_PATTERN.test(normalized)) return null;
  const firstOctet = Number.parseInt(normalized.slice(0, 2), 16);
  if ((firstOctet & 1) !== 0 || normalized === "00:00:00:00:00:00") return null;
  return normalized;
}

export function validateSsid(value) {
  if (typeof value !== "string") return false;
  if (!value.length || value.length > 32 || /[\u0000-\u001F\u007F]/.test(value)) return false;
  return new TextEncoder().encode(value).length <= 32;
}

export function sanitizeTrustedMap(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  const sanitized = {};
  let total = 0;
  for (const [ssid, values] of Object.entries(value)) {
    if (!validateSsid(ssid) || !Array.isArray(values) || Object.keys(sanitized).length >= MAX_TRUSTED_SSIDS) continue;
    const bssids = [...new Set(values.map(normalizeBssid).filter(Boolean))];
    if (!bssids.length) continue;
    if (bssids.length > MAX_BSSIDS_PER_SSID || total + bssids.length > MAX_TRUSTED_BSSIDS) continue;
    Object.defineProperty(sanitized, ssid, {
      value: bssids,
      enumerable: true,
      configurable: true,
      writable: true,
    });
    total += bssids.length;
  }
  return sanitized;
}

export function addTrustedBssid(trusted, ssid, bssid) {
  if (!validateSsid(ssid)) throw new TypeError("SSID must contain 1 to 32 UTF-8 bytes and no control characters.");
  const normalized = normalizeBssid(bssid);
  if (!normalized) throw new TypeError("Enter a valid BSSID in AA:BB:CC:DD:EE:FF format.");
  const current = sanitizeTrustedMap(trusted);
  const existing = Object.hasOwn(current, ssid) ? current[ssid] : [];
  if (existing.includes(normalized)) return current;
  const total = Object.values(current).reduce((sum, items) => sum + items.length, 0);
  if (total >= MAX_TRUSTED_BSSIDS) throw new RangeError("The trusted BSSID list has reached its configured limit.");
  if (existing.length >= MAX_BSSIDS_PER_SSID) throw new RangeError("This SSID already has the maximum number of trusted BSSIDs.");
  if (!Object.hasOwn(current, ssid) && Object.keys(current).length >= MAX_TRUSTED_SSIDS) {
    throw new RangeError("The trusted SSID list has reached its configured limit.");
  }
  return { ...current, [ssid]: [...existing, normalized] };
}

export function removeTrustedBssid(trusted, ssid, bssid) {
  const current = sanitizeTrustedMap(trusted);
  const normalized = normalizeBssid(bssid);
  if (!normalized || !Object.hasOwn(current, ssid)) return current;
  const remaining = current[ssid].filter(item => item !== normalized);
  const next = { ...current };
  if (remaining.length) next[ssid] = remaining;
  else delete next[ssid];
  return next;
}

export function assessTrustedAccessPoints(networks, trusted) {
  const baseline = sanitizeTrustedMap(trusted);
  const candidates = [];
  const seen = new Set();
  for (const network of Array.isArray(networks) ? networks : []) {
    const ssid = network?.ssid;
    if (!validateSsid(ssid) || !Object.hasOwn(baseline, ssid)) continue;
    const bssid = normalizeBssid(network?.bssid);
    if (!bssid || baseline[ssid].includes(bssid)) continue;
    const key = ssid + "\u0000" + bssid;
    if (seen.has(key)) continue;
    seen.add(key);
    candidates.push({
      ssid,
      bssid,
      rssi: network.rssi !== null && network.rssi !== undefined && network.rssi !== ""
        && Number.isFinite(Number(network.rssi)) && Number(network.rssi) >= -127 && Number(network.rssi) <= 0
        ? Number(network.rssi) : null,
      channel: network.channel ?? null,
      band: network.band ?? null,
      reason: "The SSID matches a trusted profile, but this BSSID is not in its allowlist.",
    });
  }
  return candidates.sort((first, second) => first.ssid.localeCompare(second.ssid) || first.bssid.localeCompare(second.bssid));
}
