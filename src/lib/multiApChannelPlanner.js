const BANDS = new Set(['2.4GHz', '5GHz', '6GHz']);
const WIDTHS = new Set([20, 40, 80, 160, 320]);
const SOURCES = new Set(['survey', 'controller', 'operator']);

export function parsePlannerInteger(value, fieldName, optional = false) {
  const text = String(value ?? '').trim();
  if (!text && optional) return null;
  if (!/^\d+$/.test(text)) throw new Error(fieldName + ' must be a whole number.');
  const number = Number(text);
  if (!Number.isSafeInteger(number)) throw new Error(fieldName + ' is outside the supported range.');
  return number;
}

export function parsePlannerChannelOptions(value, width, radioId) {
  const entries = String(value ?? '').split(',').map(item => item.trim()).filter(Boolean);
  if (entries.length === 0) throw new Error('Radio ' + radioId + ': enter at least one permitted channel.');
  const parsed = entries.map((entry, index) => {
    if (width === 20) return parsePlannerInteger(entry, 'Radio ' + radioId + ', option ' + (index + 1));
    const match = entry.match(/^(\d+)\s*@\s*(\d+(?:\.\d+)?)$/);
    if (!match) throw new Error('Radio ' + radioId + ': wide channel options must use channel@centreMHz, e.g. 36@5190.');
    const channel = Number(match[1]);
    const center = Number(match[2]);
    if (!Number.isSafeInteger(channel) || !Number.isFinite(center) || center <= 0) {
      throw new Error('Radio ' + radioId + ': channel and centre frequency must be valid positive numbers.');
    }
    return { channel, center_frequency_mhz: center };
  });
  const channels = parsed.map(item => typeof item === 'number' ? item : item.channel);
  if (new Set(channels).size !== channels.length) throw new Error('Radio ' + radioId + ': channel options must be unique.');
  return parsed;
}

export function buildMultiApPlannerPayload(radios, edges, penaltyValue) {
  if (!Array.isArray(radios) || radios.length < 2 || radios.length > 256) {
    throw new Error('Add between 2 and 256 AP radio records before planning.');
  }
  if (!Array.isArray(edges)) throw new Error('Interference relationships must be a list.');
  const inputRadios = radios.map((radio, index) => {
    const radioId = String(radio.radio_id ?? '').trim();
    const apId = String(radio.ap_id ?? '').trim();
    const siteId = String(radio.site_id ?? '').trim();
    if (!radioId || !apId || !siteId) throw new Error('Radio row ' + (index + 1) + ': radio ID, AP ID and site ID are required.');
    const validId = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;
    if (!validId.test(radioId) || !validId.test(apId) || !validId.test(siteId)) {
      throw new Error('Radio row ' + (index + 1) + ': IDs must use 1–64 letters, numbers, dots, underscores, colons or hyphens.');
    }
    if (!BANDS.has(radio.band)) throw new Error('Radio ' + radioId + ': select a supported Wi-Fi band.');
    const width = Number(radio.width ?? radio.channel_width_mhz);
    if (!WIDTHS.has(width) || (radio.band === '2.4GHz' && ![20, 40].includes(width)) || (radio.band === '5GHz' && width === 320)) {
      throw new Error('Radio ' + radioId + ': channel width is not supported for ' + radio.band + '.');
    }
    return {
      radio_id: radioId,
      ap_id: apId,
      site_id: siteId,
      band: radio.band,
      channel_width_mhz: width,
      current_channel: parsePlannerInteger(radio.current_channel, 'Radio ' + radioId + ' current channel', true),
      channel_options: parsePlannerChannelOptions(radio.options ?? radio.channel_options, width, radioId),
    };
  });
  const radioById = new Map();
  for (const radio of inputRadios) {
    if (radioById.has(radio.radio_id)) throw new Error('Duplicate radio ID: ' + radio.radio_id + '.');
    radioById.set(radio.radio_id, radio);
  }
  const inputEdges = edges
    .filter(edge => edge.left || edge.right || edge.weight || edge.source || edge.evidence_source)
    .map((edge, index) => {
      if (!edge.left || !edge.right) throw new Error('Interference link ' + (index + 1) + ': select both radios.');
      if (edge.left === edge.right) throw new Error('Interference link ' + (index + 1) + ': select two different radio records.');
      const left = radioById.get(edge.left);
      const right = radioById.get(edge.right);
      if (!left || !right) throw new Error('Interference link ' + (index + 1) + ': a selected radio no longer exists.');
      if (left.site_id !== right.site_id || left.band !== right.band) {
        throw new Error('Interference link ' + (index + 1) + ': radios must share a site and band.');
      }
      const rawWeight = String(edge.weight ?? '').trim();
      if (!rawWeight) throw new Error('Interference link ' + (index + 1) + ': enter a relative weight from 0 to 1.');
      const weight = Number(rawWeight);
      if (!Number.isFinite(weight) || weight < 0 || weight > 1) {
        throw new Error('Interference link ' + (index + 1) + ': weight must be from 0 to 1.');
      }
      const evidenceSource = edge.source ?? edge.evidence_source;
      if (!SOURCES.has(evidenceSource)) throw new Error('Interference link ' + (index + 1) + ': select an evidence source.');
      return { radio_ids: [edge.left, edge.right], weight, evidence_source: evidenceSource };
    });
  if (inputEdges.length === 0) {
    throw new Error('Add at least one explicit RF interference relationship. The planner does not infer proximity or fabricate measurements.');
  }
  const penaltyText = String(penaltyValue ?? '').trim();
  const changePenalty = Number(penaltyText);
  if (!penaltyText || !Number.isFinite(changePenalty) || changePenalty < 0 || changePenalty > 0.5) {
    throw new Error('Channel-change penalty must be between 0 and 0.5.');
  }
  return { radios: inputRadios, interference_edges: inputEdges, change_penalty: changePenalty };
}

export function mapSavedSiteSnapshotToPlannerRadios(snapshot) {
  if (!snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot)) {
    throw new Error('The selected site snapshot is not a valid object.');
  }
  if (!Array.isArray(snapshot.access_points)) {
    throw new Error('The selected snapshot does not contain an AP inventory.');
  }
  const siteId = typeof snapshot.site_id === 'string' ? snapshot.site_id.trim() : '';
  if (!siteId) throw new Error('The selected snapshot has no site identifier.');
  const radios = [];
  let skippedIncomplete = 0;
  let skippedWide = 0;
  let skippedCrossSite = 0;
  snapshot.access_points.forEach((ap, index) => {
    if (!ap || typeof ap !== 'object' || Array.isArray(ap)) {
      skippedIncomplete += 1;
      return;
    }
    if (typeof ap.site_id === 'string' && ap.site_id.trim() && ap.site_id.trim() !== siteId) {
      skippedCrossSite += 1;
      return;
    }
    const identity = String(ap.bssid || ap.ap_id || ap.name || '').trim();
    if (!identity || !BANDS.has(ap.band) || !Number.isSafeInteger(ap.channel) || ap.channel < 1 || ap.channel > 233) {
      skippedIncomplete += 1;
      return;
    }
    if (ap.channel_width_mhz !== 20) {
      skippedWide += 1;
      return;
    }
    const safeApId = identity.replace(/[^A-Za-z0-9._:-]/g, '-').slice(0, 42);
    const radioId = (safeApId + '-' + ap.band.replace(/[^A-Za-z0-9]/g, '') + '-' + (index + 1)).slice(0, 64);
    radios.push({
      radio_id: radioId,
      ap_id: safeApId,
      site_id: siteId,
      band: ap.band,
      width: '20',
      current_channel: String(ap.channel),
      options: String(ap.channel),
    });
  });
  return {
    radios,
    skipped_incomplete_count: skippedIncomplete,
    skipped_wide_channel_count: skippedWide,
    skipped_cross_site_count: skippedCrossSite,
  };
}
