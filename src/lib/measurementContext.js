const STRING_FIELDS = ["device_model", "antenna_type", "calibration_id"];
const NUMBER_FIELDS = ["channel", "channel_width_mhz", "antenna_orientation_deg", "antenna_height_m"];

function printableString(value, field) {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string") throw new TypeError(`measurement_context.${field} must be a string.`);
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > 128 || /[\u0000-\u001f\u007f]/.test(trimmed)) {
    throw new RangeError(`measurement_context.${field} must contain 1 to 128 printable characters.`);
  }
  return trimmed;
}

function finiteNumber(value, field) {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value === "boolean") throw new TypeError(`measurement_context.${field} must be a finite number.`);
  const number = Number(value);
  if (!Number.isFinite(number)) throw new TypeError(`measurement_context.${field} must be a finite number.`);
  return number;
}

export function buildMeasurementContext(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new TypeError("measurement_context must be an object.");
  }
  const result = {};
  for (const field of STRING_FIELDS) {
    const value = printableString(input[field], field);
    if (value !== undefined) result[field] = value;
  }

  const band = input.radio_band;
  if (band !== undefined && band !== null && band !== "") {
    if (!["2.4GHz", "5GHz", "6GHz"].includes(band)) {
      throw new RangeError("measurement_context.radio_band must be 2.4GHz, 5GHz or 6GHz.");
    }
    result.radio_band = band;
  }

  for (const field of NUMBER_FIELDS) {
    const number = finiteNumber(input[field], field);
    if (number === undefined) continue;
    if (field === "channel" && (!Number.isInteger(number) || number < 1 || number > 233)) {
      throw new RangeError("measurement_context.channel must be an integer from 1 to 233.");
    }
    if (field === "channel_width_mhz" && ![5, 10, 20, 40, 80, 160, 320].includes(number)) {
      throw new RangeError("measurement_context.channel_width_mhz must be a supported channel width.");
    }
    if (field === "antenna_orientation_deg" && (number < 0 || number > 359.9)) {
      throw new RangeError("measurement_context.antenna_orientation_deg must be between 0 and 359.9.");
    }
    if (field === "antenna_height_m" && (number < 0.1 || number > 20)) {
      throw new RangeError("measurement_context.antenna_height_m must be between 0.1 and 20 metres.");
    }
    result[field] = number;
  }
  return result;
}

export function measurementContextFormState(value) {
  const context = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  return {
    device_model: context.device_model == null ? "" : String(context.device_model),
    radio_band: context.radio_band == null ? "" : String(context.radio_band),
    channel: context.channel == null ? "" : String(context.channel),
    channel_width_mhz: context.channel_width_mhz == null ? "" : String(context.channel_width_mhz),
    antenna_type: context.antenna_type == null ? "" : String(context.antenna_type),
    antenna_orientation_deg: context.antenna_orientation_deg == null ? "" : String(context.antenna_orientation_deg),
    antenna_height_m: context.antenna_height_m == null ? "" : String(context.antenna_height_m),
    calibration_id: context.calibration_id == null ? "" : String(context.calibration_id),
  };
}
