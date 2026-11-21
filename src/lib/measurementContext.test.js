import test from "node:test";
import assert from "node:assert/strict";
import { buildMeasurementContext, measurementContextFormState } from "./measurementContext.js";

test("builds a canonical optional measurement context", () => {
  assert.deepEqual(buildMeasurementContext({
    device_model: "  SurveyClient X ",
    radio_band: "5GHz",
    channel: "36",
    channel_width_mhz: "80",
    antenna_type: "integrated",
    antenna_orientation_deg: "90",
    antenna_height_m: "1.2",
    calibration_id: "cal-2026-11",
  }), {
    device_model: "SurveyClient X",
    radio_band: "5GHz",
    channel: 36,
    channel_width_mhz: 80,
    antenna_type: "integrated",
    antenna_orientation_deg: 90,
    antenna_height_m: 1.2,
    calibration_id: "cal-2026-11",
  });
});

test("omits empty optional context fields", () => {
  assert.deepEqual(buildMeasurementContext({
    device_model: "",
    radio_band: "",
    channel: "",
    channel_width_mhz: "",
    antenna_type: "",
    antenna_orientation_deg: "",
    antenna_height_m: "",
    calibration_id: "",
  }), {});
});

test("rejects invalid band, non-integer channel and unsupported channel width", () => {
  assert.throws(() => buildMeasurementContext({ radio_band: "unknown" }), /radio_band/);
  assert.throws(() => buildMeasurementContext({ channel: "36.5" }), /integer from 1 to 233/);
  assert.throws(() => buildMeasurementContext({ channel: 234 }), /integer from 1 to 233/);
  assert.throws(() => buildMeasurementContext({ channel_width_mhz: 7 }), /supported channel width/);
});

test("rejects non-finite, boolean and out-of-range antenna values", () => {
  assert.throws(() => buildMeasurementContext({ antenna_orientation_deg: "NaN" }), /finite number/);
  assert.throws(() => buildMeasurementContext({ antenna_height_m: true }), /finite number/);
  assert.throws(() => buildMeasurementContext({ antenna_orientation_deg: 360 }), /between 0 and 359.9/);
  assert.throws(() => buildMeasurementContext({ antenna_height_m: 0 }), /between 0.1 and 20 metres/);
});

test("rejects non-printable, oversized or incorrectly typed text context", () => {
  assert.throws(() => buildMeasurementContext({ device_model: "bad\nvalue" }), /printable characters/);
  assert.throws(() => buildMeasurementContext({ antenna_type: "x".repeat(129) }), /printable characters/);
  assert.throws(() => buildMeasurementContext({ calibration_id: 42 }), /must be a string/);
});

test("converts a stored context into controlled form values without losing zeroes", () => {
  assert.deepEqual(measurementContextFormState({
    device_model: "SurveyClient",
    radio_band: "6GHz",
    channel: 5,
    channel_width_mhz: 160,
    antenna_orientation_deg: 0,
    antenna_height_m: 1.5,
  }), {
    device_model: "SurveyClient",
    radio_band: "6GHz",
    channel: "5",
    channel_width_mhz: "160",
    antenna_type: "",
    antenna_orientation_deg: "0",
    antenna_height_m: "1.5",
    calibration_id: "",
  });
});
