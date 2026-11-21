# RF survey acceptance auditor (F205)

F205 evaluates a retained F203 survey report against a customer-defined
acceptance policy. It is a measured-evidence audit, not a coverage predictor.

## API

POST /api/features/rf_survey_acceptance_auditor

The normal authenticated feature endpoint requires diagnostics.run and checks
the nested site_id against the caller's site assignments. The request contains:

- site_id: the site owning the retained report.
- report: an object containing report metadata and the immutable F203 result.
- policy: the explicit acceptance thresholds described below.
- zones: optional floor-plan rectangles for separate area-level scoring.
- as_of: optional timezone-aware assessment time for reproducible freshness.

The normal API request-size limit, feature-run allowance, audit controls and
site-scope checks apply. The auditor does not write router configuration or
modify the original F203 report.

## Policy fields

| Field | Default | Accepted range |
|---|---:|---:|
| minimum_rssi_dbm | -67 dBm | -120 to -10 dBm |
| minimum_snr_db | Not required | -20 to 150 dB |
| minimum_passing_points_pct | 95% | 0 to 100% |
| minimum_sample_count | 10 | 1 to 20,000 |
| minimum_qualifying_aps | 1 | 1 to 16 |
| maximum_sample_age_days | 7 | 1 to 30 days |

A point passes only when its number of AP readings meeting both configured
signal criteria reaches minimum_qualifying_aps. When minimum_snr_db is set,
each qualifying reading must contain a measured noise floor; absent SNR fails
that reading. SNR is checked against RSSI minus the measured noise value.

The report needs at least minimum_sample_count fresh, valid survey points.
Below that threshold the overall status is insufficient_evidence, not
accepted. Otherwise, the measured point pass percentage is compared with
minimum_passing_points_pct to return accepted or rejected. Stale measurements
are counted and excluded, while malformed stale measurements still cause
validation errors.

## Optional floor-plan zones

Zones are axis-aligned rectangles in the F203 floor-plan pixel coordinate
system. Each zone requires a unique zone_id and x1_px, y1_px, x2_px, y2_px
bounds inside the floor-plan dimensions. Each zone is scored independently
using only the actual measured points inside that rectangle. Zones may overlap;
an overlapping point is counted in each applicable zone. A zone with too few
sampled points returns insufficient_evidence.

## Interpretation and limitations

- No values are interpolated between survey points.
- Unsampled floor-plan areas are not scored and cannot be described as passing.
- The point pass criteria are customer acceptance thresholds, not universal
  Wi-Fi standards or a guarantee of application-level service.
- Evidence source labels and measurement context are caller-declared, not
  cryptographically attested.
- The report's AP inventory and per-measurement AP identifiers are validated;
  unknown APs, duplicated point/AP readings, duplicate AP IDs, invalid
  fingerprints, cross-floor measurements, future timestamps and inconsistent
  RSSI/noise/SNR values are rejected.
- Zone boundaries are operator-drawn rectangles; walls, propagation,
  interference, traffic load, roaming and capacity are not modelled.

The returned report includes overall and per-zone pass counts, failure counts,
percentages, excluded stale measurements, individual measured-point outcomes
and the policy used for the assessment.
