# Floor-plan aligned RF survey analyzer (F203)

F203 correlates measured Wi-Fi RSSI/noise samples with AP locations placed on a
floor-plan coordinate system. It is an offline, read-only analysis tool. It does
not configure APs or infer RF coverage.

## Input contract

Run the feature through the authenticated endpoint:

- POST /api/features/floorplan_rf_survey_analyzer
- Requires diagnostics.run and access to the supplied site_id.
- Request bodies are bounded by the API's normal JSON request limit.
- The Feature Workbench also exposes a guided editor and accepts a JSON file up
  to 900 KiB to stay below the API's 1 MiB JSON request limit.

The JSON object contains:

- site_id: stable site identifier used by the API's existing site-scope check.
- floorplan: floorplan_id, floor_id, width_px, height_px and 1-20 scale_references.
- access_points: 1-256 AP records with ap_id and same-floor x_px/y_px coordinates.
- survey_samples: 1-8192 timestamped points with x_px/y_px, evidence_source and
  one or more per-AP measurements containing measured rssi_dbm and optional
  noise_dbm.
- as_of: optional timezone-aware ISO-8601 timestamp for reproducible reports.
- max_age_days: optional freshness bound from 1 to 30 days (default 7).

The GUI accepts an optional PNG, JPEG or WebP floor-plan image up to 10 MiB.
That image is previewed locally in the browser and is not sent to the API or
stored by the backend. Its pixel dimensions must correspond to the width_px
and height_px declared in the JSON.

## Validation and calculations

- Pixel coordinates must be finite and inside the declared floor-plan bounds.
- APs and survey samples must belong to the selected floor.
- Scale references convert known pixel distances to metres. Multiple
  references must agree within 15% of their median scale.
- Every sample must have a unique sample ID and timezone-aware observation
  timestamp. Future observations beyond the five-minute clock tolerance are
  rejected.
- Readings are bounded to RSSI -120 through -10 dBm and optional noise -150
  through -10 dBm. Missing noise remains null; SNR is calculated only when
  both RSSI and noise are present.
- Readings are validated even when their parent sample is stale. Stale samples
  are excluded from calculations and counted separately.
- Duplicate readings for the same AP within one survey point are rejected.
- Output omits the submitted sample IDs and instead returns a short one-way
  sample fingerprint for joining each reading back to its timestamped point.

The feature reports per-AP means, medians, minima/maxima, measured planar
distances, distance-bucket RSSI summaries and a simple RSSI-versus-log-distance
descriptive fit when at least three distinct distances exist. The fit is a
summary of the supplied measurements, not a propagation model.

## Output and interpretation

The API returns accepted survey measurements with point/AP pixel coordinates,
computed planar distance, RSSI, optional noise/SNR, timestamp and the
caller-declared evidence source. The GUI displays those actual points and APs
on the optional floor-plan image, plus a per-AP distance/RSSI scatter chart.

The output does not model wall or floor attenuation, antenna patterns,
polarisation, reflections, Fresnel clearance, channel utilisation, airtime,
interference, capacity or client roaming. A stronger measured RSSI at one
sample is not a guaranteed service level elsewhere. Evidence-source labels are
caller-declared and are not cryptographically attested.

A site survey should record its measurement device, antenna orientation,
height, band/channel, AP radio identity, calibration context and collection
method in the operator's source data. Do not use a synthetic sample payload as
site evidence. The UI explicitly labels its built-in sample values as
illustrative only.

## Saved report history

Validated F203 results can be retained in the site's local SQLite survey-history
database. The authenticated API provides:

- POST /api/sites/rf-surveys to run F203 once and save the resulting report.
  The request supplies site_id, survey and an optional label.
- GET /api/sites/rf-surveys?site_id=SITE to list up to 100 reports.
- GET /api/sites/rf-surveys/REPORT_UUID?site_id=SITE to retrieve a report.
- POST /api/sites/rf-surveys with operation=delete, site_id and survey_id to remove one report.

Saving requires both diagnostics.run and sites.manage plus explicit access to
the requested site. Reads require sites.read and explicit site access. Report removal requires the same site-management scope as saving. Every delete request is audited before the row is removed and successful deletions receive an outcome event. If the request audit cannot be recorded, no report is deleted. Writes
are audited before and after persistence; if the request audit cannot be
recorded, no report is saved. The save endpoint consumes one normal F203
feature-run allowance; it does not run the feature twice.

The database is stored outside the repository. Set
WIFI_ANALYZER_RF_SURVEY_DB to override its path. POSIX state directories and
database files are restricted to owner-only permissions. The application
retains up to 250 reports per site for 365 days by default, rejects report
documents larger than 8 MiB, and verifies a SHA-256 content digest when a
saved report is reopened. These limits are configurable through the store
constructor for deployments and tests.

Report metadata and measured result JSON are retained; the original uploaded
floor-plan image is not. The browser preview uses a temporary object URL and
does not upload that image to the API. A reopened report therefore displays
its saved AP and measurement coordinates over the coordinate grid until the
operator imports the corresponding floor-plan image again.
