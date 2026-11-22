# Demo data and measurement provenance

WiFi Analyzer Pro has an explicit demo mode so users can explore the dashboard
without a Wi-Fi adapter. Demo fixtures are illustrative examples, not
measurements of the user's network.

## Source boundary

The backend labels scan responses with a `source` field. The frontend accepts
only `live` or `demo`; missing or unknown provenance is treated as an API
error and is not silently promoted to live data.

- `source: live` is used only when the backend is not in explicit demo mode.
- `source: demo` is used by the configured demo backend.
- When the API is unavailable, the dashboard may show its built-in example
  network/device fixtures, and the top-level status remains visibly marked
  DEMO/OFFLINE rather than LIVE.
- The Settings option `Hide demo observations` hides built-in example networks
  and devices while live observations are unavailable.

The Dashboard and Wireless panels label demo charts and records as previews.
Feature-grid cards are explicitly marked as planned capability previews. Demo
records are not included in the backend's persistent telemetry rollups.

## Historical charts

The Signal panel no longer generates random RSSI/SNR series or presents a
fabricated stability forecast. It aggregates valid RSSI values from successful
live scan responses only. SNR is included only when the scanner explicitly
reports a valid value derived from noise-floor evidence. The panel retains at
most 60 aggregated scan summaries in memory for the current app session; it
does not persist identifiers or create a synthetic line when observations are
missing.

The Speed Test panel no longer displays a generated throughput series. Its
history is populated only after the user starts a speed test and the API returns
valid download, upload and ping measurements. Up to 24 completed tests are
kept in the current app session. Running the test contacts Cloudflare and
transfers data over the internet; this is initiated only by the user's action.

Alerts are derived from the current live scan and latest diagnostic response.
The dashboard does not display fabricated historical alert counts or claim a
24-hour alert history where no such store is connected.

## Interpretation

A demo screenshot or demo scan must never be used as a site survey, customer
acceptance result, security finding, channel recommendation or compliance
evidence. Use a successful live scan, controller/agent evidence and timestamped
survey measurements for operational conclusions. A missing metric remains
unknown rather than being estimated from typical values.
