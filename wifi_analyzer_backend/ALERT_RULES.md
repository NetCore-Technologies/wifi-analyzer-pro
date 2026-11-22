# Site-scoped alert rules

## Evaluation scope

The persistent alert engine evaluates measured observations from the host's live Wi-Fi scans and host gateway/DNS diagnostics for the configured `WIFI_ANALYZER_LOCAL_SITE_ID` (default `local`). Rules can be read for other assigned sites, but creation is rejected until a telemetry evaluator is connected to that site. Demo observations are never evaluated.

## Supported measurements

| Metric | Source | Meaning |
|---|---|---|
| `minimum_rssi_dbm` | Live scan | Weakest valid measured RSSI in the scan |
| `network_count` | Live scan | Number of access-point records returned by the scan |
| `open_network_count` | Live scan | Count explicitly reported with open security |
| `gateway_latency_ms` | Host diagnostics | Mean RTT from the local default-gateway ping |
| `packet_loss_pct` | Host diagnostics | Packet loss from the local default-gateway ping |
| `gateway_jitter_ms` | Host diagnostics | Mean absolute change between successive gateway ping RTT samples |
| `dns_resolution_ms` | Host diagnostics | DNS resolution duration only when the optional DNS probe is configured and succeeds |

Missing, invalid, unavailable or unconfigured measurements are omitted. They do not count as healthy values and do not resolve an active incident. The open-network count is unknown if any observed AP has missing or explicitly unknown security metadata; unknown does not mean secured. The current platform scanner returns an empty list for both a genuinely empty scan and some adapter/command failures, so an empty scan is treated as unknown and does not trigger a zero-network rule. A distinct successful-empty scan status is required before that alert can be enabled safely.

## Rule semantics

Rules are scoped to a site and support greater-than/greater-or-equal/less-than/less-or-equal thresholds, `info`/`warning`/`critical` severity, an optional recovery threshold, a sustained-breach hold from 0 to 3600 seconds, a deduplication window from 60 to 86400 seconds, and optional quiet hours in an IANA time zone.

Recovery thresholds provide hysteresis. When a rule is edited, its existing active incident is resolved and any hold timer is reset; the next observation is evaluated against the new policy. A pending sustained breach is reset when successive observations are more than five minutes apart.

Repeated breaches update one active incident and increment its occurrence count rather than creating an incident for every scan. Quiet hours set an incident suppression indicator in the site's configured time zone; they do not prevent incident persistence.

Incidents transition through active, acknowledged and resolved. Acknowledgements record the authenticated username and are audited. An incident resolves only after a measured value crosses its recovery boundary. Deleting or disabling a rule resolves its active incident.

## API and access control

- `GET /api/sites/alert-rules?site_id=SITE` requires `sites.read` and explicit site assignment.
- `POST /api/sites/alert-rules` requires `sites.manage`; operations are `save`, `delete` and `acknowledge`.
- Writes are audit-first: if the request event cannot be persisted to the tamper-evident audit ledger, the rule or acknowledgement change is not applied.
- Rules are limited to 100 per site. Resolved incident history is retained for up to 365 days and bounded to 20,000 events per site; active incidents are not discarded to satisfy the history limit.
- SQLite state is stored outside the repository with owner-only permissions on POSIX systems. Override the database path with `WIFI_ANALYZER_ALERT_DB`.

External email, Slack, Discord and MQTT delivery are not configured by this feature. `quiet_hours_active` is currently a persisted suppression indicator, not proof that an external notification was sent or withheld.

## Privacy and interpretation

The rule engine stores rule configuration and incident metrics, not raw SSIDs, BSSIDs, client addresses or scan payloads. An RSSI rule uses the weakest measured RSSI in a scan, so it detects weak observations but does not estimate coverage or client experience. Gateway metrics are measured from the local host to its detected default gateway; they are not WAN performance measurements.