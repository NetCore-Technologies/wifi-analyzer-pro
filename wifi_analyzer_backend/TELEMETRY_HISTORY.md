# Persistent Wi-Fi telemetry history

WiFi Analyzer Pro can retain local, site-scoped historical scan and diagnostic
trends. The API writes telemetry automatically when it serves a successful
live scan or diagnostic response. Demo-mode observations are never inserted
into historical telemetry.

## Storage and privacy

The telemetry store uses SQLite and keeps one aggregate row per site and UTC
minute. Repeated scans within a minute update that minute's rollup instead of
creating an unbounded record for every five-second poll.

Persisted scan aggregates include scan count, average/minimum/maximum observed
BSS count, open-network count, band counts, and summary RSSI statistics.
Diagnostic aggregates include measured latency, jitter and packet-loss sample
counts, averages and extrema. Completed speed tests also retain download/upload
throughput and the speed-test ping measurement. Failed tests are not stored.

Raw SSIDs, BSSIDs, client identifiers, packet captures and complete request
payloads are not retained in this database. Measurements that were not supplied
or were invalid are omitted; an unavailable metric is not converted to zero.

The database is stored locally, outside the repository. The default path follows
the operating system's application-state directory. Override it with
WIFI_ANALYZER_TELEMETRY_DB. New state directories are created with owner-only
permissions and the database file is restricted to mode 0600 on POSIX systems.
Keep the application state volume in the deployment's backup and restore plan.

## Site identity and access control

The default local site identifier is local. Set
WIFI_ANALYZER_LOCAL_SITE_ID to a stable, installation-specific identifier
when multiple deployments report into the same operational naming scheme.
Identifiers must begin with a letter or number and may then contain letters,
numbers, periods, underscores, colons or hyphens, up to 128 characters.

History reads use sites.read and the caller's existing site assignment. A
request with an explicit site_id outside the caller's scope is rejected. The
site appears in the managed-site directory after the first telemetry bucket is
written, so an owner can assign it to a viewer or analyst.

The read-only endpoint is:

- GET /api/telemetry/history?days=7
- Optional site_id selects one visible site.
- Optional limit bounds the number of returned minute buckets.
- The maximum history window is controlled by the configured store retention.

## Retention and interpretation

The default history retention is 90 days, with a hard per-site cap of 130,000
minute buckets. Old buckets are pruned during writes. The cap provides a second
storage bound even when a deployment scans continuously.

These are host-observed scan and probe aggregates, not an RF spectrum survey,
airtime measurement, AP-to-AP propagation result, client experience SLA or
guaranteed uptime record. RSSI averages are averages of the valid BSS readings
actually returned by the local adapter. Driver permissions, scan intervals,
radio availability and probe conditions affect data coverage. A missing line
means no valid measurement was recorded for that interval.

Historical trends are read-only. This subsystem does not change channel,
transmit power, SSID, security or router configuration.
