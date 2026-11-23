# Multi-site fleet overview

The Fleet Overview page combines the authenticated site directory, one latest
telemetry row per site and the latest router-agent heartbeat/snapshot summaries.
It is a read-only operational view. It does not trigger scans, speed tests,
agent commands or router configuration changes.

## Data sources

| Source | Purpose | Access control |
|---|---|---|
| `GET /api/sites` | Site IDs visible to the current account | Authenticated site assignments |
| `GET /api/telemetry/latest?days=1&limit=100` | Latest persisted aggregate minute per site | `sites.read`, filtered to assigned sites |
| `GET /api/agents/health` | Server-time-based agent health classification | `agents.read`, visible agent assignments |
| `GET /api/agents/snapshots` | Latest retained snapshot summary per visible agent | `agents.read`, visible agent assignments |

The telemetry latest endpoint returns at most one row for each site. It uses
an indexed latest-minute query rather than returning the oldest 100 or 5,000
history rows, so a high-volume site cannot starve quieter sites from the fleet
view. The maximum is 100 sites per request. The `days` parameter bounds the
lookback window for latest measurements.

Each site's telemetry freshness is calculated from the latest bucket timestamp.
The default threshold is five minutes. A missing row is shown as **No data**;
a row older than five minutes is **Stale**. The dashboard does not equate
missing or stale telemetry with a healthy site, and missing metric values
remain unavailable rather than being displayed as zero.

## Agent status

The agent health API classifies heartbeats using server-recorded timestamps,
not device-provided clock assumptions. The Fleet Overview joins the health
summary to the latest snapshot's site assignment. Agents without a visible
latest snapshot/site assignment are shown as unassigned rather than guessed
into a site.

A stale heartbeat can mean a powered-off device, a broken network path, a
firewall block, a service outage or credential revocation. The health panel
does not infer the cause. Snapshot counts are retained observations, not a
live Wi-Fi client count or a guarantee that the data plane is operational.

## Refresh and limitations

The UI refreshes the site directory, latest rollups, agent health and latest
snapshots every 30 seconds. A manual refresh is also available. Each source
fails independently: a problem with agent inventory does not erase otherwise
available telemetry, and failed sources are explicitly reported as partial
data.

This is a single-workspace, site-scoped fleet summary. It does not yet provide
multi-tenant fleet federation, historical uptime/SLO calculations, distributed
event aggregation across API replicas, topology discovery between sites or
centralised configuration management. Use the existing site-history and
telemetry-history pages for historical trend analysis.
