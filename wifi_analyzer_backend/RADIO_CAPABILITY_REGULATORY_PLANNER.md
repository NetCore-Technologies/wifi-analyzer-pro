# Controller radio capability and regulatory channel planner (F207)

F207 is a read-only channel eligibility and change-preview tool. It compares a
fresh controller/agent radio capability snapshot with a normalized F206
regulatory evidence result and requires an explicit reviewer acknowledgement
bound to that exact F206 content fingerprint.

It does not write configuration, fetch regulator URLs, authenticate source
documents, interpret legal instruments or establish that a channel is legally
authorized. A result of eligible means only that the supplied capability
snapshot and supplied rule record agree under the checks below.

## Authenticated API

Run through the authenticated feature endpoint:

- POST /api/features/radio_capability_regulatory_channel_planner
- Requires diagnostics.run and access to the supplied site_id.
- Request JSON is limited by the backend's standard 1 MiB body limit.
- The Feature Workbench accepts a JSON file up to 900 KiB. Alternatively, select a centrally retained F206 version from the site registry; the panel submits its registry reference rather than copying the document.

## Required input

The authenticated production API accepts a site_id, a retained
regulatory_dataset_ref and 1-256 radio capability snapshots. It deliberately
does not accept inline regulatory_dataset or dataset_acknowledgement fields:
the server loads the immutable F206 dataset and reviewer acknowledgement from
the site registry and rechecks the fingerprint and revocation state on every
request.

The F206 version must be validated, effective for the assessment date, from
the current jurisdiction/domain allowlist and no older than 365 days. It must
have a canonical fingerprint that matches all normalized source and rule
records, source-clause references, date metadata and source counts. A stored
review acknowledgement must bind to that exact fingerprint and be no older
than 90 days. The retain API records the authenticated username and
server-generated UTC review time; it requires an explicit operator
acknowledgement and a review/change reference.

Each radio includes radio_id, ap_id, site_id, jurisdiction,
installation_reference, band, capability_source, capabilities_observed_at,
supported_channels, supported_channel_widths_mhz, device_class, environment,
DFS/AFC support flags and maximum EIRP. A controller or agent is the declared
capability source; operator-entered capability claims are rejected. Snapshot
freshness defaults to seven days and can be set from one to 30 days.

The pure F207 module accepts normalized inline evidence for deterministic
unit tests, but the authenticated production API requires a retained registry
reference so revocation cannot be bypassed by replaying an old exported JSON
document.

## Eligibility checks

- Radio site and jurisdiction must match the request and reviewed dataset.
- Candidate channel and width must both appear in the controller's supported
  channel/width lists and the F206 rule. The occupied channel-width frequency
  span must fit inside the rule's lower/upper frequency interval.
- Device class and indoor/outdoor installation constraints must match.
- DFS-required candidates need a fresh per-channel DFS state. Non-occupancy
  and unavailable states are excluded. A CAC-required channel can be shown
  only with requires_dfs_cac_before_activation=true.
- AFC-required candidates need a radio with AFC support and a non-expired grant
  covering the channel, jurisdiction and exact installation_reference.
- The EIRP ceiling is the minimum of the rule and radio limits, with optional
  EIRP density converted to a channel-width ceiling using
  density + 10 log10(channel width). AFC grant power is also applied when
  relevant. The proposed power never increases the current power.
- If multiple distinct rules match one channel/width combination, F207
  excludes that combination as ambiguous rather than inventing rule precedence.
- Eligible candidates are ordered to preserve the current channel/width, then
  minimize channel/width changes; 6 GHz PSC candidates are preferred as a
  deterministic tie-break. This does not estimate interference or throughput.

## Output and deployment boundary

The result contains per-radio eligible candidates, excluded-reason counts,
rule/source references, DFS CAC prerequisites, AFC/EIRP ceilings and one
lowest-change proposed configuration per radio. Radios with stale capability
snapshots are marked review_required and receive no recommendations.

change_application.applied is always false and execution_method is
preview_only. Review current controller state and site conditions, perform the
organisation's change review, and deploy through a separate controller
adapter. F207 contains no write operation or implicit approval path.
