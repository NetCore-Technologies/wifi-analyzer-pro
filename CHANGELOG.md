# Changelog

All notable changes to WiFi Analyzer Pro are documented here.

## [1.0.7] — Unreleased

### Feature library and local account
- Add 171 independently callable feature modules (F001–F168 and F172–F174; F169–F171 cover the OpenWrt agent, negotiated system-health telemetry and Router Agent Console), a stable registry, metadata catalogue and searchable Feature Workbench.
- Add multi-site AP inventory snapshots, topology redundancy and snapshot-diff analysis, and AP inventory drift detection.
- Add cross-site AP inventory and channel-reuse audits, observation freshness checks, and a bounded timestamped topology history timeline.
- Add a site-aware AP-to-gateway path audit that excludes RF-neighbour and cross-site links and distinguishes missing evidence from unreachable paths.
- Add a site-aware radio standards audit for channel width, security and transmit power, including explicit unknown results for absent observations.
- Add a deterministic multi-site topology layout and interactive Workbench diagram with selectable AP details and typed link filters.
- Add a bounded SQLite site-discovery history store, authenticated save/list/read endpoints, cursor pagination and per-site retention.
- Add a stored site-to-site change report for per-site AP/topology drift, radio/vendor profile comparisons and cross-site BSSID reuse.
- Add a consolidated multi-site audit that reuses inventory, topology redundancy, gateway path/failover, radio standards, subnet capacity and saved-history reports, with explicit not-run states for missing evidence.
- Add a versioned OpenWrt read-only adapter manifest, authenticated adapter discovery and capability negotiation that rejects unsupported capabilities and write permissions.
- Add a bounded OpenWrt snapshot normalizer for board, interface, radio, association and route records; unknown and credential-like fields are excluded from its output.
- Add a bounded SQLite router-agent heartbeat registry and authenticated health endpoint with server-received freshness, status/error-code allowlists and no credential persistence.
- Add authenticated OpenWrt agent snapshot ingestion, credential-free normalisation before storage, duplicate capture protection, bounded per-agent retention and latest-snapshot read APIs.
- Add deterministic agent snapshot diffs for board metadata, network interfaces, wireless radio configuration, client associations and routes, with capped detail lists and explicit first-snapshot baselines.
- Add per-agent read-only bearer credentials with hashed-at-rest secrets, bounded expiry, one-time enrollment/rotation responses, immediate revocation, capability-scoped heartbeat/snapshot writes and admin-only credential metadata.
- Add UUID-keyed OpenWrt snapshot delivery with payload-hash matching, replay-safe acknowledgements, conflicting-retry rejection and bounded delivery-ledger retention.
- Add append-only, bounded router-agent negotiation history persisted transactionally with enrolment, including adapter/schema versions and sanitised advertised/requested/negotiated/rejected capability scopes.
- Ship a standard-library OpenWrt read-only agent with fixed ubus/ip/iw command allowlists, no shell or configuration writes, HTTPS verification, procd service packaging and a mode-0600 single-delivery outbox for restart-safe retries.
- Refuse HTTP redirects in the agent API client so its bearer credential cannot be forwarded to a redirected endpoint.
- Collect optional OpenWrt uptime, fixed-point load averages, memory and swap counters only when the agent credential negotiates `system.health`; validate and whitelist values before snapshot persistence.
- Add an authenticated Router Agent Console with OpenWrt enrolment, explicit read-only capability selection, health/heartbeat status, latest inventory and drift, one-time credential display, rotation/revocation controls, and persisted negotiation-audit visibility.
- Add F174: a bounded multi-vendor router snapshot drift report for OpenWrt, UniFi and MikroTik. It compares stable interface/radio/client/network identities, reports added/removed/changed records, and emits only allow-listed fields.
- Add subnet capacity/correlation, gateway redundancy auditing, floor-plan anchor validation and room-zone assignment.
- Wire local first-run password setup, login, logout and bearer sessions into the running app and backend.
- Protect API routes with local authentication; add JSON feature execution, bounded request bodies and browser-Origin validation.
- Add HTTP integration tests for setup, authenticated catalogue access, feature execution, logout and rejected origins.
- Include the auth manager and all feature plugins in Docker and standalone Linux builds.

### Build, packaging and quality
- Align the npm manifest with the checked-in lockfile so clean CI installs are reproducible.
- Fix Vite source alias resolution for native ES modules.
- Use `npm ci` for the ARM64 standalone build.
- Add feature-plugin collection to the PyInstaller build.

### Verification
- GitHub Quality gates pass on Python 3.10, 3.11, 3.12 and 3.13.
- Frontend dependency installation, ESLint and Vite production build pass.
- This changelog entry does not mean a v1.0.7 GitHub Release has been published.

## [1.0.6] — 2026-07-16
- Full live-data dashboard API integration for scans, system data, PHY, link statistics, diagnostics, devices and speed tests.

## [1.0.5] — 2026-07-16
- Expanded wireless analytics, dashboard visualisation and device discovery panels.

## [1.0.4] — 2026-07-15
- Rogue AP warning UI, trusted BSSID workflow and channel recommendations.

## [1.0.3] — 2026-07-15
- Integrated speed testing and dashboard refinements.

## [1.0.2] — 2026-07-14
- Device list, ARP discovery and MAC vendor lookup.

## [1.0.1] — 2026-07-14
- macOS Wi-Fi scanning support.

## [1.0.0] — 2026-07-14
- Initial Wi-Fi scan dashboard, signal metrics, network diagnostics and demo mode.

- Add F172: a bounded UniFi Network export normalizer for APs, radios, client associations and network profiles; import is offline, schema-validated and allow-lists fields so passphrases and tokens never enter the common inventory schema.
- Add F173: a bounded MikroTik RouterOS export normalizer for board/resource health, interfaces, wireless registrations, IP addresses, VLANs and DHCP leases; imports are offline, allow-listed and credential-free.
