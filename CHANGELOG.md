# Changelog

All notable changes to WiFi Analyzer Pro are documented here.

## [1.0.7] — Unreleased

### Feature library and local account
- Add 186 independently callable feature modules (F001–F168 and F172–F189; F169–F171 cover the OpenWrt agent, negotiated system-health telemetry and Router Agent Console), a stable registry, metadata catalogue and searchable Feature Workbench.
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
- Add F175: a multi-vendor router fleet health audit for normalized OpenWrt, UniFi and MikroTik snapshots. It evaluates freshness, measured CPU/memory pressure, down interfaces/radios, offline APs and weak client signals while reporting missing telemetry as unknown.
- Add F176: a site-scoped IPv4/IPv6 subnet overlap audit across normalized OpenWrt interfaces, UniFi network profiles and MikroTik address records; it reports duplicates and overlapping ranges with context instead of assuming every repeated private subnet is a fault.
- Add F177: a cross-vendor client roaming timeline from normalized OpenWrt, UniFi and MikroTik association snapshots, reporting observed AP handoffs, short multi-AP windows and weak measured signals while skipping wired clients.
- Add F178: an OpenWrt and MikroTik route-table audit for duplicate routes, default-route candidates, disabled/inactive/blackhole defaults and gateways without a directly connected prefix match; recursive, point-to-point and tunnel routes are explicitly left for operator review.
- Add F179: a site-scoped VLAN segmentation audit for normalized UniFi network profiles and MikroTik VLAN interfaces, identifying subnet/name mismatches, duplicate VLAN IDs, missing parent interfaces and down VLAN interfaces without treating IDs reused in separate sites as conflicts.
- Add F180: a cross-router default-gateway redundancy audit for OpenWrt and MikroTik. It compares route candidates by site, address family and routing table, distinguishes shared next hops from distinct configured paths, and explicitly does not claim failover or upstream independence has been tested.
- Add F181: a deterministic router incident alert-policy evaluator with code/severity/site/adapter scopes, occurrence thresholds, stable deduplication keys, and new/ongoing/acknowledged/resolved states. It produces local alert candidates only and does not send notifications or webhooks.
- Add F182: a versioned router audit report bundle builder that combines F174–F181 summaries and allow-listed findings into a site-filterable JSON report with a deterministic SHA-256 content hash; raw snapshots, credentials and untrusted source messages are excluded.
- Add F183: a hash-validating router audit report comparator that classifies unchanged, changed, added and removed findings and reports source-section/site deltas with bounded detail output.
- Add F184: a timezone-aware scheduled-report planner for daily, weekly and monthly recurrences, including IANA timezone, DST ambiguity/gap and short-month policies. It previews deterministic idempotency keys but does not run or persist jobs.
- Add F185: a canonical HMAC-SHA256 webhook envelope builder for exact allow-listed HTTPS DNS hosts, with key ID, timestamp and batch idempotency headers. It never transmits requests or returns signing secrets; a downstream dispatcher must revalidate DNS/IP targets, refuse redirects and enforce egress rules.
- Add F186: an authenticated-encrypted report/alert archive using Scrypt-derived AES-256-GCM keys, fixed KDF parameters, authenticated metadata and strict size/schema validation; restore rejects tampering and wrong passphrases, and the passphrase is never returned or stored.
- Add F187: a webhook egress evidence verifier that requires exact HTTPS hostname allowlists, public-only DNS answers, recent DNS resolution, actual peer-IP pinning, verified TLS/hostname identity and redirect refusal; it does not open network connections.
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

- Add F188: a durable SQLite scheduled-report job outbox with stable occurrence idempotency, transactional exclusive worker leases, lease renewal/expiry recovery, bounded exponential retry, dead-letter and cancellation states; authenticated APIs expose enqueue/claim/complete/fail without sending outbound requests from the server handler.

- Add F189: a lease-guarded scheduled-report delivery package builder. It verifies the F188 job lease and normalized F182 report hashes, requires F187 approved public DNS/TLS evidence, and produces F185 HMAC-signed summary/finding events without making network requests.
