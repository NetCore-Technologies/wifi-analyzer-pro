# Changelog

All notable changes to WiFi Analyzer Pro are documented here.

## [1.0.7] — Unreleased

### Feature library and local account
- Add 156 independently callable feature modules (F001–F156), a stable registry, metadata catalogue and searchable Feature Workbench.
- Add multi-site AP inventory snapshots, topology redundancy and snapshot-diff analysis, and AP inventory drift detection.
- Add cross-site AP inventory and channel-reuse audits, observation freshness checks, and a bounded timestamped topology history timeline.
- Add a site-aware AP-to-gateway path audit that excludes RF-neighbour and cross-site links and distinguishes missing evidence from unreachable paths.
- Add a site-aware radio standards audit for channel width, security and transmit power, including explicit unknown results for absent observations.
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
