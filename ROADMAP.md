# Roadmap

This is the plan for WiFi Analyzer Pro. Dates are targets, not promises. Priorities can change based on issues, security reports, and feedback.

**Status key:** ✅ done · 🚧 in progress · 📋 planned · 💡 idea

---

## Shipped

| Version | Highlights |
|---|---|
| ✅ v1.0.0 | Initial release |
| ✅ v1.0.1 | macOS scanning |
| ✅ v1.0.2 | Device discovery |
| ✅ v1.0.3 | Speed test |
| ✅ v1.0.4 | Rogue AP detection, channel recommendations |
| ✅ v1.0.5 | Wireless analytics, dashboard visualisation and device discovery |
| ✅ v1.0.6 | Live data API integration for scans, system data, PHY, diagnostics, devices and speed tests |
| 🚧 v1.0.7 (unreleased) | 181 callable feature tools, local account gate, authenticated feature API, searchable workbench and packaging integration |

---

## v1.0.x: Stabilise (current)

Goal: keep the existing dashboard dependable and make shipped functionality verifiable.

- ✅ Frontend lint and production build run in GitHub Actions on pushes and pull requests.
- ✅ Python compilation and regression tests run on Python 3.10–3.13.
- ✅ Resolve the npm manifest/lockfile mismatch and the ESM Vite alias.
- ✅ Remove the old repository path from active README links.
- 🚧 Audit all demo placeholders and clearly separate examples from live measurements.
- 📋 Improve diagnostics when `iw`, `iwconfig` or platform Wi-Fi APIs are missing or lack permission.
- 📋 Document operating-system permissions and commands required for each live data source.
- 📋 Publish v1.0.7 only after release assets and a clean release workflow are verified.

---

## v1.1.0: Extensibility and capture

### Shipped in the current main branch
- ✅ 181 distinct callable feature modules (F001–F168 and F172–F184), each in its own module with a stable slug and metadata; F169–F171 are OpenWrt agent, negotiated system-health and Router Agent Console deliverables.
- ✅ Central feature registry and searchable Feature Workbench.
- ✅ Local first-run password setup, salted scrypt verifier, bearer sessions, expiry, logout and failed-login lockout.
- ✅ Authenticated REST feature catalogue and execution endpoints; API access fails closed before account setup.
- ✅ Docker and standalone Linux packaging include the auth and feature modules.
- ✅ Unit and HTTP integration tests cover the account gate, feature catalogue, tool execution, logout and rejected browser origins.

### Remaining v1.1.0 scope
- 📋 External plugin SDK with a stable manifest, version checks, permissions and lifecycle hooks.
- 📋 Enable/disable and safe reload for third-party plugins.
- 📋 Example plugin and developer guide.
- 📋 Packet capture with explicit interface selection, bounded file size, capture filters and PCAP export.
- 📋 Multi-user roles (admin/viewer) and per-site dashboards for multiple local agents.
- 📋 Authenticated WebSocket streaming and API rate limits for expensive diagnostics.
- 📋 Security review of LAN deployment, session lifecycle and cross-origin development settings.

---

## Feature expansion roadmap: F101–F200

These are planned deliverables, not implemented features. IDs are reserved only when a tool is implemented and tested; each tool must include a pure-function test, an API integration test where relevant, a catalog entry and a UI path.

| Wave | Planned range | Scope | Target | Estimate | Dependencies |
|---|---:|---|---|---:|---|
| ✅ | F101–F120 | Shipped: same-SSID band visibility, roaming evidence/timelines, channel-width overlap, DFS/PSC planning, Wi-Fi 7 EHT/MLO and PMF/regulatory audits | 2026-11-20 | Implemented | F001–F100 registry; 20 module-level test payloads |
| ✅ | F121–F140 | Shipped: client association inventory, airtime/throughput fairness, QoS/DSCP, retry/PHY checks, 802.11k/v/r, TWT, DHCP/DNS/gateway checks and association diagnostics | 2026-11-20 | Implemented | F001–F120; supplied AP/controller and client measurement records |
| 🚧 | F141–F160 | F141–F160 shipped: site inventory snapshots/comparisons, AP topology relationships and gateway-path audits, subnet correlation/capacity, gateway redundancy, floor-plan anchors/zones, topology redundancy/diffs/history, AP freshness, channel-reuse and radio-configuration standards audits, interactive topology visualisation, persistent site discovery history, stored site-to-site change reports, and consolidated site audit reporting; all deliverables in this wave are shipped | 2027-02-26 | 20 features shipped; 0 remains | SQLite history; consented local discovery |
| 🚧 | F161–F180 | F161–F180 implementation committed: versioned OpenWrt read-only agent and scope-gated health telemetry; authenticated Router Agent Console; credential-free UniFi/MikroTik imports; cross-vendor snapshot drift, fleet health, subnet overlap, client roaming, VLAN consistency, route-table and cross-router gateway redundancy audits | 2026-11-20 | 20 implemented; final Python matrix and frontend verification pending | Authenticated API; offline adapter contracts; bounded schema validation |
| 🚧 | F181–F200 | F181–F184 shipped: local incident alert-policy evaluation; versioned report bundles and hash-validated comparisons; timezone-aware daily/weekly/monthly schedule planning with DST and month-length policies; remaining: scheduled execution, webhook delivery, encrypted backup/restore and operator notification workflows | 2027-05-07 | 4 deliverables shipped; 16 remain | F161–F180 audit outputs; F182 report schema |

### Longer-range direction (F201–F1100)

The next 900 candidates are grouped into ten reviewable 90-feature waves. These are domain targets, not a promise to ship 900 unchecked stubs:

1. F201–F290 — Advanced RF diagnostics and channel planning.
2. F291–F380 — Client roaming, QoS and application experience.
3. F381–F470 — Multi-site topology and network inventory.
4. F471–F560 — Router and controller integrations.
5. F561–F650 — Security posture, detection evidence and audit trails.
6. F651–F740 — Capture workflows and packet-level analysis.
7. F741–F830 — Historical analytics, capacity planning and forecasting.
8. F831–F920 — Reports, alert routing and operational automation.
9. F921–F1010 — Mobile/desktop workflows and offline operation.
10. F1011–F1100 — Plugin ecosystem, accessibility, localisation and deployment tooling.

A candidate is promoted to an F-number only after checking that it is distinct from existing tools, technically supportable on documented hardware/OS combinations, privacy-safe and testable. Avoid duplicate feature counts, simulated measurements presented as live data, and network-changing operations without explicit confirmation.

## v1.2.0: Analysis depth

- 📋 Historical database (SQLite) for RSSI, speed tests and alerts, with retention settings
- 📋 Trend views: week-over-week signal and speed comparisons
- 📋 Roaming analysis: sticky-client and band-steering reports
- 📋 Channel planner that suggests a full 2.4/5/6 GHz layout for several APs
- 📋 Improved heatmaps with floor-plan upload
- 📋 Better Evil Twin detection with a trusted BSSID allowlist
- 📋 Alert rules editor (thresholds, quiet hours, deduplication)

---

## v1.3.0: Integrations and mobile

- 📋 Home Assistant integration (MQTT discovery)
- 📋 Official Grafana dashboard and Prometheus exporter documentation
- 📋 Node-RED nodes
- 📋 Mobile app: move from beta to stable on iOS and Android
- 📋 Push notifications through the mobile app
- 💡 Webhook templates for Discord, Slack and Teams
- 💡 Router support: verify and document each supported platform (OpenWrt, DD-WRT, pfSense, OPNsense, UniFi, MikroTik, Omada, ASUS, GL.iNet)

---

## v2.0.0: Desktop and cloud

- 📋 **Electron desktop app** for Windows, macOS and Linux
  - Bundled backend, no separate install steps
  - Auto-update
  - System tray status and alerts
- 📋 **Cloud dashboard** (self-hostable)
  - Multi-site overview
  - Encrypted sync from remote agents
  - Optional, never required for local use
- 💡 Installer packages: `.deb`, `.msi`, `.dmg`, and a Docker image
- 💡 Localisation (translations)

---

## Always ongoing

- Security fixes (see [SECURITY.md](SECURITY.md))
- Documentation and screenshots
- Performance: keep the dashboard smooth on a Raspberry Pi
- Accessibility: keyboard navigation and colour-contrast checks
- Dependency updates

---

## Ideas under consideration

These aren't committed. Open an issue to discuss or vote.

- Wi-Fi 7 multi-link operation (MLO) diagnostics
- Spectrum analysis with supported hardware
- Offline reports with a built-in troubleshooting wizard
- Built-in WireGuard/VPN health checks
- Community plugin gallery

---

## How to influence the roadmap

- Open an [issue](https://github.com/NetCore-Technologies/wifi-analyzer-pro/issues) with the label `feature-request`
- Add a 👍 to existing issues you want prioritised
- Send a pull request. See [CONTRIBUTING.md](CONTRIBUTING.md) first

Security issues: please follow [SECURITY.md](SECURITY.md) and do not open a public issue.

*Last updated: November 20, 2026*
