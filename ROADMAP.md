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
| 🚧 v1.0.7 (unreleased) | 197 callable feature tools (F001–F168 and F172–F200), local account gate, authenticated feature API, searchable workbench and packaging integration |

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
- ✅ 197 distinct callable feature modules (F001–F168 and F172–F200), each in its own module with a stable slug and metadata; F169–F171 are OpenWrt agent, negotiated system-health and Router Agent Console deliverables.
- ✅ Central feature registry and searchable Feature Workbench.
- ✅ Local first-run workspace owner, version-1 credential migration, named human accounts, salted scrypt verifiers, independent short-lived sessions, failed-login lockout and session revocation for disabled/password-reset accounts.
- ✅ Server-enforced role permissions for owner, administrator, network administrator, analyst and read-only viewer across user, agent, report, site and diagnostic endpoints.
- ✅ Bounded per-process token-bucket API throttling for setup/login, wireless scans, speed tests, feature execution, site audits, capture starts and report enqueue, including standard 429 retry headers and concurrency tests.
- ✅ Team Access UI for creating users, changing assigned roles, disabling/enabling accounts and assigning per-user site scopes with least-privilege defaults. Existing accounts retain pre-upgrade all-site access.
- ✅ Site-scope enforcement filters saved site history, site-audit/feature inputs, router-agent inventory/health/credential actions and scheduled-report jobs, summaries and worker claims.
- ✅ Local append-only SQLite security audit ledger with SHA-256 event chaining, row update/delete triggers, bounded event filtering/pagination, chain verification, an owner/administrator audit viewer and Ed25519-signed offline checkpoints with public-key fingerprint verification.
- ✅ Authenticated REST feature catalogue and execution endpoints; API access fails closed before account setup.
- ✅ Docker and standalone Linux packaging include the auth and feature modules.
- ✅ Unit and HTTP integration tests cover the account gate, feature catalogue, tool execution, logout and rejected browser origins.

- ✅ Durable report queue with transactional claims, lease renewal, retries and dead-letter handling.
- ✅ Offline PCAP/PCAPNG analysis with bounded packet/frame parsing and radiotap signal/noise evidence.
- ✅ Opt-in scheduled-report worker with pinned public-IP HTTPS delivery, exact host allowlists, TLS hostname verification, redirect refusal, bounded responses and lease-guarded completion.
- ✅ Stripe-hosted per-deployment subscription checkout and customer portal; webhook signatures are verified before parsing, event IDs are replay-protected, stale subscription events are ignored and payment grace is bounded.
- ✅ Owner/admin billing console with Free, Pro, Business and Enterprise entitlements. Server-side limits cover users, managed router agents, managed sites, saved webhook subscriptions and UTC-month diagnostic runs; usage is persisted in SQLite and tested against concurrent quota consumption. This is one billed workspace per installation, not pooled multi-tenant SaaS.

### Remaining v1.1.0 scope
- 📋 External plugin SDK with a stable manifest, version checks, permissions and lifecycle hooks.
- 📋 Enable/disable and safe reload for third-party plugins.
- 📋 Example plugin and developer guide.
- ✅ Explicit interface selection for local tcpdump/libpcap capture with fixed filter profiles, operator confirmation, duration/packet/snaplen/file-size bounds, stop control and PCAP download into the offline analyzer.
- ✅ Per-site authorization is enforced across sites, agents, reports and feature inputs. Full tenant isolation (separate tenant identities, storage boundaries, billing and cross-tenant operational controls) remains planned.
- 📋 Enterprise identity: OIDC/SAML SSO, WebAuthn and SCIM provisioning, external SIEM forwarding and centralised retention; local TOTP authenticator-app MFA is implemented.
- 📋 Multi-site dashboards for distributed local agents.
- ✅ Bounded token-bucket API rate limits for setup/login, scans, speed tests, feature execution, site audits, capture startup, report enqueue and webhook enqueue; authenticated limits are per account and return HTTP 429 with Retry-After.
- 📋 Authenticated WebSocket streaming for live multi-site updates.
- 📋 Security review of LAN deployment, session lifecycle and cross-origin development settings.

---

## Feature expansion roadmap: F101–F200

These are planned deliverables, not implemented features. IDs are reserved only when a tool is implemented and tested; each tool must include a pure-function test, an API integration test where relevant, a catalog entry and a UI path.

| Wave | Planned range | Scope | Target | Estimate | Dependencies |
|---|---:|---|---|---:|---|
| ✅ | F101–F120 | Shipped: same-SSID band visibility, roaming evidence/timelines, channel-width overlap, DFS/PSC planning, Wi-Fi 7 EHT/MLO and PMF/regulatory audits | 2026-11-20 | Implemented | F001–F100 registry; 20 module-level test payloads |
| ✅ | F121–F140 | Shipped: client association inventory, airtime/throughput fairness, QoS/DSCP, retry/PHY checks, 802.11k/v/r, TWT, DHCP/DNS/gateway checks and association diagnostics | 2026-11-20 | Implemented | F001–F120; supplied AP/controller and client measurement records |
| ✅ | F141–F160 | F141–F160 shipped: site inventory snapshots/comparisons, AP topology and gateway-path audits, subnet correlation/capacity, gateway redundancy, floor-plan anchors/zones, topology redundancy/diffs/history, AP freshness, channel reuse and radio standards audits, topology visualisation, discovery history, site-to-site change reports and consolidated site audits | 2026-11-21 | 20 features shipped; 0 remain | SQLite history; consented local discovery |
| ✅ | F161–F180 | F161–F180 shipped and verified in CI: versioned OpenWrt read-only agent, scope-gated health telemetry, Router Agent Console, credential-free UniFi/MikroTik imports, cross-vendor drift, fleet health, subnet overlap, client roaming, VLAN, route-table and gateway redundancy audits | 2026-11-21 | 20 features shipped; 0 remain | Authenticated API; offline adapter contracts; bounded schema validation |
| ✅ | F181–F200 | F181–F193 router incident, report, scheduling, encrypted archive, PCAP, signed webhook and durable delivery workflows; F194–F200 enterprise WLAN, switch, firewall, DHCP/DNS, VPN, asset lifecycle and consolidated security evidence audits. Delivery is opt-in, site-scoped and lease/retry guarded; audit findings distinguish missing evidence from verified violations. | 2026-11-21 | 20 features shipped; 0 remain | Authenticated API; report schema; bounded evidence contracts |

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

## Commercial launch readiness

- ✅ Vendor-owned Stripe checkout, signed webhook processing, installation-bound Ed25519 product licences, renewal and self-service Billing Portal are implemented in a separate deployment stack.
- ✅ Customer Plans & Licensing UI supports purchase, signed activation, licence sync/renewal and subscription management.
- ✅ Pro target packaging is defined at 30 per month, with Free/Pro/Business/Enterprise user, agent, site, webhook and diagnostic-run limits.
- 📋 Production launch setup: configure live Stripe recurring Prices, tax settings, public DNS/TLS, webhook endpoint, signing-key custody, backups and service monitoring.
- 📋 Vendor SaaS roadmap: tenant-isolated fleet management, OIDC/SAML SSO, SCIM, central SIEM forwarding, remote agent health, service-level reporting and customer support workflows.
- 📋 Commercial operations: subscription analytics, customer onboarding, cancellation/refund/dispute handling, incident response, SLA, status page and backup/restore drills.
- ⚠️ The repository is MIT licensed. Local licence checks do not prevent a permitted modified fork; paid value must be delivered through official maintained releases and vendor-operated services rather than an unbreakable local feature gate.

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

*Last updated: November 21, 2026*


- ✅ Saved, site-scoped webhook subscription directory with metadata-only persistence, a 100-subscription workspace bound, transient HMAC key entry, live pinned-TLS endpoint probing and short-lived F187 egress evidence reuse.
