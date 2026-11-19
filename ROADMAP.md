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
| ✅ v1.0.5 | 17 feature categories, animated UI, mobile app (beta), AI health summary, REST API, WebSocket stream |

---

## v1.0.x: Stabilise (now)

Goal: make what already exists reliable before adding more.

- 🚧 Sync version numbers across `package.json`, the README badge, `CHANGELOG.md` and the backend
- 🚧 Fix README links that still point to the old `manit6752025/wifi-analyzer-pro` path
- 📋 Add automated tests for the backend (scan parsing, PHY parsing, alert rules)
- 📋 Add a CI workflow that runs lint, tests and a frontend build on every pull request
- 📋 Add a clear "Demo Mode" banner so fake data is never mistaken for live data
- 📋 Graceful errors when `iw`, `iwconfig` or `pywifi` is missing or lacks permission
- 📋 Document which features need root or Administrator
- 📋 Publish the first GitHub Release with built assets

---

## v1.1.0: Extensibility and capture

- 📋 **Plugin SDK**
  - Stable plugin interface for custom scanners, alerts and dashboard panels
  - Plugin loader with enable/disable in the UI
  - Example plugin and developer guide
- 📋 **Packet capture (pcap)**
  - Start/stop capture from the dashboard
  - Export to `.pcap` for Wireshark
  - Capture filters and size limits
- 📋 **Multi-user remote monitoring**
  - Login and role-based access (admin, viewer)
  - Per-site dashboards for multiple Pi agents
- 📋 **API security**
  - Token authentication for REST and WebSocket
  - Configurable bind address and CORS
  - Rate limiting on heavy endpoints (speed test, port scan)

---

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

*Last updated: November 2026*
