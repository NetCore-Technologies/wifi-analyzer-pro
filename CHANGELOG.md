# Changelog

All notable changes to WiFi Analyzer Pro are documented here.

## [1.0.7] — Release foundation

### Build, test and delivery
- Add repeatable frontend build and lint checks plus Python regression tests across Python 3.10–3.13. CI, releases and source installers use npm ci against the committed lockfile.
- Add Dependabot update groups for npm production/development packages, pip dependencies and GitHub Actions.
- Add dependency review for pull requests.
- Build standalone Linux x64 and ARM64, macOS ARM64, macOS Intel x64 and Windows x64 binaries.
- Package macOS app bundles as DMG and tar.gz, Linux as AppImage/DEB/ELF/installer/tar.gz, and Windows as EXE/MSI/PowerShell/batch launchers.
- Generate platform-specific SHA-256 manifests and a combined release checksum file.
- Publish multi-architecture Linux container images to GHCR.
- Add a WiFi Analyzer Pro product website with release-aware download links and GitHub Pages deployment.
- Upgrade the React/Vite integration to `@vitejs/plugin-react` 6 for the Oxc-based Vite 8 build path.
- Add GitHub release artifact provenance attestations, container SBOM/build provenance and keyless Cosign signing.
- Support optional Developer ID signing and Apple notarisation when repository secrets are configured.

### Dashboard fixes
- Remove the duplicate `tips` declaration that prevented the React dashboard from compiling.
- Connect the primary Scan action to the local scan API instead of returning a hard-coded network count.
- Fix the live refresh closure so polling continues after the backend is detected.
- Use the current host for local API requests rather than assuming `localhost` from a remote browser.

### Notes
- The backend now avoids fabricated live observations and defaults to loopback, but it still has no built-in user authentication. Remote access must use a VPN or authenticated reverse proxy.
- macOS builds are not Apple-notarised unless signing credentials are configured in a future release.

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
