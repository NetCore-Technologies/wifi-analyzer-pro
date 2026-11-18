<div align="center">

# WiFi Analyzer Pro

**See the spectrum. Own your network.**

Professional, local-first Wi-Fi visibility and network diagnostics for engineers, IT teams and power users.

[![Quality gates](https://github.com/NetCore-Technologies/wifi-analyzer-pro/actions/workflows/ci.yml/badge.svg)](https://github.com/NetCore-Technologies/wifi-analyzer-pro/actions/workflows/ci.yml)
[![Latest release](https://img.shields.io/github/v/release/NetCore-Technologies/wifi-analyzer-pro)](https://github.com/NetCore-Technologies/wifi-analyzer-pro/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-50e3d2.svg)](LICENSE)

[Product website](https://netcore-technologies.github.io/wifi-analyzer-pro/) · [Downloads](https://github.com/NetCore-Technologies/wifi-analyzer-pro/releases) · [Source](https://github.com/NetCore-Technologies/wifi-analyzer-pro)

</div>

---

## What it does

WiFi Analyzer Pro brings wireless observations and practical network diagnostics into one dashboard. It uses the operating system's Wi-Fi utilities and local network interfaces; the available details depend on the adapter, driver, operating system and permissions.

- Discover nearby access points and inspect SSID, BSSID, band, channel, signal and advertised security.
- Compare channel occupancy and nearby networks to help investigate congestion.
- Inspect supported PHY, interface and system information.
- Check gateway reachability, latency, DNS resolution and packet loss where the host tools permit it.
- Review locally visible neighbour/ARP data and vendor hints.
- Run an explicit throughput test and export observations for troubleshooting reports.
- Use the React dashboard locally or run it on a small Linux host such as a Raspberry Pi.

The interface includes a clearly labelled demo mode for exploring the dashboard without Wi-Fi hardware. Demo observations are examples, not measurements of your network.

## Downloads

Get the latest version from [GitHub Releases](https://github.com/NetCore-Technologies/wifi-analyzer-pro/releases). Tagged releases build platform-specific packages and SHA-256 manifests:

| Platform | Release files |
|---|---|
| macOS Apple Silicon | DMG app bundle and portable tar.gz |
| macOS Intel | DMG app bundle and portable tar.gz |
| Linux x64 / ARM64 (Raspberry Pi) | AppImage, DEB, standalone ELF, installer script and tar.gz |
| Windows x64 | EXE, MSI, PowerShell launcher and batch launcher |

The app bundles include the Python runtime and built web interface. Python and Node.js are not required to run a published standalone binary. macOS bundles are ad-hoc signed by default and will not be accepted by Gatekeeper as notarised software. Configure the five Apple Developer ID / notarisation repository secrets used by the release workflow to produce signed and notarised macOS downloads.

Verify a download against `SHA256SUMS` or the platform-specific `SHA256SUMS-*.txt` attached to the same release.

## Run from source

### Linux / Raspberry Pi

```bash
bash wifi_analyzer_backend/setup.sh
```

Then open `http://127.0.0.1:199`.

### Windows

Run `install_windows.bat` from the repository root. It creates a local Python virtual environment, builds the frontend and starts the backend.

### macOS

```bash
npm install
npm run build
python3 -m venv wifi_analyzer_backend/.venv
wifi_analyzer_backend/.venv/bin/python -m pip install -r wifi_analyzer_backend/requirements.txt
cp -R dist wifi_analyzer_backend/dist
wifi_analyzer_backend/.venv/bin/python wifi_analyzer_backend/server.py
```

Open `http://127.0.0.1:199`.

### Demo / frontend development

```bash
npm install
npm run dev
```

The app can be explored with sample data. To run the backend in explicit demo mode:

```bash
WIFI_ANALYZER_DEMO=1 python3 wifi_analyzer_backend/server.py
```

## API

The local HTTP service currently exposes:

| Route | Purpose |
|---|---|
| `GET /health` | Basic server health |
| `GET /api/has_wifi` | Wi-Fi adapter availability |
| `GET /api/scan` | Nearby access point scan and channel counts |
| `GET /api/system` | Host system information |
| `GET /api/phy` | Available PHY/link details |
| `GET /api/link` | Interface counters |
| `GET /api/diagnostics` | Gateway, latency, DNS and packet-loss checks |
| `GET /api/devices` | Locally visible neighbour/ARP entries |
| `GET /api/speedtest` | Explicit throughput test |

## Security and privacy

WiFi Analyzer Pro is intended to run close to the network being diagnosed. Network scans and system diagnostics are performed by the local host. No cloud account is required for local use.

**Important:** the current HTTP API does not provide user authentication or enterprise SSO/RBAC. Keep it on a trusted machine/network. Do not expose port `199` directly to the public internet. For team or remote access, place it behind a VPN or an authenticated reverse proxy and restrict network access. Review [SECURITY.md](SECURITY.md) before deployment.

Only scan networks and devices you own or are authorised to assess. A Wi-Fi adapter may require OS-specific permissions for full scan details.

## Development and quality

```bash
npm install
npm run lint
npm run build
python3 -m compileall -q wifi_analyzer_backend tests
python3 -m unittest discover -s tests -v
```

Pull requests and pushes to `main` run frontend build/lint and Python regression tests across supported Python versions. Dependabot checks npm, pip and GitHub Actions dependencies. Tagged releases build desktop/server packages, platform and master SHA-256 manifests, GitHub artifact provenance attestations, and a multi-architecture GHCR image with SBOM, build provenance and keyless Cosign signature. macOS Developer ID signing and notarisation are enabled when the required repository secrets are configured.


### Optional macOS Developer ID signing and notarisation

Configure these repository Actions secrets to sign and notarise the macOS DMG/app bundle:

- `APPLE_CERTIFICATE_P12_BASE64` — base64-encoded Developer ID Application certificate export.
- `APPLE_CERTIFICATE_P12_PASSWORD` — password for that certificate export.
- `APPLE_ID` — Apple ID used for notarisation.
- `APPLE_TEAM_ID` — Apple Developer Team ID.
- `APPLE_APP_SPECIFIC_PASSWORD` — app-specific password for `notarytool`.

Without these secrets, the workflow still builds the macOS binaries, but the downloads are not notarised and may require a user override at first launch.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Bug reports should include the OS, Python/Node versions, Wi-Fi adapter/driver and reproducible steps. Please remove SSIDs, BSSIDs, IP addresses and other private network details before attaching logs or exports.

## License

MIT — see [LICENSE](LICENSE).
