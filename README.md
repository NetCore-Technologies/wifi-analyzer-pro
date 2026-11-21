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

The app bundles include the Python runtime and built web interface. Python and Node.js are not required to run a published standalone binary. On first launch, create a local password; the verifier is stored in your user configuration directory and bearer sessions expire automatically. macOS bundles are ad-hoc signed by default and will not be accepted by Gatekeeper as notarised software. Configure the five Apple Developer ID / notarisation repository secrets used by the release workflow to produce signed and notarised macOS downloads.

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

## Docker deployment

The recommended single-host deployment is Docker Compose:

    cp .env.example .env
    docker compose up -d --build

The API binds to loopback by default. To make it reachable from a trusted LAN, set WIFI_ANALYZER_BIND_ADDRESS=0.0.0.0 in the protected .env file, then enforce firewall rules and use a VPN or authenticated TLS reverse proxy. Never expose port 199 directly to the public internet.

Enable the optional multi-subscription dispatcher sidecar with:

    docker compose --profile webhook-dispatcher up -d

The dispatcher shares the API's persistent state volume, runs as the image's unprivileged UID, has no listening port and does not receive HMAC signing secrets. The scheduled-report worker requires destination credentials and is configured separately; see deploy/README.md and the report worker guide. Compose stores account/configuration and application state in named volumes; back them up before upgrades.

For systemd deployments, including the API and both optional workers, see deploy/README.md.

## Optional subscription billing

WiFi Analyzer Pro supports two separate billing concepts:

- **Vendor product licensing:** the NetCore product licence is a signed Ed25519
  token bound to one installation. Customer installations contain only the
  vendor public verification key. The vendor signing private key belongs on a
  separate licensing control plane and must never be copied to customer hosts.
  Owners activate a signed token in Plans & Licensing. This local verifier is
  implemented; the vendor-hosted checkout/issuance service is a separate
  deployment milestone and is not claimed as live yet.
- **Optional workspace billing:** an installation operator can configure its
  own Stripe account to charge its own organisation or customers. This is not
  payment to NetCore and is not the vendor subscription flow.

Workspace Stripe billing is disabled by default. Create recurring Stripe
Prices for Pro, Business and/or Enterprise and configure their IDs as
server-side environment variables. Amounts, intervals and currency are defined
by those Stripe Prices rather than hard-coded in the application.

For Docker Compose, copy `.env.example` to `.env` and set:

- `WIFI_ANALYZER_PUBLIC_URL`: the public HTTPS origin of this installation.
- `WIFI_ANALYZER_STRIPE_SECRET_KEY`: a restricted or standard Stripe secret key.
- `WIFI_ANALYZER_STRIPE_WEBHOOK_SECRET`: the signing secret for the webhook endpoint.
- `WIFI_ANALYZER_STRIPE_PRICE_PRO`, `WIFI_ANALYZER_STRIPE_PRICE_BUSINESS`, and `WIFI_ANALYZER_STRIPE_PRICE_ENTERPRISE`: optional Stripe recurring Price IDs.
- `WIFI_ANALYZER_VENDOR_LICENSE_PUBLIC_KEY` and `WIFI_ANALYZER_VENDOR_LICENSE_KEY_ID`: public verification key and key ID for vendor-issued product licences. These are not secret values.

Configure a Stripe webhook at `{WIFI_ANALYZER_PUBLIC_URL}/api/billing/webhook`
for `checkout.session.completed`, `customer.subscription.created`,
`customer.subscription.updated`, and `customer.subscription.deleted`.
Set the webhook signing secret from Stripe's endpoint configuration in
`WIFI_ANALYZER_STRIPE_WEBHOOK_SECRET`. Restart the API after changing these
settings. Do not put Stripe secrets in frontend build variables, source files,
screenshots or Git.

The backend creates hosted Checkout and Billing Portal sessions; it does not
collect card details. The subscription screen shows plan quotas and usage.
Free, Pro, Business and Enterprise quotas are enforced for local users,
managed router agents, managed sites, webhook subscriptions and monthly
diagnostic executions. The initial allowances are:

| Plan | Users | Router agents | Sites | Webhook subscriptions | Diagnostic runs / month |
|---|---:|---:|---:|---:|---:|
| Free | 1 | 1 | 1 | 1 | 100 |
| Pro | 5 | 5 | 3 | 5 | 5,000 |
| Business | 25 | 50 | 25 | 25 | 25,000 |
| Enterprise | 100 | 256 | 100 | 100 | 100,000 |

Diagnostic runs are metered per UTC calendar month and failed feature
validations do not consume an allowance. Site quotas count sites with saved
topology history or a managed router-agent assignment. Payment events are
verified and replay-protected. One application deployment represents one
paying workspace in this integration; pooled multi-tenant hosting still
requires a separate tenant-isolated control plane and is not claimed as shipped.

## API

The local HTTP service exposes:

| Route | Purpose |
|---|---|
| `GET /health` | Basic server health (public) |
| `GET /api/auth/status` | First-run account and session status |
| `POST /api/auth/setup` | Create the first workspace owner and local password during first-run setup |
| `POST /api/auth/login` | Create a short-lived bearer session |
| `POST /api/auth/logout` | Revoke the current bearer session |
| `GET /api/features` | Authenticated catalogue of the 189 built-in tools |
| `GET /api/users`, `POST /api/users`, `POST /api/users/{id}/update` | Owner/administrator user directory, account creation, role updates, site-scope assignment and disable/enable controls |
| `GET /api/sites` | List saved sites visible to the current user's site scope |
| `GET /api/security/audit` | Owner/administrator paginated security events and outcome filters |
| `GET /api/security/audit/verify` | Verify the local append-only hash chain and report the verified event count |
| `POST /api/features/{slug}` | Execute a selected read-only feature tool with JSON input |
| `GET /api/reports/jobs` | List authenticated scheduled-report jobs and state counts |
| `POST /api/reports/jobs/enqueue` | Queue a hash-validated report occurrence idempotently |
| `POST /api/reports/jobs/claim` | Claim due jobs using exclusive, expiring worker leases |
| `POST /api/reports/jobs/{id}/renew` | Extend an active worker lease without reviving expired leases |
| `POST /api/reports/jobs/{id}/delivery-package` | Verify the current SQLite lease and prepare an approved, signed delivery package without sending it |
| `POST /api/reports/jobs/{id}/complete`, `/fail`, `/cancel` | Complete a lease, schedule a bounded retry/dead-letter, or cancel a pending job |
| `GET /api/webhooks/subscriptions` | Site-scoped saved subscription metadata (signing secrets are never returned or stored) |
| `POST /api/webhooks/subscriptions` | Create a saved, site-scoped subscription definition |
| `POST /api/webhooks/subscriptions/{id}/update`, `/delete` | Update or remove a saved subscription |
| `GET /api/webhooks/deliveries` | Site-scoped durable webhook delivery queue and state counts |
| `POST /api/webhooks/deliveries/enqueue` | Idempotently enqueue prepared, HMAC-signed subscription envelopes |
| `POST /api/webhooks/deliveries/{id}/retry`, `/cancel` | Retry dead-lettered deliveries or cancel pending work |
| [Webhook dispatch worker](wifi_analyzer_backend/WEBHOOK_DISPATCH_WORKER.md) | Separate pinned-TLS worker for outbound delivery; no signing-secret storage required |
| [Scheduled report worker](wifi_analyzer_backend/REPORT_WORKER.md) | Opt-in, pinned-TLS HTTPS delivery of due report jobs; run separately from the API server |
| [Webhook dispatch worker](wifi_analyzer_backend/WEBHOOK_DISPATCH_WORKER.md) | Durable multi-subscription signed webhook delivery with leases, retries, dead letters and fresh pinned-TLS egress checks |
| [Deployment and operations](deploy/README.md) | Hardened Compose and systemd deployment, shared state, upgrades, backup and rollback |
| `POST /api/sites/history` | Validate and persist a site AP/topology snapshot locally |
| `GET /api/sites/history` | List snapshots with optional site filter and `limit` / `before_id` pagination |
| `GET /api/sites/history/{id}` | Read one saved site snapshot |
| `GET /api/sites/history/report` | Compare latest stored snapshots across sites; accepts optional comma-separated `site_ids` (maximum 20) |
| `POST /api/sites/audit` | Run the consolidated, authenticated multi-site inventory/topology/gateway/radio/subnet audit |
| `GET /api/adapters` | List installed versioned router-adapter manifests and read-only capabilities |
| `POST /api/adapters/negotiate` | Negotiate an authenticated agent’s advertised capabilities against an installed adapter contract |
| `POST /api/adapters/openwrt/normalise` | Validate and normalise a supplied OpenWrt board/network/wireless/route snapshot |
| `POST /api/agents/heartbeat` | Record a heartbeat using that agent’s scoped bearer token |
| `POST /api/agents/snapshot` | Store a normalised OpenWrt snapshot using the agent token and its `inventory.snapshot` scope |
| `POST /api/agents/snapshots/batch` | Recommended retry-safe snapshot delivery using a stable UUID `delivery_id`; identical retries return the original acknowledgement |
| `GET /api/agents/health` | Report latest agent health using server-received heartbeat timestamps |
| `POST /api/agents/enroll` | Admin-only enrolment that issues a one-time, read-only scoped agent token |
| `GET /api/agents/credentials` | Admin-only credential metadata listing; token hashes and bearer tokens are never returned |
| `GET /api/agents/negotiations` | Admin-only latest versioned capability-negotiation record for each enrolled agent |
| `GET /api/agents/{agent_id}/negotiations` | Admin-only negotiation history for one agent, in enrolment chronology within the retained window |
| `POST /api/agents/{agent_id}/credentials/rotate` | Admin-only token rotation; the previous token is invalidated immediately |
| `POST /api/agents/{agent_id}/credentials/revoke` | Admin-only credential revocation |
| `GET /api/agents/snapshots` | List latest snapshot metadata for registered agents |
| `GET /api/agents/snapshots/{agent_id}` | Read one agent’s latest credential-free normalised snapshot |
| `GET /api/agents/snapshots/{agent_id}/diff` | Compare the two most recent retained snapshots and list board/network/wireless/client/route changes |
| `GET /api/has_wifi`, `/api/scan`, `/api/system`, `/api/phy`, `/api/link`, `/api/diagnostics`, `/api/devices`, `/api/speedtest` | Authenticated local diagnostics and observations |

After login, send `Authorization: Bearer <token>` to protected endpoints. JSON POST requests are limited to 1 MiB. The browser UI includes a searchable Feature Workbench and automatically attaches the session token. The Settings panel stores local preferences for refresh cadence, compact navigation, hiding demo observations when offline and reduced motion; preferences stay in the current browser profile.

The SYSTEM → Router Agents page provides the authenticated Router Agent Console for enrolment, least-privilege capability selection, heartbeat health, snapshot drift, credential rotation/revocation and negotiation audit. It does not reveal stored credentials.

The `unifi_snapshot_normalizer` (F172) and `mikrotik_snapshot_normalizer` (F173) features accept caller-supplied controller/router exports through their `/api/features/{slug}` endpoints. They validate inventory, radio, client, address and network records and omit unknown and credential-like fields. These are offline imports, not live controller integrations.

The `router_snapshot_drift_report` (F174) compares two normalized snapshots from the same supported adapter. It reports bounded inventory drift for interfaces, radios, associations, network profiles and routes; only allow-listed fields are returned. The `router_fleet_health_audit` (F175) rolls up the same vendor schemas across sites, scoring only measured health evidence and marking absent telemetry as unknown. The `router_subnet_overlap_audit` (F176) checks IPv4 and IPv6 CIDRs across routers within each site and reports overlaps for operator review. The `router_client_roaming_audit` (F177) builds AP handoff timelines from the same normalized vendor snapshots. The `router_route_table_audit` (F178) validates OpenWrt and MikroTik route metadata and connected prefixes without probing or changing routes. The `router_vlan_segmentation_audit` (F179) checks VLAN consistency across UniFi and MikroTik within each site. The `router_gateway_redundancy_audit` (F180) compares configured default routes across routers without running a failover test. The `router_incident_alert_policy_evaluator` (F181) turns normalized findings into scoped, deduplicated local alert candidates and lifecycle updates. The `router_audit_report_bundle_builder` (F182) combines audit outputs into versioned, site-filterable JSON report bundles with stable content hashes. The `router_audit_report_comparator` (F183) validates those hashes and compares findings and site/source summaries across reports. The `router_scheduled_report_planner` (F184) previews recurring report times across IANA timezones without executing background jobs. The `router_webhook_envelope_builder` (F185) prepares canonical HMAC-signed HTTPS event batches for exact host allowlists without sending them. The `router_encrypted_report_archive` (F186) protects report/alert backups with authenticated encryption and a caller-held passphrase. The `router_webhook_egress_policy_verifier` (F187) checks DNS, peer-IP and TLS evidence before a dispatcher accepts a connection.

For router-side, read-only telemetry collection, see the [OpenWrt agent installation and service guide](agent/README.md). The agent uses an enrolled scoped token, TLS verification, a private on-disk retry spool and the idempotent snapshot-delivery endpoint. Optional uptime, load-average, memory and swap telemetry is collected only when the enrolled credential grants `system.health`.

For a Vite development server accessed from another device, add its exact origin to `WIFI_ANALYZER_CORS_ORIGINS` (comma-separated). Keep the default backend bind address on loopback unless LAN access is intentionally configured.

## Security and privacy

WiFi Analyzer Pro is intended to run close to the network being diagnosed. Network scans and system diagnostics are performed by the local host. No cloud account is required for local use. First-run setup creates a local workspace owner and stores individual salted scrypt password verifiers outside the repository with owner-only file permissions. Existing version-1 single-password files migrate to an `admin` owner identity without resetting the credential. Sessions are process-local, expire after a fixed lifetime and are revoked when an account is disabled or its password is reset. Five consecutive failed logins trigger a temporary lockout.

The local directory supports named accounts, role-based API permissions and site scopes. Newly created accounts receive no site access by default; owners can grant access to selected site IDs or all sites. Existing accounts are migrated with their previous all-site access preserved. The API filters saved site history, router-agent inventory and credential operations, and scheduled-report jobs by the same site assignments. Expensive operations are protected by bounded per-IP or per-account token-bucket limits and return HTTP 429 with Retry-After when throttled. This remains a single-workspace RBAC implementation, not full tenant isolation, OIDC/SAML SSO, WebAuthn, SCIM provisioning or centralised identity federation. Local TOTP authenticator-app MFA is available. The owner/administrator Security Audit screen records successful authentication, permission denials, user changes and router-agent credential lifecycle events in a local hash-chained SQLite ledger. Ordinary row updates/deletes are blocked and a verification endpoint detects local edits or chain gaps; this is tamper-evident, not externally immutable, and failed-login attempts are not all retained individually. Do not expose port `199` directly to the public internet. For team or remote access, place it behind a VPN or an authenticated reverse proxy, restrict network access, and explicitly configure allowed CORS origins. Review [SECURITY.md](SECURITY.md) before deployment.

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


## Scheduled report delivery

Scheduled-report jobs are stored in the local SQLite outbox and claimed using exclusive, expiring leases. The opt-in report worker can now send due jobs: run the worker from the repository root with python -m wifi_analyzer_backend.report_worker, or use report_worker.py in the Docker sidecar. It sends signed notifications over direct HTTPS connections pinned to a freshly resolved public IP, verifies the original hostname and trusted TLS certificate, refuses redirects, applies bounded request/response limits and only completes a job after a 2xx response. Configure an exact destination allowlist and a protected signing secret as documented in the [report-worker guide](wifi_analyzer_backend/REPORT_WORKER.md).

The authenticated delivery-package endpoint remains available for external integrations. It verifies the active lease and prepares the signed envelope using supplied DNS/TLS evidence; it does not transmit network traffic. The built-in worker and external dispatchers must not share the same claimed lease.

F190 maps normalized events into bounded, deterministic subscription batches. F192 and the Webhook Delivery Center now prepare a separate HMAC-signed delivery for each matched subscription only when its signing key and matching fresh DNS/TLS evidence are provided. It does not send network requests or store secrets; the downstream dispatcher must re-resolve and re-verify at send time. The built-in pinned-TLS report worker remains single-destination per process, so persistent multi-subscription fan-out and a dedicated dispatcher are still planned. The F191 PCAP/PCAPNG analyzer remains an offline file analyzer, not a live interface capture service.


### API request limits

The local API applies process-local token-bucket limits to first-run setup,
password login, wireless scan, speed test, feature execution, site audits,
live packet-capture starts and scheduled-report enqueue. Authentication limits
are keyed by the direct peer IP; authenticated operation limits are keyed by
the account identity. Rate-limit responses use HTTP 429 with Retry-After,
X-RateLimit-Limit, X-RateLimit-Remaining and X-RateLimit-Reset headers. The
limiter has a bounded in-memory bucket table and does not persist client
identifiers. These controls protect a single API process; they are not a
distributed gateway quota or a substitute for reverse-proxy/WAF controls.


Local accounts can optionally enable TOTP authenticator-app MFA from **Account
Security**. Enrolment is verified before activation, the secret is encrypted
at rest with password-derived AES-256-GCM key material, and ten single-use
recovery codes are provided. Password resets clear MFA so it must be enrolled
again. Use this alongside VPN/reverse-proxy access controls and protected
backups of the local account file.


The **Webhook Delivery Center** saves site-scoped subscription metadata (endpoint,
exact host allowlist, event filters and key ID), prepares signed multi-subscription
envelopes and queues them into a durable outbox. HMAC secrets are entered only
for a preparation request and are never saved in the subscription directory or
outbox. The screen displays queue state, attempt counts and safe error codes.
A separate worker performs fresh DNS resolution, pinned-IP TLS delivery,
redirect refusal, retries and dead-letter recovery.


## Enterprise WLAN security audit (F194)

The `enterprise_wlan_security_audit` feature evaluates supplied office, guest, IoT and management profile evidence for 802.1X/EAP policy, RADIUS redundancy, certificate validation, Protected Management Frames, WPS and network segmentation. It is offline and read-only: it does not connect to controllers or return SSIDs, RADIUS addresses or credential material, and it reports missing evidence separately from observed policy violations.


## Vendor product licensing control plane

The vendor-owned licensing service runs separately from customer installations.
It creates vendor Stripe Checkout sessions, verifies signed Stripe webhooks,
and issues 24-hour Ed25519 licences tied to one installation. Customer
installations hold only the vendor public key, their signed licence, and a
private per-installation activation credential. The vendor Stripe secret and
signing private key never belong in customer deployments.

### Configure the vendor service

Create recurring Stripe Prices for Pro, Business and Enterprise in the vendor's
Stripe account. Generate an Ed25519 signing key and store its raw 32-byte
private key as base64 in a file outside the repository, owned by the service
account with mode 0600. Configure the matching public key in customer
installations. Back up the vendor licensing SQLite database.

Set `WIFI_ANALYZER_LICENSE_SERVICE_PUBLIC_URL`, the vendor Stripe secret and
webhook signing secret, the recurring Price IDs, and
`WIFI_ANALYZER_VENDOR_LICENSE_SIGNING_PRIVATE_KEY_FILE` in a vendor-only
environment file. Start the separate service with:

```sh
docker compose --profile licensing-control-plane up -d licensing-control-plane
```

Terminate public HTTPS using a trusted reverse proxy to the loopback listener
on port 1999. Configure a Stripe webhook at
`{WIFI_ANALYZER_LICENSE_SERVICE_PUBLIC_URL}/api/webhook` for
`checkout.session.completed`, `customer.subscription.created`,
`customer.subscription.updated`, and `customer.subscription.deleted`.
Do not expose the plain HTTP listener directly to the internet.

In each customer installation, configure
`WIFI_ANALYZER_VENDOR_LICENSE_PUBLIC_KEY`,
`WIFI_ANALYZER_VENDOR_LICENSE_KEY_ID`, and
`WIFI_ANALYZER_VENDOR_LICENSE_SERVICE_URL`. The Plans & Licensing screen
starts vendor checkout and syncs the signed licence after Stripe confirms
payment. The customer installation never receives vendor Stripe or signing
private credentials.

This is the first vendor billing control plane, not yet a multi-region
high-availability payment platform. A live launch still needs real DNS/TLS,
Stripe live-mode activation, backups, monitoring, refund/dispute operations
and full customer onboarding.
