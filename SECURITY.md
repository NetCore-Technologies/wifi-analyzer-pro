# Security Policy

## Reporting a Vulnerability

If you find a security vulnerability in WiFi Analyzer Pro, please do NOT open a public issue.

Email: manit6752025@gmail.com  
HackerOne: https://hackerone.com/irule675

I will respond within 48 hours.

 
## Continuous dependency vulnerability checks

The Quality gates workflow audits the complete npm lockfile with
`npm audit --audit-level=high` and scans the Python runtime requirements,
including resolved dependencies, with `pip-audit` 2.10.1. These checks run
on pushes and pull requests to `main`, manual workflow dispatches and the
weekly scheduled build. A reported high/critical npm advisory or a known
Python package vulnerability fails the dependency-audit job.

The audit tools query their configured public advisory services at run time.
A clean result means no matching known advisory was reported for the resolved
dependency versions at that time; it is not a proof that dependencies are
free from unknown vulnerabilities, malicious packages, or vulnerable native
system libraries in the container base image.


## Local security audit trail

The application writes selected security events to a separate SQLite database under the local state directory. The default path is derived from the same platform state directory as site history and is named \`security-audit.sqlite3\`. Set \`WIFI_ANALYZER_HISTORY_DB\` to a custom database location to keep the audit ledger alongside a custom state database.

The endpoints and dashboard page require the \`users.manage\` permission, which is limited to the workspace owner and administrator roles. Events deliberately omit passwords, bearer tokens, webhook signing secrets and request bodies.

Rows are append-only through SQLite triggers. Each SHA-256 digest links a canonical JSON representation of the event to the previous event digest. Verification detects altered rows and deleted middle records. This is tamper-evident local storage, not a remote immutable archive: a privileged host administrator can replace the database, remove triggers or rewrite the full chain. For stronger evidence, export and sign periodic head-hash checkpoints or forward events to an independently administered SIEM.

Failed login attempts are not all written individually, to avoid turning unauthenticated traffic into unbounded disk writes. Account lockout events and authenticated permission denials are recorded. Audit writes are best-effort; monitor service logs and host storage. See [the audit trail operator guide](wifi_analyzer_backend/SECURITY_AUDIT.md) for details.


## API abuse controls

The API uses bounded in-memory token buckets for account setup and login,
wireless scans, speed tests, feature execution, site audits, capture starts
and report enqueue. Authentication endpoints are keyed by the socket peer IP;
authenticated operations use the local account identifier. The server does
not trust X-Forwarded-For or other client-supplied forwarding headers.

A throttled request receives HTTP 429, a Retry-After value and rate-limit
metadata headers. Bucket state is process-local, bounded and intentionally
not persisted; restarting the API resets the buckets. When deploying behind
a reverse proxy, configure an additional per-client-IP login/setup limit at
the proxy because the API sees the proxy address for unauthenticated requests.
For multi-worker or horizontally scaled deployments, enforce aggregate limits
at the gateway as well; these local buckets do not coordinate between processes.



## Authenticated live-stream transport

The live WebSocket endpoint does not accept long-lived bearer session tokens in
its URL. A client first requests a random, one-use ticket over the authenticated
REST API. The ticket is short-lived, bound to the authenticated user/session and
an explicit site set, and passed in the WebSocket subprotocol header rather
than a query string. Ticket issuance is permission-checked, rate-limited and
requires a successful security-audit write.

The server revalidates the session, `sites.read` permission and site assignments
while the connection is open. Logout, expiry or loss of any subscribed site
closes the stream. Tickets are held in memory and consumed once. The stream
is read-only and accepts no application commands.

The event hub has bounded connection and queue limits, caps event size, closes
slow consumers, and uses WebSocket ping/pong timeouts. Event summaries omit
SSIDs, BSSIDs, client/MAC identifiers, IP addresses and raw scan payloads.
The stream is process-local and is not a durable log or a shared multi-replica
message bus; clients must refresh REST snapshots after reconnecting.


## Session lifecycle and memory bounds

Bearer sessions are process-local and expire after the configured session TTL. The local account directory is limited to 100 users, and each account may hold at most 16 concurrent sessions. On a new successful login at that limit, the oldest session for that same account is revoked; another user's sessions are never evicted to make room. Expired or malformed session records are pruned when a new session is issued. This places a hard upper bound of 1,600 entries on the in-memory session table. Users should sign out of unused devices and sign in again if an older session is displaced.

## Account multi-factor authentication

Local accounts can enable TOTP authenticator-app MFA. Enrolment requires the
current account password and a successful authenticator-code confirmation.
The TOTP secret is encrypted in the local auth file with AES-256-GCM using
password-derived key material and the account ID as authenticated additional
data; it is never returned by the user-directory or status APIs. Ten recovery
codes are issued once and only salted hashes are retained. Recovery codes are
single-use. Password resets clear active/pending MFA and recovery codes, so the
account must enrol a new authenticator. Keep a protected backup of the auth
file and store recovery codes separately. MFA does not replace HTTPS for
remote access or protect against a compromised host.


## Webhook signing-key handling

The Webhook Delivery Center accepts a signing-key map for one local preparation
request and clears it from the editor after success. Keys are passed in the
authenticated request body and are not written to the security audit metadata or
returned by the orchestrator. Treat them as secrets in transit: use local loopback
or a protected VPN/HTTPS reverse proxy for remote operation, avoid browser
extensions or shared workstations, and use a dedicated secret manager for
production automation. Prepared envelopes are copied or exported only when an
operator explicitly requests it. The browser UI is not a persistent secret store.


## Durable webhook dispatch

Prepared multi-subscription envelopes are stored in a private local SQLite outbox.
The outbox retains only already-signed request bodies and signature headers; it
never stores the HMAC signing secret. Delivery is opt-in through the separate
webhook dispatcher process. The dispatcher resolves the endpoint immediately
before each attempt, rejects any non-public answer, connects to the exact peer
IP while retaining the DNS hostname for TLS SNI/certificate verification,
requires TLS 1.2 or 1.3 and refuses redirects. Only 2xx responses mark a
delivery as delivered. Delivery retries use bounded exponential backoff,
exclusive expiring leases and dead-letter state.

Queue reads, enqueue, retry and cancel operations are permission-gated and
respect per-site access. The queue stores signed event payloads, so protect the
state directory with restrictive host permissions, volume encryption and a
retention policy appropriate to the event data. The dispatch worker has no
listening port. Run it with the same private state volume as the API and do not
expose the SQLite file over a network filesystem unless the deployment's
SQLite locking semantics have been validated.


## Production deployment boundary

Use a dedicated non-root service identity, persistent private state, host firewall
rules and a TLS reverse proxy or VPN for remote access. The Docker image drops
all Linux capabilities and runs as UID 10001. Its Compose configuration binds
to loopback by default, uses a read-only container filesystem with a temporary
filesystem for scratch data, and shares only required named state volumes with
optional workers. Live packet capture is intentionally not granted host
network capabilities by default; enable it only through a separately reviewed
host-specific capability policy.

Keep account state, audit ledger, site history, router-agent credentials,
report queue and webhook outbox on durable local storage with reliable SQLite
locking. Back up those files before upgrades and test restore procedures. Do not
use a shared network filesystem for SQLite queue databases without validating
locking semantics. The example systemd units use a dedicated account, restrictive
umask, NoNewPrivileges and filesystem/kernel hardening. They do not grant
CAP_NET_ADMIN or CAP_NET_RAW.


Webhook subscription records retain only endpoint metadata, exact DNS host
allowlists, event filters, site assignments and key identifiers. HMAC signing
secrets are not accepted by the subscription CRUD API and are not stored in
the subscription database. Operators provide signing keys transiently when
preparing an envelope; the API clears them from the editor after success and
stores only the resulting signed envelope in the protected delivery outbox.


## Saved webhook subscriptions and endpoint probes

The subscription directory stores only metadata: subscription ID, HTTPS
endpoint, exact DNS hostname allowlist, event filters, minimum severity,
site allowlist, key ID and batching limits. It does not accept or persist HMAC
signing secrets. Operators enter the secret transiently in the Webhook Delivery
Center when preparing an envelope; after successful preparation the browser
clears the transient key field and the server stores only the signed envelope.

The endpoint probe requires `webhooks.manage` and site access to the saved
subscription. It resolves the configured DNS hostname, rejects non-public
answers through the existing resolver, connects directly to a resolved IP,
verifies TLS with the original hostname and performs no HTTP request. The
result is short-lived and must be refreshed before the next preparation run.

## Subscription billing and entitlement controls

Stripe billing is optional and remains disabled until the deployment operator
sets server-side credentials and price IDs. The dashboard never receives the
Stripe secret key or webhook signing secret. Hosted checkout and the customer
portal are created by the backend, and returned URLs are restricted to Stripe's
checkout and billing hosts.

The webhook endpoint is `/api/billing/webhook`. It verifies Stripe's
timestamped HMAC-SHA256 signature against the raw request bytes before parsing
JSON, enforces a five-minute timestamp tolerance and bounds the payload to
256 KiB. Event IDs are stored in a bounded SQLite idempotency ledger. Only
subscription events containing the installation's server-generated workspace
reference (or the already-linked Stripe customer) can change entitlements.
Paid plan IDs are resolved from server-configured Stripe price IDs; webhook
metadata or browser requests cannot select a paid tier.

A payment that enters `past_due` has a three-day grace period before the
installation falls back to free entitlements. User, router-agent and webhook
subscription quotas are checked server-side under a process lock before
creation. Quotas are installation-local because this release bills one
workspace per deployment; it is not a shared multi-tenant SaaS control plane.


## Subscription quota enforcement

The local subscription integration enforces quotas for users, managed router
agents, site inventory, saved webhook subscriptions and monthly diagnostic
feature executions. Diagnostic usage is persisted as a UTC calendar-month
SQLite counter; invalid feature slugs and failed feature validations do not
consume the allowance. Site counts include saved topology-history sites and
managed router-agent assignments. Creation and reassignment checks are guarded
by a process lock and are designed for the single-process local API server.
Do not use these local quotas as a shared multi-process SaaS billing boundary;
pooled hosting needs central tenant isolation and transactional quota
coordination.


## MIT licensing and product licences

The source is MIT licensed. Users may legally inspect, modify, fork and
self-host the source, including changing local licence validation. The
vendor-issued Ed25519 token is an official-build entitlement and a credential
for vendor-operated services; it is not DRM and cannot prevent a modified
fork. Do not represent local activation as tamper-proof. Keep recurring
subscription value in maintained official releases, vendor-hosted services,
managed fleet operations, integrations and support.

## Vendor product licence boundary

Customer installations verify vendor-issued Ed25519 product licences using
public keys configured through `WIFI_ANALYZER_VENDOR_LICENSE_PUBLIC_KEY`.
The licence token is bound to the installation's generated identifier and
contains a plan whose quota limits must exactly match the server's plan
catalogue. Tokens are stored with owner-only file permissions and have a
bounded 72-hour offline grace period. An installed invalid or expired licence
fails closed to Free entitlements.

The matching Ed25519 private signing key must remain on the vendor-controlled
licensing service. Do not configure that private key, Stripe vendor credentials
or vendor control-plane database on customer installations. The local
`WIFI_ANALYZER_STRIPE_SECRET_KEY` feature is optional customer-managed
workspace billing and does not collect subscription revenue for NetCore.
