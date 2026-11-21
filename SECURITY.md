# Security Policy

## Reporting a Vulnerability

If you find a security vulnerability in WiFi Analyzer Pro, please do NOT open a public issue.

Email: manit6752025@gmail.com  
HackerOne: https://hackerone.com/irule675

I will respond within 48 hours.


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
