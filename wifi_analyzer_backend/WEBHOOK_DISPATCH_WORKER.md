# Multi-subscription webhook dispatcher

WiFi Analyzer Pro stores prepared signed subscription batches in a durable SQLite outbox. The API does not send outbound HTTP requests. A separate opt-in worker claims pending batches and delivers them through pinned-IP TLS connections.

## Start

Run from the repository root:

    python -m wifi_analyzer_backend.webhook_dispatch_worker

The worker does not need HMAC signing secrets. Each envelope is signed during F192 preparation, and the outbox stores only the signed body and headers. The worker validates the envelope structure, re-resolves the endpoint immediately before delivery, verifies the actual socket peer against the fresh DNS answer set, requires a trusted TLS certificate with the original DNS hostname, refuses redirects, and records success only after a 2xx response.

Optional environment settings:

| Variable | Default | Purpose |
|---|---:|---|
| WIFI_ANALYZER_WEBHOOK_DELIVERY_DB | platform state path | Shared SQLite queue path; normally leave unset |
| WIFI_ANALYZER_WEBHOOK_WORKER_ID | generated | Worker identifier |
| WIFI_ANALYZER_WEBHOOK_WORKER_POLL_SECONDS | 5 | Idle polling interval (1–300 seconds) |
| WIFI_ANALYZER_WEBHOOK_WORKER_BATCH_SIZE | 5 | Maximum claims per cycle (1–20) |
| WIFI_ANALYZER_WEBHOOK_WORKER_TIMEOUT_SECONDS | 8 | DNS/socket timeout budget (1–30 seconds) |
| WIFI_ANALYZER_WEBHOOK_WORKER_LEASE_SECONDS | 120 | Expiring delivery lease (15–3600 seconds) |

## Docker sidecar

The API and worker must use the same HOME configuration volume and XDG state volume. Example after starting the API container as wifi-analyzer-pro:

    docker run --rm --volumes-from wifi-analyzer-pro \
      --entrypoint python wifi-analyzer-pro:local webhook_dispatch_worker.py

The worker has no listening port. Run it as the image's non-root UID and do not mount signing secrets into it; it does not need the HMAC keys. Use a service manager/orchestrator to restart the worker after host maintenance.

## Queue and recovery

The Webhook Delivery Center exposes the site-scoped queue. Enqueue is idempotent on the (subscription_id, batch_id) pair; submitting the same content again returns the original queue item, while reusing the key for different content produces HTTP 409. Queue listings expose only status metadata and never return signed bodies or signature headers.

The worker claims rows with exclusive expiring leases. A worker crash leaves a lease that can be reclaimed after expiry. Network or endpoint failures receive bounded exponential retries; exhausted deliveries move to dead_letter. An operator with webhooks.manage can manually retry a dead-lettered/cancelled item or cancel work that has not started. Only 2xx responses are final success. HTTP redirects are rejected, not followed.

## Egress and privacy controls

- Endpoint URLs must be HTTPS on port 443 and the DNS hostname must be an exact entry in the subscription allowlist. IP literals, embedded credentials, URL query strings and fragments are rejected.
- The worker resolves DNS on every attempt and rejects the whole answer set if any address is private, loopback, link-local, multicast, reserved, unspecified or otherwise non-global.
- The TCP socket connects directly to the selected resolved IP. TLS SNI and certificate hostname verification use the original DNS hostname. TLS 1.2 or 1.3 is required.
- The actual connected peer must match the selected DNS address and be present in the answer set supplied to the egress verifier. Environment proxy variables are not used by the pinned transport.
- Redirects are never followed. Response bodies are bounded to 16 KiB and discarded; raw receiver content, request-body excerpts and exception strings are not persisted.
- The API stores signed event content in SQLite but does not store signing secrets. Protect the state directory, encrypt its volume where appropriate and define an event-data retention policy for your environment.
- The queue uses SQLite WAL mode and is designed for local disk with reliable file locking. Do not place it on NFS/SMB or a shared network filesystem unless the specific locking semantics have been tested. Use one local queue per API instance until a separately coordinated distributed queue is deployed.

This is a single-workspace local delivery service, not a multi-tenant managed notification SaaS. Customer-specific storage, billing/entitlements and centralised dispatcher fleet management remain separate enterprise work.


## Retention

The outbox prunes only terminal rows (`delivered`, `dead_letter` and
`cancelled`) after the configured retention window. Pending, retry-wait and
currently leased rows are never removed by retention cleanup. The default is
90 days. Set `WIFI_ANALYZER_WEBHOOK_DELIVERY_RETENTION_DAYS` to an integer
between 7 and 3650 before starting the API/worker. The worker performs pruning
at the start of each queue cycle and reports only a deleted-row count to logs;
no event content is emitted.


## Subscription directory

Use the Webhook Delivery Center to save subscription definitions. The registry
stores subscription ID, endpoint, exact DNS host allowlist, key ID, event types,
minimum severity, site allowlist and bounded batch settings. It deliberately
does not store HMAC signing secrets. The preparation form receives the signing
key for the selected key ID transiently and returns a signed envelope; the
delivery queue persists the envelope, not the secret.

New subscriptions are limited to 100 per local workspace. Restricted site users
must define an explicit non-empty site allowlist entirely contained in their
assigned sites. Global/all-site definitions can be created only by all-site
administrators. Subscription list, update and delete operations hide records
outside the caller's site scope.


## Saved subscriptions and egress proof

Create or edit saved subscription definitions in the Webhook Delivery Center.
The directory is capped at 100 records and stores endpoint routing metadata,
exact host allowlists, event filters, site assignments and key IDs only.
Restricted users can create or manage subscriptions only for explicitly
assigned sites. The API hides definitions outside the account's scope.

Use **Test TLS** on each enabled subscription before preparing a batch. This
calls the local API's endpoint probe, which performs a fresh DNS resolution
and pinned TLS handshake and then evaluates the evidence using F187. It sends
no webhook HTTP request. Approved evidence is added to the next orchestration
request; it expires quickly by design, so prepare promptly after testing.
Signing secrets are entered in the UI only for the preparation request and
are never part of the saved subscription record.


## Site alert notifications

Site-alert incidents can be routed into this same delivery queue by the
separate `alert_webhook_worker`. It consumes durable incident transitions,
applies saved event/severity/site filters, signs envelopes with a protected
key file and enqueues them; it does not perform network I/O. Configure it as
described in `ALERT_WEBHOOK_BRIDGE.md`. Run both workers when alert
notifications need to reach their destination. The dispatcher itself never
receives HMAC signing secrets.
