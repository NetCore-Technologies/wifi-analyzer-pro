# Site alert notification bridge

WiFi Analyzer Pro can turn persisted site-alert incidents into signed webhook
notifications using the same durable queue as router events and the existing
DNS-pinned HTTPS dispatcher.

The bridge has two independent processes:

1. `alert_webhook_worker` reads incident transitions, applies saved subscription
   event/severity/site filters, signs matching payloads and enqueues them. It
   performs no DNS lookups and makes no network connections.
2. `webhook_dispatch_worker` claims signed queue entries and sends them over
   freshly resolved, pinned-IP TLS connections. It does not receive signing
   keys.

## Configure a signing key

Create a JSON key map outside the repository. Each key ID must match the
subscription's `key_id`; each secret must contain at least 32 UTF-8 bytes.

```sh
sudo install -d -o root -g root -m 0700 /etc/wifi-analyzer-pro
KEY="$(openssl rand -hex 32)"
printf '{"primary":"%s"}\n' "$KEY" | sudo tee /etc/wifi-analyzer-pro/webhook-signing-keys.json >/dev/null
unset KEY
sudo chmod 0600 /etc/wifi-analyzer-pro/webhook-signing-keys.json
```

Never commit signing keys, paste them into the dashboard, or put them in
`.env`. Keep a backup in your approved secret manager and rotate keys using
a new key ID while subscriptions are updated. The worker rejects symbolic
links, non-regular files, files larger than 64 KiB and POSIX files accessible
by group or other users.

## Create a saved subscription

In the Webhook Delivery Center, create a saved subscription with an exact
HTTPS hostname allowlist and the same key ID used in the key file. Subscribe
to these event types:

- `site.alert.opened`
- `site.alert.acknowledged`
- `site.alert.resolved`

Set an explicit site allowlist. Choose the minimum severity that should be
sent; a warning-level minimum includes warning and critical alerts, while
info includes all three severities. Configure only public DNS hostnames on
HTTPS port 443. The dispatcher deliberately refuses private, loopback,
link-local, reserved and other non-global addresses.

## Docker Compose

Set the signing-key file path in your protected, untracked `.env` file:

```dotenv
WIFI_ANALYZER_WEBHOOK_SIGNING_KEYS_FILE=/etc/wifi-analyzer-pro/webhook-signing-keys.json
WIFI_ANALYZER_ALERT_WEBHOOK_POLL_SECONDS=5
WIFI_ANALYZER_ALERT_WEBHOOK_BATCH_SIZE=50
```

The image runs as UID 10001. With local file-backed Compose secrets, ensure the
mounted source file is readable by that UID and remains owner-only; for example,
on a host where UID 10001 is reserved for this service:

```sh
sudo chown 10001:10001 /etc/wifi-analyzer-pro/webhook-signing-keys.json
sudo chmod 0600 /etc/wifi-analyzer-pro/webhook-signing-keys.json
docker compose --profile alert-webhooks up -d
# Also start the network delivery worker:
docker compose --profile webhook-dispatcher --profile alert-webhooks up -d
docker compose ps
```

The `alert-webhooks` profile starts only the non-root, read-only, resource-bounded notification bridge. The separate `webhook-dispatcher` profile starts the network delivery worker. Enable both profiles when notifications should actually leave the host.
Both workers share the local state volume. Only the bridge mounts the signing
key file. The dispatcher receives signed envelopes only. Do not expose the
container's Docker socket to either worker.

## Linux systemd

Install the new unit with the existing application services:

```sh
sudo install -m 0644 deploy/systemd/wifi-analyzer-alert-webhook-bridge.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wifi-analyzer-alert-webhook-bridge.service
sudo systemctl status wifi-analyzer-alert-webhook-bridge.service
```

The unit uses systemd `LoadCredential` to provide a private, service-readable
copy of the source key file at runtime. The bridge is restricted to Unix-domain
sockets because it only signs and enqueues local data. The separate dispatcher
is the only process that requires outbound network access.

## Delivery and lifecycle semantics

The alert engine writes an `opened`, `acknowledged` or `resolved` transition
into its SQLite notification outbox in the same transaction as the corresponding
incident change. This prevents a committed incident from being silently lost
between the alert database update and notification preparation. Repeated scans
do not create duplicate opening messages for an existing active incident.

The bridge routes events against the current enabled subscription directory,
builds canonical HMAC-SHA256 envelopes and inserts them into the existing
idempotent delivery outbox. The stable subscription/batch ID means a process
restart after enqueue but before marking the alert transition complete does not
create a second delivery. If a key or subscription store is temporarily
unavailable, the transition remains pending and is retried with bounded
exponential backoff. When no enabled subscription matches, the transition is
marked `not_configured`; it is not delivered retroactively when a subscription
is created later.

Incident history shows `pending`, `queued` or `not_configured` for the
notification-preparation stage. This does not claim that the receiver accepted
a message. The Webhook Delivery Center reports transport states separately:
pending, sending, retry wait, delivered, dead letter and cancelled.

Notification payloads include the site and alert rule identifiers, transition,
severity, summary and measured value/threshold. They intentionally exclude raw
SSID, BSSID, client, MAC and IP-address data. Do not put secrets or private
network inventories into alert rule names or summaries.

The alert transition outbox is local SQLite state, bounded to 100,000 pending
notifications and retained for up to 365 days after processing. Back up the
alert database, webhook subscription database and delivery outbox together.
Keep their SQLite files on local storage with reliable locking, not NFS/SMB.
