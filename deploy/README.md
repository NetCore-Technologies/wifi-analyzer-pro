# Production deployment and operations

This guide describes a single-host production deployment. It does not turn the current local-workspace product into a managed multi-tenant SaaS; tenant isolation, vendor billing, centralised customer management and enterprise federation remain separate product work.

## Docker Compose

Requirements: Docker Engine with Docker Compose v2. Copy the example environment file and start the API:

    cp .env.example .env
    docker compose up -d --build
    docker compose ps

The default published bind address is 127.0.0.1:199. This is deliberate. Put a TLS reverse proxy or VPN in front of the service for team access. To publish on a trusted LAN, set WIFI_ANALYZER_BIND_ADDRESS=0.0.0.0 only after configuring host firewall rules and an authenticated TLS reverse proxy.

Enable the durable multi-subscription dispatcher when webhook delivery is required:

    docker compose --profile webhook-dispatcher up -d

The API and dispatcher share the application state volume. The dispatcher is a non-root sidecar with no listening port and does not receive signing secrets. Site-alert notification preparation is a separate optional bridge; it requires an external protected signing-key file and starts with the `alert-webhooks` profile. To run both the bridge and dispatcher, use:

    docker compose --profile webhook-dispatcher --profile alert-webhooks up -d

### Third-party feature plugins

The API stores enabled/disabled plugin lifecycle state in its persistent state
volume and discovers packages from
`/home/wifi-analyzer/.local/state/wifi-analyzer-pro/plugins`. Configure the
public Ed25519 publisher trust store with
`WIFI_ANALYZER_PLUGIN_TRUST_KEYS_FILE` in `.env`; its contents are mounted as
a read-only Compose secret. The trust store is public verification material,
not a signing secret. Do not put publisher private keys on customer systems.

Create the host trust directory and file before starting the API:

    sudo install -d -o root -g root -m 0755 /etc/wifi-analyzer-pro
    sudo install -o root -g root -m 0644 plugin-trust-keys.json /etc/wifi-analyzer-pro/plugin-trust-keys.json

Set:

    WIFI_ANALYZER_PLUGIN_TRUST_KEYS_FILE=/etc/wifi-analyzer-pro/plugin-trust-keys.json

To install a signed package into the named state volume, stage the package
directory using a one-shot helper container that mounts the same state volume.
Run the helper as root only for the copy, then make the package owned by
UID/GID 10001 and owner-only:

    docker volume ls
    docker run --rm --user 0:0 \
      -v <compose-project>_state:/state \
      -v /secure/path/acme.channel_quality:/package:ro \
      --entrypoint sh ${WIFI_ANALYZER_IMAGE:-wifi-analyzer-pro:local} -c '
        install -d -o 10001 -g 10001 -m 0700 /state/wifi-analyzer-pro/plugins/acme.channel_quality &&
        install -o 10001 -g 10001 -m 0600 /package/manifest.json /state/wifi-analyzer-pro/plugins/acme.channel_quality/manifest.json &&
        install -o 10001 -g 10001 -m 0600 /package/plugin.py /state/wifi-analyzer-pro/plugins/acme.channel_quality/plugin.py
      '

Use the actual Compose project state volume name shown by `docker volume ls`.
After staging, an owner/admin can inspect `GET /api/plugins` and enable,
reload or disable the signed package through the audited lifecycle API. The
HTTP API does not accept plugin uploads. See
`wifi_analyzer_backend/PLUGIN_SDK.md` for the package format and signing
process.

The bridge prepares and queues signed event notifications without network access; the dispatcher transmits them. The report worker is configured separately because it requires a destination URL, exact DNS allowlist and HMAC signing secret. Do not put those values in the repository or a committed Compose file.

Useful operations:

    docker compose logs --tail=200 api
    docker compose logs --tail=200 webhook-dispatcher
    docker compose restart api
    docker compose stop
    docker compose down

Do not use docker compose down -v unless you intentionally want to delete persistent configuration and application state volumes.

## systemd on Linux

The example services assume an application release under /opt/wifi-analyzer-pro/releases/<version>, a current symlink, a Python virtual environment at /opt/wifi-analyzer-pro/venv, a service user named wifi-analyzer, persistent state in /var/lib/wifi-analyzer-pro, and protected configuration in /etc/wifi-analyzer-pro.

Create the service account and directories:

    sudo useradd --system --home-dir /var/lib/wifi-analyzer-pro --shell /usr/sbin/nologin wifi-analyzer
    sudo install -d -o root -g root -m 0755 /opt/wifi-analyzer-pro/releases
    sudo install -d -o root -g root -m 0755 /etc/wifi-analyzer-pro
    sudo install -d -o wifi-analyzer -g wifi-analyzer -m 0700 /var/lib/wifi-analyzer-pro

Build a release directory from a verified source checkout or release archive. Build the frontend, create /opt/wifi-analyzer-pro/venv with Python 3.11 or newer and install wifi_analyzer_backend/requirements.txt. Copy the built dist directory into wifi_analyzer_backend/dist. Make release code root-owned and non-writable by the service account. Point current at the selected version:

    sudo ln -sfn /opt/wifi-analyzer-pro/releases/<version> /opt/wifi-analyzer-pro/current

Install the service units:

    sudo install -m 0644 deploy/systemd/wifi-analyzer-pro.service /etc/systemd/system/
    sudo install -m 0644 deploy/systemd/wifi-analyzer-webhook-dispatcher.service /etc/systemd/system/
    sudo install -m 0644 deploy/systemd/wifi-analyzer-report-worker.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable --now wifi-analyzer-pro.service

The API binds to loopback. Create /etc/wifi-analyzer-pro/server.env as root-owned mode 0600 only when overriding defaults. For remote access, use a VPN or authenticated TLS reverse proxy and firewall; do not publish the API directly to the public internet.

### Third-party feature plugins

The systemd unit configures a persistent plugin directory at
`/var/lib/wifi-analyzer-pro/plugins` and plugin lifecycle state in
`/var/lib/wifi-analyzer-pro/plugin-registry.sqlite3`. Install the public
Ed25519 trust store as a root-controlled, service-readable file:

    sudo install -o root -g wifi-analyzer -m 0640 plugin-trust-keys.json /etc/wifi-analyzer-pro/plugin-trust-keys.json

The trust store contains public verification keys only. Stage each reviewed,
signed plugin package under `/var/lib/wifi-analyzer-pro/plugins/<publisher.plugin>/`
with ownership `wifi-analyzer:wifi-analyzer`, directory mode 0700 and
manifest/source mode 0600. For example:

    sudo install -d -o wifi-analyzer -g wifi-analyzer -m 0700 /var/lib/wifi-analyzer-pro/plugins/acme.channel_quality
    sudo install -o wifi-analyzer -g wifi-analyzer -m 0600 manifest.json /var/lib/wifi-analyzer-pro/plugins/acme.channel_quality/manifest.json
    sudo install -o wifi-analyzer -g wifi-analyzer -m 0600 plugin.py /var/lib/wifi-analyzer-pro/plugins/acme.channel_quality/plugin.py

After staging the package, an owner/admin can verify it with `GET /api/plugins`
and enable, reload or disable it using the audited lifecycle API. The API
does not accept plugin uploads. See
`wifi_analyzer_backend/PLUGIN_SDK.md` for the signed package contract and
trusted publisher key rotation process.

The webhook dispatcher can be enabled independently:

    sudo systemctl enable --now wifi-analyzer-webhook-dispatcher.service

The alert notification bridge is optional and needs a protected
`/etc/wifi-analyzer-pro/webhook-signing-keys.json` file before it is enabled:

    sudo install -m 0644 deploy/systemd/wifi-analyzer-alert-webhook-bridge.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable --now wifi-analyzer-alert-webhook-bridge.service

The scheduled report worker remains disabled until its protected environment file exists:

    sudo install -o root -g wifi-analyzer -m 0640 /dev/null /etc/wifi-analyzer-pro/report-worker.env
    sudoedit /etc/wifi-analyzer-pro/report-worker.env
    sudo systemctl enable --now wifi-analyzer-report-worker.service

The report worker environment file contains destination and signing-secret configuration. Prefer WIFI_ANALYZER_REPORT_WEBHOOK_SIGNING_SECRET_FILE with a separate root-owned 0640 secret file rather than storing a secret inline. Rotate keys through the receiver's key-management process.

## State, backup and restore

The persistent state includes local account verifiers/MFA state, security audit events, signed audit key material, site history, router-agent credentials/telemetry, scheduled-report jobs and the webhook outbox. It can contain network inventory and signed event details.

1. Stop the API and workers before a consistent filesystem-level backup, or use a SQLite-aware backup procedure for every database.
2. Back up /var/lib/wifi-analyzer-pro (systemd) or both named Compose volumes (Docker) using encrypted, access-controlled storage.
3. Back up protected configuration and external secret-manager references separately. Never include signing secrets in a public artifact.
4. Restore files with ownership wifi-analyzer:wifi-analyzer and restrictive directory/file permissions before restarting services.
5. Validate the API health endpoint, sign-in, audit-chain verification, site-history reads and queue summaries after restoration.

The webhook outbox has a configurable retention window. Delivered, dead-letter and cancelled terminal rows are pruned by the dispatcher only after the configured number of days; pending, retry-wait and leased items are preserved.

## Upgrade and rollback

1. Verify the release checksum and provenance and review the release notes.
2. Take a consistent backup of state and protected configuration.
3. Extract/build the next version under a new versioned directory. Do not overwrite the active release in place.
4. Build the frontend and install Python dependencies into the shared or release-specific virtual environment.
5. Point the current symlink to the new version, then restart the API and optional workers.
6. Verify /health, login, site and agent inventory, audit-chain verification, report-job summary and webhook-delivery summary.
7. If validation fails, stop services, point current back to the previous release and restart. Do not automatically roll back state databases after a forward migration; restore the pre-upgrade backup only after checking schema compatibility and data-loss implications.

## Operational boundaries

- Use local storage with reliable SQLite locking. Do not place active SQLite files on NFS/SMB or shared network storage.
- The example systemd units run as a dedicated user with NoNewPrivileges, restrictive umask, protected system/home paths and no Linux capabilities.
- Live tcpdump capture is not enabled by default. The Docker image drops all capabilities and does not install tcpdump. Grant packet-capture capabilities only through a separately reviewed host-specific service override.
- Monitor disk capacity, service restarts, worker dead letters and backup success. The current local deployment does not provide external SIEM forwarding or hosted fleet supervision.
- Keep the API behind a VPN or authenticated TLS reverse proxy for remote use.
