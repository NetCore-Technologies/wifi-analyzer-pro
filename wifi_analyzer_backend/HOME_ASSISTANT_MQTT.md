# Home Assistant MQTT discovery

WiFi Analyzer Pro can publish the local site's privacy-preserving aggregate
telemetry to a configured MQTT broker and automatically create Home Assistant
entities using MQTT discovery.

The integration is an optional, outbound-only worker. The API remains usable
without an MQTT broker, and the worker never accepts commands or changes
router/network configuration.

## Prerequisites

- Home Assistant with the MQTT integration configured.
- An MQTT 3.1.1 broker reachable from the WiFi Analyzer Pro host or container.
- A dedicated broker account with permission to publish below
  `homeassistant/#` and `wifi-analyzer-pro/<device_id>/#`.
- A stable per-installation `WIFI_ANALYZER_HA_DEVICE_ID`, containing only
  letters, digits, underscores or hyphens.

The worker uses Paho MQTT 2.x with the MQTT 3.1.1 protocol. TLS certificate
validation is enabled by default. Use a CA certificate file when the broker
uses a private certificate authority. Do not set the client to skip hostname
verification.

## Docker Compose

Copy `.env.example` to `.env`, then configure:

```dotenv
WIFI_ANALYZER_HA_MQTT_HOST=mqtt.example.internal
WIFI_ANALYZER_HA_DEVICE_ID=main-office
WIFI_ANALYZER_HA_MQTT_PORT=8883
WIFI_ANALYZER_HA_MQTT_USERNAME=wifi-analyzer-pro
WIFI_ANALYZER_HA_MQTT_PASSWORD_FILE=/etc/wifi-analyzer-pro/mqtt-password
WIFI_ANALYZER_HA_MQTT_CA_CERT_FILE=
WIFI_ANALYZER_HA_MQTT_TLS=true
WIFI_ANALYZER_HA_MQTT_DISCOVERY_PREFIX=homeassistant
WIFI_ANALYZER_HA_MQTT_POLL_SECONDS=60
```

Create the MQTT password file outside the repository. On a host where UID
10001 is reserved for this container, make it readable only by the service
account:

```sh
sudo install -d -o root -g root -m 0700 /etc/wifi-analyzer-pro
sudo install -o 10001 -g 10001 -m 0400 /dev/null /etc/wifi-analyzer-pro/mqtt-password
sudoedit /etc/wifi-analyzer-pro/mqtt-password
sudo chown 10001:10001 /etc/wifi-analyzer-pro/mqtt-password
sudo chmod 0400 /etc/wifi-analyzer-pro/mqtt-password
docker compose --profile home-assistant up -d --build
```

The password file is bind-mounted read-only into the non-root worker. If the
broker uses a private CA, set `WIFI_ANALYZER_HA_MQTT_CA_CERT_FILE` to a host
certificate path; it is also mounted read-only. Keep `.env` and credential
files out of source control.

To use a broker on a trusted private network without TLS, explicitly set
`WIFI_ANALYZER_HA_MQTT_TLS=false` and normally use port 1883. This disables
transport encryption and must not be used over untrusted networks or the
public Internet. TLS remains the recommended default.

The MQTT worker is in a separate `home-assistant` Compose profile. It shares
the API's state volume and has no published listening port. Its container
drops Linux capabilities, runs read-only, and has bounded memory/CPU/PID use.

## Linux systemd

Create a root-owned configuration file:

```sh
sudo install -o root -g root -m 0600 /dev/null /etc/wifi-analyzer-pro/homeassistant-mqtt.env
sudoedit /etc/wifi-analyzer-pro/homeassistant-mqtt.env
```

Set the same variables as the Compose example, but point
`WIFI_ANALYZER_HA_MQTT_PASSWORD_FILE` and any private CA path to their
host-side paths. The password file must be readable by the `wifi-analyzer`
service account and inaccessible to group/other users (for example, owned by
`wifi-analyzer:wifi-analyzer` with mode `0400`).

Install and start the optional service:

```sh
sudo install -m 0644 deploy/systemd/wifi-analyzer-homeassistant-mqtt.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now wifi-analyzer-homeassistant-mqtt.service
sudo systemctl status wifi-analyzer-homeassistant-mqtt.service
```

## Discovered entities

The worker publishes 15 numeric sensors and one connectivity binary sensor.
They include access-point counts by band, explicitly open access points,
average observed RSSI, measured local default-gateway latency/jitter/loss,
completed speed-test download/upload/ping values, and 24-hour scan/diagnostic/
speed-test sample counts. The connectivity sensor indicates whether the latest
stored telemetry minute is no more than five minutes old.

The sensor values are derived from the same minute-level aggregates used by
the Prometheus exporter. Missing measurements are published as `unknown`, not
invented zeroes. The 24-hour sample gauges may decrease as old samples age out.

## MQTT topics and lifecycle

For device ID `main-office`, the state and availability topics are:

- `wifi-analyzer-pro/main-office/state`
- `wifi-analyzer-pro/main-office/availability`

The discovery prefix defaults to `homeassistant`. Each component has a stable
unique ID and a retained configuration payload. The worker publishes retained
QoS 1 discovery configuration, state and availability messages. Its MQTT Last
Will is the retained `offline` availability state; a successful connection
publishes `online`.

The worker subscribes to Home Assistant's default `homeassistant/status`
birth topic. When Home Assistant publishes `online`, the worker republishes
discovery and current state so entities are restored after Home Assistant
restarts. Discovery and state are also retained at the broker.

Stopping or disabling the worker does not delete retained discovery
configuration. The availability topic is set to `offline` on graceful stop
and by the MQTT Last Will after an ungraceful disconnect. To remove this
device from Home Assistant, publish an empty retained payload to each
`<discovery_prefix>/sensor/<device_id>_<sensor>/config` and
`<discovery_prefix>/binary_sensor/<device_id>_telemetry_fresh/config` topic,
or remove its discovery components through Home Assistant.

## Privacy and security

The worker queries only the configured `WIFI_ANALYZER_LOCAL_SITE_ID` (default
`local`) from the local SQLite telemetry store. It does not publish site IDs,
SSIDs, BSSIDs, client/MAC addresses, IP addresses, raw scan records or router
credentials. It runs as a separate process with no listening API and makes no
router configuration changes.

Configure a dedicated least-privilege broker account, use TLS with certificate
and hostname validation, restrict the account's topic ACL, and rotate broker
credentials through your secret-management process. The integration is
telemetry-only: Home Assistant cannot start scans, trigger speed tests, or
change the Wi-Fi network through these topics.
