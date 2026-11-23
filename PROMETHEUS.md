# Prometheus and Grafana integration

WiFi Analyzer Pro exposes an optional Prometheus text exporter at GET /metrics and ships an importable Grafana dashboard at deploy/grafana/wifi-analyzer-pro.json.

## Enable the exporter

The endpoint is disabled by default. Create a dedicated random token with at least 32 characters:

    openssl rand -hex 32

For Docker Compose, put the value in the protected, ignored .env file:

    WIFI_ANALYZER_PROMETHEUS_TOKEN=replace-with-the-random-token
    WIFI_ANALYZER_LOCAL_SITE_ID=local

Then recreate the API container:

    docker compose up -d --force-recreate api

For a systemd or source installation, set the same variables in the service protected environment file and restart WiFi Analyzer Pro. Never commit the token, put it in a URL, or expose it in browser JavaScript.

The exporter accepts only an Authorization: Bearer token header. Missing or incorrect credentials receive HTTP 401. If the token is absent or shorter than 32 characters, the route is hidden and returns HTTP 404. The token is checked with a constant-time comparison and is not written to application state or logs.

## Prometheus scrape configuration

Store the token in a file readable only by the Prometheus service account, for example /etc/prometheus/secrets/wifi-analyzer-token, then reference it from the scrape configuration:

    scrape_configs:
      - job_name: wifi-analyzer-pro
        metrics_path: /metrics
        scheme: https
        static_configs:
          - targets:
              - analyzer.example.internal
        authorization:
          type: Bearer
          credentials_file: /etc/prometheus/secrets/wifi-analyzer-token
        scrape_interval: 30s
        scrape_timeout: 5s

Use HTTPS for traffic that leaves the local host or a trusted private Docker network. For a loopback-only installation, Prometheus can scrape 127.0.0.1:199 over HTTP on the same host. Do not publish port 199 directly to the public Internet; use a firewall and a VPN or authenticated TLS reverse proxy for remote access.

## Data and privacy semantics

The exporter reads the existing SQLite minute-rollup store. It does not start a scan, ping a gateway, run a speed test, or make any outbound request during a scrape. It exports only the configured local site identified by WIFI_ANALYZER_LOCAL_SITE_ID (default: local).

The endpoint deliberately emits no SSID, BSSID, client, MAC, IP-address or site labels. The exported measurements are:

- Scan, diagnostic and completed speed-test sample counts for the rolling 24-hour history window.
- Access-point counts per scan, separated into 2.4, 5 and 6 GHz bands, plus explicitly open networks per scan, averaged over the latest stored minute.
- Mean measured RSSI, local default-gateway latency, jitter and packet loss when such values exist in the latest minute.
- Completed speed-test download, upload and ping averages when measurements exist in the latest minute.
- The last stored telemetry-minute timestamp, update timestamp and a freshness indicator. Freshness means the most recent minute bucket is no more than five minutes old.

A missing measurement is omitted, not exported as zero. An empty history is reported as telemetry unavailable; it is not treated as a healthy scan. The sample totals are rolling-window gauges, not monotonically increasing Prometheus counters. The current metrics describe the single configured site local-host telemetry; remote router agents do not automatically populate these host rollups.

## Grafana dashboard

In Grafana, add the Prometheus data source and import deploy/grafana/wifi-analyzer-pro.json. Select the Prometheus data source during import. The dashboard panels cover access-point density, signal, gateway latency/jitter/loss, speed-test results, sample volume and telemetry freshness.

The dashboard is an operational summary, not a spectrum analyser or a prediction. Values appear only after the corresponding real measurements have been collected by the local application.
