# OpenWrt read-only agent

The agent collects router telemetry locally and sends normalised, credential-free snapshots to WiFi Analyzer Pro. It uses the per-agent token issued by the Agent enrolment API and the idempotent snapshot-delivery endpoint.

It is deliberately read-only. The collector invokes only fixed ubus, ip and iw read commands. It does not run a shell, invoke uci, alter firewall/network configuration, trigger a disruptive wireless scan, or copy wireless PSKs/passwords into its payload. System health collection (`ubus call system info`) is optional and runs only when `system.health` is included in the agent credential scope.

## Requirements

- OpenWrt/NoobWRT with ubus, ip and Python 3.10 or later.
- Python's standard library only; no pip packages are required.
- iw is used for associated-client station details. Missing optional telemetry is reported as a degraded heartbeat rather than being fabricated.
- HTTPS connectivity from the router to the WiFi Analyzer Pro API, with a working CA bundle.

## 1. Enrol the router

Use an administrator session to call POST /api/agents/enroll on the WiFi Analyzer Pro server. Include the capabilities the router should receive; inventory.snapshot is required for snapshot delivery.

Example JSON body:

    {
      "agent_id": "openwrt-home",
      "adapter_id": "openwrt",
      "agent_version": "1.0.0",
      "advertised_capabilities": [
        "system.board",
        "system.health",
        "network.interfaces",
        "network.routes",
        "wireless.radios",
        "wireless.associations",
        "inventory.snapshot"
      ],
      "requested_capabilities": [
        "system.board",
        "system.health",
        "network.interfaces",
        "network.routes",
        "wireless.radios",
        "wireless.associations",
        "inventory.snapshot"
      ],
      "requested_permissions": ["read"]
    }

The response contains a one-time credential.token. Copy it directly into the router's protected configuration. It is not shown again by the server; rotate the credential from the admin API if it is lost. Existing agents must be re-enrolled or have their credential rotated with `system.health` added before that optional query is enabled; older credentials continue to collect the base inventory only.

## 2. Install the agent

Copy openwrt_agent.py to /usr/lib/wifi-analyzer/openwrt_agent.py and the procd service file files/wifi-analyzer-agent.init to /etc/init.d/wifi-analyzer-agent.

From a workstation with the repository checkout:

    ssh root@ROUTER 'mkdir -p /usr/lib/wifi-analyzer /etc/wifi-analyzer /var/lib/wifi-analyzer-agent'
    scp agent/openwrt_agent.py root@ROUTER:/usr/lib/wifi-analyzer/openwrt_agent.py
    scp agent/files/wifi-analyzer-agent.init root@ROUTER:/etc/init.d/wifi-analyzer-agent
    ssh root@ROUTER 'chmod 755 /usr/lib/wifi-analyzer/openwrt_agent.py /etc/init.d/wifi-analyzer-agent'

Create /etc/wifi-analyzer/openwrt-agent.json using the example in openwrt-agent.example.json. Replace the example URL and token with the actual API URL and one-time enrolled token:

    umask 077
    cat > /etc/wifi-analyzer/openwrt-agent.json <<'JSON'
    {
      "agent_id": "openwrt-home",
      "server_url": "https://wifi-analyzer.example:199",
      "token": "wpa_REPLACE_WITH_THE_ONE_TIME_ENROLMENT_TOKEN",
      "state_dir": "/var/lib/wifi-analyzer-agent",
      "interval_seconds": 300,
      "request_timeout_seconds": 10,
      "allow_insecure_http": false
    }
    JSON
    chmod 600 /etc/wifi-analyzer/openwrt-agent.json

The placeholder token is intentionally invalid; replace it before starting the service. Keep the file private and do not paste its contents into support logs or screenshots.

## 3. Validate and start

    python3 /usr/lib/wifi-analyzer/openwrt_agent.py check-config --config /etc/wifi-analyzer/openwrt-agent.json
    python3 /usr/lib/wifi-analyzer/openwrt_agent.py run-once --config /etc/wifi-analyzer/openwrt-agent.json
    /etc/init.d/wifi-analyzer-agent enable
    /etc/init.d/wifi-analyzer-agent start

The service runs under procd. It sends a heartbeat each collection cycle, verifies that the credential includes inventory.snapshot, and then posts a UUID-keyed delivery to /api/agents/snapshots/batch. When the credential also includes `system.health`, it reads the read-only `system info` ubus method and sends uptime, 1/5/15-minute load averages, and raw memory/swap byte counters. Load averages are converted from procd's 16.16 fixed-point representation; no memory-use percentage is inferred.

## Retry and local storage

Only one pending delivery is retained at a time. Before a new capture, the agent retries that exact UUID and payload. A successful acknowledgement clears the spool; an unavailable API leaves it in place for the next cycle. The state directory is mode 0700, and the pending delivery file is mode 0600. The outbox has a strict byte limit.

The server's idempotency ledger returns the original acknowledgement for identical retries and rejects re-use of the same UUID with different data. This also protects against the router restarting after a request reached the server but before its response arrived.

## Transport security

HTTPS with certificate verification is the default. Redirect responses are refused so the agent bearer token cannot be forwarded to another URL; configure the final API URL directly. Plain HTTP is refused unless allow_insecure_http is explicitly set to true; use that option only on a trusted isolated LAN for testing. Prefer HTTPS even for local deployments.

The agent's logs include cycle status and safe error categories only. They never print the bearer token, configuration contents, wireless keys, or raw command output. Revoke or rotate the agent credential from the administrator API if the router is decommissioned or the token may have been exposed.
