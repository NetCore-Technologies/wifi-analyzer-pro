# Node-RED integration for WiFi Analyzer Pro

This directory is an installable Node-RED contribution package named
`node-red-contrib-wifi-analyzer-pro`. It provides five output nodes and one
shared connection configuration node.

## Install

From a Node-RED user directory:

```sh
cd ~/.node-red
npm install /path/to/wifi-analyzer-pro/integrations/node-red
```

Restart Node-RED after installation. The package has no additional runtime
dependencies beyond Node.js and Node-RED.

## Configure the connection

Add a **WiFi Analyzer Pro** connection config and set:

- **Base URL:** `https://analyzer.example.internal` for a remote endpoint, or
  `http://127.0.0.1:199` when Node-RED and WiFi Analyzer Pro share a host.
- **API token:** a WiFi Analyzer Pro bearer token stored in the Node-RED
  credential store.

Plain HTTP is deliberately accepted only for loopback. Remote API endpoints
must use HTTPS with certificate validation. Do not put the token in a flow
message, function node, environment variable, URL or debug output. Configure
Node-RED's credential encryption secret and protect its user directory.

Grant only the permissions required by the nodes in a flow:

| Node | API operation | Required API permission |
|---|---|---|
| WiFi Analyzer Pro Scan | `GET /api/scan` | `diagnostics.read` |
| WiFi Analyzer Pro Feature | `POST /api/features/{slug}` | `diagnostics.run` |
| WiFi Analyzer Pro Telemetry | `GET /api/telemetry/history` | `sites.read` |
| WiFi Analyzer Pro Alerts | `GET /api/sites/alert-rules` | `sites.read` |
| WiFi Analyzer Pro Feature Catalog | `GET /api/features` | `diagnostics.read` |

Site-specific telemetry and alerts remain subject to the API token's explicit
site assignments. A Node-RED flow cannot use these nodes to elevate its
account's permissions.

## Nodes

### WiFi Analyzer Pro Scan

Performs an authenticated live scan. The output `msg.payload` is the complete
`/api/scan` response, including networks, timestamp, interface and telemetry
status. This node can return SSIDs and BSSIDs because the scan API returns
inventory; treat downstream flows and debug logs as sensitive network data.

### WiFi Analyzer Pro Feature

Executes one registered feature using the configured feature slug. The node
sends `msg.payload` as the feature's JSON input object. The API validates the
slug, validates the feature's schema, enforces diagnostics permission and
applies the normal monthly feature-run entitlement. The output is the complete
feature result envelope.

### WiFi Analyzer Pro Telemetry

Fetches privacy-preserving minute-level aggregates. Configure an optional
site ID, history window (1–365 days) and maximum result count (1–5000).
When the site ID is blank, the API returns only sites visible to the bearer
token. The output includes `rollups`, `site_ids`, retention days and the
API's privacy description; raw SSIDs, BSSIDs and client identifiers are not
stored in this telemetry history.

### WiFi Analyzer Pro Alerts

Reads the rules, current incident history, measured metric catalogue and
delivery-preparation status for one explicitly configured site. The node is
read-only; use the WiFi Analyzer Pro alert-management UI or authenticated API
operations for changes.

### WiFi Analyzer Pro Feature Catalog

Fetches the authenticated live feature catalogue, including stable slugs,
names, categories, descriptions and parameter metadata. Use this node to
discover features available in the running server version rather than
hard-coding a stale catalogue in a flow.

## Message and error behaviour

All nodes accept an input message and return the same message with
`msg.payload` replaced by the API response. A `msg.wifiAnalyzerPro` object
records the operation and configured base URL; it never includes the bearer
token.

Requests are limited to GET/POST and the five documented API operations.
Response bodies are capped at 4 MiB, request timeouts default to 15 seconds
and can be configured up to 60 seconds. Non-2xx responses, invalid JSON,
timeouts and schema/configuration errors are reported through the standard
Node-RED node error path and status indicator. The package does not retry
non-idempotent feature executions automatically.

The package uses Node.js built-in HTTP/HTTPS modules, performs TLS certificate
validation, does not accept arbitrary host/path values from message payloads
and never places bearer credentials in output messages.
