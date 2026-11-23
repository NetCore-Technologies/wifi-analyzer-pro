# Authenticated live WebSocket stream

WiFi Analyzer Pro exposes a read-only, authenticated live event stream for
local host observations and site-assigned router agents. It uses the same local
account sessions and site permissions as the REST API.

This implementation is an in-memory event hub for a single API process. It is
not a distributed message bus and does not yet coordinate events between
multiple API replicas or installations.

## Obtain a one-use ticket

The client must first obtain a short-lived ticket over the authenticated API:

```http
POST /api/live/ticket
Authorization: Bearer <session-token>
Content-Type: application/json

{"site_ids":["office","branch"]}
```

The `site_ids` property is optional. When omitted, the API selects the
authenticated user's assigned sites; all-site administrators receive the
locally managed site set plus the local host site. A request is rejected if it
contains an unassigned site, duplicate IDs, invalid IDs or more than 100 sites.
The permission `sites.read` is required.

The response contains `websocket_url`, `websocket_protocol`,
`expires_in_seconds` and the accepted `site_ids`. Tickets expire after 30
seconds and are consumed exactly once. The random ticket is not the API bearer
session token.

## Connect

Pass the returned protocol as the WebSocket subprotocol. Do not put the ticket
in the URL, a query string, application logs or browser storage.

```js
import { apiBase, apiFetch } from "./lib/api.js";

const response = await apiFetch(apiBase() + "/api/live/ticket", {
  method: "POST",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ site_ids: ["office"] }),
});
if (!response.ok) throw new Error("Live ticket request failed");

const ticket = await response.json();
const base = new URL(apiBase());
const target = new URL(ticket.websocket_url, base);
target.protocol = target.protocol === "https:" ? "wss:" : "ws:";
const socket = new WebSocket(target.toString(), ticket.websocket_protocol);
```

The supported browser client is `src/lib/liveStream.js`. It uses the existing
authenticated `apiFetch` session, validates the API origin, obtains a new
one-use ticket on reconnect, applies bounded exponential retry and stops on
authentication/policy closure. The dashboard connects when a live adapter is
detected and displays its stream status separately from the scan status.

Remote API deployments must use HTTPS so the corresponding WebSocket uses
WSS. Local loopback HTTP/WSS development is supported only when the API host is
the same origin as the page. The WebSocket route rejects URL query strings and
fragments.

## Event types

Events use the common envelope:

```json
{
  "type": "scan.updated",
  "site_id": "office",
  "occurred_at": "2026-11-23T12:00:00+00:00",
  "data": {}
}
```

Current event types:

| Event | Source | Data |
|---|---|---|
| `scan.updated` | Local host scan | Timestamp, network count, interface, observation source and telemetry persistence status |
| `diagnostics.updated` | Local host diagnostics | Probe/resolution status, measured gateway latency, jitter, packet loss and optional DNS timing |
| `alerts.updated` | Local site alert evaluation | Counts of opened, updated and resolved incidents |
| `agent.snapshot.updated` | Authenticated router-agent snapshot | Agent ID, adapter ID, capture time, interface/radio/association/route counts |

The live event summaries do not include SSIDs, BSSIDs, client/MAC identifiers,
IP addresses, router credentials or raw scan payloads. The REST scan endpoint
remains the source for full network inventory when a user has permission to
read it; this event channel is not a replacement for that endpoint.

## Authentication and lifecycle

- Ticket issuance requires a valid authenticated session, `sites.read`,
  explicit access to every requested site and a successful security-audit
  write. Ticket issuance is rate limited.
- A ticket has a 30-second lifetime, is single-use and binds to the user ID,
  session and site set. Only one `wfa-ticket.*` subprotocol value is accepted.
  The server echoes that subprotocol during the WebSocket handshake.
- The API session, `sites.read` permission and full site assignment set are
  revalidated while the socket is open and before each event is sent. Logout,
  session expiry, disabled/revoked access or lost site assignment closes the
  connection with policy close code 1008.
- The hub permits at most 100 connections in one API process and at most five
  per user. Each connection subscribes to at most 100 sites.
- Event payloads are finite JSON objects no larger than 16 KiB. Each client
  queue holds at most 64 events. A full queue closes that slow consumer with
  close code 1013 instead of growing memory without bound.
- The server sends protocol ping frames periodically and closes a connection
  when a pong is not returned within the bounded timeout. Clients may send only
  close, ping and pong control frames; the stream does not accept commands,
  scans, configuration writes or arbitrary client messages.

## Deployment boundary

The event hub, ticket table and connection registry live in memory in the API
process. Run one API instance for a deployment unless a future release adds a
coordinated shared event broker. A reverse proxy must support HTTP/1.1 WebSocket
upgrade and preserve the authenticated origin. In multi-worker deployments,
sticky routing alone does not replicate events between processes.

The WebSocket server uses the same port and host firewall policy as the REST
API (port 199 by default). Keep the service behind a VPN or authenticated TLS
reverse proxy for remote use; do not publish port 199 directly to the public
Internet.

## Operational interpretation

This is an event stream, not a durable event log. Events are delivered only to
currently connected, authorised clients and are not replayed after reconnect.
Clients should refresh the relevant REST resource after connection, on a
reconnect and after an event when they need a complete authoritative snapshot.
The durable audit ledger, site history, telemetry rollups and incident store
remain the persistence layers.
