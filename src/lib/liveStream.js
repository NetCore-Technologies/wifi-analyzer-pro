const SITE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const DEFAULT_RETRY_MIN_MS = 1000;
const DEFAULT_RETRY_MAX_MS = 30000;

async function requestLiveTicket(siteIds, signal) {
  const { apiBase, apiFetch } = await import("./api.js");
  const baseUrl = apiBase();
  const response = await apiFetch(baseUrl + "/api/live/ticket", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(siteIds ? { site_ids: siteIds } : {}),
    signal,
  });
  if (!response.ok) {
    let message = "Live-stream ticket request failed (HTTP " + response.status + ")";
    try {
      const payload = await response.json();
      if (typeof payload.error === "string") message = payload.error;
    } catch {
      // Keep the bounded status message when the error body is not JSON.
    }
    const error = new Error(message);
    error.status = response.status;
    throw error;
  }
  const ticket = await response.json();
  if (
    !ticket ||
    typeof ticket.websocket_url !== "string" ||
    ticket.websocket_url !== "/ws/live" ||
    typeof ticket.websocket_protocol !== "string" ||
    !/^wfa-ticket\.[A-Za-z0-9_-]{32,80}$/.test(ticket.websocket_protocol)
  ) {
    throw new Error("WiFi Analyzer Pro returned an invalid live-stream ticket");
  }
  return { ...ticket, apiBase: baseUrl };
}

function validateEvent(value) {
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    typeof value.type !== "string" ||
    !/^[a-z][a-z0-9_.-]{0,63}$/.test(value.type) ||
    typeof value.site_id !== "string" ||
    !SITE_ID.test(value.site_id) ||
    typeof value.occurred_at !== "string" ||
    !value.data ||
    typeof value.data !== "object" ||
    Array.isArray(value.data)
  ) {
    throw new Error("WiFi Analyzer Pro sent an invalid live event");
  }
  return value;
}

/**
 * Open a resilient read-only live stream.
 *
 * The initial ticket is obtained through the authenticated REST client and
 * passed as a WebSocket subprotocol, never in the URL. Reconnects obtain a
 * fresh one-use ticket. A 401/403 or policy close stops automatic retries.
 */
export function createLiveStream({
  siteIds,
  onEvent = () => {},
  onStatus = () => {},
  onError = () => {},
  requestTicket = requestLiveTicket,
  WebSocketImpl = typeof WebSocket === "function" ? WebSocket : null,
  retryMinMs = DEFAULT_RETRY_MIN_MS,
  retryMaxMs = DEFAULT_RETRY_MAX_MS,
} = {}) {
  if (siteIds !== undefined) {
    if (
      !Array.isArray(siteIds) ||
      siteIds.length < 1 ||
      siteIds.length > 100 ||
      siteIds.some((siteId) => typeof siteId !== "string" || !SITE_ID.test(siteId)) ||
      new Set(siteIds).size !== siteIds.length
    ) {
      throw new Error("siteIds must contain 1 to 100 unique valid site identifiers");
    }
  }
  if (typeof onEvent !== "function" || typeof onStatus !== "function" || typeof onError !== "function") {
    throw new Error("live-stream callbacks must be functions");
  }
  if (typeof requestTicket !== "function") {
    throw new Error("requestTicket must be a function");
  }
  if (typeof WebSocketImpl !== "function") {
    throw new Error("WebSocket is not available in this runtime");
  }
  if (!Number.isInteger(retryMinMs) || retryMinMs < 100 || retryMinMs > 60000) {
    throw new Error("retryMinMs must be from 100 to 60000 milliseconds");
  }
  if (!Number.isInteger(retryMaxMs) || retryMaxMs < retryMinMs || retryMaxMs > 300000) {
    throw new Error("retryMaxMs must be from retryMinMs to 300000 milliseconds");
  }

  let active = true;
  let socket = null;
  let ticketAbort = null;
  let retryTimer = null;
  let retryAttempt = 0;
  let currentStatus = "connecting";

  const setStatus = (status, detail = null) => {
    currentStatus = status;
    try {
      onStatus({ status, detail });
    } catch {
      // A UI observer must not interrupt the transport lifecycle.
    }
  };

  const reportError = (error) => {
    try {
      onError(error instanceof Error ? error : new Error("Live stream failed"));
    } catch {
      // A UI observer must not interrupt reconnection.
    }
  };

  const scheduleReconnect = () => {
    if (!active || retryTimer !== null) return;
    const delay = Math.min(retryMaxMs, retryMinMs * (2 ** Math.min(retryAttempt, 10)));
    retryAttempt += 1;
    setStatus("reconnecting", { retry_in_ms: delay, attempt: retryAttempt });
    retryTimer = setTimeout(() => {
      retryTimer = null;
      connect();
    }, delay);
  };

  const connect = async () => {
    if (!active) return;
    ticketAbort = new AbortController();
    setStatus("connecting");
    try {
      const ticket = await requestTicket(siteIds, ticketAbort.signal);
      if (!active) return;
      if (
        !ticket ||
        typeof ticket.websocket_url !== "string" ||
        typeof ticket.websocket_protocol !== "string" ||
        typeof ticket.apiBase !== "string"
      ) {
        throw new Error("The live-stream ticket response is invalid");
      }
      const target = new URL(ticket.websocket_url, ticket.apiBase);
      if (!["http:", "https:"].includes(target.protocol) || target.pathname !== "/ws/live" || target.search || target.hash) {
        throw new Error("The live-stream endpoint is invalid");
      }
      target.protocol = target.protocol === "https:" ? "wss:" : "ws:";
      const candidate = new WebSocketImpl(target.toString(), ticket.websocket_protocol);
      socket = candidate;

      candidate.onopen = () => {
        if (!active || socket !== candidate) {
          try { candidate.close(1000, "stream no longer active"); } catch {}
          return;
        }
        retryAttempt = 0;
        setStatus("connected");
      };
      candidate.onmessage = (message) => {
        if (!active || socket !== candidate) return;
        try {
          const event = validateEvent(JSON.parse(message.data));
          onEvent(event);
        } catch (error) {
          reportError(error);
        }
      };
      candidate.onerror = () => {
        if (active && socket === candidate) {
          reportError(new Error("The live WebSocket connection encountered an error"));
        }
      };
      candidate.onclose = (event) => {
        if (socket === candidate) socket = null;
        if (!active) return;
        if (event && (event.code === 1000 || event.code === 1008)) {
          setStatus(event.code === 1008 ? "unauthorized" : "stopped");
          active = false;
          return;
        }
        scheduleReconnect();
      };
    } catch (error) {
      if (!active || error?.name === "AbortError") return;
      reportError(error);
      if (error?.status === 401 || error?.status === 403) {
        active = false;
        setStatus("unauthorized", { status: error.status });
        return;
      }
      scheduleReconnect();
    } finally {
      ticketAbort = null;
    }
  };

  connect();

  return {
    close() {
      if (!active) return;
      active = false;
      if (retryTimer !== null) {
        clearTimeout(retryTimer);
        retryTimer = null;
      }
      if (ticketAbort) {
        ticketAbort.abort();
        ticketAbort = null;
      }
      const current = socket;
      socket = null;
      if (current && current.readyState < 2) {
        try { current.close(1000, "client closed"); } catch {}
      }
      setStatus("stopped");
    },
    get status() {
      return currentStatus;
    },
  };
}

export { validateEvent };
