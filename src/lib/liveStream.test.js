import test from "node:test";
import assert from "node:assert/strict";
import { createLiveStream, validateEvent } from "./liveStream.js";

class FakeWebSocket {
  static instances = [];

  constructor(url, protocol) {
    this.url = url;
    this.protocol = protocol;
    this.readyState = 0;
    this.closeCalls = [];
    FakeWebSocket.instances.push(this);
    queueMicrotask(() => {
      if (this.readyState === 0) {
        this.readyState = 1;
        this.onopen?.({});
      }
    });
  }

  close(code = 1000, reason = "") {
    this.closeCalls.push({code, reason});
    if (this.readyState >= 2) return;
    this.readyState = 3;
    queueMicrotask(() => this.onclose?.({code, reason}));
  }

  emit(value) {
    this.onmessage?.({data: JSON.stringify(value)});
  }

  disconnect(code = 1006) {
    this.readyState = 3;
    this.onclose?.({code});
  }
}

const ticket = (index = 1) => ({
  websocket_url: "/ws/live",
  websocket_protocol: "wfa-ticket." + ("a".repeat(40 - String(index).length) + index),
  apiBase: "https://wifi-analyzer.example.internal",
});

const tick = () => new Promise((resolve) => setImmediate(resolve));

test("validates bounded site identifiers before requesting a ticket", () => {
  assert.throws(() => createLiveStream({
    siteIds: [],
    requestTicket: async () => ticket(),
    WebSocketImpl: FakeWebSocket,
  }), /siteIds/);
  assert.throws(() => createLiveStream({
    siteIds: ["office", "office"],
    requestTicket: async () => ticket(),
    WebSocketImpl: FakeWebSocket,
  }), /unique/);
  assert.throws(() => validateEvent({
    type: "scan.updated",
    site_id: "bad/site",
    occurred_at: new Date().toISOString(),
    data: {},
  }), /invalid live event/);
});

test("opens secure WebSocket using the one-use protocol and dispatches validated events", async () => {
  FakeWebSocket.instances = [];
  const seen = [];
  const statuses = [];
  const stream = createLiveStream({
    siteIds: ["office"],
    requestTicket: async (siteIds) => {
      assert.deepEqual(siteIds, ["office"]);
      return ticket();
    },
    WebSocketImpl: FakeWebSocket,
    onEvent: (event) => seen.push(event),
    onStatus: (status) => statuses.push(status.status),
  });
  await tick();
  await tick();

  const socket = FakeWebSocket.instances[0];
  assert.ok(socket);
  assert.equal(socket.url, "wss://wifi-analyzer.example.internal/ws/live");
  assert.equal(socket.protocol, ticket().websocket_protocol);
  assert.equal(stream.status, "connected");

  const event = {
    type: "scan.updated",
    site_id: "office",
    occurred_at: new Date().toISOString(),
    data: {network_count: 8},
  };
  socket.emit(event);
  assert.deepEqual(seen, [event]);
  assert.deepEqual(statuses.slice(0, 2), ["connecting", "connected"]);

  stream.close();
  assert.equal(stream.status, "stopped");
  assert.equal(socket.closeCalls[0].code, 1000);
});

test("reconnects with a fresh one-use ticket after an unexpected close", async () => {
  FakeWebSocket.instances = [];
  let requests = 0;
  const stream = createLiveStream({
    requestTicket: async () => ticket(++requests),
    WebSocketImpl: FakeWebSocket,
    retryMinMs: 100,
    retryMaxMs: 100,
  });
  await tick();
  await tick();
  assert.equal(FakeWebSocket.instances.length, 1);

  FakeWebSocket.instances[0].disconnect(1006);
  await new Promise((resolve) => setTimeout(resolve, 140));
  await tick();
  await tick();
  assert.equal(requests, 2);
  assert.equal(FakeWebSocket.instances.length, 2);
  assert.equal(stream.status, "connected");
  stream.close();
});

test("does not retry unauthorised ticket responses", async () => {
  let requests = 0;
  const statuses = [];
  const stream = createLiveStream({
    requestTicket: async () => {
      requests += 1;
      const error = new Error("Forbidden");
      error.status = 403;
      throw error;
    },
    WebSocketImpl: FakeWebSocket,
    onStatus: (status) => statuses.push(status.status),
  });
  await tick();
  await tick();
  await new Promise((resolve) => setTimeout(resolve, 130));
  assert.equal(requests, 1);
  assert.equal(stream.status, "unauthorized");
  assert.ok(statuses.includes("unauthorized"));
  stream.close();
});

test("aborts an in-flight ticket request when the stream is closed", async () => {
  let signal;
  const stream = createLiveStream({
    requestTicket: (_sites, suppliedSignal) => new Promise((_resolve, reject) => {
      signal = suppliedSignal;
      suppliedSignal.addEventListener("abort", () => {
        const error = new Error("aborted");
        error.name = "AbortError";
        reject(error);
      }, {once: true});
    }),
    WebSocketImpl: FakeWebSocket,
  });
  await tick();
  stream.close();
  assert.equal(signal.aborted, true);
  assert.equal(stream.status, "stopped");
});
