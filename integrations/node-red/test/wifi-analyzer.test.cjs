"use strict";

const assert = require("node:assert/strict");
const http = require("node:http");
const test = require("node:test");
const registerNodes = require("../wifi-analyzer.js");
const { parseBaseUrl, requestJson, requireSiteId, MAX_RESPONSE_BYTES } = registerNodes._test;

async function withServer(handler, run) {
  const server = http.createServer(handler);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const baseUrl = "http://127.0.0.1:" + server.address().port;
  try {
    await run(baseUrl, server);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test("base URL rejects remote plaintext, URL credentials and non-origin paths", () => {
  assert.equal(parseBaseUrl("http://127.0.0.1:199").origin, "http://127.0.0.1:199");
  assert.equal(parseBaseUrl("https://analyzer.example.internal").protocol, "https:");
  assert.throws(() => parseBaseUrl("http://analyzer.example.internal"), /HTTPS/);
  assert.throws(() => parseBaseUrl("https://user:pass@analyzer.example.internal"), /credentials/);
  assert.throws(() => parseBaseUrl("https://analyzer.example.internal/api"), /origin/);
  assert.throws(() => parseBaseUrl("ftp://analyzer.example.internal"), /HTTP or HTTPS/);
});

test("site identifiers are checked against the platform site identifier contract", () => {
  assert.equal(requireSiteId("main-office"), "main-office");
  assert.equal(requireSiteId("s".repeat(128)), "s".repeat(128));
  assert.throws(() => requireSiteId("bad/site"), /valid/);
  assert.throws(() => requireSiteId(""), /valid/);
});

test("requestJson sends only bearer credentials and serializes a bounded JSON request", async () => {
  await withServer((request, response) => {
    assert.equal(request.method, "POST");
    assert.equal(request.url, "/api/features/channel_congestion");
    assert.equal(request.headers.authorization, "Bearer test-api-token");
    assert.match(request.headers["content-type"], /application\/json/);
    let body = "";
    request.setEncoding("utf8");
    request.on("data", (chunk) => body += chunk);
    request.on("end", () => {
      assert.deepEqual(JSON.parse(body), {networks:[{rssi:-50}]});
      response.writeHead(200, {"Content-Type":"application/json"});
      response.end(JSON.stringify({feature:"F028",result:{channel_count:3}}));
    });
  }, async (baseUrl) => {
    const result = await requestJson(
      {baseUrl,bearerToken:"test-api-token"},
      "POST",
      "/api/features/channel_congestion",
      {networks:[{rssi:-50}]},
      5000
    );
    assert.equal(result.feature, "F028");
    assert.equal(result.result.channel_count, 3);
  });
});

test("requestJson refuses arbitrary methods, paths and cross-origin routes", async () => {
  const config = {baseUrl:"https://analyzer.example.internal",bearerToken:"token"};
  await assert.rejects(requestJson(config,"DELETE","/api/scan"), /Only GET and POST/);
  await assert.rejects(requestJson(config,"GET","/health"), /allow-listed/);
  await assert.rejects(requestJson(config,"GET","/api/../private"), /outside the configured origin/);
  await assert.rejects(requestJson(config,"GET","https://evil.example/api/scan"), /allow-listed/);
});

test("requestJson reports non-success status without exposing authorization values", async () => {
  await withServer((_request, response) => {
    response.writeHead(403, {"Content-Type":"application/json"});
    response.end(JSON.stringify({error:"site access denied"}));
  }, async (baseUrl) => {
    await assert.rejects(
      requestJson({baseUrl,bearerToken:"super-secret-token"},"GET","/api/scan"),
      (error) => {
        assert.match(error.message,/\\(403\\)/);
        assert.equal(error.statusCode, 403);
        assert.match(error.message,/site access denied/);
        assert.doesNotMatch(error.message,/super-secret-token/);
        return true;
      }
    );
  });
});

test("requestJson enforces the response size bound", async () => {
  await withServer((_request, response) => {
    response.writeHead(200, {"Content-Type":"application/json"});
    response.end("x".repeat(MAX_RESPONSE_BYTES + 1));
  }, async (baseUrl) => {
    await assert.rejects(
      requestJson({baseUrl,bearerToken:"token"},"GET","/api/scan",undefined,5000),
      /4 MiB limit/
    );
  });
});

test("Node-RED registers the connection and five dedicated API nodes", () => {
  const registrations = {};
  const RED = {
    nodes: {
      registerType(name, constructor, options) {
        registrations[name] = {constructor,options};
      },
      createNode(node, config) {
        node.config = config;
        node.listeners = {};
        node.on = (name, callback) => { node.listeners[name] = callback; };
        node.status = () => {};
        node.error = () => {};
        node.send = () => {};
      },
      getNode() {
        return {baseUrl:"https://analyzer.example.internal",bearerToken:"secret-token"};
      }
    }
  };
  registerNodes(RED);
  assert.deepEqual(Object.keys(registrations).sort(), [
    "wifi-analyzer-alerts",
    "wifi-analyzer-catalog",
    "wifi-analyzer-config",
    "wifi-analyzer-feature",
    "wifi-analyzer-scan",
    "wifi-analyzer-telemetry"
  ]);
  assert.equal(registrations["wifi-analyzer-config"].options.credentials.bearerToken.type,"password");
});

test("feature node uses its configured slug and forwards JSON parameters", async () => {
  await withServer((request, response) => {
    assert.equal(request.method,"POST");
    assert.equal(request.url,"/api/features/channel_congestion");
    assert.equal(request.headers.authorization,"Bearer secret-token");
    request.resume();
    request.on("end", () => {
      response.writeHead(200,{"Content-Type":"application/json"});
      response.end(JSON.stringify({feature:"F028",result:{status:"ok"}}));
    });
  }, async (baseUrl) => {
    const registrations = {};
    const RED = {
      nodes: {
        registerType(name, constructor, options) {
          registrations[name] = {constructor,options};
        },
        createNode(node, config) {
          node.listeners = {};
          node.on = (name, callback) => { node.listeners[name] = callback; };
          node.status = () => {};
          node.error = (error) => { throw error; };
          node.send = () => {};
        },
        getNode() {
          return {baseUrl,bearerToken:"secret-token"};
        }
      }
    };
    registerNodes(RED);
    const instance = {};
    registrations["wifi-analyzer-feature"].constructor.call(instance,{
      server:"connection",
      slug:"channel_congestion",
      timeoutMs:5000
    });
    const sent = [];
    const message = {payload:{networks:[{rssi:-50}]}};
    await new Promise((resolve,reject) => {
      instance.listeners.input(
        message,
        (output) => sent.push(output),
        (error) => error ? reject(error) : resolve()
      );
    });
    assert.equal(sent.length,1);
    assert.deepEqual(sent[0].payload,{feature:"F028",result:{status:"ok"}});
    assert.equal(sent[0].wifiAnalyzerPro.operation,"wifi-analyzer-feature");
    assert.ok(!JSON.stringify(sent[0]).includes("secret-token"));
  });
});
