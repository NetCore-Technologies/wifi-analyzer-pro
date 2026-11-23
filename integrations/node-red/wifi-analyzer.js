"use strict";

const http = require("node:http");
const https = require("node:https");
const net = require("node:net");

const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 15000;
const MAX_TIMEOUT_MS = 60000;
const SITE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const FEATURE_SLUG = /^[a-z0-9_]{1,128}$/;

function parseBaseUrl(value) {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error("WiFi Analyzer Pro base URL is required");
  }
  let parsed;
  try {
    parsed = new URL(value.trim());
  } catch {
    throw new Error("WiFi Analyzer Pro base URL is invalid");
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("WiFi Analyzer Pro base URL must use HTTP or HTTPS");
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash || parsed.pathname !== "/") {
    throw new Error("Base URL must contain only an HTTP(S) origin; credentials, paths, queries and fragments are not allowed");
  }
  if (parsed.protocol === "http:") {
    const host = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase();
    const loopback = host === "localhost" || host.endsWith(".localhost") ||
      (net.isIP(host) === 4 && host.startsWith("127.")) ||
      (net.isIP(host) === 6 && (host === "::1" || host === "0:0:0:0:0:0:0:1"));
    if (!loopback) {
      throw new Error("Remote WiFi Analyzer Pro endpoints must use HTTPS; plain HTTP is allowed only for loopback");
    }
  }
  return parsed;
}

function requestJson(serverConfig, method, pathname, body, timeoutMs = DEFAULT_TIMEOUT_MS) {
  const base = parseBaseUrl(serverConfig.baseUrl);
  const token = serverConfig.bearerToken;
  if (typeof token !== "string" || !token.trim()) {
    return Promise.reject(new Error("WiFi Analyzer Pro API bearer token is not configured"));
  }
  if (!["GET", "POST"].includes(method)) {
    return Promise.reject(new Error("Only GET and POST API operations are supported"));
  }
  if (typeof pathname !== "string" || !pathname.startsWith("/api/") || pathname.startsWith("//")) {
    return Promise.reject(new Error("Requested API path is not allow-listed"));
  }
  if (pathname.includes("\\") || /[\u0000-\u001f\u007f]/.test(pathname)) {
    return Promise.reject(new Error("Requested API path contains invalid characters"));
  }
  if (typeof timeoutMs !== "number" || !Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > MAX_TIMEOUT_MS) {
    return Promise.reject(new Error("API timeout must be an integer from 1000 to 60000 milliseconds"));
  }

  let target;
  try {
    target = new URL(pathname, base);
  } catch {
    return Promise.reject(new Error("Requested API URL is invalid"));
  }
  if (target.origin !== base.origin || !target.pathname.startsWith("/api/")) {
    return Promise.reject(new Error("Requested API URL is outside the configured origin"));
  }
  const transport = target.protocol === "https:" ? https : http;
  const encodedBody = body === undefined ? null : Buffer.from(JSON.stringify(body), "utf8");

  return new Promise((resolve, reject) => {
    const headers = {
      Accept: "application/json",
      Authorization: "Bearer " + token.trim(),
    };
    if (encodedBody) {
      headers["Content-Type"] = "application/json";
      headers["Content-Length"] = encodedBody.length;
    }
    const request = transport.request({
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || undefined,
      method,
      path: target.pathname + target.search,
      headers,
      timeout: timeoutMs,
      rejectUnauthorized: true,
    }, (response) => {
      const chunks = [];
      let total = 0;
      response.on("data", (chunk) => {
        total += chunk.length;
        if (total > MAX_RESPONSE_BYTES) {
          request.destroy(new Error("WiFi Analyzer Pro response exceeded the 4 MiB limit"));
          return;
        }
        chunks.push(chunk);
      });
      response.on("end", () => {
        const raw = Buffer.concat(chunks).toString("utf8");
        let parsed = {};
        if (raw) {
          try {
            parsed = JSON.parse(raw);
          } catch {
            reject(new Error("WiFi Analyzer Pro returned invalid JSON"));
            return;
          }
        }
        if (response.statusCode < 200 || response.statusCode >= 300) {
          const error = new Error(
            typeof parsed.error === "string"
              ? "WiFi Analyzer Pro API error (" + response.statusCode + "): " + parsed.error.slice(0, 240)
              : "WiFi Analyzer Pro API returned HTTP " + response.statusCode
          );
          error.statusCode = response.statusCode;
          error.code = parsed.code || "WIFI_ANALYZER_API_ERROR";
          reject(error);
          return;
        }
        resolve(parsed);
      });
    });
    request.on("timeout", () => request.destroy(new Error("WiFi Analyzer Pro API request timed out")));
    request.on("error", (error) => reject(error));
    if (encodedBody) request.write(encodedBody);
    request.end();
  });
}

function requireSiteId(value, field = "site_id") {
  if (typeof value !== "string" || !SITE_ID.test(value)) {
    throw new Error(field + " must be a valid 1 to 128 character site identifier");
  }
  return value;
}

function createOutputNode(RED, type, label, execute) {
  function WifiAnalyzerNode(config) {
    RED.nodes.createNode(this, config);
    const node = this;
    node.server = RED.nodes.getNode(config.server);
    node.timeoutMs = Number(config.timeoutMs || DEFAULT_TIMEOUT_MS);

    node.on("input", async function (msg, send, done) {
      send = send || node.send.bind(node);
      const complete = typeof done === "function" ? done : function (error) {
        if (error) node.error(error, msg);
      };
      if (!node.server) {
        const error = new Error("A WiFi Analyzer Pro connection must be configured");
        node.status({fill:"red",shape:"ring",text:"configuration missing"});
        complete(error);
        return;
      }
      try {
        node.status({fill:"blue",shape:"dot",text:"requesting"});
        const result = await execute(node, msg);
        msg.payload = result;
        msg.wifiAnalyzerPro = {
          operation: type,
          baseUrl: node.server.baseUrl,
        };
        node.status({fill:"green",shape:"dot",text:"success"});
        send(msg);
        complete();
      } catch (error) {
        node.status({fill:"red",shape:"ring",text:"request failed"});
        node.error(error, msg);
        complete(error);
      }
    });

    node.on("close", function (removed, done) {
      node.status({});
      if (typeof done === "function") done();
    });
  }
  RED.nodes.registerType(type, WifiAnalyzerNode);
}

module.exports = function register(RED) {
  function WifiAnalyzerConfig(config) {
    RED.nodes.createNode(this, config);
    this.baseUrl = parseBaseUrl(config.baseUrl).origin;
    this.bearerToken = this.credentials && this.credentials.bearerToken;
    this.label = config.name || this.baseUrl;
  }
  RED.nodes.registerType("wifi-analyzer-config", WifiAnalyzerConfig, {
    credentials: {
      bearerToken: { type: "password" },
    },
  });

  createOutputNode(RED, "wifi-analyzer-scan", "WiFi Analyzer Pro Scan", async (node) => {
    return await requestJson(node.server, "GET", "/api/scan", undefined, node.timeoutMs);
  });

  createOutputNode(RED, "wifi-analyzer-feature", "WiFi Analyzer Pro Feature", async (node, msg) => {
    const slug = String(node.context().get("featureSlug") || node.featureSlug || "");
    const configuredSlug = node._config && node._config.slug;
    const featureSlug = configuredSlug || node.featureSlug || slug;
    if (!FEATURE_SLUG.test(featureSlug)) {
      throw new Error("A valid WiFi Analyzer Pro feature slug must be configured");
    }
    const payload = msg.payload === undefined ? {} : msg.payload;
    if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
      throw new Error("Feature input msg.payload must be a JSON object");
    }
    return await requestJson(
      node.server,
      "POST",
      "/api/features/" + encodeURIComponent(featureSlug),
      payload,
      node.timeoutMs
    );
  });

  createOutputNode(RED, "wifi-analyzer-telemetry", "WiFi Analyzer Pro Telemetry", async (node, msg) => {
    const siteId = node.siteId || (msg.site_id ? requireSiteId(msg.site_id) : "");
    const params = new URLSearchParams();
    if (siteId) params.set("site_id", requireSiteId(siteId));
    const days = Number(node.days || 7);
    const limit = Number(node.limit || 5000);
    if (!Number.isInteger(days) || days < 1 || days > 365) {
      throw new Error("Telemetry days must be an integer from 1 to 365");
    }
    if (!Number.isInteger(limit) || limit < 1 || limit > 5000) {
      throw new Error("Telemetry limit must be an integer from 1 to 5000");
    }
    params.set("days", String(days));
    params.set("limit", String(limit));
    return await requestJson(
      node.server, "GET", "/api/telemetry/history?" + params.toString(), undefined, node.timeoutMs
    );
  });

  createOutputNode(RED, "wifi-analyzer-alerts", "WiFi Analyzer Pro Alerts", async (node, msg) => {
    const siteId = requireSiteId(node.siteId || msg.site_id);
    const params = new URLSearchParams({ site_id: siteId });
    return await requestJson(
      node.server, "GET", "/api/sites/alert-rules?" + params.toString(), undefined, node.timeoutMs
    );
  });

  createOutputNode(RED, "wifi-analyzer-catalog", "WiFi Analyzer Pro Feature Catalog", async (node) => {
    return await requestJson(node.server, "GET", "/api/features", undefined, node.timeoutMs);
  });
};

module.exports._test = {
  parseBaseUrl,
  requestJson,
  requireSiteId,
  MAX_RESPONSE_BYTES,
};
