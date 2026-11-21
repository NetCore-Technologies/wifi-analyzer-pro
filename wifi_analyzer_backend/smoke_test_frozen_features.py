"""Smoke-test authenticated dynamic feature loading in a running frozen server."""
from __future__ import annotations

import json
import os
from urllib.request import Request, urlopen


BASE_URL = os.environ.get("WIFI_ANALYZER_SMOKE_URL", "http://127.0.0.1:199").rstrip("/")
PASSWORD = "packaged-smoke-test-password-2026"
REQUIRED_FEATURES = {
    "router_webhook_subscription_router",
    "router_scheduled_report_delivery_package",
    "pcap_capture_analyzer",
    "router_webhook_delivery_orchestrator",
    "multi_ap_channel_reuse_planner",
    "rf_survey_evidence_normalizer",
}
MINIMUM_FEATURE_COUNT = 199
PCAP_FIXTURE = "1MOyoQIABAAAAAAAAAAAAP//AAABAAAA"


def request(path: str, payload: dict | None = None, token: str | None = None) -> dict:
    headers = {"Content-Type": "application/json"} if payload is not None else {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = json.dumps(payload).encode("utf-8") if payload is not None else None
    request_object = Request(BASE_URL + path, data=body, headers=headers)
    with urlopen(request_object, timeout=10) as response:
        return json.load(response)


def main() -> None:
    setup = request("/api/auth/setup", {"password": PASSWORD})
    token = setup["token"]
    catalog = request("/api/features", token=token)
    slugs = {feature["slug"] for feature in catalog["features"]}
    missing = REQUIRED_FEATURES - slugs
    if catalog["count"] < MINIMUM_FEATURE_COUNT or missing:
        raise SystemExit(
            f"Frozen feature registry incomplete: count={catalog['count']}, "
            f"missing={sorted(missing)}"
        )

    result = request(
        "/api/features/pcap_capture_analyzer",
        {"capture_base64": PCAP_FIXTURE},
        token=token,
    )
    if result.get("feature") != "F191" or result.get("result", {}).get("status") != "analysed":
        raise SystemExit("Frozen PCAP analyzer did not execute successfully")

    now = "2026-11-20T10:00:00Z"
    webhook = request(
        "/api/features/router_webhook_delivery_orchestrator",
        {
            "now": now,
            "subscriptions": [{
                "subscription_id": "smoke-home",
                "endpoint": "https://hooks.example.net/router/events",
                "allowed_hosts": ["hooks.example.net"],
                "key_id": "smoke-key",
                "event_types": ["router.health"],
                "minimum_severity": "warning",
                "site_allowlist": ["home"],
            }],
            "events": [{
                "event_id": "a" * 64,
                "event_type": "router.health",
                "severity": "warning",
                "occurred_at": "2026-11-20T09:59:00Z",
                "site_id": "home",
                "router_id": "smoke-router",
                "summary": "Frozen webhook smoke event",
            }],
            "signing_keys": {"smoke-key": "smoke-signing-key-material-with-at-least-32-bytes"},
            "egress_evidence": [{
                "subscription_id": "smoke-home",
                "endpoint": "https://hooks.example.net/router/events",
                "allowed_hosts": ["hooks.example.net"],
                "resolution_at": "2026-11-20T09:59:55Z",
                "connected_at": now,
                "resolved_addresses": ["1.1.1.1"],
                "peer_ip": "1.1.1.1",
                "connected_port": 443,
                "tls_version": "TLSv1.3",
                "tls_verified": True,
                "hostname_verified": True,
                "redirect_location": None,
            }],
        },
        token=token,
    )
    if webhook.get("feature") != "F192" or webhook.get("result", {}).get("status") != "prepared":
        raise SystemExit("Frozen multi-subscription webhook orchestrator did not execute successfully")

    rf_plan = request(
        "/api/features/multi_ap_channel_reuse_planner",
        {
            "radios": [
                {"radio_id":"smoke-ap1-24","ap_id":"smoke-ap1","site_id":"smoke","band":"2.4GHz","channel_width_mhz":20,"current_channel":6,"channel_options":[1,6,11]},
                {"radio_id":"smoke-ap2-24","ap_id":"smoke-ap2","site_id":"smoke","band":"2.4GHz","channel_width_mhz":20,"current_channel":6,"channel_options":[1,6,11]},
            ],
            "interference_edges": [
                {"radio_ids":["smoke-ap1-24","smoke-ap2-24"],"weight":0.9,"evidence_source":"survey"}
            ],
        },
        token=token,
    )
    if rf_plan.get("feature") != "F201" or rf_plan.get("result", {}).get("status") != "planned":
        raise SystemExit("Frozen multi-AP RF channel planner did not execute successfully")
    rf_evidence = request(
        "/api/features/rf_survey_evidence_normalizer",
        {
            "radios": [
                {"radio_id": "smoke-ap1-24", "site_id": "smoke", "band": "2.4GHz"},
                {"radio_id": "smoke-ap2-24", "site_id": "smoke", "band": "2.4GHz"},
            ],
            "observations": [
                {"sample_id": "frozen-survey-001", "radio_ids": ["smoke-ap1-24", "smoke-ap2-24"],
                 "observed_at": now, "evidence_source": "survey", "radio_rssi_dbm": [-54, -63],
                 "channel_utilization_pct": 65},
            ],
        },
        token=token,
    )
    if rf_evidence.get("feature") != "F202" or rf_evidence.get("result", {}).get("status") != "normalised":
        raise SystemExit("Frozen RF survey evidence normalizer did not execute successfully")
    print(f"Frozen feature smoke test passed ({catalog['count']} registered features)")


if __name__ == "__main__":
    main()
