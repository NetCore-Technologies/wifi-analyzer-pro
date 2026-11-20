"""Smoke-test authenticated dynamic feature loading in a running frozen server."""
from __future__ import annotations

import json
from urllib.request import Request, urlopen


BASE_URL = "http://127.0.0.1:199"
PASSWORD = "packaged-smoke-test-password-2026"
REQUIRED_FEATURES = {
    "router_webhook_subscription_router",
    "router_scheduled_report_delivery_package",
    "pcap_capture_analyzer",
}
MINIMUM_FEATURE_COUNT = 188
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
    print(f"Frozen feature smoke test passed ({catalog['count']} registered features)")


if __name__ == "__main__":
    main()
