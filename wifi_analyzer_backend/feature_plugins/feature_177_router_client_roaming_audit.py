"""Build a cross-vendor client roaming timeline from normalised snapshots."""
from __future__ import annotations

import json
import math
import re
from collections import defaultdict
from datetime import datetime, timezone

MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_SNAPSHOTS = 64
MAX_CLIENTS_PER_SNAPSHOT = 8192
MAX_TOTAL_OBSERVATIONS = 32768
MAX_DETAIL_RECORDS = 500
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
MAC = re.compile(r"^[0-9A-F]{2}(?::[0-9A-F]{2}){5}$")


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone offset")
    return parsed.astimezone(timezone.utc)


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise ValueError(f"{field} must be a 1 to 64 character identifier")
    return value


def _records(snapshot: dict, field: str, maximum: int, adapter: str) -> list[dict]:
    values = snapshot.get(field, [])
    if not isinstance(values, list) or len(values) > maximum:
        raise ValueError(f"{adapter}.{field} must be a list containing no more than {maximum} records")
    if any(not isinstance(value, dict) for value in values):
        raise ValueError(f"{adapter}.{field} entries must be objects")
    return values


def _snapshot_entry(value: object, index: int) -> dict:
    field = f"snapshots[{index}]"
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    snapshot = value.get("snapshot", value)
    if not isinstance(snapshot, dict):
        raise ValueError(f"{field}.snapshot must be an object")
    adapter = snapshot.get("adapter_id", value.get("adapter_id"))
    if adapter not in {"openwrt", "unifi", "mikrotik"}:
        raise ValueError(f"{field} must contain a normalised OpenWrt, UniFi or MikroTik snapshot")
    captured_at = _timestamp(value.get("captured_at", snapshot.get("captured_at")), f"{field}.captured_at")
    raw_router = (
        value.get("router_id") or value.get("agent_id") or value.get("id")
        or snapshot.get("router_id") or snapshot.get("agent_id")
    )
    if raw_router is None and adapter == "unifi":
        controller = snapshot.get("controller", {})
        if isinstance(controller, dict):
            raw_router = controller.get("hostname")
    if raw_router is None and adapter == "mikrotik":
        router = snapshot.get("router", {})
        if isinstance(router, dict):
            raw_router = router.get("serial_number")
    router_id = _identifier(raw_router, f"{field}.router_id")
    site_id = _identifier(value.get("site_id", "unassigned"), f"{field}.site_id")
    return {
        "router_id": router_id,
        "site_id": site_id,
        "adapter_id": adapter,
        "captured_at": captured_at,
        "snapshot": snapshot,
    }


def _mac(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a valid client MAC address")
    value = value.strip().replace("-", ":").upper()
    if not MAC.fullmatch(value):
        raise ValueError(f"{field} must be a valid client MAC address")
    return value


def _signal(value: object, field: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a finite signal value")
    try:
        result = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field} must be numeric") from error
    if not math.isfinite(result) or not -150 <= result <= 0:
        raise ValueError(f"{field} is outside the supported RSSI range")
    return result


def _resource(value: object, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > 128:
        raise ValueError(f"{field} must be a non-empty string of at most 128 characters")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise ValueError(f"{field} contains invalid control characters")
    return value.strip()


def _observations(entry: dict) -> tuple[list[dict], int, int]:
    snapshot = entry["snapshot"]
    adapter = entry["adapter_id"]
    radio_by_interface = {}
    if adapter in {"openwrt", "mikrotik"}:
        radios = _records(snapshot, "wireless_radios", 8192, adapter)
        for index, radio in enumerate(radios):
            interface = radio.get("interface")
            if interface is None:
                continue
            if not isinstance(interface, str) or not interface or len(interface) > 64:
                raise ValueError(f"{adapter}.wireless_radios[{index}].interface is invalid")
            if interface in radio_by_interface:
                raise ValueError(f"{adapter}.wireless_radios contains duplicate interface names")
            radio_by_interface[interface] = radio

    associations = _records(snapshot, "associations", MAX_CLIENTS_PER_SNAPSHOT, adapter)
    observations = []
    wired_count = 0
    unmapped_count = 0
    for index, association in enumerate(associations):
        field = f"{adapter}.associations[{index}]"
        if adapter == "unifi" and association.get("is_wired") is True:
            wired_count += 1
            continue
        client_mac = _mac(association.get("client_mac"), f"{field}.client_mac")
        if adapter == "unifi":
            ap_value = association.get("ap_mac")
            if ap_value is None:
                ap_id = None
                radio = {}
            else:
                ap_id = _mac(ap_value, f"{field}.ap_mac")
                radio = {}
        else:
            interface = association.get("interface")
            if interface is None or not isinstance(interface, str) or not interface:
                ap_id = None
                radio = {}
            else:
                radio = radio_by_interface.get(interface, {})
                bssid = radio.get("bssid")
                ap_id = _mac(bssid, f"{field}.bssid") if bssid is not None else f"{entry['router_id']}/{interface}"
        if ap_id is None:
            unmapped_count += 1
            continue

        ssid = association.get("ssid", radio.get("ssid"))
        if ssid is not None and (not isinstance(ssid, str) or len(ssid) > 64):
            raise ValueError(f"{field}.ssid must be a string of at most 64 characters")
        channel = association.get("channel", radio.get("channel"))
        if channel is not None and (
            isinstance(channel, bool) or not isinstance(channel, int) or not 1 <= channel <= 233
        ):
            raise ValueError(f"{field}.channel must be an integer from 1 to 233")
        observations.append({
            "site_id": entry["site_id"],
            "client_mac": client_mac,
            "ap_id": ap_id,
            "router_id": entry["router_id"],
            "adapter_id": adapter,
            "captured_at": entry["captured_at"],
            "ssid": ssid,
            "channel": channel,
            "signal_dbm": _signal(association.get("signal_dbm"), f"{field}.signal_dbm"),
        })
    return observations, wired_count, unmapped_count


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    try:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError("roaming input must contain JSON-compatible finite values") from error
    if len(encoded.encode("utf-8")) > MAX_INPUT_BYTES:
        raise ValueError(f"roaming input exceeds the {MAX_INPUT_BYTES}-byte input limit")

    raw_snapshots = payload.get("snapshots")
    if not isinstance(raw_snapshots, list) or not 1 <= len(raw_snapshots) <= MAX_SNAPSHOTS:
        raise ValueError(f"snapshots must contain from 1 to {MAX_SNAPSHOTS} records")
    concurrent_window = payload.get("concurrent_window_seconds", 30)
    if (isinstance(concurrent_window, bool) or not isinstance(concurrent_window, int)
            or not 1 <= concurrent_window <= 300):
        raise ValueError("concurrent_window_seconds must be an integer between 1 and 300")
    roam_window = payload.get("max_roam_interval_seconds", 1800)
    if (isinstance(roam_window, bool) or not isinstance(roam_window, int)
            or not 60 <= roam_window <= 86400 or roam_window <= concurrent_window):
        raise ValueError("max_roam_interval_seconds must exceed the concurrent window and be between 60 and 86400")
    weak_signal = payload.get("weak_signal_dbm", -75)
    critical_signal = payload.get("critical_signal_dbm", -85)
    if isinstance(weak_signal, bool) or not isinstance(weak_signal, int) or not -100 <= weak_signal <= -40:
        raise ValueError("weak_signal_dbm must be an integer between -100 and -40")
    if (isinstance(critical_signal, bool) or not isinstance(critical_signal, int)
            or not -110 <= critical_signal <= -50 or critical_signal >= weak_signal):
        raise ValueError("critical_signal_dbm must be lower than weak_signal_dbm and between -110 and -50")

    entries = [_snapshot_entry(value, index) for index, value in enumerate(raw_snapshots)]
    identities = [(item["site_id"], item["router_id"], item["captured_at"]) for item in entries]
    if len(identities) != len(set(identities)):
        raise ValueError("snapshot identities must be unique for each site, router and capture time")

    observations = []
    wired_count = 0
    unmapped_count = 0
    for entry in entries:
        items, wired, unmapped = _observations(entry)
        observations.extend(items)
        wired_count += wired
        unmapped_count += unmapped
        if len(observations) > MAX_TOTAL_OBSERVATIONS:
            raise ValueError(f"roaming inventory may contain no more than {MAX_TOTAL_OBSERVATIONS} observations")

    by_client: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for item in observations:
        by_client[(item["site_id"], item["client_mac"])].append(item)

    handoffs = []
    multi_ap_windows = []
    weak_observations = []
    for (site_id, client_mac), client_observations in sorted(by_client.items()):
        ordered = sorted(client_observations, key=lambda item: (
            item["captured_at"], item["ap_id"], item["router_id"]
        ))
        # Deduplicate repeat rows from the same AP/router at an identical capture time.
        unique = []
        seen = set()
        for item in ordered:
            key = (item["captured_at"], item["ap_id"], item["router_id"])
            if key in seen:
                continue
            seen.add(key)
            unique.append(item)

        previous = None
        for item in unique:
            signal = item["signal_dbm"]
            if signal is not None and signal <= weak_signal:
                weak_observations.append({
                    "severity": "critical" if signal <= critical_signal else "warning",
                    "code": "client.signal_critical" if signal <= critical_signal else "client.signal_weak",
                    "site_id": site_id,
                    "client_mac": client_mac,
                    "ap_id": item["ap_id"],
                    "router_id": item["router_id"],
                    "captured_at": item["captured_at"].isoformat(),
                    "signal_dbm": round(signal, 2),
                    "threshold_dbm": critical_signal if signal <= critical_signal else weak_signal,
                })

            if previous is not None and item["ap_id"] != previous["ap_id"]:
                delta = (item["captured_at"] - previous["captured_at"]).total_seconds()
                if 0 <= delta <= concurrent_window:
                    multi_ap_windows.append({
                        "site_id": site_id,
                        "client_mac": client_mac,
                        "observed_at": item["captured_at"].isoformat(),
                        "window_seconds": int(delta),
                        "ap_ids": sorted({previous["ap_id"], item["ap_id"]}),
                        "router_ids": sorted({previous["router_id"], item["router_id"]}),
                        "ssid_values": sorted({
                            value for value in (previous["ssid"], item["ssid"]) if value
                        }),
                        "note": (
                            "The same client was observed on multiple access points within one collection "
                            "window; this may reflect roaming overlap or multi-link operation."
                        ),
                    })
                elif concurrent_window < delta <= roam_window:
                    handoffs.append({
                        "site_id": site_id,
                        "client_mac": client_mac,
                        "from_ap_id": previous["ap_id"],
                        "to_ap_id": item["ap_id"],
                        "from_router_id": previous["router_id"],
                        "to_router_id": item["router_id"],
                        "from_captured_at": previous["captured_at"].isoformat(),
                        "to_captured_at": item["captured_at"].isoformat(),
                        "elapsed_seconds": int(delta),
                        "from_signal_dbm": previous["signal_dbm"],
                        "to_signal_dbm": item["signal_dbm"],
                        "ssid_changed": (
                            previous["ssid"] is not None and item["ssid"] is not None
                            and previous["ssid"] != item["ssid"]
                        ),
                    })
            previous = item

    handoffs.sort(key=lambda item: (item["site_id"], item["to_captured_at"], item["client_mac"]))
    multi_ap_windows.sort(key=lambda item: (item["site_id"], item["observed_at"], item["client_mac"]))
    weak_observations.sort(key=lambda item: (
        item["site_id"], item["captured_at"], item["client_mac"], item["ap_id"]
    ))

    site_summary = []
    sites = sorted({item["site_id"] for item in observations})
    for site in sites:
        site_observations = [item for item in observations if item["site_id"] == site]
        site_handoffs = [item for item in handoffs if item["site_id"] == site]
        site_multi_ap = [item for item in multi_ap_windows if item["site_id"] == site]
        site_weak = [item for item in weak_observations if item["site_id"] == site]
        site_summary.append({
            "site_id": site,
            "client_count": len({item["client_mac"] for item in site_observations}),
            "observation_count": len(site_observations),
            "handoff_count": len(site_handoffs),
            "multi_ap_window_count": len(site_multi_ap),
            "weak_signal_observation_count": len(site_weak),
        })

    weak_counts = Counter(item["severity"] for item in weak_observations)
    return {
        "status": "audited" if observations else "no_wireless_associations",
        "summary": {
            "snapshot_count": len(entries),
            "site_count": len({item["site_id"] for item in entries}),
            "client_count": len(by_client),
            "observation_count": len(observations),
            "handoff_count": len(handoffs),
            "multi_ap_window_count": len(multi_ap_windows),
            "weak_signal_observation_count": len(weak_observations),
            "critical_signal_count": weak_counts["critical"],
            "warning_signal_count": weak_counts["warning"],
            "wired_client_rows_skipped": wired_count,
            "unmapped_client_rows_skipped": unmapped_count,
        },
        "sites": site_summary,
        "handoffs": handoffs[:MAX_DETAIL_RECORDS],
        "multi_ap_windows": multi_ap_windows[:MAX_DETAIL_RECORDS],
        "weak_signal_observations": weak_observations[:MAX_DETAIL_RECORDS],
        "details_truncated": any(
            len(items) > MAX_DETAIL_RECORDS
            for items in (handoffs, multi_ap_windows, weak_observations)
        ),
        "thresholds": {
            "concurrent_window_seconds": concurrent_window,
            "max_roam_interval_seconds": roam_window,
            "weak_signal_dbm": weak_signal,
            "critical_signal_dbm": critical_signal,
        },
        "note": (
            "A handoff is inferred from successive normalized observations; collection intervals can hide "
            "intermediate access points. Multi-AP observations can be normal during roaming or Wi-Fi 7 MLO. "
            "Signal thresholds are screening defaults, not proof of a client fault."
        ),
    }


FEATURE = {
    "id": "F177",
    "slug": "router_client_roaming_audit",
    "name": "Multi-vendor client roaming audit",
    "category": "Router integrations",
    "description": (
        "Create client association timelines across normalized OpenWrt, UniFi and MikroTik snapshots, "
        "detect observed AP handoffs and multi-AP collection windows, and flag weak measured RSSI."
    ),
    "parameters": {
        "snapshots": "1 to 64 normalized router/controller snapshots with site and capture identities",
        "concurrent_window_seconds": "optional collection window for multi-AP observations",
        "max_roam_interval_seconds": "maximum gap between observations to infer a handoff",
        "weak_signal_dbm": "optional weak-client signal threshold",
        "critical_signal_dbm": "optional critical-client signal threshold",
    },
    "run": run,
}
