"""Shared validation and safe conversion helpers for feature plugins."""
from __future__ import annotations
import html
import ipaddress
import math
import re
from collections import Counter, defaultdict
from typing import Any


def networks(p: dict) -> list[dict]:
    values = p.get("networks", [])
    if not isinstance(values, list):
        raise ValueError("'networks' must be a list")
    return [dict(v) for v in values if isinstance(v, dict)]


def number(value: Any, default: float = 0.0) -> float:
    try:
        result = float(value)
        return result if math.isfinite(result) else default
    except (TypeError, ValueError):
        return default


def mac_address(value: Any) -> str:
    raw = str(value or "").strip().replace("-", ":").upper()
    if not re.fullmatch(r"[0-9A-F]{2}(?::[0-9A-F]{2}){5}", raw):
        raise ValueError("A valid six-octet MAC/BSSID is required")
    return raw


def band_from_frequency(frequency_mhz: Any) -> str:
    freq = number(frequency_mhz)
    if 5925 <= freq <= 7125:
        return "6GHz"
    if 4900 <= freq < 5925:
        return "5GHz"
    if 2400 <= freq < 2500:
        return "2.4GHz"
    return "unknown"


def frequency_to_channel(frequency_mhz: Any) -> int:
    freq = int(round(number(frequency_mhz)))
    if freq == 2484:
        return 14
    if freq == 5935:
        return 2
    if 2412 <= freq <= 2472 and (freq - 2407) % 5 == 0:
        return (freq - 2407) // 5
    if 5000 <= freq <= 5895 and (freq - 5000) % 5 == 0:
        return (freq - 5000) // 5
    if 5955 <= freq <= 7115 and (freq - 5950) % 5 == 0:
        return (freq - 5950) // 5
    return 0


def channel_to_frequency(channel: Any, band: str = "2.4GHz") -> int:
    ch = int(number(channel, -1))
    if band == "2.4GHz":
        return 2484 if ch == 14 else (2407 + ch * 5 if 1 <= ch <= 13 else 0)
    if band == "5GHz":
        return 5000 + ch * 5 if 1 <= ch <= 196 else 0
    if band == "6GHz":
        return 5935 if ch == 2 else (5950 + ch * 5 if 1 <= ch <= 233 else 0)
    return 0


def signal_quality(rssi: Any) -> int | None:
    if rssi is None:
        return None
    val = number(rssi, -200)
    return max(0, min(100, round(2 * (val + 100))))


def security_name(network: dict) -> str:
    return str(network.get("security") or network.get("security_detail") or "unknown").strip()


def congestion_map(items: list[dict]) -> dict:
    result = {"2.4GHz": {}, "5GHz": {}, "6GHz": {}}
    for net in items:
        band = str(net.get("band") or "2.4GHz")
        channel = int(number(net.get("channel", net.get("ch")), 0))
        if band not in result or channel < 1:
            continue
        channels = range(max(1, channel - 2), min(14, channel + 2) + 1) if band == "2.4GHz" else (channel,)
        for candidate in channels:
            result[band][candidate] = result[band].get(candidate, 0) + 1
    return result


def safe_text(value: Any, limit: int = 128) -> str:
    text = str(value if value is not None else "")
    text = "".join(ch for ch in text if ch >= " " and ch != "\x7f")
    return text[:limit]


def percentile(values: list[float], pct: float) -> float | None:
    values = sorted(float(v) for v in values if math.isfinite(float(v)))
    if not values:
        return None
    position = (len(values) - 1) * max(0.0, min(100.0, pct)) / 100.0
    low = math.floor(position)
    high = math.ceil(position)
    if low == high:
        return values[low]
    return values[low] * (high - position) + values[high] * (position - low)


def ip_network(value: str):
    try:
        return ipaddress.ip_interface(value).network
    except ValueError:
        return ipaddress.ip_network(value, strict=False)


def html_escape(value: Any) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)
