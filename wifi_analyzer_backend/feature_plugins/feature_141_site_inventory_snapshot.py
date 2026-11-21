"""Multi-site AP inventory snapshot from an explicit operator/controller inventory.

This is a deterministic snapshot normaliser and data-quality check. It does
not scan networks, infer unobserved APs, or persist location data.
"""
from __future__ import annotations

import math
import re


VALID_BANDS = {"2.4GHz", "5GHz", "6GHz"}
VALID_WIDTHS = {20, 40, 80, 160, 320}


def _mac(value: object) -> str:
    normalised = str(value or "").replace("-", ":").upper()
    if not re.fullmatch(r"[0-9A-F]{2}(?::[0-9A-F]{2}){5}", normalised):
        raise ValueError("Each access point needs a valid BSSID")
    return normalised


def _optional_int(value: object, field: str, allowed: set[int] | None = None) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"{field} must be an integer")
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{field} must be an integer")
    if str(number) != str(value).strip() and not isinstance(value, int):
        raise ValueError(f"{field} must be a whole number")
    if allowed is not None and number not in allowed:
        raise ValueError(f"{field} must be one of {sorted(allowed)}")
    return number


def _primary_frequency(band: str, channel: int) -> float:
    if band == "2.4GHz" and 1 <= channel <= 14:
        return 2484.0 if channel == 14 else 2407.0 + 5.0 * channel
    if band == "5GHz" and 32 <= channel <= 177:
        return 5000.0 + 5.0 * channel
    if band == "6GHz" and channel == 2:
        return 5935.0
    if band == "6GHz" and 1 <= channel <= 233:
        return 5950.0 + 5.0 * channel
    raise ValueError(f"channel {channel} is outside the supported {band} range")


def _optional_center_frequency(value, *, band, channel, width):
    if value is None:
        return None
    if band not in VALID_BANDS or channel is None or width is None:
        raise ValueError("center_frequency_mhz requires band, channel and channel_width_mhz evidence")
    if isinstance(value, bool):
        raise ValueError("center_frequency_mhz must be finite and numeric")
    try:
        frequency = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError("center_frequency_mhz must be finite and numeric") from error
    if not math.isfinite(frequency):
        raise ValueError("center_frequency_mhz must be finite and numeric")
    lower, upper = {
        "2.4GHz": (2300.0, 2600.0),
        "5GHz": (4900.0, 5900.0),
        "6GHz": (5925.0, 7125.0),
    }[band]
    if not lower <= frequency <= upper:
        raise ValueError(f"center_frequency_mhz is outside the supported {band} range")
    primary = _primary_frequency(band, channel)
    if abs(frequency - primary) > width / 2.0:
        raise ValueError("center_frequency_mhz does not contain the primary channel within the declared width")
    if width == 20 and abs(frequency - primary) > 0.5:
        raise ValueError("20 MHz center_frequency_mhz must match the primary channel frequency")
    return round(frequency, 3)


def run(payload: dict) -> dict:
    access_points = payload.get("access_points", [])
    default_site_id = str(payload.get("site_id") or "unassigned").strip()
    if not default_site_id:
        raise ValueError("site_id must not be empty")
    if not isinstance(access_points, list):
        raise ValueError("'access_points' must be a list")
    if len(access_points) > 2048:
        raise ValueError("'access_points' may contain no more than 2048 records")

    records = []
    seen_bssids: dict[str, list[int]] = {}
    by_site: dict[str, int] = {}
    by_band: dict[str, int] = {}
    missing_fields = {"name": 0, "model": 0, "band": 0, "channel": 0, "location": 0}
    wide_channel_missing_center_frequency_count = 0

    for index, access_point in enumerate(access_points):
        if not isinstance(access_point, dict):
            raise ValueError("Each access point must be an object")
        bssid = _mac(access_point.get("bssid"))
        site_id = str(access_point.get("site_id") or default_site_id).strip()
        if not site_id:
            raise ValueError("site_id must not be empty")
        band = access_point.get("band")
        if band is not None:
            band = str(band).strip()
            if band not in VALID_BANDS:
                raise ValueError("band must be 2.4GHz, 5GHz or 6GHz when supplied")
        channel = _optional_int(access_point.get("channel"), "channel")
        if channel is not None and not 1 <= channel <= 233:
            raise ValueError("channel must be between 1 and 233")
        width = _optional_int(access_point.get("channel_width_mhz"), "channel_width_mhz", VALID_WIDTHS)
        if width is not None and band is not None:
            if (band == "2.4GHz" and width not in {20, 40}) or (band == "5GHz" and width == 320):
                raise ValueError(f"channel_width_mhz is not supported for {band}")
        if channel is not None and band is not None:
            _primary_frequency(band, channel)
        center_frequency = _optional_center_frequency(
            access_point.get("center_frequency_mhz"),
            band=band,
            channel=channel,
            width=width,
        )

        record = {
            "inventory_index": index,
            "site_id": site_id,
            "name": str(access_point.get("name") or "").strip() or None,
            "bssid": bssid,
            "ssid": str(access_point.get("ssid") or ""),
            "model": str(access_point.get("model") or "").strip() or None,
            "vendor": str(access_point.get("vendor") or "").strip() or None,
            "band": band,
            "channel": channel,
            "channel_width_mhz": width,
            "center_frequency_mhz": center_frequency,
            "location": str(access_point.get("location") or "").strip() or None,
            "source": str(access_point.get("source") or "operator_supplied"),
        }
        records.append(record)
        seen_bssids.setdefault(bssid, []).append(index)
        by_site[site_id] = by_site.get(site_id, 0) + 1
        if band is not None:
            by_band[band] = by_band.get(band, 0) + 1
        if width is not None and width > 20 and center_frequency is None:
            wide_channel_missing_center_frequency_count += 1
        for field in missing_fields:
            if record[field] is None:
                missing_fields[field] += 1

    duplicate_bssids = [
        {"bssid": bssid, "inventory_indexes": indexes, "count": len(indexes)}
        for bssid, indexes in sorted(seen_bssids.items()) if len(indexes) > 1
    ]
    total = len(records)
    populated = sum(total - count for count in missing_fields.values())
    quality_coverage = round(populated * 100.0 / (total * len(missing_fields)), 1) if total else None

    return {
        "access_point_count": total,
        "site_count": len(by_site),
        "access_points_by_site": dict(sorted(by_site.items())),
        "access_points_by_band": dict(sorted(by_band.items())),
        "duplicate_bssids": duplicate_bssids,
        "duplicate_bssid_count": len(duplicate_bssids),
        "missing_field_counts": missing_fields,
        "inventory_field_coverage_pct": quality_coverage,
        "wide_channel_missing_center_frequency_count": wide_channel_missing_center_frequency_count,
        "access_points": records,
        "note": (
            "Snapshot only: records come from the supplied inventory and are not live scan results. "
            "A duplicate BSSID is reported for review; this tool does not assume which record is authoritative."
        ),
    }


FEATURE = {
    "id": "F141",
    "slug": "site_inventory_snapshot",
    "name": "Multi-site access-point inventory snapshot",
    "category": "Site inventory",
    "description": "Normalise supplied AP inventories across sites, preserve explicit radio centre-frequency evidence, surface duplicate BSSIDs and measure inventory-field coverage.",
    "parameters": {"site_id": "string", "access_points": "access_point[] with optional center_frequency_mhz for wide-channel planning"},
    "run": run,
}
