"""Find same-site AP radio channel reuse and measured-frequency overlap."""
from __future__ import annotations


WIDTHS = {20, 40, 80, 160, 320}


def _integer(value: object, field: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be an integer")
    try:
        result = int(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field} must be an integer") from error
    if str(result) != str(value).strip() and not isinstance(value, int):
        raise ValueError(f"{field} must be a whole number")
    return result


def _center_frequency(band: str, channel: int) -> float:
    if band == "2.4GHz" and 1 <= channel <= 14:
        return 2484.0 if channel == 14 else 2407.0 + 5.0 * channel
    if band == "5GHz" and 32 <= channel <= 177:
        return 5000.0 + 5.0 * channel
    if band == "6GHz" and 1 <= channel <= 233:
        return 5950.0 + 5.0 * channel
    raise ValueError(f"channel {channel} is outside the supported {band} range")


def run(payload: dict) -> dict:
    radios = payload.get("radios", [])
    if not isinstance(radios, list):
        raise ValueError("'radios' must be a list")
    if len(radios) > 8192:
        raise ValueError("'radios' may contain no more than 8192 records")

    seen = set()
    normalized = []
    for radio in radios:
        if not isinstance(radio, dict):
            raise ValueError("Each radio must be an object")
        radio_id = str(radio.get("radio_id") or "").strip()
        ap_id = str(radio.get("ap_id") or "").strip()
        site_id = str(radio.get("site_id") or "unassigned").strip()
        band = str(radio.get("band") or "").strip()
        if not radio_id or not ap_id or not site_id:
            raise ValueError("Each radio needs radio_id, ap_id and site_id")
        if radio_id in seen:
            raise ValueError("radio_id values must be unique")
        seen.add(radio_id)
        if band not in {"2.4GHz", "5GHz", "6GHz"}:
            raise ValueError("band must be 2.4GHz, 5GHz or 6GHz")
        channel = _integer(radio.get("channel"), "channel")
        width = _integer(radio.get("channel_width_mhz"), "channel_width_mhz")
        if width not in WIDTHS or (band == "2.4GHz" and width not in {20, 40}) or (band == "5GHz" and width == 320):
            raise ValueError("channel_width_mhz is not supported for the supplied band")
        center = _center_frequency(band, channel)
        normalized.append({
            "radio_id": radio_id, "ap_id": ap_id, "site_id": site_id,
            "band": band, "channel": channel, "channel_width_mhz": width,
            "center_frequency_mhz": center,
            "low_frequency_mhz": center - width / 2.0,
            "high_frequency_mhz": center + width / 2.0,
        })

    conflicts = []
    for index, left in enumerate(normalized):
        for right in normalized[index + 1:]:
            if left["site_id"] != right["site_id"] or left["band"] != right["band"] or left["ap_id"] == right["ap_id"]:
                continue
            overlap = min(left["high_frequency_mhz"], right["high_frequency_mhz"]) - max(
                left["low_frequency_mhz"], right["low_frequency_mhz"]
            )
            if overlap <= 0:
                continue
            conflicts.append({
                "site_id": left["site_id"],
                "band": left["band"],
                "radio_ids": [left["radio_id"], right["radio_id"]],
                "ap_ids": [left["ap_id"], right["ap_id"]],
                "channels": [left["channel"], right["channel"]],
                "overlap_mhz": round(overlap, 2),
                "type": "co_channel" if left["channel"] == right["channel"] else "adjacent_channel_overlap",
            })

    conflicts.sort(key=lambda item: (item["site_id"], item["band"], item["radio_ids"]))
    return {
        "radio_count": len(normalized),
        "conflict_count": len(conflicts),
        "co_channel_conflict_count": sum(item["type"] == "co_channel" for item in conflicts),
        "adjacent_overlap_count": sum(item["type"] == "adjacent_channel_overlap" for item in conflicts),
        "conflicts": conflicts,
        "radios": normalized,
        "note": (
            "The calculation compares nominal channel-width frequency ranges, not measured spectrum energy. "
            "Same-AP radios are excluded, and regulatory availability/power constraints need a separate country-specific review."
        ),
    }


FEATURE = {
    "id": "F153",
    "slug": "site_ap_channel_reuse_audit",
    "name": "Site AP channel reuse audit",
    "category": "Site inventory",
    "description": "Compare same-site AP radio frequency ranges to identify co-channel reuse and adjacent-channel overlap.",
    "parameters": {"radios": "radio[]"},
    "run": run,
}
