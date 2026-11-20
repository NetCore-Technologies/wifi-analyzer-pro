"""Compare AP radio settings with an explicit per-site/per-band standard."""
from __future__ import annotations

import math


CHECKABLE = ("channel_width_mhz", "security", "tx_power_dbm")


def run(payload: dict) -> dict:
    radios = payload.get("radios", [])
    standards = payload.get("standards", [])
    if not isinstance(radios, list) or not isinstance(standards, list):
        raise ValueError("radios and standards must be lists")
    if len(radios) > 8192 or len(standards) > 512:
        raise ValueError("radio standard audit exceeds the supported record limit")

    standard_index = {}
    for standard in standards:
        if not isinstance(standard, dict) or not standard.get("band"):
            raise ValueError("Each standard needs a band")
        site_id = str(standard.get("site_id") or "*")
        band = str(standard["band"])
        key = (site_id, band)
        if key in standard_index:
            raise ValueError("A site/band standard may be declared only once")
        rule = {}
        if standard.get("channel_width_mhz") is not None:
            width = standard["channel_width_mhz"]
            if isinstance(width, bool) or not isinstance(width, int) or width not in {20, 40, 80, 160, 320}:
                raise ValueError("standard channel_width_mhz must be a supported integer width")
            rule["channel_width_mhz"] = width
        if standard.get("security") is not None:
            rule["security"] = str(standard["security"]).strip()
        for bound in ("min_tx_power_dbm", "max_tx_power_dbm"):
            if standard.get(bound) is not None:
                value = float(standard[bound])
                if not math.isfinite(value) or not -20 <= value <= 60:
                    raise ValueError(f"{bound} must be finite and between -20 and 60 dBm")
                rule[bound] = value
        if "min_tx_power_dbm" in rule and "max_tx_power_dbm" in rule and rule["min_tx_power_dbm"] > rule["max_tx_power_dbm"]:
            raise ValueError("min_tx_power_dbm must not exceed max_tx_power_dbm")
        standard_index[key] = rule

    seen_radios = set()
    results = []
    for radio in radios:
        if not isinstance(radio, dict) or not radio.get("radio_id"):
            raise ValueError("Each radio needs radio_id")
        radio_id = str(radio["radio_id"]).strip()
        if not radio_id or radio_id in seen_radios:
            raise ValueError("radio_id values must be unique and non-empty")
        seen_radios.add(radio_id)
        site_id = str(radio.get("site_id") or "unassigned")
        band = str(radio.get("band") or "")
        rule = standard_index.get((site_id, band), standard_index.get(("*", band)))
        if rule is None:
            results.append({
                "radio_id": radio_id, "site_id": site_id, "band": band,
                "status": "no_standard", "deviations": [], "unknown_fields": list(CHECKABLE),
            })
            continue

        deviations = []
        unknown = []
        width = radio.get("channel_width_mhz")
        if "channel_width_mhz" in rule:
            if width is None:
                unknown.append("channel_width_mhz")
            elif width != rule["channel_width_mhz"]:
                deviations.append({"field": "channel_width_mhz", "observed": width, "expected": rule["channel_width_mhz"]})
        security = radio.get("security")
        if "security" in rule:
            if security is None:
                unknown.append("security")
            elif str(security).strip().casefold() != rule["security"].casefold():
                deviations.append({"field": "security", "observed": security, "expected": rule["security"]})
        tx_power = radio.get("tx_power_dbm")
        if "min_tx_power_dbm" in rule or "max_tx_power_dbm" in rule:
            if tx_power is None:
                unknown.append("tx_power_dbm")
            else:
                try:
                    observed = float(tx_power)
                except (TypeError, ValueError) as error:
                    raise ValueError("tx_power_dbm must be numeric") from error
                if not math.isfinite(observed):
                    raise ValueError("tx_power_dbm must be finite")
                if "min_tx_power_dbm" in rule and observed < rule["min_tx_power_dbm"]:
                    deviations.append({"field": "tx_power_dbm", "observed": observed, "minimum": rule["min_tx_power_dbm"]})
                if "max_tx_power_dbm" in rule and observed > rule["max_tx_power_dbm"]:
                    deviations.append({"field": "tx_power_dbm", "observed": observed, "maximum": rule["max_tx_power_dbm"]})
        results.append({
            "radio_id": radio_id, "site_id": site_id, "band": band,
            "status": "deviation" if deviations else "unknown" if unknown else "compliant",
            "deviations": deviations, "unknown_fields": unknown,
        })

    return {
        "radio_count": len(results),
        "standard_count": len(standard_index),
        "compliant_count": sum(item["status"] == "compliant" for item in results),
        "deviation_count": sum(item["status"] == "deviation" for item in results),
        "unknown_count": sum(item["status"] in {"unknown", "no_standard"} for item in results),
        "radios": results,
        "note": "Only fields with an explicit standard and observed value are evaluated; missing radio telemetry is reported as unknown.",
    }


FEATURE = {
    "id": "F154",
    "slug": "site_radio_configuration_audit",
    "name": "Site radio configuration audit",
    "category": "Site inventory",
    "description": "Compare supplied AP radio widths, security and transmit power with explicit site/band standards.",
    "parameters": {"radios": "radio[]", "standards": "standard[]"},
    "run": run,
}
