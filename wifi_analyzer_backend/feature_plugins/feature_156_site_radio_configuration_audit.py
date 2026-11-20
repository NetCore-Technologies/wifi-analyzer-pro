"""Audit observed AP radio settings against explicit site/band standards."""
from __future__ import annotations

import math

SUPPORTED_BANDS = {"2.4GHz", "5GHz", "6GHz"}
CHANNEL_WIDTHS = {20, 40, 80, 160, 320}
MIN_POWER_DBM = -20.0
MAX_POWER_DBM = 60.0
MAX_RADIOS = 8192
MAX_STANDARDS = 512
CHECKABLE = ("channel_width_mhz", "security", "tx_power_dbm")


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    value = value.strip()
    if not value or len(value) > 128:
        raise ValueError(f"{field} must contain 1 to 128 non-whitespace characters")
    return value


def _power(value: object, field: str) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a finite number between {MIN_POWER_DBM:g} and {MAX_POWER_DBM:g} dBm")
    try:
        result = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field} must be numeric") from error
    if not math.isfinite(result) or not MIN_POWER_DBM <= result <= MAX_POWER_DBM:
        raise ValueError(f"{field} must be a finite number between {MIN_POWER_DBM:g} and {MAX_POWER_DBM:g} dBm")
    return result


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    radios = payload.get("radios", [])
    standards = payload.get("standards", [])
    if not isinstance(radios, list) or not isinstance(standards, list):
        raise ValueError("radios and standards must be lists")
    if len(radios) > MAX_RADIOS or len(standards) > MAX_STANDARDS:
        raise ValueError("radio standard audit exceeds the supported record limit")

    standard_index = {}
    for index, standard in enumerate(standards):
        if not isinstance(standard, dict):
            raise ValueError(f"standards[{index}] must be an object")
        band = _identifier(standard.get("band"), f"standards[{index}].band")
        if band not in SUPPORTED_BANDS:
            raise ValueError(f"standards[{index}].band must be one of {sorted(SUPPORTED_BANDS)}")
        site_id = "*" if standard.get("site_id") is None else _identifier(standard.get("site_id"), f"standards[{index}].site_id")
        key = (site_id, band)
        if key in standard_index:
            raise ValueError("A site/band standard may be declared only once")

        rule = {}
        width = standard.get("channel_width_mhz")
        if width is not None:
            if isinstance(width, bool) or not isinstance(width, int) or width not in CHANNEL_WIDTHS:
                raise ValueError("standard channel_width_mhz must be a supported integer width")
            rule["channel_width_mhz"] = width

        security = standard.get("security")
        if security is not None:
            security = _identifier(security, f"standards[{index}].security")
            rule["security"] = security

        for bound in ("min_tx_power_dbm", "max_tx_power_dbm"):
            if standard.get(bound) is not None:
                rule[bound] = _power(standard[bound], f"standards[{index}].{bound}")
        if "min_tx_power_dbm" in rule and "max_tx_power_dbm" in rule:
            if rule["min_tx_power_dbm"] > rule["max_tx_power_dbm"]:
                raise ValueError("min_tx_power_dbm must not exceed max_tx_power_dbm")
        if not rule:
            raise ValueError("Each standard must define at least one checkable radio setting")
        standard_index[key] = rule

    seen_radios = set()
    results = []
    for index, radio in enumerate(radios):
        if not isinstance(radio, dict):
            raise ValueError(f"radios[{index}] must be an object")
        radio_id = _identifier(radio.get("radio_id"), f"radios[{index}].radio_id")
        if radio_id in seen_radios:
            raise ValueError("radio_id values must be unique")
        seen_radios.add(radio_id)

        site_id = "unassigned" if radio.get("site_id") is None else _identifier(radio.get("site_id"), f"radios[{index}].site_id")
        band = _identifier(radio.get("band"), f"radios[{index}].band")
        if band not in SUPPORTED_BANDS:
            raise ValueError(f"radios[{index}].band must be one of {sorted(SUPPORTED_BANDS)}")
        rule = standard_index.get((site_id, band), standard_index.get(("*", band)))
        if rule is None:
            results.append({
                "radio_id": radio_id,
                "site_id": site_id,
                "band": band,
                "status": "no_standard",
                "deviations": [],
                "unknown_fields": list(CHECKABLE),
            })
            continue

        deviations = []
        unknown = []
        if "channel_width_mhz" in rule:
            width = radio.get("channel_width_mhz")
            if width is None:
                unknown.append("channel_width_mhz")
            elif isinstance(width, bool) or not isinstance(width, int) or width not in CHANNEL_WIDTHS:
                raise ValueError(f"radios[{index}].channel_width_mhz must be a supported integer width")
            elif width != rule["channel_width_mhz"]:
                deviations.append({
                    "field": "channel_width_mhz",
                    "observed": width,
                    "expected": rule["channel_width_mhz"],
                })

        if "security" in rule:
            security = radio.get("security")
            if security is None or not str(security).strip():
                unknown.append("security")
            elif str(security).strip().casefold() != rule["security"].casefold():
                deviations.append({
                    "field": "security",
                    "observed": str(security).strip()[:128],
                    "expected": rule["security"],
                })

        if "min_tx_power_dbm" in rule or "max_tx_power_dbm" in rule:
            if radio.get("tx_power_dbm") is None:
                unknown.append("tx_power_dbm")
            else:
                observed = _power(radio["tx_power_dbm"], f"radios[{index}].tx_power_dbm")
                if "min_tx_power_dbm" in rule and observed < rule["min_tx_power_dbm"]:
                    deviations.append({
                        "field": "tx_power_dbm",
                        "observed": observed,
                        "minimum": rule["min_tx_power_dbm"],
                    })
                if "max_tx_power_dbm" in rule and observed > rule["max_tx_power_dbm"]:
                    deviations.append({
                        "field": "tx_power_dbm",
                        "observed": observed,
                        "maximum": rule["max_tx_power_dbm"],
                    })

        results.append({
            "radio_id": radio_id,
            "site_id": site_id,
            "band": band,
            "status": "deviation" if deviations else "unknown" if unknown else "compliant",
            "deviations": deviations,
            "unknown_fields": unknown,
        })

    return {
        "radio_count": len(results),
        "standard_count": len(standard_index),
        "compliant_count": sum(item["status"] == "compliant" for item in results),
        "deviation_count": sum(item["status"] == "deviation" for item in results),
        "unknown_count": sum(item["status"] in {"unknown", "no_standard"} for item in results),
        "radios": results,
        "note": (
            "Only explicitly standardised settings are evaluated. Missing observations remain unknown; "
            "a missing site/band standard is not treated as compliant."
        ),
    }


FEATURE = {
    "id": "F156",
    "slug": "site_radio_configuration_audit",
    "name": "Site radio configuration audit",
    "category": "Site inventory",
    "description": "Compare AP radio channel widths, security and transmit power with explicit site/band standards.",
    "parameters": {"radios": "radio[]", "standards": "standard[]"},
    "run": run,
}
