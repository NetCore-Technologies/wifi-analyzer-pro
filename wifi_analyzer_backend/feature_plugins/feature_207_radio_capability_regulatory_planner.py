"""Controller-capability and reviewed-regulatory-dataset channel eligibility planner (F207).

This is a read-only eligibility and configuration-preview tool. It accepts
controller/agent capability snapshots and a normalized F206 dataset whose
canonical fingerprint is recomputed before use. It does not apply radio
configuration or independently authenticate regulatory documents.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from datetime import date, datetime, timedelta, timezone

from .feature_206_radio_regulatory_evidence_validator import (
    AUTHORITY_ALLOWLIST_VERSION,
    _is_allowlisted,
    _public_https_host,
)

MAX_RADIOS = 256
MAX_RULES = 5000
MAX_CHANNELS_PER_RADIO = 64
MAX_WIDTHS_PER_RADIO = 7
MAX_OUTPUT_CANDIDATES = 50_000
MAX_RULE_EVALUATIONS = 2_000_000
MAX_CAPABILITY_AGE_DAYS = 30
SUPPORTED_WIDTHS = {5, 10, 20, 40, 80, 160, 320}
DEVICE_CLASSES = {"LPI", "VLP", "SP"}
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
CHANNEL_RANGES = {
    "2.4GHz": (1, 14),
    "5GHz": (32, 196),
    "6GHz": (1, 233),
}


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value.strip()):
        raise ValueError(f"{field} must be a valid 1 to 128 character identifier")
    return value.strip()


def _text(value: object, field: str, maximum: int = 128) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    value = value.strip()
    if not value or len(value) > maximum or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(f"{field} must contain 1 to {maximum} printable characters")
    return value


def _number(value: object, field: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a finite number from {minimum:g} to {maximum:g}")
    try:
        result = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field} must be numeric") from error
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise ValueError(f"{field} must be a finite number from {minimum:g} to {maximum:g}")
    return result


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


def _channel_frequency(band: str, channel: int) -> float:
    if band == "2.4GHz":
        return 2484.0 if channel == 14 else 2407.0 + 5.0 * channel
    if band == "5GHz":
        return 5000.0 + 5.0 * channel
    return 5950.0 + 5.0 * channel


def _fingerprint_dataset(dataset: dict) -> str:
    required = (
        "authority_allowlist_version", "jurisdiction", "dataset_id", "version",
        "regulator", "retrieved_at", "effective_from", "effective_to", "sources", "rules",
    )
    missing = [field for field in required if field not in dataset]
    if missing:
        raise ValueError("regulatory_dataset is missing fingerprint fields: " + ", ".join(missing))
    sources = dataset["sources"]
    rules = dataset["rules"]
    if not isinstance(sources, list) or not 1 <= len(sources) <= 100:
        raise ValueError("regulatory_dataset.sources must contain 1 to 100 records")
    if not isinstance(rules, list) or not 1 <= len(rules) <= MAX_RULES:
        raise ValueError(f"regulatory_dataset.rules must contain 1 to {MAX_RULES} records")
    if any(not isinstance(item, dict) for item in sources + rules):
        raise ValueError("regulatory_dataset source and rule records must be objects")
    if dataset.get("source_count") != len(sources) or dataset.get("allowlisted_source_domain_count") != len(sources):
        raise ValueError("regulatory_dataset source counters do not match the supplied source records")
    if dataset.get("rule_count") != len(rules):
        raise ValueError("regulatory_dataset rule counter does not match the supplied rule records")
    if dataset.get("unverified_source_domains") != []:
        raise ValueError("regulatory_dataset contains unverified source domains")
    source_map = {}
    for index, source in enumerate(sources):
        source_id = _identifier(source.get("source_id"), f"regulatory_dataset.sources[{index}].source_id")
        if source_id in source_map:
            raise ValueError("regulatory_dataset source_id values must be unique")
        _, actual_host = _public_https_host(source.get("source_url"), f"regulatory_dataset.sources[{index}].source_url")
        if actual_host != source.get("source_host") or source.get("source_domain_allowlisted") is not True:
            raise ValueError(f"regulatory_dataset source {source_id} has inconsistent authority metadata")
        if not isinstance(source.get("content_sha256"), str) or not SHA256.fullmatch(source["content_sha256"]):
            raise ValueError(f"regulatory_dataset source {source_id} has an invalid content digest")
        if source.get("content_digest_status") != "provided_not_independently_verified":
            raise ValueError(f"regulatory_dataset source {source_id} digest status is invalid")
        if not _is_allowlisted(actual_host, jurisdiction):
            raise ValueError(f"regulatory_dataset source {source_id} is not on the current jurisdiction allowlist")
        clauses = source.get("clause_references")
        if not isinstance(clauses, list) or not clauses or any(not isinstance(item, str) for item in clauses):
            raise ValueError(f"regulatory_dataset source {source_id} has invalid clause references")
        source_map[source_id] = source
    canonical = {
        "authority_allowlist_version": dataset["authority_allowlist_version"],
        "jurisdiction": dataset["jurisdiction"],
        "dataset_id": dataset["dataset_id"],
        "version": dataset["version"],
        "regulator": dataset["regulator"],
        "retrieved_at": dataset["retrieved_at"],
        "effective_from": dataset["effective_from"],
        "effective_to": dataset["effective_to"],
        "sources": sorted(sources, key=lambda item: item.get("source_id", "")),
        "rules": sorted(rules, key=lambda item: item.get("rule_id", "")),
    }
    try:
        encoded = json.dumps(
            canonical, sort_keys=True, ensure_ascii=False,
            separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ValueError("regulatory_dataset is not canonical JSON data") from error
    return hashlib.sha256(encoded).hexdigest()


def _validate_dataset(dataset: object, acknowledgement: object, as_of: datetime) -> tuple[dict, str]:
    if not isinstance(dataset, dict):
        raise ValueError("regulatory_dataset must be a normalized F206 result object")
    if dataset.get("status") != "validated":
        raise ValueError("regulatory_dataset must have F206 status validated")
    if dataset.get("authority_allowlist_version") != AUTHORITY_ALLOWLIST_VERSION:
        raise ValueError("regulatory_dataset authority allowlist version is not current")
    jurisdiction = dataset.get("jurisdiction")
    if not isinstance(jurisdiction, str) or not re.fullmatch(r"(?:[A-Z]{2}|EU)", jurisdiction):
        raise ValueError("regulatory_dataset jurisdiction is invalid")
    if dataset.get("effective_status") != "in_effect":
        raise ValueError("regulatory_dataset must be in effect for the assessment date")
    if dataset.get("provenance_status") != "allowlisted_domains":
        raise ValueError("regulatory_dataset source provenance requires review")
    fingerprint = dataset.get("dataset_fingerprint_sha256")
    if not isinstance(fingerprint, str) or not SHA256.fullmatch(fingerprint):
        raise ValueError("regulatory_dataset dataset fingerprint is invalid")
    actual = _fingerprint_dataset(dataset)
    if actual != fingerprint:
        raise ValueError("regulatory_dataset fingerprint does not match its normalized contents")
    if not isinstance(acknowledgement, dict):
        raise ValueError("dataset_acknowledgement must be an explicit operator review object")
    acknowledged_fingerprint = acknowledgement.get("dataset_fingerprint_sha256")
    if acknowledged_fingerprint != fingerprint:
        raise ValueError("dataset_acknowledgement must reference the exact regulatory dataset fingerprint")
    _identifier(acknowledgement.get("reviewer_id"), "dataset_acknowledgement.reviewer_id")
    _identifier(acknowledgement.get("review_reference"), "dataset_acknowledgement.review_reference")
    reviewed_at = _timestamp(acknowledgement.get("reviewed_at"), "dataset_acknowledgement.reviewed_at")
    retrieved_at = _timestamp(dataset.get("retrieved_at"), "regulatory_dataset.retrieved_at")
    try:
        effective_from = date.fromisoformat(dataset["effective_from"])
        effective_to = None if dataset["effective_to"] is None else date.fromisoformat(dataset["effective_to"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("regulatory_dataset effective dates are invalid") from error
    if retrieved_at > as_of + timedelta(minutes=5):
        raise ValueError("regulatory_dataset.retrieved_at is too far in the future")
    if as_of - retrieved_at > timedelta(days=365):
        raise ValueError("regulatory_dataset is older than 365 days and must be revalidated")
    if as_of.date() < effective_from or (effective_to is not None and as_of.date() > effective_to):
        raise ValueError("regulatory_dataset is not effective for the assessment date")
    if reviewed_at > as_of + timedelta(minutes=5):
        raise ValueError("dataset_acknowledgement.reviewed_at is too far in the future")
    if reviewed_at < as_of - timedelta(days=90):
        raise ValueError("dataset_acknowledgement is older than 90 days and must be reviewed again")
    return dataset, fingerprint, source_map


def _channel_list(value: object, field: str, band: str) -> list[int]:
    lower, upper = CHANNEL_RANGES[band]
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_CHANNELS_PER_RADIO:
        raise ValueError(f"{field} must contain 1 to {MAX_CHANNELS_PER_RADIO} channels")
    channels = []
    for index, channel in enumerate(value):
        if isinstance(channel, bool) or not isinstance(channel, int) or not lower <= channel <= upper:
            raise ValueError(f"{field}[{index}] is outside the supported {band} channel range")
        if channel not in channels:
            channels.append(channel)
    return sorted(channels)


def _width_list(value: object, field: str) -> list[int]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_WIDTHS_PER_RADIO:
        raise ValueError(f"{field} must contain 1 to {MAX_WIDTHS_PER_RADIO} channel widths")
    widths = []
    for index, width in enumerate(value):
        if isinstance(width, bool) or not isinstance(width, int) or width not in SUPPORTED_WIDTHS:
            raise ValueError(f"{field}[{index}] is not a supported channel width")
        if width not in widths:
            widths.append(width)
    return sorted(widths)


def _validate_radio(value: object, index: int, site_id: str, jurisdiction: str, as_of: datetime, max_age_days: int) -> dict:
    prefix = f"radios[{index}]"
    if not isinstance(value, dict):
        raise ValueError(f"{prefix} must be an object")
    radio_id = _identifier(value.get("radio_id"), prefix + ".radio_id")
    ap_id = _identifier(value.get("ap_id"), prefix + ".ap_id")
    if value.get("site_id") != site_id:
        raise ValueError(f"{prefix}.site_id must match the requested site")
    if value.get("jurisdiction") != jurisdiction:
        raise ValueError(f"{prefix}.jurisdiction must match the reviewed regulatory dataset")
    installation_reference = _identifier(value.get("installation_reference"), prefix + ".installation_reference")
    band = value.get("band")
    if not isinstance(band, str) or band not in CHANNEL_RANGES:
        raise ValueError(f"{prefix}.band must be 2.4GHz, 5GHz or 6GHz")
    source = value.get("capability_source")
    if not isinstance(source, str) or source not in {"controller", "agent"}:
        raise ValueError(f"{prefix}.capability_source must be controller or agent")
    observed_at = _timestamp(value.get("capabilities_observed_at"), prefix + ".capabilities_observed_at")
    if observed_at > as_of + timedelta(minutes=5):
        raise ValueError(f"{prefix}.capabilities_observed_at is too far in the future")
    fresh = observed_at >= as_of - timedelta(days=max_age_days)
    channels = _channel_list(value.get("supported_channels"), prefix + ".supported_channels", band)
    widths = _width_list(value.get("supported_channel_widths_mhz"), prefix + ".supported_channel_widths_mhz")
    device_class = value.get("device_class")
    if not isinstance(device_class, str) or device_class not in DEVICE_CLASSES:
        raise ValueError(f"{prefix}.device_class must be one of {sorted(DEVICE_CLASSES)}")
    environment = value.get("environment")
    if not isinstance(environment, str) or environment not in {"indoor", "outdoor"}:
        raise ValueError(f"{prefix}.environment must be indoor or outdoor")
    dfs_supported = value.get("dfs_supported")
    afc_supported = value.get("afc_supported")
    if not isinstance(dfs_supported, bool) or not isinstance(afc_supported, bool):
        raise ValueError(f"{prefix}.dfs_supported and afc_supported must be booleans")
    maximum_eirp = _number(value.get("maximum_eirp_dbm"), prefix + ".maximum_eirp_dbm", -20.0, 60.0)
    density_raw = value.get("maximum_eirp_density_dbm_per_mhz")
    density = None if density_raw is None else _number(
        density_raw, prefix + ".maximum_eirp_density_dbm_per_mhz", -60.0, 60.0,
    )
    current_channel = value.get("current_channel")
    if current_channel is not None and (
        isinstance(current_channel, bool) or not isinstance(current_channel, int)
        or not CHANNEL_RANGES[band][0] <= current_channel <= CHANNEL_RANGES[band][1]
    ):
        raise ValueError(f"{prefix}.current_channel is outside the supported {band} channel range")
    current_width = value.get("current_channel_width_mhz")
    if current_width is not None and (
        isinstance(current_width, bool) or not isinstance(current_width, int)
        or current_width not in SUPPORTED_WIDTHS
    ):
        raise ValueError(f"{prefix}.current_channel_width_mhz is unsupported")
    current_eirp = value.get("current_eirp_dbm")
    if current_eirp is not None:
        current_eirp = _number(current_eirp, prefix + ".current_eirp_dbm", -20.0, 60.0)
    dfs_states_value = value.get("dfs_channel_states", [])
    if not isinstance(dfs_states_value, list) or len(dfs_states_value) > MAX_CHANNELS_PER_RADIO:
        raise ValueError(f"{prefix}.dfs_channel_states must contain no more than {MAX_CHANNELS_PER_RADIO} records")
    dfs_channel_states = {}
    for state_index, state in enumerate(dfs_states_value):
        state_prefix = f"{prefix}.dfs_channel_states[{state_index}]"
        if not isinstance(state, dict):
            raise ValueError(f"{state_prefix} must be an object")
        channel = state.get("channel")
        if isinstance(channel, bool) or not isinstance(channel, int) or not CHANNEL_RANGES[band][0] <= channel <= CHANNEL_RANGES[band][1]:
            raise ValueError(f"{state_prefix}.channel is invalid for {band}")
        if channel in dfs_channel_states:
            raise ValueError(f"{prefix}.dfs_channel_states contains duplicate channels")
        status = state.get("status")
        if not isinstance(status, str) or status not in {"available", "cac_required", "non_occupancy_period", "unavailable"}:
            raise ValueError(f"{state_prefix}.status is invalid")
        observed = _timestamp(state.get("observed_at"), state_prefix + ".observed_at")
        if observed > as_of + timedelta(minutes=5):
            raise ValueError(f"{state_prefix}.observed_at is too far in the future")
        dfs_channel_states[channel] = {
            "status": status,
            "observed_at": observed,
            "fresh": observed >= as_of - timedelta(days=max_age_days),
        }

    afc_grant = value.get("afc_grant")
    if afc_grant is not None:
        if not isinstance(afc_grant, dict):
            raise ValueError(f"{prefix}.afc_grant must be an object")
        if afc_grant.get("status") != "active":
            raise ValueError(f"{prefix}.afc_grant.status must be active")
        _identifier(afc_grant.get("grant_id"), prefix + ".afc_grant.grant_id")
        expires_at = _timestamp(afc_grant.get("expires_at"), prefix + ".afc_grant.expires_at")
        grant_channels = _channel_list(afc_grant.get("channel_numbers"), prefix + ".afc_grant.channel_numbers", band)
        grant_eirp = _number(afc_grant.get("maximum_eirp_dbm"), prefix + ".afc_grant.maximum_eirp_dbm", -20.0, 60.0)
        if afc_grant.get("installation_reference") != installation_reference:
            raise ValueError(f"{prefix}.afc_grant is not scoped to this installation")
        if afc_grant.get("jurisdiction") != jurisdiction:
            raise ValueError(f"{prefix}.afc_grant jurisdiction does not match the dataset")
        afc_grant = {
            "grant_id": afc_grant["grant_id"],
            "expires_at": expires_at,
            "channel_numbers": grant_channels,
            "maximum_eirp_dbm": grant_eirp,
            "installation_reference": installation_reference,
            "active": expires_at > as_of,
        }
    return {
        "radio_id": radio_id,
        "ap_id": ap_id,
        "site_id": site_id,
        "jurisdiction": jurisdiction,
        "installation_reference": installation_reference,
        "band": band,
        "capability_source": source,
        "capabilities_observed_at": observed_at,
        "capabilities_fresh": fresh,
        "supported_channels": channels,
        "supported_channel_widths_mhz": widths,
        "device_class": device_class,
        "environment": environment,
        "dfs_supported": dfs_supported,
        "afc_supported": afc_supported,
        "maximum_eirp_dbm": maximum_eirp,
        "maximum_eirp_density_dbm_per_mhz": density,
        "current_channel": current_channel,
        "current_channel_width_mhz": current_width,
        "current_eirp_dbm": current_eirp,
        "afc_grant": afc_grant,
        "dfs_channel_states": dfs_channel_states,
    }


def _normalise_rules(dataset: dict, source_map: dict) -> dict:
    result = {}
    for index, rule in enumerate(dataset["rules"]):
        prefix = f"regulatory_dataset.rules[{index}]"
        if not isinstance(rule, dict):
            raise ValueError(f"{prefix} must be an object")
        rule_id = _identifier(rule.get("rule_id"), prefix + ".rule_id")
        band = rule.get("band")
        if not isinstance(band, str) or band not in CHANNEL_RANGES:
            raise ValueError(f"{prefix}.band is invalid")
        low = _number(rule.get("lower_frequency_mhz"), prefix + ".lower_frequency_mhz", 2300.0, 7125.0)
        high = _number(rule.get("upper_frequency_mhz"), prefix + ".upper_frequency_mhz", 2300.0, 7125.0)
        if low >= high:
            raise ValueError(f"{prefix} frequency range is invalid")
        max_eirp = _number(rule.get("maximum_eirp_dbm"), prefix + ".maximum_eirp_dbm", -20.0, 60.0)
        density_raw = rule.get("maximum_eirp_density_dbm_per_mhz")
        density = None if density_raw is None else _number(
            density_raw, prefix + ".maximum_eirp_density_dbm_per_mhz", -60.0, 60.0,
        )
        widths = _width_list(rule.get("channel_widths_mhz"), prefix + ".channel_widths_mhz")
        channels = _channel_list(rule.get("channel_numbers"), prefix + ".channel_numbers", band)
        if rule_id in result:
            raise ValueError("regulatory_dataset rule_id values must be unique")
        classes = rule.get("device_classes")
        if not isinstance(classes, list) or not classes or any(not isinstance(item, str) or item not in DEVICE_CLASSES for item in classes):
            raise ValueError(f"{prefix}.device_classes is invalid")
        flags = [rule.get("indoor_only"), rule.get("outdoor_allowed"), rule.get("dfs_required"), rule.get("afc_required")]
        if any(not isinstance(flag, bool) for flag in flags):
            raise ValueError(f"{prefix} restriction flags must be booleans")
        if rule["indoor_only"] and rule["outdoor_allowed"]:
            raise ValueError(f"{prefix} cannot be both indoor_only and outdoor_allowed")
        refs = rule.get("source_references")
        if not isinstance(refs, list) or not refs:
            raise ValueError(f"{prefix}.source_references is required")
        for ref_index, reference in enumerate(refs):
            ref_prefix = f"{prefix}.source_references[{ref_index}]"
            if not isinstance(reference, dict):
                raise ValueError(f"{ref_prefix} must be an object")
            source_id = _identifier(reference.get("source_id"), ref_prefix + ".source_id")
            clause = reference.get("clause")
            if source_id not in source_map or not isinstance(clause, str) or clause not in source_map[source_id]["clause_references"]:
                raise ValueError(f"{ref_prefix} is not linked to an exact validated source clause")
        result[rule_id] = {
            "rule_id": rule_id,
            "band": band,
            "lower_frequency_mhz": low,
            "upper_frequency_mhz": high,
            "maximum_eirp_dbm": max_eirp,
            "maximum_eirp_density_dbm_per_mhz": density,
            "channel_widths_mhz": widths,
            "channel_numbers": channels,
            "device_classes": classes,
            "indoor_only": rule["indoor_only"],
            "outdoor_allowed": rule["outdoor_allowed"],
            "dfs_required": rule["dfs_required"],
            "afc_required": rule["afc_required"],
            "source_references": refs,
        }
    return result


def _candidate(radio: dict, rule: dict, channel: int, width: int) -> tuple[dict | None, str | None]:
    centre = _channel_frequency(radio["band"], channel)
    lower = centre - width / 2.0
    upper = centre + width / 2.0
    if lower < rule["lower_frequency_mhz"] or upper > rule["upper_frequency_mhz"]:
        return None, "channel_width_outside_rule_frequency_range"
    if radio["device_class"] not in rule["device_classes"]:
        return None, "device_class_not_permitted"
    if rule["indoor_only"] and radio["environment"] != "indoor":
        return None, "rule_is_indoor_only"
    if radio["environment"] == "outdoor" and not rule["outdoor_allowed"]:
        return None, "outdoor_operation_not_permitted_by_rule"
    dfs_state = None
    requires_dfs_cac = False
    if rule["dfs_required"]:
        if not radio["dfs_supported"]:
            return None, "radio_does_not_support_dfs"
        dfs_state = radio["dfs_channel_states"].get(channel)
        if not dfs_state or not dfs_state["fresh"]:
            return None, "fresh_dfs_channel_state_required"
        if dfs_state["status"] in {"non_occupancy_period", "unavailable"}:
            return None, "dfs_channel_currently_unavailable"
        requires_dfs_cac = dfs_state["status"] == "cac_required"
    eirp_limits = [rule["maximum_eirp_dbm"], radio["maximum_eirp_dbm"]]
    rule_density = rule["maximum_eirp_density_dbm_per_mhz"]
    radio_density = radio["maximum_eirp_density_dbm_per_mhz"]
    if rule_density is not None:
        eirp_limits.append(rule_density + 10.0 * math.log10(width))
    if radio_density is not None:
        eirp_limits.append(radio_density + 10.0 * math.log10(width))
    grant = radio["afc_grant"]
    if rule["afc_required"]:
        if not radio["afc_supported"]:
            return None, "radio_does_not_support_afc"
        if not grant or not grant["active"]:
            return None, "active_afc_grant_required"
        if grant["installation_reference"] != radio["installation_reference"]:
            return None, "afc_grant_location_mismatch"
        if channel not in grant["channel_numbers"]:
            return None, "channel_not_covered_by_afc_grant"
        eirp_limits.append(grant["maximum_eirp_dbm"])
    eirp_ceiling = round(min(eirp_limits), 2)
    proposed_eirp = (
        round(min(radio["current_eirp_dbm"], eirp_ceiling), 2)
        if radio["current_eirp_dbm"] is not None else None
    )
    current_match = (
        radio["current_channel"] == channel
        and radio["current_channel_width_mhz"] == width
    )
    return {
        "channel": channel,
        "channel_width_mhz": width,
        "centre_frequency_mhz": round(centre, 3),
        "occupied_frequency_range_mhz": [round(lower, 3), round(upper, 3)],
        "rule_id": rule["rule_id"],
        "source_references": rule["source_references"],
        "dfs_required": rule["dfs_required"],
        "dfs_state": dfs_state["status"] if dfs_state else None,
        "requires_dfs_cac_before_activation": requires_dfs_cac,
        "six_ghz_psc": radio["band"] == "6GHz" and channel >= 5 and (channel - 5) % 16 == 0,
        "afc_required": rule["afc_required"],
        "eirp_ceiling_dbm": eirp_ceiling,
        "proposed_eirp_dbm": proposed_eirp,
        "matches_current_channel_and_width": current_match,
    }, None


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    site_id = _identifier(payload.get("site_id"), "site_id")
    as_of = _timestamp(payload.get("as_of"), "as_of") if payload.get("as_of") is not None else datetime.now(timezone.utc)
    now = datetime.now(timezone.utc)
    if as_of > now + timedelta(minutes=5):
        raise ValueError("as_of is too far in the future")
    max_age_days = payload.get("maximum_capability_age_days", 7)
    if isinstance(max_age_days, bool) or not isinstance(max_age_days, int) or not 1 <= max_age_days <= MAX_CAPABILITY_AGE_DAYS:
        raise ValueError(f"maximum_capability_age_days must be an integer from 1 to {MAX_CAPABILITY_AGE_DAYS}")

    dataset, fingerprint, source_map = _validate_dataset(
        payload.get("regulatory_dataset"),
        payload.get("dataset_acknowledgement"),
        as_of,
    )
    rules = _normalise_rules(dataset, source_map)
    radios_value = payload.get("radios")
    if not isinstance(radios_value, list) or not 1 <= len(radios_value) <= MAX_RADIOS:
        raise ValueError(f"radios must contain 1 to {MAX_RADIOS} controller capability records")

    seen_radios = set()
    radios = []
    for index, item in enumerate(radios_value):
        radio = _validate_radio(item, index, site_id, dataset["jurisdiction"], as_of, max_age_days)
        if radio["radio_id"] in seen_radios:
            raise ValueError("radio_id values must be unique")
        seen_radios.add(radio["radio_id"])
        radios.append(radio)

    rule_index = {}
    for rule in rules.values():
        for channel in rule["channel_numbers"]:
            rule_index.setdefault((rule["band"], channel), []).append(rule)

    output = []
    evaluations = 0
    stale_radio_count = 0
    no_match_radio_count = 0
    for radio in radios:
        if not radio["capabilities_fresh"]:
            stale_radio_count += 1
            output.append({
                "radio_id": radio["radio_id"],
                "ap_id": radio["ap_id"],
                "band": radio["band"],
                "status": "review_required",
                "reason": "controller_capability_snapshot_is_stale",
                "capabilities_observed_at": radio["capabilities_observed_at"].isoformat(timespec="seconds"),
                "eligible_candidate_count": 0,
                "eligible_candidates": [],
                "recommended_configuration": None,
            })
            continue

        candidates = []
        rejected_reasons = {}
        ambiguity_count = 0
        for channel in radio["supported_channels"]:
            matching_rules = rule_index.get((radio["band"], channel), [])
            for width in radio["supported_channel_widths_mhz"]:
                evaluations += len(matching_rules)
                if evaluations > MAX_RULE_EVALUATIONS:
                    raise ValueError(f"regulatory matching exceeds the {MAX_RULE_EVALUATIONS} evaluation limit")
                applicable = []
                for rule in matching_rules:
                    candidate, rejection = _candidate(radio, rule, channel, width)
                    if candidate:
                        applicable.append(candidate)
                    elif rejection:
                        rejected_reasons[rejection] = rejected_reasons.get(rejection, 0) + 1
                if len(applicable) > 1:
                    ambiguity_count += 1
                    rejected_reasons["multiple_regulatory_rules_match"] = rejected_reasons.get("multiple_regulatory_rules_match", 0) + 1
                    continue
                if applicable:
                    candidates.append(applicable[0])
                    if len(candidates) > MAX_OUTPUT_CANDIDATES:
                        raise ValueError(f"eligible candidates exceed the {MAX_OUTPUT_CANDIDATES} output limit")

        candidates.sort(key=lambda item: (
            0 if item["matches_current_channel_and_width"] else 1,
            0 if item["channel"] == radio["current_channel"] else 1,
            0 if item["channel_width_mhz"] == radio["current_channel_width_mhz"] else 1,
            0 if item["six_ghz_psc"] else 1,
            abs(item["channel"] - radio["current_channel"]) if radio["current_channel"] is not None else item["channel"],
            item["channel_width_mhz"],
            item["channel"],
        ))
        recommendation = None
        if candidates:
            selected = candidates[0]
            recommendation = {
                "channel": selected["channel"],
                "channel_width_mhz": selected["channel_width_mhz"],
                "centre_frequency_mhz": selected["centre_frequency_mhz"],
                "eirp_ceiling_dbm": selected["eirp_ceiling_dbm"],
                "proposed_eirp_dbm": selected["proposed_eirp_dbm"],
                "power_review_required": selected["proposed_eirp_dbm"] is None,
                "dfs_required": selected["dfs_required"],
                "dfs_state": selected["dfs_state"],
                "requires_dfs_cac_before_activation": selected["requires_dfs_cac_before_activation"],
                "six_ghz_psc": selected["six_ghz_psc"],
                "afc_required": selected["afc_required"],
                "rule_id": selected["rule_id"],
                "source_references": selected["source_references"],
                "change_required": not selected["matches_current_channel_and_width"]
                    or (
                        selected["proposed_eirp_dbm"] is not None
                        and radio["current_eirp_dbm"] is not None
                        and selected["proposed_eirp_dbm"] < radio["current_eirp_dbm"]
                    ),
            }
        status = "eligible" if recommendation else "no_eligible_candidate"
        if ambiguity_count and not candidates:
            status = "review_required"
        output.append({
            "radio_id": radio["radio_id"],
            "ap_id": radio["ap_id"],
            "band": radio["band"],
            "status": status,
            "capability_source": radio["capability_source"],
            "capabilities_observed_at": radio["capabilities_observed_at"].isoformat(timespec="seconds"),
            "supported_channel_count": len(radio["supported_channels"]),
            "supported_widths_mhz": radio["supported_channel_widths_mhz"],
            "eligible_candidate_count": len(candidates),
            "eligible_candidates": candidates[:64],
            "rejected_reason_counts": dict(sorted(rejected_reasons.items())),
            "overlapping_rule_ambiguity_count": ambiguity_count,
            "recommended_configuration": recommendation,
        })

    eligible = sum(item["status"] == "eligible" for item in output)
    status = "eligible" if eligible == len(output) else "partial" if eligible else "no_eligible_radios"
    return {
        "status": status,
        "site_id": site_id,
        "dataset": {
            "dataset_id": dataset["dataset_id"],
            "jurisdiction": dataset["jurisdiction"],
            "version": dataset["version"],
            "fingerprint_sha256": fingerprint,
            "authority_allowlist_version": dataset["authority_allowlist_version"],
            "review_reference": payload["dataset_acknowledgement"]["review_reference"],
            "reviewer_id": payload["dataset_acknowledgement"]["reviewer_id"],
            "reviewed_at": payload["dataset_acknowledgement"]["reviewed_at"],
        },
        "radio_count": len(radios),
        "eligible_radio_count": eligible,
        "stale_capability_radio_count": stale_radio_count,
        "no_eligible_candidate_radio_count": sum(item["status"] == "no_eligible_candidate" for item in output),
        "rule_evaluation_count": evaluations,
        "radios": output,
        "change_application": {
            "applied": False,
            "requires_operator_approval": True,
            "execution_method": "preview_only",
            "note": "No controller configuration was written. Re-check the live controller state, authority dataset and site-specific conditions, then approve and deploy through the organisation's change-management process.",
        },
        "limitations": [
            "The F206 source URLs and submitted document digests are provenance metadata; this feature does not fetch, authenticate or interpret legal instruments.",
            "The operator acknowledgement is caller-declared and is not a cryptographically verified approval or proof of legal review.",
            "Controller/agent capability-source labels and timestamps are caller-declared; the capability response is not independently signed by this feature.",
            "A channel marked eligible is only compatible with the supplied capability snapshot and submitted rule records; it is not a legal authorization or a guarantee of interference-free operation.",
            "DFS support does not establish radar clearance or a currently available channel. AFC support does not establish an active grant; an eligible AFC rule requires a supplied active grant covering the channel.",
            "Indoor/outdoor suitability, device class and EIRP are evaluated against supplied values. Installation location, antenna system gain, local coordination and other jurisdiction-specific conditions may require additional review.",
            "Recommendations minimize configuration changes; they do not optimize RF interference, airtime, throughput, roaming or client experience.",
            "No AP configuration is applied by this feature.",
        ],
    }


FEATURE = {
    "id": "F207",
    "slug": "radio_capability_regulatory_channel_planner",
    "name": "Controller radio capability and regulatory channel planner",
    "category": "RF assurance",
    "description": (
        "Cross-check fresh controller/agent radio capabilities against a fingerprint-verified, operator-reviewed F206 rule dataset; evaluate channel/width, DFS/AFC, device class, installation environment and EIRP constraints, then produce a read-only lowest-change configuration preview."
    ),
    "parameters": {
        "site_id": "The site that owns every supplied controller radio",
        "regulatory_dataset": "Normalized F206 result including its canonical dataset fingerprint",
        "dataset_acknowledgement": "Explicit reviewer ID, date, review reference and matching dataset fingerprint",
        "radios": "1-256 fresh controller/agent radio capability snapshots with supported channels, widths, DFS/AFC and power limits",
        "maximum_capability_age_days": "1-30 day freshness window; defaults to 7",
        "as_of": "Optional timezone-aware assessment timestamp",
    },
    "run": run,
}
