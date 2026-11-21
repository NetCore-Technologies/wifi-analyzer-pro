"""Evidence-weighted multi-AP channel assignment planner.

The planner evaluates only caller-supplied channel options and explicit RF
interference evidence. It does not infer regulatory availability, measure
spectrum, estimate propagation, or apply radio configuration.
"""
from __future__ import annotations

import math
import re

MAX_RADIOS = 256
MAX_CHANNEL_OPTIONS = 32
MAX_EDGES = 8192
VALID_BANDS = {"2.4GHz", "5GHz", "6GHz"}
WIDTHS = {20, 40, 80, 160, 320}
EVIDENCE_SOURCES = {"survey", "controller", "operator"}
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value.strip()):
        raise ValueError(f"{field} must be a 1 to 64 character identifier")
    return value.strip()


def _integer(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be an integer")
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


def _channel_frequency(band: str, channel: int) -> float:
    if band == "2.4GHz" and 1 <= channel <= 14:
        return 2484.0 if channel == 14 else 2407.0 + 5.0 * channel
    if band == "5GHz" and 32 <= channel <= 177:
        return 5000.0 + 5.0 * channel
    if band == "6GHz" and channel == 2:
        return 5935.0
    if band == "6GHz" and 1 <= channel <= 233:
        return 5950.0 + 5.0 * channel
    raise ValueError(f"channel {channel} is outside the supported {band} range")


def _normalise_radio(value: object, index: int) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"radios[{index}] must be an object")
    radio_id = _identifier(value.get("radio_id"), f"radios[{index}].radio_id")
    ap_id = _identifier(value.get("ap_id"), f"radios[{index}].ap_id")
    site_id = _identifier(value.get("site_id"), f"radios[{index}].site_id")
    band = value.get("band")
    if not isinstance(band, str) or band not in VALID_BANDS:
        raise ValueError(f"radios[{index}].band must be one of {sorted(VALID_BANDS)}")
    width = _integer(value.get("channel_width_mhz"), f"radios[{index}].channel_width_mhz")
    if width not in WIDTHS or (band == "2.4GHz" and width not in {20, 40}) or (band == "5GHz" and width == 320):
        raise ValueError(f"radios[{index}].channel_width_mhz is not supported for {band}")

    options = value.get("channel_options")
    if not isinstance(options, list) or not 1 <= len(options) <= MAX_CHANNEL_OPTIONS:
        raise ValueError(f"radios[{index}].channel_options must contain 1 to {MAX_CHANNEL_OPTIONS} options")
    seen_channels = set()
    normalised_options = []
    for option_index, option in enumerate(options):
        field = f"radios[{index}].channel_options[{option_index}]"
        if isinstance(option, int) and not isinstance(option, bool):
            channel = option
            explicit_frequency = None
        elif isinstance(option, dict):
            channel = _integer(option.get("channel"), f"{field}.channel")
            explicit_frequency = option.get("center_frequency_mhz")
        else:
            raise ValueError(f"{field} must be a channel integer or an option object")
        if channel in seen_channels:
            raise ValueError(f"radios[{index}].channel_options must not contain duplicate channels")
        seen_channels.add(channel)
        nominal_frequency = _channel_frequency(band, channel)
        if band == "2.4GHz" and channel == 14 and width != 20:
            raise ValueError("2.4 GHz channel 14 is supported only at 20 MHz")
        if explicit_frequency is None:
            if width != 20:
                raise ValueError(f"{field}.center_frequency_mhz is required for widths above 20 MHz")
            center_frequency = nominal_frequency
        else:
            center_frequency = _number(
                explicit_frequency, f"{field}.center_frequency_mhz",
                2300.0 if band == "2.4GHz" else 4900.0 if band == "5GHz" else 5900.0,
                2600.0 if band == "2.4GHz" else 6000.0 if band == "5GHz" else 7200.0,
            )
            if width == 20 and abs(center_frequency - nominal_frequency) > 0.5:
                raise ValueError(f"{field}.center_frequency_mhz must match the 20 MHz channel centre")
        normalised_options.append({"channel": channel, "center_frequency_mhz": round(center_frequency, 3)})

    current_channel = value.get("current_channel")
    if current_channel is not None:
        current_channel = _integer(current_channel, f"radios[{index}].current_channel")
        _channel_frequency(band, current_channel)
    return {
        "radio_id": radio_id, "ap_id": ap_id, "site_id": site_id, "band": band,
        "channel_width_mhz": width,
        "channel_options": sorted(normalised_options, key=lambda item: (item["channel"], item["center_frequency_mhz"])),
        "current_channel": current_channel,
    }


def _overlap_fraction(left: dict, left_option: dict, right: dict, right_option: dict) -> float:
    if left["site_id"] != right["site_id"] or left["band"] != right["band"]:
        return 0.0
    left_center = left_option["center_frequency_mhz"]
    right_center = right_option["center_frequency_mhz"]
    left_width = left["channel_width_mhz"]
    right_width = right["channel_width_mhz"]
    overlap = min(left_center + left_width / 2, right_center + right_width / 2) - max(
        left_center - left_width / 2, right_center - right_width / 2
    )
    return 0.0 if overlap <= 0 else min(1.0, overlap / min(left_width, right_width))


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    radio_values = payload.get("radios")
    edge_values = payload.get("interference_edges", [])
    if not isinstance(radio_values, list) or not 1 <= len(radio_values) <= MAX_RADIOS:
        raise ValueError(f"radios must contain 1 to {MAX_RADIOS} records")
    if not isinstance(edge_values, list) or len(edge_values) > MAX_EDGES:
        raise ValueError(f"interference_edges must contain no more than {MAX_EDGES} records")
    change_penalty = _number(payload.get("change_penalty", 0.05), "change_penalty", 0.0, 0.5)

    radios = {}
    for index, value in enumerate(radio_values):
        radio = _normalise_radio(value, index)
        if radio["radio_id"] in radios:
            raise ValueError("radio_id values must be unique")
        radios[radio["radio_id"]] = radio

    edges = []
    seen_pairs = set()
    neighbours = {radio_id: [] for radio_id in radios}
    for index, value in enumerate(edge_values):
        if not isinstance(value, dict):
            raise ValueError(f"interference_edges[{index}] must be an object")
        radio_ids = value.get("radio_ids")
        if not isinstance(radio_ids, list) or len(radio_ids) != 2:
            raise ValueError(f"interference_edges[{index}].radio_ids must contain exactly two radio IDs")
        left_id = _identifier(radio_ids[0], f"interference_edges[{index}].radio_ids[0]")
        right_id = _identifier(radio_ids[1], f"interference_edges[{index}].radio_ids[1]")
        if left_id == right_id:
            raise ValueError("an interference edge must reference two different radios")
        if left_id not in radios or right_id not in radios:
            raise ValueError("an interference edge references an unknown radio")
        left, right = radios[left_id], radios[right_id]
        if left["site_id"] != right["site_id"] or left["band"] != right["band"]:
            raise ValueError("interference edges must join radios in the same site and band")
        pair = tuple(sorted((left_id, right_id)))
        if pair in seen_pairs:
            raise ValueError("interference edge pairs must be unique")
        seen_pairs.add(pair)
        weight = _number(value.get("weight"), f"interference_edges[{index}].weight", 0.0, 1.0)
        source = value.get("evidence_source")
        if not isinstance(source, str) or source not in EVIDENCE_SOURCES:
            raise ValueError(f"interference_edges[{index}].evidence_source must be one of {sorted(EVIDENCE_SOURCES)}")
        edge = {"radio_ids": [pair[0], pair[1]], "weight": weight, "evidence_source": source}
        edges.append(edge)
        neighbours[left_id].append((right_id, weight))
        neighbours[right_id].append((left_id, weight))

    if not edges:
        return {
            "status": "insufficient_interference_evidence",
            "radio_count": len(radios),
            "evidence_edge_count": 0,
            "assignments": [{
                "radio_id": radio["radio_id"], "ap_id": radio["ap_id"], "site_id": radio["site_id"],
                "band": radio["band"], "current_channel": radio["current_channel"],
                "recommended_channel": None, "status": "not_planned",
            } for radio in sorted(radios.values(), key=lambda item: item["radio_id"])],
            "note": (
                "No explicit RF interference relationships were supplied. The planner does not infer "
                "AP proximity or interference from names, channel counts or fabricated measurements."
            ),
        }

    order = sorted(radios, key=lambda radio_id: (
        -sum(weight for _, weight in neighbours[radio_id]),
        len(radios[radio_id]["channel_options"]),
        radio_id,
    ))
    assignments = {}

    def candidate_cost(radio_id: str, option: dict) -> tuple[float, float]:
        radio = radios[radio_id]
        interference_cost = sum(
            weight * _overlap_fraction(radio, option, radios[other_id], assignments[other_id])
            for other_id, weight in neighbours[radio_id] if other_id in assignments
        )
        change_cost = change_penalty if (
            radio["current_channel"] is not None and option["channel"] != radio["current_channel"]
        ) else 0.0
        return interference_cost + change_cost, interference_cost

    def choose(radio_id: str) -> dict:
        radio = radios[radio_id]
        return min(radio["channel_options"], key=lambda option: (
            round(candidate_cost(radio_id, option)[0], 12),
            0 if option["channel"] == radio["current_channel"] else 1,
            option["channel"], option["center_frequency_mhz"],
        ))

    for radio_id in order:
        assignments[radio_id] = choose(radio_id)
    for _ in range(12):
        changed = False
        for radio_id in order:
            selected = choose(radio_id)
            if selected != assignments[radio_id]:
                assignments[radio_id] = selected
                changed = True
        if not changed:
            break

    baseline_available = all(
        radio["current_channel"] is not None
        and any(option["channel"] == radio["current_channel"] for option in radio["channel_options"])
        for radio in radios.values()
    )
    baseline_cost = 0.0
    planned_cost = 0.0
    conflict_edges = []
    for edge in sorted(edges, key=lambda item: item["radio_ids"]):
        left_id, right_id = edge["radio_ids"]
        left, right = radios[left_id], radios[right_id]
        left_option, right_option = assignments[left_id], assignments[right_id]
        overlap = _overlap_fraction(left, left_option, right, right_option)
        cost = edge["weight"] * overlap
        planned_cost += cost
        if baseline_available:
            left_current = next(option for option in left["channel_options"] if option["channel"] == left["current_channel"])
            right_current = next(option for option in right["channel_options"] if option["channel"] == right["current_channel"])
            baseline_cost += edge["weight"] * _overlap_fraction(left, left_current, right, right_current)
        if overlap > 0:
            conflict_edges.append({
                "radio_ids": [left_id, right_id], "ap_ids": [left["ap_id"], right["ap_id"]],
                "site_id": left["site_id"], "band": left["band"],
                "channels": [left_option["channel"], right_option["channel"]],
                "spectral_overlap_fraction": round(overlap, 4),
                "weighted_interference_cost": round(cost, 6),
                "evidence_weight": edge["weight"], "evidence_source": edge["evidence_source"],
                "type": "co_channel" if left_option["center_frequency_mhz"] == right_option["center_frequency_mhz"] else "partial_channel_overlap",
            })

    change_count = sum(
        radio["current_channel"] is not None and assignments[radio_id]["channel"] != radio["current_channel"]
        for radio_id, radio in radios.items()
    )
    assignments_out = []
    for radio_id in sorted(radios):
        radio, option = radios[radio_id], assignments[radio_id]
        incident_cost = sum(
            weight * _overlap_fraction(radio, option, radios[other_id], assignments[other_id])
            for other_id, weight in neighbours[radio_id]
        )
        changed = radio["current_channel"] is not None and option["channel"] != radio["current_channel"]
        assignments_out.append({
            "radio_id": radio_id, "ap_id": radio["ap_id"], "site_id": radio["site_id"], "band": radio["band"],
            "channel_width_mhz": radio["channel_width_mhz"], "current_channel": radio["current_channel"],
            "recommended_channel": option["channel"], "center_frequency_mhz": option["center_frequency_mhz"],
            "change_recommended": changed, "weighted_interference_cost": round(incident_cost, 6),
            "status": "change_recommended" if changed else "retain_current" if radio["current_channel"] is not None else "candidate_selected",
        })

    change_cost = change_count * change_penalty
    return {
        "status": "planned", "radio_count": len(radios), "evidence_edge_count": len(edges),
        "conflict_count": len(conflict_edges),
        "co_channel_conflict_count": sum(item["type"] == "co_channel" for item in conflict_edges),
        "partial_overlap_count": sum(item["type"] == "partial_channel_overlap" for item in conflict_edges),
        "channel_change_count": change_count,
        "baseline_interference_cost": round(baseline_cost, 6) if baseline_available else None,
        "planned_interference_cost": round(planned_cost, 6),
        "interference_cost_reduction_percent": (
            round((baseline_cost - planned_cost) / baseline_cost * 100, 2)
            if baseline_available and baseline_cost > 0 else None
        ),
        "channel_change_cost": round(change_cost, 6),
        "objective_cost": round(planned_cost + change_cost, 6),
        "assignments": assignments_out, "remaining_conflicts": conflict_edges,
        "note": (
            "This deterministic optimisation uses only supplied channel options and explicit relative "
            "interference weights. Channel options must already be validated for the deployment's regulatory "
            "domain, radio capabilities and DFS rules. The weights are not measured by this tool; the result "
            "is a planning recommendation, not a propagation simulation, spectrum measurement or compliance "
            "certification. No router configuration is changed."
        ),
    }


FEATURE = {
    "id": "F201", "slug": "multi_ap_channel_reuse_planner",
    "name": "Multi-AP RF channel reuse planner", "category": "RF planning",
    "description": (
        "Optimise channel assignments across same-site AP radios using caller-supplied regulatory channel "
        "options and explicit, weighted RF interference evidence, with a measurable baseline comparison."
    ),
    "parameters": {
        "radios": "1-256 radios, each with site/AP/radio identity, band, channel width, current channel and 1-32 regulatory-approved channel options",
        "interference_edges": "Up to 8192 same-site/same-band AP radio relationships with explicit 0-1 relative weights and survey/controller/operator provenance",
        "change_penalty": "Optional 0-0.5 penalty per changed radio to balance interference reduction and deployment churn",
    },
    "run": run,
}
