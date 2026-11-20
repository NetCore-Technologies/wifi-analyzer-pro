"""Correlate AP management addresses with explicitly supplied site subnets.

This tool validates and joins inventory records only. It performs no host
discovery, reachability probing, or network configuration changes.
"""
from __future__ import annotations

import ipaddress


def _identifier(value: object, field: str) -> str:
    result = str(value or "").strip()
    if not result or len(result) > 128:
        raise ValueError(f"{field} must be a non-empty identifier up to 128 characters")
    return result


def run(payload: dict) -> dict:
    segments = payload.get("segments", [])
    access_points = payload.get("access_points", [])
    if not isinstance(segments, list) or not isinstance(access_points, list):
        raise ValueError("segments and access_points must be lists")
    if len(segments) > 4096 or len(access_points) > 2048:
        raise ValueError("site network snapshot exceeds the supported record limit")

    parsed_segments = []
    segment_ids = set()
    for item in segments:
        if not isinstance(item, dict):
            raise ValueError("Each segment must be an object")
        segment_id = _identifier(item.get("segment_id"), "segment_id")
        if segment_id in segment_ids:
            raise ValueError("segment_id values must be unique")
        segment_ids.add(segment_id)
        site_id = _identifier(item.get("site_id") or "unassigned", "site_id")
        try:
            network = ipaddress.ip_network(str(item.get("cidr") or ""), strict=False)
        except ValueError as error:
            raise ValueError("Each segment needs a valid IPv4 or IPv6 CIDR") from error

        gateway = None
        if item.get("gateway_ip") is not None:
            try:
                gateway = ipaddress.ip_address(str(item["gateway_ip"]))
            except ValueError as error:
                raise ValueError("gateway_ip must be a valid IPv4 or IPv6 address") from error
            if gateway.version != network.version or gateway not in network:
                raise ValueError("gateway_ip must belong to the segment CIDR")

        parsed_segments.append({
            "segment_id": segment_id,
            "site_id": site_id,
            "name": str(item.get("name") or segment_id),
            "network": network,
            "gateway_ip": str(gateway) if gateway is not None else None,
            "vlan_id": item.get("vlan_id"),
        })

    overlaps = []
    for index, left in enumerate(parsed_segments):
        for right in parsed_segments[index + 1:]:
            if left["site_id"] == right["site_id"] and left["network"].version == right["network"].version and left["network"].overlaps(right["network"]):
                overlaps.append({
                    "site_id": left["site_id"],
                    "segment_ids": [left["segment_id"], right["segment_id"]],
                    "cidrs": [str(left["network"]), str(right["network"])],
                    "relationship": "duplicate" if left["network"] == right["network"] else "overlap",
                })

    aps = []
    ap_ids = set()
    for ap in access_points:
        if not isinstance(ap, dict):
            raise ValueError("Each access point must be an object")
        ap_id = _identifier(ap.get("ap_id"), "ap_id")
        if ap_id in ap_ids:
            raise ValueError("ap_id values must be unique")
        ap_ids.add(ap_id)
        site_id = _identifier(ap.get("site_id") or "unassigned", "site_id")
        raw_ip = ap.get("management_ip")
        if raw_ip is None:
            aps.append({
                "ap_id": ap_id, "site_id": site_id, "management_ip": None,
                "matching_segments": [], "matched_segment_id": None,
                "status": "missing_management_ip",
            })
            continue
        try:
            address = ipaddress.ip_address(str(raw_ip))
        except ValueError as error:
            raise ValueError(f"Invalid management_ip for AP {ap_id}") from error

        matches = [
            segment for segment in parsed_segments
            if segment["site_id"] == site_id
            and segment["network"].version == address.version
            and address in segment["network"]
        ]
        aps.append({
            "ap_id": ap_id,
            "site_id": site_id,
            "management_ip": str(address),
            "matching_segments": [segment["segment_id"] for segment in matches],
            "matched_segment_id": matches[0]["segment_id"] if len(matches) == 1 else None,
            "status": "matched" if len(matches) == 1 else "ambiguous" if matches else "unmatched",
        })

    counts = {"matched": 0, "ambiguous": 0, "unmatched": 0, "missing_management_ip": 0}
    for ap in aps:
        counts[ap["status"]] += 1
    by_segment = {segment["segment_id"]: 0 for segment in parsed_segments}
    for ap in aps:
        if ap["status"] == "matched":
            by_segment[ap["matched_segment_id"]] += 1

    return {
        "segment_count": len(parsed_segments),
        "access_point_count": len(aps),
        "access_points_by_match_status": counts,
        "access_points_by_segment": by_segment,
        "overlapping_segments": overlaps,
        "overlap_count": len(overlaps),
        "segments": [
            {"segment_id": item["segment_id"], "site_id": item["site_id"],
             "name": item["name"], "cidr": str(item["network"]),
             "address_family": item["network"].version,
             "gateway_ip": item["gateway_ip"], "vlan_id": item["vlan_id"]}
            for item in parsed_segments
        ],
        "access_points": aps,
        "note": (
            "AP membership is matched only when exactly one same-site supplied CIDR contains the management IP. "
            "Overlapping networks are surfaced as ambiguity rather than arbitrarily assigning a segment."
        ),
    }


FEATURE = {
    "id": "F143",
    "slug": "site_network_segment_correlation",
    "name": "Site subnet and gateway correlation",
    "category": "Site inventory",
    "description": "Match AP management IPs to explicit site CIDRs, validate gateways, and report duplicate or overlapping segments.",
    "parameters": {"segments": "network_segment[]", "access_points": "access_point[]"},
    "run": run,
}
