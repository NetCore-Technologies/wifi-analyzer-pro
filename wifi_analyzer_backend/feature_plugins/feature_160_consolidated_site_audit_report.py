"""Consolidate supported site inventory, topology and service-readiness audits."""
from __future__ import annotations

import re
from collections import Counter

from .feature_141_site_inventory_snapshot import run as inventory_snapshot
from .feature_142_ap_topology_relationships import run as topology_relationships
from .feature_146_site_network_segment_capacity import run as segment_capacity
from .feature_147_site_gateway_redundancy_audit import run as gateway_redundancy
from .feature_149_site_topology_redundancy_audit import run as topology_redundancy
from .feature_151_site_inventory_comparison import run as inventory_comparison
from .feature_155_site_topology_gateway_path_audit import run as gateway_path_audit
from .feature_156_site_radio_configuration_audit import run as radio_configuration_audit
from .feature_159_site_to_site_change_report import run as site_change_report

MAX_SITES = 20
MAX_ACCESS_POINTS = 4096
MAX_LINKS = 8192
MAX_RADIOS = 8192
MAX_GATEWAYS = 512
MAX_SEGMENTS = 512
BSSID_PATTERN = re.compile(r"^[0-9A-F]{2}(?::[0-9A-F]{2}){5}$")


def _records(site: dict, field: str, limit: int) -> list:
    value = site.get(field, [])
    if not isinstance(value, list) or len(value) > limit:
        raise ValueError(f"{field} must be a list containing no more than {limit} records")
    return value


def _not_run(reason: str) -> dict:
    return {"status": "not_run", "reason": reason}


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    sites = payload.get("sites", [])
    if not isinstance(sites, list) or len(sites) > MAX_SITES:
        raise ValueError(f"sites must be a list containing no more than {MAX_SITES} sites")

    seen_sites = set()
    site_reports = []
    all_access_points = []
    findings = []
    check_counts = Counter()

    for index, site in enumerate(sites):
        if not isinstance(site, dict):
            raise ValueError(f"sites[{index}] must be an object")
        site_id = site.get("site_id")
        if not isinstance(site_id, str) or not site_id.strip() or len(site_id.strip()) > 128:
            raise ValueError(f"sites[{index}].site_id must contain 1 to 128 characters")
        site_id = site_id.strip()
        if site_id in seen_sites:
            raise ValueError("site_id values must be unique")
        seen_sites.add(site_id)

        access_points = _records(site, "access_points", MAX_ACCESS_POINTS)
        links = _records(site, "links", MAX_LINKS)
        radios = _records(site, "radios", MAX_RADIOS)
        radio_standards = _records(site, "radio_standards", MAX_RADIOS)
        gateways = _records(site, "gateways", MAX_GATEWAYS)
        segments = _records(site, "segments", MAX_SEGMENTS)
        gateway_ap_ids = site.get("gateway_ap_ids", [])
        if not isinstance(gateway_ap_ids, list) or len(gateway_ap_ids) > MAX_ACCESS_POINTS:
            raise ValueError("gateway_ap_ids must be a bounded list")

        normalised_aps = []
        for ap_index, ap in enumerate(access_points):
            if not isinstance(ap, dict):
                raise ValueError(f"sites[{index}].access_points[{ap_index}] must be an object")
            ap_site_id = ap.get("site_id")
            if ap_site_id is not None and str(ap_site_id).strip() not in ("", site_id):
                raise ValueError(f"sites[{index}].access_points[{ap_index}] belongs to a different site")
            normalised = dict(ap)
            normalised["site_id"] = site_id
            normalised_aps.append(normalised)
        all_access_points.extend(normalised_aps)

        inventory_ready = all(
            BSSID_PATTERN.fullmatch(str(ap.get("bssid") or "").replace("-", ":").upper())
            for ap in normalised_aps
        )
        if inventory_ready:
            inventory = inventory_snapshot({"site_id": site_id, "access_points": normalised_aps})
            inventory_check = {"status": "complete", "result": inventory}
            check_counts["inventory"] += 1
        else:
            inventory_check = _not_run("A valid BSSID is required for every AP before the inventory snapshot check can run")
        topology_ready = all(
            isinstance(ap.get("ap_id"), str) and ap["ap_id"].strip()
            for ap in normalised_aps
        )
        if topology_ready:
            topology = topology_relationships({"access_points": normalised_aps, "links": links})
            redundancy = topology_redundancy({"access_points": normalised_aps, "links": links})
            check_counts.update(("topology_relationships", "topology_redundancy"))
            topology_check = {"status": "complete", "result": topology}
            redundancy_check = {"status": "complete", "result": redundancy}
        else:
            reason = "Every AP needs a stable ap_id before topology checks can run"
            topology_check = _not_run(reason)
            redundancy_check = _not_run(reason)

        if topology_ready and gateway_ap_ids:
            gateway_paths = gateway_path_audit({
                "access_points": normalised_aps,
                "links": links,
                "gateway_ap_ids": gateway_ap_ids,
            })
            gateway_paths_check = {"status": "complete", "result": gateway_paths}
            check_counts["gateway_paths"] += 1
        else:
            gateway_paths_check = _not_run(
                "Supply stable AP identifiers and at least one gateway_ap_id to evaluate paths"
            )

        if radios or radio_standards:
            radio_audit = radio_configuration_audit({"radios": radios, "standards": radio_standards})
            radio_check = {"status": "complete", "result": radio_audit}
            check_counts["radio_configuration"] += 1
        else:
            radio_check = _not_run("No radio observations or explicit radio standards were supplied")

        if gateways:
            gateway_audit = gateway_redundancy({"gateways": gateways})
            gateway_check = {"status": "complete", "result": gateway_audit}
            check_counts["gateway_redundancy"] += 1
        else:
            gateway_check = _not_run("No gateway failover records were supplied")

        if segments:
            capacity_audit = segment_capacity({"segments": segments})
            capacity_check = {"status": "complete", "result": capacity_audit}
            check_counts["segment_capacity"] += 1
        else:
            capacity_check = _not_run("No network segment allocation records were supplied")

        checks = {
            "inventory": inventory_check,
            "topology_relationships": topology_check,
            "topology_redundancy": redundancy_check,
            "gateway_paths": gateway_paths_check,
            "radio_configuration": radio_check,
            "gateway_redundancy": gateway_check,
            "segment_capacity": capacity_check,
        }
        for check_name, check in checks.items():
            if check.get("status") == "not_run":
                check_counts[f"{check_name}_not_run"] += 1

        if redundancy_check["status"] == "complete":
            result = redundancy_check["result"]
            if result.get("status") == "review":
                findings.append({
                    "severity": "warning",
                    "site_id": site_id,
                    "check": "topology_redundancy",
                    "message": "The supplied backhaul graph contains one or more cut links, articulation APs or unresolved relationships.",
                })
        if gateway_paths_check["status"] == "complete":
            result = gateway_paths_check["result"]
            if result.get("summary", {}).get("unreachable_count", 0):
                findings.append({
                    "severity": "warning",
                    "site_id": site_id,
                    "check": "gateway_paths",
                    "message": "One or more supplied APs have no confirmed backhaul path to the listed gateway.",
                })
        if radio_check["status"] == "complete":
            result = radio_check["result"]
            if result.get("deviation_count", 0):
                findings.append({
                    "severity": "warning",
                    "site_id": site_id,
                    "check": "radio_configuration",
                    "message": f"{result['deviation_count']} radio configuration(s) differ from the supplied site/band standards.",
                })
        if gateway_check["status"] == "complete":
            result = gateway_check["result"]
            for group in result.get("groups", []):
                if group.get("issues"):
                    findings.append({
                        "severity": "warning",
                        "site_id": site_id,
                        "check": "gateway_redundancy",
                        "message": f"Gateway redundancy group {group.get('group_id', 'unknown')} has reported issues.",
                    })
        if capacity_check["status"] == "complete":
            result = capacity_check["result"]
            for segment in result.get("segments", []):
                if segment.get("status") in {"warning", "critical"}:
                    findings.append({
                        "severity": "critical" if segment["status"] == "critical" else "warning",
                        "site_id": site_id,
                        "check": "segment_capacity",
                        "message": f"Network segment {segment.get('segment_id', segment.get('cidr', 'unknown'))} is at {segment['status']} capacity.",
                    })

        site_reports.append({
            "site_id": site_id,
            "access_point_count": len(normalised_aps),
            "link_count": len(links),
            "radio_count": len(radios),
            "gateway_record_count": len(gateways),
            "network_segment_count": len(segments),
            "checks": checks,
        })

    cross_site_inventory = _not_run("No site AP inventory was supplied")
    if all_access_points:
        complete_bssids = all(
            BSSID_PATTERN.fullmatch(str(ap.get("bssid") or "").replace("-", ":").upper())
            for ap in all_access_points
        )
        if complete_bssids:
            cross_site_inventory = {
                "status": "complete",
                "result": inventory_comparison({"access_points": all_access_points}),
            }
            check_counts["cross_site_inventory"] += 1
        else:
            cross_site_inventory = _not_run(
                "Cross-site BSSID comparison needs a valid BSSID on every AP; individual site audits still run."
            )
    if cross_site_inventory["status"] == "not_run":
        check_counts["cross_site_inventory_not_run"] += 1

    history_sites = payload.get("history_sites")
    if history_sites is not None:
        history_audit = {"status": "complete", "result": site_change_report({"sites": history_sites})}
        check_counts["site_history"] += 1
    else:
        history_audit = _not_run("No persisted history pairs were supplied to this audit request")
        check_counts["site_history_not_run"] += 1

    severity_counts = Counter(item["severity"] for item in findings)
    skipped = sum(value for key, value in check_counts.items() if key.endswith("_not_run"))
    completed = sum(value for key, value in check_counts.items() if not key.endswith("_not_run"))
    return {
        "summary": {
            "site_count": len(site_reports),
            "access_point_count": len(all_access_points),
            "finding_count": len(findings),
            "warning_count": severity_counts["warning"],
            "critical_count": severity_counts["critical"],
            "completed_check_count": completed,
            "not_run_check_count": skipped,
        },
        "sites": site_reports,
        "cross_site_inventory": cross_site_inventory,
        "site_history": history_audit,
        "findings": findings,
        "note": (
            "The report combines only supplied inventory, topology, gateway, radio, subnet and history evidence. "
            "A not_run check means its required inputs were absent or incomplete; it is not a pass. "
            "Warnings and critical findings are review prompts, not proof of an outage or compromise."
        ),
    }


FEATURE = {
    "id": "F160",
    "slug": "consolidated_site_audit_report",
    "name": "Consolidated site audit report",
    "category": "Site inventory",
    "description": "Combine per-site AP inventory, topology redundancy, gateway paths and failover, radio standards, subnet capacity and optional stored-history comparisons into one evidence-based audit report.",
    "parameters": {"sites": "site_audit[]", "history_sites": "site_snapshot_pair[]"},
    "run": run,
}
