"""Compare AP inventory composition across explicitly named sites."""
from __future__ import annotations

from collections import Counter


def run(payload: dict) -> dict:
    access_points = payload.get("access_points", [])
    if not isinstance(access_points, list):
        raise ValueError("'access_points' must be a list")
    if len(access_points) > 8192:
        raise ValueError("'access_points' may contain no more than 8192 records")

    sites = {}
    seen = {}
    for ap in access_points:
        if not isinstance(ap, dict) or not ap.get("bssid") or not ap.get("site_id"):
            raise ValueError("Each AP needs bssid and site_id")
        bssid = str(ap["bssid"]).replace("-", ":").upper()
        site_id = str(ap["site_id"]).strip()
        if not site_id:
            raise ValueError("site_id must not be empty")
        seen.setdefault(bssid, set()).add(site_id)
        site = sites.setdefault(site_id, {
            "ap_count": 0, "bands": Counter(), "vendors": Counter(),
            "models": Counter(), "firmware_versions": Counter(),
        })
        site["ap_count"] += 1
        for key, counter in (("band", "bands"), ("vendor", "vendors"), ("model", "models"), ("firmware_version", "firmware_versions")):
            value = str(ap.get(key) or "").strip()
            if value:
                site[counter][value] += 1

    summaries = []
    for site_id, site in sorted(sites.items()):
        summaries.append({
            "site_id": site_id,
            "ap_count": site["ap_count"],
            "bands": dict(sorted(site["bands"].items())),
            "vendors": dict(sorted(site["vendors"].items())),
            "models": dict(sorted(site["models"].items())),
            "firmware_versions": dict(sorted(site["firmware_versions"].items())),
            "metadata_coverage": {
                field: sum(counter.values())
                for field, counter in (
                    ("band", site["bands"]), ("vendor", site["vendors"]),
                    ("model", site["models"]), ("firmware_version", site["firmware_versions"])
                )
            },
        })
    collisions = [
        {"bssid": bssid, "site_ids": sorted(site_ids)}
        for bssid, site_ids in sorted(seen.items()) if len(site_ids) > 1
    ]
    all_bands = sorted({band for site in sites.values() for band in site["bands"]})
    all_vendors = sorted({vendor for site in sites.values() for vendor in site["vendors"]})
    all_models = sorted({model for site in sites.values() for model in site["models"]})
    return {
        "site_count": len(summaries),
        "access_point_count": len(access_points),
        "sites": summaries,
        "cross_site_comparison": {
            "bands_observed": all_bands,
            "vendors_observed": all_vendors,
            "models_observed": all_models,
            "sites_missing_each_band": {
                band: [site["site_id"] for site in summaries if band not in site["bands"]]
                for band in all_bands
            },
        },
        "cross_site_bssid_collisions": collisions,
        "collision_count": len(collisions),
        "note": (
            "Differences between sites are descriptive, not automatically faults. "
            "BSSID reuse across sites is flagged for review and may reflect a copied or synthetic inventory record."
        ),
    }


FEATURE = {
    "id": "F151",
    "slug": "site_inventory_comparison",
    "name": "Multi-site AP inventory comparison",
    "category": "Site inventory",
    "description": "Compare AP counts, bands, vendors, models and firmware distribution across sites and flag cross-site BSSID reuse.",
    "parameters": {"access_points": "access_point[]"},
    "run": run,
}
