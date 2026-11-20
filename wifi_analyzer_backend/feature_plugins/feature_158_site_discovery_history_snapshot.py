"""Validate and normalise one site-scoped discovery snapshot before persistence."""
from __future__ import annotations

import json
from datetime import datetime, timezone

from .feature_150_site_topology_snapshot_diff import run as validate_topology


MAX_ACCESS_POINTS = 4096
MAX_LINKS = 8192
MAX_SNAPSHOT_BYTES = 512 * 1024


def _timestamp(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("captured_at must be an ISO-8601 timestamp with a timezone")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("captured_at must be an ISO-8601 timestamp with a timezone") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("captured_at must include a timezone offset")
    return parsed.astimezone(timezone.utc).isoformat()


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    site_id = payload.get("site_id")
    if not isinstance(site_id, str) or not site_id.strip() or len(site_id.strip()) > 128:
        raise ValueError("site_id must contain 1 to 128 non-whitespace characters")
    site_id = site_id.strip()
    captured_at = _timestamp(payload.get("captured_at"))
    access_points = payload.get("access_points", [])
    links = payload.get("links", [])
    if not isinstance(access_points, list):
        raise ValueError("access_points must be a list")
    if not isinstance(links, list):
        raise ValueError("links must be a list")
    if len(access_points) > MAX_ACCESS_POINTS:
        raise ValueError(f"access_points may contain no more than {MAX_ACCESS_POINTS} records")
    if len(links) > MAX_LINKS:
        raise ValueError(f"links may contain no more than {MAX_LINKS} records")

    normalized_aps = []
    for index, ap in enumerate(access_points):
        if not isinstance(ap, dict):
            raise ValueError(f"access_points[{index}] must be an object")
        ap_site = ap.get("site_id")
        if ap_site is not None and str(ap_site).strip() and str(ap_site).strip() != site_id:
            raise ValueError(f"access_points[{index}] belongs to a different site")
        normalized = dict(ap)
        normalized["site_id"] = site_id
        normalized_aps.append(normalized)

    normalized_links = links
    # Reuse the canonical AP/link schema and reject duplicate identifiers or invalid relationships.
    validate_topology({
        "previous": {"access_points": [], "links": []},
        "current": {"access_points": normalized_aps, "links": normalized_links},
    })
    snapshot = {
        "site_id": site_id,
        "captured_at": captured_at,
        "access_points": normalized_aps,
        "links": normalized_links,
    }
    try:
        encoded_size = len(json.dumps(snapshot, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8"))
    except (TypeError, ValueError) as error:
        raise ValueError("snapshot must contain JSON-compatible finite values") from error
    if encoded_size > MAX_SNAPSHOT_BYTES:
        raise ValueError(f"snapshot exceeds the {MAX_SNAPSHOT_BYTES}-byte limit")

    return {
        **snapshot,
        "access_point_count": len(normalized_aps),
        "link_count": len(normalized_links),
        "snapshot_bytes": encoded_size,
    }


FEATURE = {
    "id": "F158",
    "slug": "site_discovery_history_snapshot",
    "name": "Persistent site discovery history snapshot",
    "category": "Site inventory",
    "description": "Validate and normalise bounded, timestamped per-site AP and topology snapshots before they are saved to the local history database.",
    "parameters": {
        "site_id": "string",
        "captured_at": "ISO-8601",
        "access_points": "access_point[]",
        "links": "topology_link[]",
    },
    "run": run,
}
