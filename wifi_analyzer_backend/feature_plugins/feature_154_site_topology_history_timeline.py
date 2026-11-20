"""Summarise topology changes across a bounded sequence of caller-supplied snapshots."""
from __future__ import annotations

from datetime import datetime, timezone

from .feature_150_site_topology_snapshot_diff import run as compare_topology


MAX_SNAPSHOTS = 256
MAX_ACCESS_POINTS_PER_SNAPSHOT = 4096
MAX_LINKS_PER_SNAPSHOT = 8192
MAX_TOTAL_RECORDS = 65536


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be an ISO-8601 timestamp with a timezone")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field} must be an ISO-8601 timestamp with a timezone") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone offset")
    return parsed.astimezone(timezone.utc)


def run(payload: dict) -> dict:
    snapshots = payload.get("snapshots", [])
    if not isinstance(snapshots, list):
        raise ValueError("'snapshots' must be a list")
    if len(snapshots) > MAX_SNAPSHOTS:
        raise ValueError(f"'snapshots' may contain no more than {MAX_SNAPSHOTS} records")

    normalized = []
    previous_time = None
    total_records = 0
    for index, snapshot in enumerate(snapshots):
        field = f"snapshots[{index}]"
        if not isinstance(snapshot, dict):
            raise ValueError(f"{field} must be an object")
        captured_at = _timestamp(snapshot.get("captured_at"), f"{field}.captured_at")
        if previous_time is not None and captured_at <= previous_time:
            raise ValueError("snapshot timestamps must be strictly increasing")
        previous_time = captured_at

        access_points = snapshot.get("access_points", [])
        links = snapshot.get("links", [])
        if not isinstance(access_points, list):
            raise ValueError(f"{field}.access_points must be a list")
        if not isinstance(links, list):
            raise ValueError(f"{field}.links must be a list")
        if len(access_points) > MAX_ACCESS_POINTS_PER_SNAPSHOT:
            raise ValueError(f"{field}.access_points may contain no more than {MAX_ACCESS_POINTS_PER_SNAPSHOT} records")
        if len(links) > MAX_LINKS_PER_SNAPSHOT:
            raise ValueError(f"{field}.links may contain no more than {MAX_LINKS_PER_SNAPSHOT} records")
        total_records += len(access_points) + len(links)
        if total_records > MAX_TOTAL_RECORDS:
            raise ValueError(f"All snapshots combined may contain no more than {MAX_TOTAL_RECORDS} AP and link records")

        # Reuse the canonical topology validator even for a one-snapshot timeline.
        compare_topology({
            "previous": {"access_points": [], "links": []},
            "current": {"access_points": access_points, "links": links},
        })
        normalized.append({
            "captured_at": captured_at,
            "snapshot": {"access_points": access_points, "links": links},
            "access_point_count": len(access_points),
            "link_count": len(links),
        })

    change_windows = []
    totals = {
        "added_access_point_count": 0,
        "removed_access_point_count": 0,
        "changed_access_point_count": 0,
        "added_link_count": 0,
        "removed_link_count": 0,
        "total_topology_changes": 0,
    }
    for previous, current in zip(normalized, normalized[1:]):
        difference = compare_topology({
            "previous": previous["snapshot"],
            "current": current["snapshot"],
        })
        added_aps = difference["added_access_points"]
        removed_aps = difference["removed_access_points"]
        changed_aps = difference["changed_access_points"]
        added_links = difference["added_links"]
        removed_links = difference["removed_links"]
        change_count = difference["topology_change_count"]

        totals["added_access_point_count"] += len(added_aps)
        totals["removed_access_point_count"] += len(removed_aps)
        totals["changed_access_point_count"] += len(changed_aps)
        totals["added_link_count"] += len(added_links)
        totals["removed_link_count"] += len(removed_links)
        totals["total_topology_changes"] += change_count

        change_windows.append({
            "from_timestamp": previous["captured_at"].isoformat(),
            "to_timestamp": current["captured_at"].isoformat(),
            "interval_seconds": round((current["captured_at"] - previous["captured_at"]).total_seconds(), 3),
            "access_point_delta": current["access_point_count"] - previous["access_point_count"],
            "link_delta": current["link_count"] - previous["link_count"],
            "change_count": change_count,
            "added_access_points": added_aps,
            "removed_access_points": removed_aps,
            "changed_access_points": changed_aps,
            "added_links": added_links,
            "removed_links": removed_links,
        })

    snapshot_summaries = [
        {
            "captured_at": item["captured_at"].isoformat(),
            "access_point_count": item["access_point_count"],
            "link_count": item["link_count"],
        }
        for item in normalized
    ]
    span_seconds = (
        (normalized[-1]["captured_at"] - normalized[0]["captured_at"]).total_seconds()
        if len(normalized) > 1 else 0.0
    )
    return {
        "summary": {
            "snapshot_count": len(normalized),
            "comparison_count": len(change_windows),
            "unchanged_window_count": sum(item["change_count"] == 0 for item in change_windows),
            "observed_span_seconds": round(span_seconds, 3),
            **totals,
        },
        "snapshots": snapshot_summaries,
        "change_windows": change_windows,
        "note": (
            "This timeline compares only the snapshots supplied in this request. "
            "It does not collect telemetry or persist history; changes are observed differences, not proof of an outage or cause."
        ),
    }


FEATURE = {
    "id": "F154",
    "slug": "site_topology_history_timeline",
    "name": "Site topology history timeline",
    "category": "Site inventory",
    "description": "Summarise AP and topology-link changes across up to 256 timestamped site snapshots.",
    "parameters": {"snapshots": "timestamped topology_snapshot[]"},
    "run": run,
}
