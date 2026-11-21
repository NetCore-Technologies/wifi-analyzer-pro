"""Correlate explicit client roam transactions from controller/agent event exports.

Only explicit roam_start/roam_complete/roam_failure timestamps are timed.
Snapshot gaps, unmatched events and unobserved handoff details remain unknown.
"""
from __future__ import annotations

import json
import math
import re
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone

MAX_INPUT_BYTES = 1024 * 1024
MAX_EVENTS = 10000
MAX_CLIENTS = 4096
MAX_TRANSACTIONS = 8192
MAX_DETAIL_RECORDS = 500
MAX_FUTURE_SKEW_SECONDS = 300
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
EVENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
EVENT_TYPES = {"association", "disassociation", "roam_start", "roam_complete", "roam_failure"}
EVIDENCE_SOURCES = {"controller", "agent", "client", "import"}


def _identifier(value: object, field: str, *, short: bool = False) -> str:
    pattern = EVENT_ID if short else IDENTIFIER
    maximum = 64 if short else 128
    if not isinstance(value, str) or not pattern.fullmatch(value.strip()):
        raise ValueError(f"{field} must be a valid 1 to {maximum} character identifier")
    return value.strip()


def _timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must be timezone-aware and include a timezone offset")
    return parsed.astimezone(timezone.utc)


def _reason(value: object, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > 128:
        raise ValueError(f"{field} must be a string of at most 128 characters")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(f"{field} contains invalid control characters")
    return value.strip() or None


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return round(ordered[index], 2)


def _normalise_event(value: object, index: int, seen_event_ids: set[str], now: datetime) -> dict:
    field = f"events[{index}]"
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    event_id = _identifier(value.get("event_id"), f"{field}.event_id", short=True)
    if event_id in seen_event_ids:
        raise ValueError("event_id values must be unique")
    seen_event_ids.add(event_id)

    site_id = _identifier(value.get("site_id"), f"{field}.site_id", short=True)
    client_ref = _identifier(value.get("client_ref"), f"{field}.client_ref")
    event_type = value.get("event_type")
    if not isinstance(event_type, str) or event_type not in EVENT_TYPES:
        raise ValueError(f"{field}.event_type must be one of {sorted(EVENT_TYPES)}")
    source = value.get("evidence_source")
    if not isinstance(source, str) or source not in EVIDENCE_SOURCES:
        raise ValueError(f"{field}.evidence_source must be one of {sorted(EVIDENCE_SOURCES)}")
    occurred_at = _timestamp(value.get("occurred_at"), f"{field}.occurred_at")
    if (occurred_at - now).total_seconds() > MAX_FUTURE_SKEW_SECONDS:
        raise ValueError(f"{field}.occurred_at is too far in the future")

    event = {
        "event_id": event_id,
        "site_id": site_id,
        "client_ref": client_ref,
        "event_type": event_type,
        "evidence_source": source,
        "occurred_at": occurred_at,
    }
    if event_type in {"association", "disassociation"}:
        event["ap_id"] = _identifier(value.get("ap_id"), f"{field}.ap_id", short=True)
        reason_code = value.get("reason_code")
        if reason_code is not None:
            if isinstance(reason_code, bool) or not isinstance(reason_code, int) or not 0 <= reason_code <= 65535:
                raise ValueError(f"{field}.reason_code must be an integer from 0 to 65535")
        if event_type == "association" and reason_code is not None:
            raise ValueError(f"{field}.reason_code is only valid for disassociation events")
        event["reason_code"] = reason_code
        event["reason"] = _reason(value.get("reason"), f"{field}.reason")
        return event

    event["roam_id"] = _identifier(value.get("roam_id"), f"{field}.roam_id", short=True)
    if event_type == "roam_start":
        event["from_ap_id"] = _identifier(value.get("from_ap_id"), f"{field}.from_ap_id", short=True)
        event["to_ap_id"] = _identifier(value.get("to_ap_id"), f"{field}.to_ap_id", short=True)
        if event["from_ap_id"] == event["to_ap_id"]:
            raise ValueError(f"{field} must identify two different access points")
    else:
        from_ap = value.get("from_ap_id")
        to_ap = value.get("to_ap_id")
        if (from_ap is None) != (to_ap is None):
            raise ValueError(f"{field} must supply both from_ap_id and to_ap_id, or neither")
        event["from_ap_id"] = _identifier(from_ap, f"{field}.from_ap_id", short=True) if from_ap is not None else None
        event["to_ap_id"] = _identifier(to_ap, f"{field}.to_ap_id", short=True) if to_ap is not None else None
        if event["from_ap_id"] is not None and event["from_ap_id"] == event["to_ap_id"]:
            raise ValueError(f"{field} must identify two different access points")
    reason_code = value.get("reason_code")
    if reason_code is not None:
        if isinstance(reason_code, bool) or not isinstance(reason_code, int) or not 0 <= reason_code <= 65535:
            raise ValueError(f"{field}.reason_code must be an integer from 0 to 65535")
    if event_type == "roam_complete" and reason_code is not None:
        raise ValueError(f"{field}.reason_code is only valid for failure or disassociation events")
    event["reason_code"] = reason_code
    event["reason"] = _reason(value.get("reason"), f"{field}.reason")
    return event


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    try:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError("roaming input must contain JSON-compatible finite values") from error
    if len(encoded.encode("utf-8")) > MAX_INPUT_BYTES:
        raise ValueError(f"roaming input exceeds the {MAX_INPUT_BYTES}-byte input limit")

    raw_events = payload.get("events")
    if not isinstance(raw_events, list) or not 1 <= len(raw_events) <= MAX_EVENTS:
        raise ValueError(f"events must contain from 1 to {MAX_EVENTS} records")
    slow_threshold = payload.get("slow_roam_threshold_ms", 1000)
    if (isinstance(slow_threshold, bool) or not isinstance(slow_threshold, int)
            or not 50 <= slow_threshold <= 30000):
        raise ValueError("slow_roam_threshold_ms must be an integer from 50 to 30000")

    now = datetime.now(timezone.utc)
    seen_event_ids: set[str] = set()
    events = [_normalise_event(value, index, seen_event_ids, now) for index, value in enumerate(raw_events)]
    clients = sorted({(event["site_id"], event["client_ref"]) for event in events})
    if len(clients) > MAX_CLIENTS:
        raise ValueError(f"events may reference no more than {MAX_CLIENTS} site/client pairs")

    transactions: dict[tuple[str, str, str], dict[str, dict | None]] = {}
    association_counts = Counter()
    disassociation_counts = Counter()
    reason_counts = defaultdict(Counter)
    failure_reason_counts = defaultdict(Counter)
    source_counts = Counter()
    for event in events:
        source_counts[event["evidence_source"]] += 1
        if event["event_type"] == "association":
            association_counts[event["site_id"]] += 1
        elif event["event_type"] == "disassociation":
            disassociation_counts[event["site_id"]] += 1
            if event["reason_code"] is not None:
                reason_counts[event["site_id"]][str(event["reason_code"])] += 1
        else:
            key = (event["site_id"], event["client_ref"], event["roam_id"])
            group = transactions.setdefault(key, {"start": None, "terminal": None})
            slot = "start" if event["event_type"] == "roam_start" else "terminal"
            if group[slot] is not None:
                raise ValueError(f"{event['event_type']} is duplicated for one site/client/roam_id")
            group[slot] = event
    if len(transactions) > MAX_TRANSACTIONS:
        raise ValueError(f"events may contain no more than {MAX_TRANSACTIONS} roam transactions")

    aliases = {client: f"client-{index:04d}" for index, client in enumerate(clients, start=1)}
    rows = []
    for (site_id, client_ref, _roam_id), group in transactions.items():
        start = group["start"]
        terminal = group["terminal"]
        if start is None:
            status = "incomplete_missing_start"
            start_at = None
            terminal_at = terminal["occurred_at"]
            from_ap = terminal["from_ap_id"]
            to_ap = terminal["to_ap_id"]
            latency = None
            failure_duration = None
        elif terminal is None:
            status = "incomplete_missing_terminal"
            start_at = start["occurred_at"]
            terminal_at = None
            from_ap = start["from_ap_id"]
            to_ap = start["to_ap_id"]
            latency = None
            failure_duration = None
        else:
            start_at = start["occurred_at"]
            terminal_at = terminal["occurred_at"]
            from_ap = start["from_ap_id"]
            to_ap = start["to_ap_id"]
            if terminal_at < start_at:
                raise ValueError("roam terminal timestamp must not precede roam_start")
            if terminal["from_ap_id"] is not None and (
                terminal["from_ap_id"] != from_ap or terminal["to_ap_id"] != to_ap
            ):
                raise ValueError("roam terminal AP pair does not match its roam_start")
            duration_ms = round((terminal_at - start_at).total_seconds() * 1000, 2)
            if terminal["event_type"] == "roam_complete":
                status = "completed"
                latency = duration_ms
                failure_duration = None
            else:
                status = "failed"
                latency = None
                failure_duration = duration_ms
                if terminal["reason_code"] is not None:
                    failure_reason_counts[site_id][str(terminal["reason_code"])] += 1
        rows.append({
            "site_id": site_id,
            "client_ref": aliases[(site_id, client_ref)],
            "transaction_ref": f"roam-{len(rows) + 1:04d}",
            "status": status,
            "from_ap_id": from_ap,
            "to_ap_id": to_ap,
            "started_at": start_at.isoformat().replace("+00:00", "Z") if start_at else None,
            "terminal_at": terminal_at.isoformat().replace("+00:00", "Z") if terminal_at else None,
            "roam_latency_ms": latency,
            "time_to_failure_ms": failure_duration,
            "failure_reason_code": terminal["reason_code"] if terminal and status == "failed" else None,
            "failure_reason": terminal["reason"] if terminal and status == "failed" else None,
            "evidence_sources": sorted({
                event["evidence_source"] for event in (start, terminal) if event is not None
            }),
            "slow_roam": latency is not None and latency > slow_threshold,
        })

    rows.sort(key=lambda row: (row["site_id"], row["started_at"] or row["terminal_at"] or "", row["client_ref"]))
    for index, row in enumerate(rows, start=1):
        row["transaction_ref"] = f"roam-{index:04d}"

    sites = sorted({event["site_id"] for event in events})
    site_summaries = []
    for site_id in sites:
        site_rows = [row for row in rows if row["site_id"] == site_id]
        completed = [row for row in site_rows if row["status"] == "completed"]
        failed = [row for row in site_rows if row["status"] == "failed"]
        incomplete = [row for row in site_rows if row["status"].startswith("incomplete")]
        latencies = [row["roam_latency_ms"] for row in completed if row["roam_latency_ms"] is not None]
        denominator = len(completed) + len(failed)
        site_summaries.append({
            "site_id": site_id,
            "client_count": sum(client_site == site_id for client_site, _client_ref in clients),
            "transaction_count": len(site_rows),
            "completed_roams": len(completed),
            "failed_roams": len(failed),
            "incomplete_transactions": len(incomplete),
            "association_events": association_counts[site_id],
            "disassociation_events": disassociation_counts[site_id],
            "disassociation_reason_counts": dict(sorted(reason_counts[site_id].items())),
            "roam_failure_reason_counts": dict(sorted(failure_reason_counts[site_id].items())),
            "roam_failure_rate_pct": round(len(failed) / denominator * 100, 2) if denominator else None,
            "latency_sample_count": len(latencies),
            "mean_roam_latency_ms": round(statistics.mean(latencies), 2) if latencies else None,
            "median_roam_latency_ms": round(statistics.median(latencies), 2) if latencies else None,
            "p95_roam_latency_ms": _percentile(latencies, 0.95),
            "slow_roam_count": sum(row["slow_roam"] for row in completed),
        })

    completed = [row for row in rows if row["status"] == "completed"]
    failed = [row for row in rows if row["status"] == "failed"]
    incomplete = [row for row in rows if row["status"].startswith("incomplete")]
    latency_samples = [row["roam_latency_ms"] for row in completed if row["roam_latency_ms"] is not None]
    matched_count = len(completed) + len(failed)
    return {
        "status": "analysed",
        "summary": {
            "event_count": len(events),
            "site_count": len(sites),
            "client_count": len(clients),
            "transaction_count": len(rows),
            "completed_roams": len(completed),
            "failed_roams": len(failed),
            "incomplete_transactions": len(incomplete),
            "unmatched_terminal_events": sum(row["status"] == "incomplete_missing_start" for row in incomplete),
            "unmatched_start_events": sum(row["status"] == "incomplete_missing_terminal" for row in incomplete),
            "association_events": sum(association_counts.values()),
            "disassociation_events": sum(disassociation_counts.values()),
            "roam_failure_rate_pct": round(len(failed) / matched_count * 100, 2) if matched_count else None,
            "latency_sample_count": len(latency_samples),
            "mean_roam_latency_ms": round(statistics.mean(latency_samples), 2) if latency_samples else None,
            "median_roam_latency_ms": round(statistics.median(latency_samples), 2) if latency_samples else None,
            "p95_roam_latency_ms": _percentile(latency_samples, 0.95),
            "slow_roam_count": sum(row["slow_roam"] for row in completed),
        },
        "sites": site_summaries,
        "transactions": rows[:MAX_DETAIL_RECORDS],
        "details_truncated": len(rows) > MAX_DETAIL_RECORDS,
        "evidence_source_counts": dict(sorted(source_counts.items())),
        "slow_roam_threshold_ms": slow_threshold,
        "note": (
            "Only matched roam_start and roam_complete events contribute to roam-latency statistics. "
            "Only matched roam_start and roam_failure pairs contribute to the failure rate. Unpaired start "
            "or terminal events are reported as incomplete and excluded from both metrics. The tool does not "
            "infer timing from periodic association snapshots. Client references are replaced with aliases "
            "local to this report; caller-declared evidence sources are not cryptographically attested."
        ),
    }


FEATURE = {
    "id": "F291",
    "slug": "client_roam_transaction_analyzer",
    "name": "Client roam transaction analyzer",
    "category": "Roaming",
    "description": (
        "Correlate explicit per-client roam-start, roam-complete and roam-failure events to calculate "
        "successful roam latency percentiles, matched failure rates, incomplete telemetry and disassociation reasons."
    ),
    "parameters": {
        "events": "1-10000 timestamped association, disassociation and roam transaction events, scoped by site and pseudonymous client reference",
        "slow_roam_threshold_ms": "Optional 50-30000 ms threshold for completed roam transactions; defaults to 1000 ms",
    },
    "run": run,
}
