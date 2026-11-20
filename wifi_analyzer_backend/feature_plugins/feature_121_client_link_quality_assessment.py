"""Client link-quality assessment from observed RSSI, SNR and station counters.

The score is a transparent heuristic over supplied measurements. Missing
telemetry is excluded; it is never replaced with an assumed/default value.
"""
from __future__ import annotations

import math


def _number(record: dict, key: str, minimum: float | None = None,
            maximum: float | None = None) -> float | None:
    raw = record.get(key)
    if raw is None:
        return None
    if isinstance(raw, bool):
        raise ValueError(f"{key} must be numeric")
    try:
        value = float(raw)
    except (TypeError, ValueError):
        raise ValueError(f"{key} must be numeric")
    if not math.isfinite(value):
        raise ValueError(f"{key} must be finite")
    if minimum is not None and value < minimum:
        raise ValueError(f"{key} must be at least {minimum}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{key} must be no more than {maximum}")
    return value


def _counter(record: dict, key: str) -> int | None:
    value = _number(record, key, minimum=0)
    if value is None:
        return None
    if not value.is_integer():
        raise ValueError(f"{key} must be a whole-number counter")
    return int(value)


def _label(score: float | None) -> str:
    if score is None:
        return "insufficient_evidence"
    if score >= 85:
        return "excellent"
    if score >= 70:
        return "good"
    if score >= 50:
        return "fair"
    if score >= 30:
        return "weak"
    return "poor"


def run(payload: dict) -> dict:
    clients = payload.get("clients", [])
    if not isinstance(clients, list):
        raise ValueError("'clients' must be a list")
    if len(clients) > 512:
        raise ValueError("'clients' may contain no more than 512 records")

    results = []
    for index, client in enumerate(clients):
        if not isinstance(client, dict):
            raise ValueError("Each client must be an object")

        rssi = _number(client, "rssi_dbm", minimum=-127, maximum=0)
        noise = _number(client, "noise_dbm", minimum=-127, maximum=0)
        retries = _counter(client, "tx_retries")
        successes = _counter(client, "tx_successes")
        failures = _counter(client, "tx_failed")

        components = {}
        snr = None
        retry_pct = None
        failure_pct = None

        if rssi is not None:
            components["signal"] = round(max(0.0, min(100.0, (rssi + 90.0) * 2.5)), 1)
        if rssi is not None and noise is not None:
            snr = round(rssi - noise, 1)
            components["snr"] = round(max(0.0, min(100.0, (snr - 5.0) * 100.0 / 35.0)), 1)
        if retries is not None and successes is not None and retries + successes > 0:
            retry_pct = round(retries * 100.0 / (retries + successes), 2)
            components["retry_rate"] = round(max(0.0, 100.0 - min(100.0, retry_pct * 2.0)), 1)
        if failures is not None and successes is not None and failures + successes > 0:
            failure_pct = round(failures * 100.0 / (failures + successes), 2)
            components["tx_failure_rate"] = round(max(0.0, 100.0 - min(100.0, failure_pct * 2.0)), 1)

        score = round(sum(components.values()) / len(components), 1) if components else None
        results.append({
            "client_id": str(client.get("client_id") or client.get("mac") or f"client-{index + 1}"),
            "rssi_dbm": rssi,
            "noise_dbm": noise,
            "snr_db": snr,
            "tx_retry_pct": retry_pct,
            "tx_failure_pct": failure_pct,
            "score_components": components,
            "evidence_count": len(components),
            "evidence_coverage_pct": round(len(components) * 25.0, 1),
            "quality_score": score,
            "quality_label": _label(score),
            "score_type": "heuristic",
        })

    scored = [item["quality_score"] for item in results if item["quality_score"] is not None]
    return {
        "client_count": len(results),
        "scored_client_count": len(scored),
        "overall_quality_score": round(sum(scored) / len(scored), 1) if scored else None,
        "clients": results,
        "note": (
            "Heuristic indicator, not a vendor-specific link-rate prediction. "
            "Retry and failure percentages use the supplied success counters; "
            "missing measurements are excluded rather than assumed."
        ),
    }


FEATURE = {
    "id": "F121",
    "slug": "client_link_quality_assessment",
    "name": "Client link-quality assessment",
    "category": "Client quality",
    "description": "Assess observed client RSSI, measured SNR, retries and transmit failures with explicit evidence coverage.",
    "parameters": {"clients": "client[]"},
    "run": run,
}
