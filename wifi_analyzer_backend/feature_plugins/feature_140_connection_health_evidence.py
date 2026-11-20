"""Connection health evidence: Flag measured per-client link quality concerns using explicit and configurable signal, retry, rate, loss and latency evidence."""
from __future__ import annotations
import math
import re
import statistics
from datetime import datetime, timezone

def run(p: dict) -> dict:
    clients = p.get("clients", [])
    diagnostics = p.get("diagnostics", {})
    thresholds = p.get("thresholds", {})
    if not isinstance(clients, list) or not isinstance(diagnostics, dict) or not isinstance(thresholds, dict):
        raise ValueError("clients, diagnostics and thresholds have invalid types")
    weak_rssi = float(thresholds.get("weak_rssi_dbm", -75))
    high_retries = float(thresholds.get("high_retry_pct", 20))
    low_rate = float(thresholds.get("low_phy_rate_mbps", 6))
    high_loss = float(thresholds.get("high_packet_loss_pct", 5))
    high_latency = float(thresholds.get("high_latency_ms", 100))
    if not all(math.isfinite(x) for x in (weak_rssi, high_retries, low_rate, high_loss, high_latency)):
        raise ValueError("Thresholds must be finite numbers")
    if not -100 <= weak_rssi <= 0 or any(x < 0 for x in (high_retries, low_rate, high_loss, high_latency)):
        raise ValueError("Thresholds are outside valid ranges")
    results = []
    for client in clients:
        if not isinstance(client, dict) or not client.get("client_mac"):
            raise ValueError("Each client needs client_mac")
        evidence = []
        def measured(key):
            if client.get(key) is None:
                return None
            value = float(client[key])
            if not math.isfinite(value):
                raise ValueError(f"{key} must be finite")
            return value
        rssi, retries = measured("rssi_dbm"), measured("retry_rate_pct")
        tx_rate, rx_rate = measured("tx_rate_mbps"), measured("rx_rate_mbps")
        if rssi is not None and rssi <= weak_rssi: evidence.append("weak_rssi")
        if retries is not None and retries >= high_retries: evidence.append("high_retry_rate")
        if (tx_rate is not None and tx_rate < low_rate) or (rx_rate is not None and rx_rate < low_rate): evidence.append("low_phy_rate")
        results.append({"client_mac": str(client["client_mac"]).upper(), "evidence": evidence,
                        "assessment": "review" if evidence else "no_threshold_exceeded" if any(x is not None for x in (rssi,retries,tx_rate,rx_rate)) else "insufficient_measurements"})
    loss = None if diagnostics.get("packet_loss_pct") is None else float(diagnostics["packet_loss_pct"])
    latency = None if diagnostics.get("latency_ms") is None else float(diagnostics["latency_ms"])
    network_flags = []
    if loss is not None and loss >= high_loss: network_flags.append("high_packet_loss")
    if latency is not None and latency >= high_latency: network_flags.append("high_latency")
    return {"clients": results, "network_evidence": network_flags,
            "thresholds": {"weak_rssi_dbm": weak_rssi, "high_retry_pct": high_retries, "low_phy_rate_mbps": low_rate,
                           "high_packet_loss_pct": high_loss, "high_latency_ms": high_latency},
            "note": "Evidence summary only; no score is inferred when measurements are absent."}

FEATURE = {
    "id": "F140",
    "slug": "connection_health_evidence",
    "name": "Connection health evidence",
    "category": "Client QoS",
    "description": "Flag measured per-client link quality concerns using explicit and configurable signal, retry, rate, loss and latency evidence.",
    "parameters": {"clients":"client[]","diagnostics":"object","thresholds":"object"},
    "run": run,
}
