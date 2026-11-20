"""Wi-Fi 7 EHT capability summary: Summarise explicitly supplied EHT and Wi-Fi 7 capability flags without inferring unsupported features."""
from __future__ import annotations
import math
import statistics
from datetime import datetime

FEATURE = None

def run(p: dict) -> dict:
    capabilities = p.get("capabilities", {})
    if not isinstance(capabilities, dict):
        raise ValueError("'capabilities' must be an object")
    flags = ("eht", "mlo", "puncturing", "320mhz", "4096qam")
    known = {key: bool(capabilities[key]) for key in flags if isinstance(capabilities.get(key), bool)}
    unknown = [key for key in flags if key not in known]
    return {"wifi7_eht_advertised": known.get("eht"), "capabilities": known,
            "unknown_capabilities": unknown, "has_explicit_eht_evidence": known.get("eht") is True,
            "note": "Missing flags remain unknown; this is not a certification or negotiated-link report."}

FEATURE = {
    "id": "F117",
    "slug": "wifi7_eht_summary",
    "name": "Wi-Fi 7 EHT capability summary",
    "category": "PHY analysis",
    "description": "Summarise explicitly supplied EHT and Wi-Fi 7 capability flags without inferring unsupported features.",
    "parameters": {"capabilities":"object"},
    "run": run,
}
