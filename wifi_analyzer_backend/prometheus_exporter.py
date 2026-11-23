"""Privacy-preserving Prometheus metrics rendered from persisted telemetry rollups."""
from __future__ import annotations

import math
from datetime import datetime, timezone
from typing import Any

MAX_PROMETHEUS_ROLLUPS = 1_440
TELEMETRY_FRESHNESS_SECONDS = 300


def _parse_timestamp(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone offset")
    return parsed.astimezone(timezone.utc)


def _count(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return 0
    return value


def _number(value: object) -> float | int | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    parsed = float(value)
    return parsed if math.isfinite(parsed) else None


def _format(value: float | int) -> str:
    if isinstance(value, int):
        return str(value)
    return format(value, ".15g")


def render_prometheus_metrics(
    rollups: list[dict[str, Any]],
    *,
    now: datetime | None = None,
) -> str:
    """Render at most 24 hours of one site's aggregate telemetry as Prometheus text.

    Site identifiers and network/client identifiers are deliberately omitted from
    labels. Values for the latest minute are averages of actual observations in
    that minute; sample totals cover the returned rolling 24-hour window.
    """
    if not isinstance(rollups, list) or len(rollups) > MAX_PROMETHEUS_ROLLUPS:
        raise ValueError(
            f"rollups must be a list containing no more than {MAX_PROMETHEUS_ROLLUPS} records"
        )
    if any(not isinstance(item, dict) for item in rollups):
        raise ValueError("each telemetry rollup must be an object")

    moment = now or datetime.now(timezone.utc)
    if not isinstance(moment, datetime) or moment.tzinfo is None or moment.utcoffset() is None:
        raise ValueError("now must be a timezone-aware datetime")
    moment = moment.astimezone(timezone.utc)

    dated_rows = [
        (_parse_timestamp(item.get("minute_utc"), "minute_utc"), item)
        for item in rollups
    ]
    dated_rows.sort(key=lambda pair: pair[0])
    latest = dated_rows[-1][1] if dated_rows else None
    latest_minute = dated_rows[-1][0] if dated_rows else None

    totals = {
        "wifi_analyzer_scan_samples_24h": sum(_count(row.get("scan_count")) for row in rollups),
        "wifi_analyzer_diagnostic_samples_24h": sum(
            _count(row.get("diagnostics_count")) for row in rollups
        ),
        "wifi_analyzer_speedtest_samples_24h": sum(
            _count(row.get("speedtest_count")) for row in rollups
        ),
    }

    lines: list[str] = []

    def emit(name: str, description: str, value: float | int) -> None:
        lines.extend((
            f"# HELP {name} {description}",
            f"# TYPE {name} gauge",
            f"{name} {_format(value)}",
        ))

    emit("wifi_analyzer_up", "Whether the WiFi Analyzer Pro metrics exporter is responding.", 1)
    emit(
        "wifi_analyzer_telemetry_available",
        "Whether at least one persisted telemetry minute exists in the rolling 24-hour window.",
        1 if latest is not None else 0,
    )
    age_seconds = (moment - latest_minute).total_seconds() if latest_minute is not None else None
    emit(
        "wifi_analyzer_telemetry_fresh",
        f"Whether the latest telemetry minute is no more than {TELEMETRY_FRESHNESS_SECONDS} seconds old.",
        1 if age_seconds is not None and 0 <= age_seconds <= TELEMETRY_FRESHNESS_SECONDS else 0,
    )
    descriptions = {
        "wifi_analyzer_scan_samples_24h": "Number of scan observations aggregated in the rolling 24-hour window.",
        "wifi_analyzer_diagnostic_samples_24h": "Number of diagnostic observations aggregated in the rolling 24-hour window.",
        "wifi_analyzer_speedtest_samples_24h": "Number of completed speed tests aggregated in the rolling 24-hour window.",
    }
    for name, value in totals.items():
        emit(name, descriptions[name], value)

    if latest is not None and latest_minute is not None:
        emit(
            "wifi_analyzer_last_observation_minute_timestamp_seconds",
            "Unix timestamp of the latest persisted telemetry minute bucket, not an individual scan timestamp.",
            latest_minute.timestamp(),
        )
        updated_at = latest.get("updated_at")
        if updated_at is not None:
            parsed_update = _parse_timestamp(updated_at, "updated_at")
            emit(
                "wifi_analyzer_last_update_timestamp_seconds",
                "Unix timestamp when the latest telemetry minute bucket was last updated.",
                parsed_update.timestamp(),
            )

        latest_metrics = (
            ("wifi_analyzer_networks_per_scan", "Mean detected access points per scan in the latest telemetry minute.", "average_network_count"),
            ("wifi_analyzer_open_networks_per_scan", "Mean explicitly open access points per scan in the latest telemetry minute.", "average_open_network_count"),
            ("wifi_analyzer_2_4ghz_networks_per_scan", "Mean detected 2.4 GHz access points per scan in the latest telemetry minute.", "average_2_4ghz_network_count"),
            ("wifi_analyzer_5ghz_networks_per_scan", "Mean detected 5 GHz access points per scan in the latest telemetry minute.", "average_5ghz_network_count"),
            ("wifi_analyzer_6ghz_networks_per_scan", "Mean detected 6 GHz access points per scan in the latest telemetry minute.", "average_6ghz_network_count"),
            ("wifi_analyzer_average_rssi_dbm", "Mean measured RSSI in dBm in the latest telemetry minute.", "average_rssi_dbm"),
            ("wifi_analyzer_gateway_latency_ms", "Mean measured local default-gateway latency in milliseconds in the latest telemetry minute.", "average_latency_ms"),
            ("wifi_analyzer_gateway_jitter_ms", "Mean measured local default-gateway jitter in milliseconds in the latest telemetry minute.", "average_jitter_ms"),
            ("wifi_analyzer_gateway_packet_loss_percent", "Mean measured local default-gateway packet loss percentage in the latest telemetry minute.", "average_packet_loss_pct"),
            ("wifi_analyzer_speedtest_download_mbps", "Mean completed speed-test download rate in Mbps in the latest telemetry minute.", "average_speedtest_download_mbps"),
            ("wifi_analyzer_speedtest_upload_mbps", "Mean completed speed-test upload rate in Mbps in the latest telemetry minute.", "average_speedtest_upload_mbps"),
            ("wifi_analyzer_speedtest_ping_ms", "Mean completed speed-test ping in milliseconds in the latest telemetry minute.", "average_speedtest_ping_ms"),
        )
        for name, description, field in latest_metrics:
            value = _number(latest.get(field))
            if value is not None:
                emit(name, description, value)

    return "\n".join(lines) + "\n"
