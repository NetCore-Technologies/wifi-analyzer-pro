"""Validate and normalise caller-supplied UniFi Network exports.

Offline import only: no controller login, network request or configuration change.
Only known, validated inventory fields are copied to the common output schema.
"""
from __future__ import annotations

import ipaddress
import json
import math
import re
from datetime import datetime, timezone

MAX_INPUT_BYTES = 1024 * 1024
MAX_DEVICES = 1024
MAX_RADIOS_PER_DEVICE = 8
MAX_CLIENTS = 8192
MAX_NETWORKS = 1024
MAC_PATTERN = re.compile(r"^[0-9A-F]{2}(?::[0-9A-F]{2}){5}$")
WIDTH_PATTERN = re.compile(r"^(?:(?:HT|VHT|HE|EHT))?(20|40|80|160|320)$", re.IGNORECASE)
BANDS = {
    "ng": "2.4GHz", "2g": "2.4GHz", "2.4": "2.4GHz", "2.4ghz": "2.4GHz",
    "na": "5GHz", "5g": "5GHz", "5ghz": "5GHz",
    "6e": "6GHz", "6g": "6GHz", "6ghz": "6GHz",
}


def _records(value: object, field: str, maximum: int) -> list:
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError(f"{field} must be a list containing no more than {maximum} records")
    return value


def _text(value: object, field: str, maximum: int = 256, required: bool = False) -> str | None:
    if value is None:
        if required:
            raise ValueError(f"{field} is required")
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    value = "".join(ch for ch in value.strip() if ord(ch) >= 32 and ord(ch) != 127)
    if required and not value:
        raise ValueError(f"{field} is required")
    if len(value) > maximum:
        raise ValueError(f"{field} exceeds the {maximum}-character limit")
    return value or None


def _number(value: object, field: str, minimum: float, maximum: float) -> float | int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a finite number")
    try:
        parsed = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field} must be numeric") from error
    if not math.isfinite(parsed) or not minimum <= parsed <= maximum:
        raise ValueError(f"{field} is outside the supported range")
    return int(parsed) if parsed.is_integer() else parsed


def _integer(value: object, field: str, minimum: int, maximum: int) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{field} must be an integer from {minimum} to {maximum}")
    return value


def _channel(value: object, band: str, field: str) -> int | None:
    maximum = {"2.4GHz": 14, "5GHz": 196, "6GHz": 233}[band]
    parsed = _integer(value, field, 1, maximum)
    if parsed is not None and parsed > maximum:
        raise ValueError(f"{field} is outside the valid {band} channel range")
    return parsed


def _boolean(value: object, field: str) -> bool | None:
    if value is None:
        return None
    if not isinstance(value, bool):
        raise ValueError(f"{field} must be a boolean")
    return value


def _vlan(value: object, enabled: bool | None, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, int) and not isinstance(value, bool) and value == 0 and enabled is not True:
        return None
    return _integer(value, field, 1, 4094)


def _timestamp(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("captured_at must be a timezone-aware ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("captured_at must be a timezone-aware ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("captured_at must include a timezone offset")
    return parsed.astimezone(timezone.utc).isoformat()


def _mac(value: object, field: str, required: bool = False) -> str | None:
    if value is None:
        if required:
            raise ValueError(f"{field} is required")
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a MAC address")
    normalised = value.strip().replace("-", ":").upper()
    if not MAC_PATTERN.fullmatch(normalised):
        raise ValueError(f"{field} must be a valid MAC address")
    return normalised


def _ip(value: object, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an IP address")
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as error:
        raise ValueError(f"{field} must be a valid IP address") from error


def _band(value: object, field: str) -> str | None:
    if value is None:
        return None
    token = _text(value, field, maximum=24, required=True).lower()
    result = BANDS.get(token)
    if result is None:
        raise ValueError(f"{field} must identify a supported band (2.4GHz, 5GHz or 6GHz)")
    return result


def _width(value: object, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a supported channel width")
    if isinstance(value, int):
        parsed = value
    elif isinstance(value, str):
        match = WIDTH_PATTERN.fullmatch(value.strip())
        if not match:
            raise ValueError(f"{field} must be a supported channel width")
        parsed = int(match.group(1))
    else:
        raise ValueError(f"{field} must be a supported channel width")
    if parsed not in {20, 40, 80, 160, 320}:
        raise ValueError(f"{field} must be a supported channel width")
    return parsed


def _state(value: object) -> str:
    if isinstance(value, bool):
        return "unknown"
    if value in (1, "1", "connected", "online"):
        return "online"
    if value in (0, "0", "disconnected", "offline"):
        return "offline"
    return "unknown"


def normalize_snapshot(payload: dict) -> dict:
    """Normalise a bounded UniFi export, omitting every unrecognised field."""
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    try:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError("UniFi export must contain JSON-compatible finite values") from error
    if len(encoded.encode("utf-8")) > MAX_INPUT_BYTES:
        raise ValueError(f"UniFi export exceeds the {MAX_INPUT_BYTES}-byte input limit")

    captured_at = _timestamp(payload.get("captured_at"))
    controller = payload.get("controller", {})
    if not isinstance(controller, dict):
        raise ValueError("controller must be an object")
    normalised_controller = {
        "model": _text(controller.get("model"), "controller.model"),
        "version": _text(controller.get("version"), "controller.version", 64),
        "hostname": _text(controller.get("hostname"), "controller.hostname", 128),
    }

    devices = _records(payload.get("devices", payload.get("access_points", [])), "devices", MAX_DEVICES)
    access_points = []
    known_ap_macs = set()
    device_ids = set()
    radios = []
    radio_keys = set()

    for index, device in enumerate(devices):
        field = f"devices[{index}]"
        if not isinstance(device, dict):
            raise ValueError(f"{field} must be an object")
        mac = _mac(device.get("mac", device.get("bssid")), f"{field}.mac", required=True)
        if mac in known_ap_macs:
            raise ValueError("access-point MAC addresses must be unique")
        known_ap_macs.add(mac)

        device_id = _text(device.get("_id", device.get("id")), f"{field}.id", 96)
        if device_id is not None:
            if device_id in device_ids:
                raise ValueError("access-point identifiers must be unique")
            device_ids.add(device_id)

        radios_for_ap = _records(
            device.get("radio_table", device.get("radios", [])),
            f"{field}.radio_table",
            MAX_RADIOS_PER_DEVICE,
        )
        for radio_index, radio in enumerate(radios_for_ap):
            radio_field = f"{field}.radio_table[{radio_index}]"
            if not isinstance(radio, dict):
                raise ValueError(f"{radio_field} must be an object")
            radio_name = _text(
                radio.get("radio", radio.get("radio_name", radio.get("name", radio.get("band")))),
                f"{radio_field}.radio",
                32,
            )
            band = _band(radio_name, f"{radio_field}.radio")
            if band is None:
                raise ValueError(f"{radio_field}.radio must identify a supported band")
            channel = _channel(radio.get("channel"), band, f"{radio_field}.channel")
            width = _width(
                radio.get("channel_width_mhz", radio.get("channel_width", radio.get("ht", radio.get("htmode")))),
                f"{radio_field}.channel_width",
            )
            frequency = _number(
                radio.get("frequency_mhz", radio.get("frequency")),
                f"{radio_field}.frequency_mhz",
                2000,
                8000,
            )
            tx_power = _number(
                radio.get("tx_power_dbm", radio.get("tx_power", radio.get("txpower"))),
                f"{radio_field}.tx_power_dbm",
                -20,
                60,
            )
            radio_bssid = _mac(radio.get("bssid"), f"{radio_field}.bssid")
            identity = (mac, radio_name.lower())
            if identity in radio_keys:
                raise ValueError("radio identifiers must be unique per access point")
            radio_keys.add(identity)
            radios.append({
                "ap_mac": mac,
                "radio": radio_name,
                "band": band,
                "bssid": radio_bssid,
                "channel": channel,
                "channel_width_mhz": width,
                "frequency_mhz": frequency,
                "tx_power_dbm": tx_power,
                "up": _boolean(radio.get("up"), f"{radio_field}.up"),
            })

        access_points.append({
            "id": device_id,
            "mac": mac,
            "name": _text(device.get("name", device.get("hostname")), f"{field}.name", 128),
            "model": _text(device.get("model"), f"{field}.model", 128),
            "ip_address": _ip(device.get("ip", device.get("ip_address")), f"{field}.ip"),
            "status": _state(device.get("state", device.get("status"))),
            "adopted": _boolean(device.get("adopted"), f"{field}.adopted"),
            "radio_count": len(radios_for_ap),
        })

    clients = _records(payload.get("clients", []), "clients", MAX_CLIENTS)
    associations = []
    client_macs = set()
    for index, client in enumerate(clients):
        field = f"clients[{index}]"
        if not isinstance(client, dict):
            raise ValueError(f"{field} must be an object")
        mac = _mac(client.get("mac", client.get("client_mac")), f"{field}.mac", required=True)
        if mac in client_macs:
            raise ValueError("client MAC addresses must be unique in one snapshot")
        client_macs.add(mac)
        ap_mac = _mac(
            client.get("ap_mac", client.get("ap_mac_address", client.get("bssid"))),
            f"{field}.ap_mac",
        )
        wired = _boolean(client.get("is_wired"), f"{field}.is_wired")
        associations.append({
            "client_mac": mac,
            "ap_mac": ap_mac,
            "ap_known": (ap_mac in known_ap_macs) if ap_mac is not None else None,
            "hostname": _text(client.get("hostname", client.get("name")), f"{field}.hostname", 128),
            "ip_address": _ip(client.get("ip"), f"{field}.ip"),
            "ssid": _text(client.get("essid", client.get("ssid")), f"{field}.ssid", 64),
            "signal_dbm": _number(
                client.get("signal", client.get("rssi", client.get("rssi_dbm"))),
                f"{field}.signal_dbm",
                -150,
                0,
            ),
            "channel": _integer(client.get("channel"), f"{field}.channel", 1, 233),
            "is_wired": wired,
            "tx_bytes": _integer(client.get("tx_bytes"), f"{field}.tx_bytes", 0, 2**63 - 1),
            "rx_bytes": _integer(client.get("rx_bytes"), f"{field}.rx_bytes", 0, 2**63 - 1),
        })

    raw_networks = _records(payload.get("networks", []), "networks", MAX_NETWORKS)
    networks = []
    network_ids = set()
    for index, network in enumerate(raw_networks):
        field = f"networks[{index}]"
        if not isinstance(network, dict):
            raise ValueError(f"{field} must be an object")
        network_id = _text(network.get("_id", network.get("id")), f"{field}.id", 96)
        if network_id is not None:
            if network_id in network_ids:
                raise ValueError("network identifiers must be unique")
            network_ids.add(network_id)
        subnet = network.get("ip_subnet", network.get("subnet", network.get("network")))
        if subnet is not None:
            if not isinstance(subnet, str):
                raise ValueError(f"{field}.ip_subnet must be a CIDR network")
            try:
                subnet = str(ipaddress.ip_network(subnet.strip(), strict=False))
            except ValueError as error:
                raise ValueError(f"{field}.ip_subnet must be a valid CIDR network") from error
        vlan_enabled = _boolean(network.get("vlan_enabled"), f"{field}.vlan_enabled")
        vlan_id = _vlan(network.get("vlan", network.get("vlan_id")), vlan_enabled, f"{field}.vlan")
        networks.append({
            "id": network_id,
            "name": _text(network.get("name", network.get("ssid")), f"{field}.name", 128),
            "purpose": _text(network.get("purpose"), f"{field}.purpose", 64),
            "enabled": _boolean(network.get("enabled"), f"{field}.enabled"),
            "vlan_enabled": vlan_enabled,
            "vlan_id": vlan_id,
            "ip_subnet": subnet,
        })

    associated_by_ap = {}
    for association in associations:
        ap_mac = association["ap_mac"]
        if ap_mac is not None and association["is_wired"] is not True:
            associated_by_ap[ap_mac] = associated_by_ap.get(ap_mac, 0) + 1
    for access_point in access_points:
        access_point["associated_client_count"] = associated_by_ap.get(access_point["mac"], 0)

    wired_count = sum(item["is_wired"] is True for item in associations)
    return {
        "adapter_id": "unifi",
        "captured_at": captured_at,
        "controller": normalised_controller,
        "access_points": access_points,
        "wireless_radios": radios,
        "associations": associations,
        "networks": networks,
        "summary": {
            "access_point_count": len(access_points),
            "wireless_radio_count": len(radios),
            "client_count": len(associations),
            "wired_client_count": wired_count,
            "wireless_client_count": len(associations) - wired_count,
            "network_count": len(networks),
            "clients_with_unmatched_ap_count": sum(
                item["ap_mac"] is not None and item["ap_known"] is False for item in associations
            ),
        },
        "note": (
            "Normalised from caller-supplied UniFi controller export data. This is an offline import: "
            "no controller connection is opened, no configuration is changed, and unknown or "
            "credential-like fields (including Wi-Fi passphrases) are not copied."
        ),
    }
