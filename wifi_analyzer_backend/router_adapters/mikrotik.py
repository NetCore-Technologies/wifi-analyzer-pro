"""Validate and normalise caller-supplied MikroTik RouterOS exports.

This is an offline import adapter. It never logs into RouterOS, performs network calls,
runs scripts, changes configuration, or copies unknown/credential-like fields.
"""
from __future__ import annotations

import ipaddress
import json
import math
import re
from datetime import datetime, timezone

MAX_INPUT_BYTES = 1024 * 1024
MAX_INTERFACES = 512
MAX_WIRELESS = 128
MAX_REGISTRATIONS = 8192
MAX_ADDRESSES = 2048
MAX_VLANS = 1024
MAX_DHCP_LEASES = 8192
MAX_ROUTES = 2048
MAC_PATTERN = re.compile(r"^[0-9A-F]{2}(?::[0-9A-F]{2}){5}$")
WIDTH_PATTERN = re.compile(r"^(20|40|80|160|320)(?:MHZ)?$", re.IGNORECASE)
BAND_ALIASES = {
    "2ghz": "2.4GHz", "2.4ghz": "2.4GHz", "2ghz-b": "2.4GHz",
    "2ghz-g": "2.4GHz", "2ghz-n": "2.4GHz", "2ghz-ax": "2.4GHz",
    "5ghz": "5GHz", "5ghz-a": "5GHz", "5ghz-n": "5GHz",
    "5ghz-ac": "5GHz", "5ghz-ax": "5GHz",
    "6ghz": "6GHz", "6ghz-ax": "6GHz",
}
INTERFACE_NAME = re.compile(r"^[^\x00-\x1f\x7f]{1,64}$")


def _object(value: object, field: str) -> dict:
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object")
    return value


def _records(value: object, field: str, maximum: int) -> list:
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError(f"{field} must be a list containing no more than {maximum} records")
    return value


def _text(value: object, field: str, maximum: int = 128, required: bool = False) -> str | None:
    if value is None:
        if required:
            raise ValueError(f"{field} is required")
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    result = "".join(ch for ch in value.strip() if ord(ch) >= 32 and ord(ch) != 127)
    if required and not result:
        raise ValueError(f"{field} is required")
    if len(result) > maximum:
        raise ValueError(f"{field} exceeds the {maximum}-character limit")
    return result or None


def _number(value: object, field: str, minimum: float, maximum: float) -> float | int | None:
    if value is None or value == "":
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
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        raise ValueError(f"{field} must be an integer from {minimum} to {maximum}")
    try:
        token = str(value).strip()
        if not re.fullmatch(r"[+-]?[0-9]+", token):
            raise ValueError
        parsed = int(token, 10)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field} must be an integer from {minimum} to {maximum}") from error
    if not minimum <= parsed <= maximum:
        raise ValueError(f"{field} must be an integer from {minimum} to {maximum}")
    return parsed


def _boolean(value: object, field: str) -> bool | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    if value in (1, "1", "yes", "true"):
        return True
    if value in (0, "0", "no", "false"):
        return False
    raise ValueError(f"{field} must be a boolean")


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
    if value is None or value == "":
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
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an IP address")
    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError as error:
        raise ValueError(f"{field} must be a valid IP address") from error


def _ip_interface(value: object, field: str) -> dict | None:
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ValueError(f"{field} must contain an IP address and prefix")
    try:
        parsed = ipaddress.ip_interface(value.strip())
    except ValueError as error:
        raise ValueError(f"{field} must be a valid IP address and prefix") from error
    return {
        "address": str(parsed.ip),
        "prefix_length": parsed.network.prefixlen,
        "network": str(parsed.network),
        "version": parsed.version,
    }


def _interface_name(value: object, field: str, required: bool = False) -> str | None:
    name = _text(value, field, 64, required)
    if name is not None and not INTERFACE_NAME.fullmatch(name):
        raise ValueError(f"{field} contains invalid interface-name characters")
    return name


def _band(value: object, field: str) -> str | None:
    token = _text(value, field, 32)
    if token is None:
        return None
    normalised = token.lower().replace(" ", "").replace("_", "")
    result = BAND_ALIASES.get(normalised)
    if result is None:
        raise ValueError(f"{field} must identify 2.4GHz, 5GHz or 6GHz")
    return result


def _width(value: object, field: str) -> tuple[int | None, str | None]:
    token = _text(value, field, 48)
    if token is None:
        return None, None
    match = WIDTH_PATTERN.fullmatch(token.replace(" ", ""))
    if match:
        return int(match.group(1)), token
    # RouterOS may report a permitted set such as 20/40/80mhz. Preserve it as
    # a setting hint, but do not mistake it for the currently negotiated width.
    if re.fullmatch(r"(?:20|40|80|160|320)(?:/(?:20|40|80|160|320))+(?:mhz)?", token, re.IGNORECASE):
        return None, token
    raise ValueError(f"{field} must be a supported channel width or width setting")


def _channel(value: object, band: str | None, field: str) -> int | None:
    maximum = {"2.4GHz": 14, "5GHz": 196, "6GHz": 233}.get(band, 233)
    return _integer(value, field, 1, maximum)


def _state(running: bool | None, disabled: bool | None) -> str:
    if disabled is True:
        return "disabled"
    if running is True:
        return "up"
    if running is False:
        return "down"
    return "unknown"


def _status(value: object) -> str:
    token = str(value or "").strip().lower()
    if token in {"bound", "active", "connected", "online"}:
        return "bound"
    if token in {"blocked", "disabled"}:
        return "blocked"
    if token in {"offered", "offered-to"}:
        return "offered"
    return "unknown"


def normalize_snapshot(payload: dict) -> dict:
    """Normalise a bounded RouterOS export to a credential-free inventory schema."""
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    try:
        encoded = json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ValueError("RouterOS export must contain JSON-compatible finite values") from error
    if len(encoded.encode("utf-8")) > MAX_INPUT_BYTES:
        raise ValueError(f"RouterOS export exceeds the {MAX_INPUT_BYTES}-byte input limit")

    captured_at = _timestamp(payload.get("captured_at"))
    router = _object(payload.get("router", {}), "router")
    resource = _object(payload.get("resource", {}), "resource")
    router_output = {
        "board_name": _text(router.get("board_name", router.get("model")), "router.board_name"),
        "model": _text(router.get("model_name", router.get("model")), "router.model", 128),
        "version": _text(router.get("version", router.get("routeros_version")), "router.version", 64),
        "architecture": _text(router.get("architecture_name", router.get("architecture")), "router.architecture", 64),
        "serial_number": _text(router.get("serial_number"), "router.serial_number", 96),
    }
    resource_output = {
        "uptime": _text(resource.get("uptime"), "resource.uptime", 48),
        "cpu_load_pct": _number(resource.get("cpu_load", resource.get("cpu-load")), "resource.cpu_load", 0, 100),
        "free_memory_bytes": _integer(resource.get("free_memory", resource.get("free-memory")), "resource.free_memory", 0, 2**63 - 1),
        "total_memory_bytes": _integer(resource.get("total_memory", resource.get("total-memory")), "resource.total_memory", 1, 2**63 - 1),
    }
    free_memory = resource_output["free_memory_bytes"]
    total_memory = resource_output["total_memory_bytes"]
    if free_memory is not None and total_memory is not None and free_memory > total_memory:
        raise ValueError("resource.free_memory cannot exceed total_memory")

    raw_interfaces = _records(payload.get("interfaces", []), "interfaces", MAX_INTERFACES)
    interfaces = []
    interface_names = set()
    for index, item in enumerate(raw_interfaces):
        field = f"interfaces[{index}]"
        record = _object(item, field)
        name = _interface_name(record.get("name"), f"{field}.name", required=True)
        if name in interface_names:
            raise ValueError("interface names must be unique")
        interface_names.add(name)
        running = _boolean(record.get("running"), f"{field}.running")
        disabled = _boolean(record.get("disabled"), f"{field}.disabled")
        interfaces.append({
            "name": name,
            "type": _text(record.get("type"), f"{field}.type", 32),
            "mac_address": _mac(record.get("mac_address", record.get("mac-address")), f"{field}.mac_address"),
            "mtu": _integer(record.get("mtu"), f"{field}.mtu", 576, 9216),
            "actual_mtu": _integer(record.get("actual_mtu", record.get("actual-mtu")), f"{field}.actual_mtu", 576, 9216),
            "running": running,
            "disabled": disabled,
            "state": _state(running, disabled),
        })

    raw_wireless = _records(payload.get("wireless", payload.get("wifi", [])), "wireless", MAX_WIRELESS)
    wireless_radios = []
    wireless_names = set()
    for index, item in enumerate(raw_wireless):
        field = f"wireless[{index}]"
        record = _object(item, field)
        configuration = record.get("configuration", {})
        if not isinstance(configuration, dict):
            raise ValueError(f"{field}.configuration must be an object")
        name = _interface_name(record.get("name"), f"{field}.name", required=True)
        if name in wireless_names:
            raise ValueError("wireless interface names must be unique")
        wireless_names.add(name)
        band = _band(record.get("band", configuration.get("band")), f"{field}.band")
        channel_width, channel_width_setting = _width(
            record.get("channel_width", record.get("channel_width_mhz", record.get("channel-width"))),
            f"{field}.channel_width",
        )
        channel = _channel(record.get("channel"), band, f"{field}.channel")
        frequency = _number(
            record.get("frequency", record.get("frequency_mhz")),
            f"{field}.frequency_mhz",
            2000,
            8000,
        )
        tx_power = _number(
            record.get("tx_power", record.get("tx_power_dbm")),
            f"{field}.tx_power_dbm",
            -20,
            60,
        )
        running = _boolean(record.get("running"), f"{field}.running")
        disabled = _boolean(record.get("disabled"), f"{field}.disabled")
        interface_mac = _mac(record.get("mac_address", record.get("mac-address")), f"{field}.mac_address")
        wireless_radios.append({
            "interface": name,
            "ssid": _text(record.get("ssid", configuration.get("ssid")), f"{field}.ssid", 64),
            "band": band,
            "channel": channel,
            "frequency_mhz": frequency,
            "channel_width_mhz": channel_width,
            "channel_width_setting": channel_width_setting,
            "tx_power_dbm": tx_power,
            "bssid": interface_mac,
            "state": _state(running, disabled),
        })

    raw_registrations = _records(payload.get("registrations", payload.get("registration_table", [])), "registrations", MAX_REGISTRATIONS)
    associations = []
    registration_ids = set()
    for index, item in enumerate(raw_registrations):
        field = f"registrations[{index}]"
        record = _object(item, field)
        mac = _mac(record.get("mac_address", record.get("mac-address")), f"{field}.mac_address", required=True)
        interface = _interface_name(record.get("interface"), f"{field}.interface")
        identity = (mac, interface)
        if identity in registration_ids:
            raise ValueError("wireless registration identities must be unique")
        registration_ids.add(identity)
        associations.append({
            "client_mac": mac,
            "interface": interface,
            "interface_known": interface in wireless_names if interface is not None else None,
            "signal_dbm": _number(record.get("signal_strength", record.get("signal-strength", record.get("signal"))), f"{field}.signal_dbm", -150, 0),
            "tx_rate": _text(record.get("tx_rate", record.get("tx-rate")), f"{field}.tx_rate", 64),
            "rx_rate": _text(record.get("rx_rate", record.get("rx-rate")), f"{field}.rx_rate", 64),
            "uptime": _text(record.get("uptime"), f"{field}.uptime", 48),
        })

    raw_addresses = _records(payload.get("addresses", []), "addresses", MAX_ADDRESSES)
    addresses = []
    address_ids = set()
    for index, item in enumerate(raw_addresses):
        field = f"addresses[{index}]"
        record = _object(item, field)
        interface = _interface_name(record.get("interface"), f"{field}.interface", required=True)
        address = _ip_interface(record.get("address"), f"{field}.address")
        if address is None:
            raise ValueError(f"{field}.address is required")
        identity = (interface, address["address"], address["prefix_length"])
        if identity in address_ids:
            raise ValueError("interface address identities must be unique")
        address_ids.add(identity)
        addresses.append({**address, "interface": interface, "interface_known": interface in interface_names})

    raw_routes = _records(payload.get("routes", payload.get("ip_routes", [])), "routes", MAX_ROUTES)
    routes = []
    for index, item in enumerate(raw_routes):
        field = f"routes[{index}]"
        record = _object(item, field)
        destination = record.get(
            "dst_address",
            record.get("dst-address", record.get("target", record.get("destination"))),
        )
        if not isinstance(destination, str):
            raise ValueError(f"{field}.target must be an IP network")
        try:
            target_network = ipaddress.ip_network(destination.strip(), strict=False)
        except ValueError as error:
            raise ValueError(f"{field}.target must be a valid IP network") from error

        gateway = None
        gateway_interface = None
        raw_gateway = record.get("gateway", record.get("nexthop", record.get("next_hop")))
        if raw_gateway not in (None, ""):
            token = _text(raw_gateway, f"{field}.gateway", 128, required=True)
            address_token, separator, suffix = token.partition("%")
            try:
                parsed_gateway = ipaddress.ip_address(address_token.strip())
            except ValueError as error:
                if separator:
                    raise ValueError(
                        f"{field}.gateway must contain a valid IP address before the interface suffix"
                    ) from error
                gateway_interface = _interface_name(
                    token, f"{field}.gateway_interface", required=True
                )
            else:
                gateway = str(parsed_gateway)
                if separator:
                    gateway_interface = _interface_name(
                        suffix.strip(), f"{field}.gateway_interface", required=True
                    )

        distance = _integer(record.get("distance"), f"{field}.distance", 1, 255)
        table = _text(
            record.get("routing_table", record.get("routing-table", record.get("table", "main"))),
            f"{field}.routing_table",
            64,
            required=True,
        )
        routes.append({
            "target": str(target_network),
            "gateway": gateway,
            "gateway_interface": gateway_interface,
            "routing_table": table,
            "distance": distance,
            "active": _boolean(record.get("active"), f"{field}.active"),
            "disabled": _boolean(record.get("disabled"), f"{field}.disabled"),
            "blackhole": _boolean(record.get("blackhole"), f"{field}.blackhole"),
            "dynamic": _boolean(record.get("dynamic"), f"{field}.dynamic"),
        })

    raw_vlans = _records(payload.get("vlans", []), "vlans", MAX_VLANS)
    vlans = []
    vlan_ids = set()
    for index, item in enumerate(raw_vlans):
        field = f"vlans[{index}]"
        record = _object(item, field)
        name = _interface_name(record.get("name"), f"{field}.name", required=True)
        parent = _interface_name(record.get("interface"), f"{field}.interface", required=True)
        vlan_id = _integer(record.get("vlan_id", record.get("vlan-id")), f"{field}.vlan_id", 1, 4094)
        if vlan_id is None:
            raise ValueError(f"{field}.vlan_id is required")
        identity = (name, parent, vlan_id)
        if identity in vlan_ids:
            raise ValueError("VLAN interface identities must be unique")
        vlan_ids.add(identity)
        vlans.append({
            "name": name,
            "interface": parent,
            "interface_known": parent in interface_names,
            "vlan_id": vlan_id,
            "running": _boolean(record.get("running"), f"{field}.running"),
        })

    raw_leases = _records(payload.get("dhcp_leases", payload.get("leases", [])), "dhcp_leases", MAX_DHCP_LEASES)
    dhcp_leases = []
    lease_ids = set()
    for index, item in enumerate(raw_leases):
        field = f"dhcp_leases[{index}]"
        record = _object(item, field)
        mac = _mac(record.get("mac_address", record.get("mac-address")), f"{field}.mac_address")
        address = _ip(record.get("address"), f"{field}.address")
        if mac is None and address is None:
            raise ValueError(f"{field} must contain a MAC address or IP address")
        identity = (mac, address)
        if identity in lease_ids:
            raise ValueError("DHCP lease identities must be unique")
        lease_ids.add(identity)
        dhcp_leases.append({
            "mac_address": mac,
            "address": address,
            "host_name": _text(record.get("host_name", record.get("host-name")), f"{field}.host_name", 128),
            "status": _status(record.get("status", record.get("server"))),
            "expires_after": _text(record.get("expires_after", record.get("expires-after")), f"{field}.expires_after", 48),
        })

    up_count = sum(item["state"] == "up" for item in interfaces)
    return {
        "adapter_id": "mikrotik",
        "captured_at": captured_at,
        "router": router_output,
        "resource": resource_output,
        "interfaces": interfaces,
        "wireless_radios": wireless_radios,
        "associations": associations,
        "addresses": addresses,
        "routes": routes,
        "vlans": vlans,
        "dhcp_leases": dhcp_leases,
        "summary": {
            "interface_count": len(interfaces),
            "interface_up_count": up_count,
            "wireless_radio_count": len(wireless_radios),
            "association_count": len(associations),
            "address_count": len(addresses),
            "route_count": len(routes),
            "active_route_count": sum(item["active"] is True and item["disabled"] is not True for item in routes),
            "default_route_count": sum(
                ipaddress.ip_network(item["target"]).prefixlen == 0 for item in routes
            ),
            "vlan_count": len(vlans),
            "dhcp_lease_count": len(dhcp_leases),
        },
        "note": (
            "Normalised from caller-supplied MikroTik RouterOS export data. This is an offline import: "
            "no router connection is opened, no command or script is executed, no configuration is "
            "changed, and unknown or credential-like fields are not copied."
        ),
    }
