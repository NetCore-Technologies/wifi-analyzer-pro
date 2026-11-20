"""Bounded, privacy-preserving analysis of classic PCAP captures.

This feature analyses a caller-supplied capture offline. It does not open interfaces,
capture live traffic, transmit packets, or return packet payloads or endpoint addresses.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
from collections import Counter
from datetime import datetime, timezone

MAX_CAPTURE_BYTES = 512 * 1024
MAX_ENCODED_BYTES = ((MAX_CAPTURE_BYTES + 2) // 3) * 4
MAX_PACKETS = 5000
MAX_SNAPLEN = 262144
MAX_FRAME_BYTES = 262144

MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("little", 1_000_000, "microsecond"),
    b"\xa1\xb2\xc3\xd4": ("big", 1_000_000, "microsecond"),
    b"\x4d\x3c\xb2\xa1": ("little", 1_000_000_000, "nanosecond"),
    b"\xa1\xb2\x3c\x4d": ("big", 1_000_000_000, "nanosecond"),
}
SUPPORTED_LINK_TYPES = {1: "ethernet", 105: "ieee80211", 113: "linux_cooked", 127: "radiotap", 276: "linux_cooked_v2"}
VLAN_TYPES = {0x8100, 0x88A8, 0x9100}
IP_PROTOCOLS = {
    1: "icmp",
    2: "igmp",
    6: "tcp",
    17: "udp",
    47: "gre",
    50: "esp",
    58: "icmpv6",
}
ETHERTYPES = {
    0x0800: "ipv4",
    0x0806: "arp",
    0x86DD: "ipv6",
    0x88CC: "lldp",
}


def _integer(data: bytes, start: int, length: int, byteorder: str) -> int:
    return int.from_bytes(data[start:start + length], byteorder)


def _utc_timestamp(seconds: int, fraction: int, divisor: int) -> str:
    try:
        moment = datetime.fromtimestamp(seconds + fraction / divisor, timezone.utc)
    except (OverflowError, OSError, ValueError) as error:
        raise ValueError("capture contains an out-of-range packet timestamp") from error
    return moment.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _increment(counter: Counter, key: str) -> None:
    counter[key] += 1


def _transport(
    packet: bytes,
    offset: int,
    protocol: int,
    protocol_counts: Counter,
    destination_ports: Counter,
) -> None:
    name = IP_PROTOCOLS.get(protocol, "other")
    _increment(protocol_counts, name)
    if protocol == 6 and len(packet) >= offset + 20:
        destination_ports[_integer(packet, offset + 2, 2, "big")] += 1
    elif protocol == 17 and len(packet) >= offset + 8:
        destination_ports[ _integer(packet, offset + 2, 2, "big") ] += 1


def _ipv4(packet: bytes, offset: int, state: dict) -> None:
    if len(packet) < offset + 20:
        state["malformed"] += 1
        return
    first = packet[offset]
    version = first >> 4
    header_length = (first & 0x0F) * 4
    if version != 4 or header_length < 20 or len(packet) < offset + header_length:
        state["malformed"] += 1
        return
    total_length = _integer(packet, offset + 2, 2, "big")
    if total_length < header_length:
        state["malformed"] += 1
        return
    state["ipv4"] += 1
    state["dscp"][str(packet[offset + 1] >> 2)] += 1
    _transport(
        packet,
        offset + header_length,
        packet[offset + 9],
        state["ip_protocols"],
        state["destination_ports"],
    )


def _ipv6(packet: bytes, offset: int, state: dict) -> None:
    if len(packet) < offset + 40:
        state["malformed"] += 1
        return
    first_word = _integer(packet, offset, 4, "big")
    if first_word >> 28 != 6:
        state["malformed"] += 1
        return
    traffic_class = (first_word >> 20) & 0xFF
    state["ipv6"] += 1
    state["dscp"][str(traffic_class >> 2)] += 1
    payload_length = _integer(packet, offset + 4, 2, "big")
    next_header = packet[offset + 6]
    cursor = offset + 40
    end = min(len(packet), cursor + payload_length)
    extension_headers = {0, 43, 60, 135, 139, 140}
    for _ in range(8):
        if next_header in extension_headers:
            if cursor + 2 > end:
                state["malformed"] += 1
                return
            following = packet[cursor]
            extension_length = (packet[cursor + 1] + 1) * 8
            if extension_length < 8 or cursor + extension_length > end:
                state["malformed"] += 1
                return
            next_header = following
            cursor += extension_length
            continue
        if next_header == 44:
            if cursor + 8 > end:
                state["malformed"] += 1
                return
            next_header = packet[cursor]
            cursor += 8
            continue
        if next_header == 51:
            if cursor + 2 > end:
                state["malformed"] += 1
                return
            following = packet[cursor]
            extension_length = (packet[cursor + 1] + 2) * 4
            if extension_length < 8 or cursor + extension_length > end:
                state["malformed"] += 1
                return
            next_header = following
            cursor += extension_length
            continue
        break
    else:
        state["malformed"] += 1
        return
    _transport(
        packet[:end],
        cursor,
        next_header,
        state["ip_protocols"],
        state["destination_ports"],
    )


def _ether_payload(packet: bytes, cursor: int, ether_type: int, state: dict) -> None:
    vlan_depth = 0
    while ether_type in VLAN_TYPES and vlan_depth < 4:
        if len(packet) < cursor + 4:
            state["malformed"] += 1
            return
        ether_type = _integer(packet, cursor + 2, 2, "big")
        cursor += 4
        vlan_depth += 1
    name = ETHERTYPES.get(ether_type, "other")
    _increment(state["ether_types"], name)
    if ether_type == 0x0800:
        _ipv4(packet, cursor, state)
    elif ether_type == 0x86DD:
        _ipv6(packet, cursor, state)
    elif ether_type == 0x0806:
        state["arp"] += 1


def _ethernet(packet: bytes, state: dict) -> None:
    if len(packet) < 14:
        state["malformed"] += 1
        return
    _ether_payload(packet, 14, _integer(packet, 12, 2, "big"), state)


def _linux_cooked(packet: bytes, state: dict, *, version: int) -> None:
    if version == 1:
        if len(packet) < 16:
            state["malformed"] += 1
            return
        ether_type = _integer(packet, 14, 2, "big")
        cursor = 16
    else:
        if len(packet) < 20:
            state["malformed"] += 1
            return
        ether_type = _integer(packet, 0, 2, "big")
        cursor = 20
    _ether_payload(packet, cursor, ether_type, state)


def _wireless(packet: bytes, state: dict) -> None:
    if len(packet) < 2:
        state["malformed"] += 1
        return
    frame_control = _integer(packet, 0, 2, "little")
    frame_type = (frame_control >> 2) & 0x03
    subtype = (frame_control >> 4) & 0x0F
    names = ("management", "control", "data", "extension")
    _increment(state["wireless_types"], names[frame_type])
    subtype_names = {
        0: {
            0: "association_request", 1: "association_response",
            2: "reassociation_request", 3: "reassociation_response",
            4: "probe_request", 5: "probe_response",
            8: "beacon", 10: "disassociation", 11: "authentication",
            12: "deauthentication", 13: "action",
        },
        1: {
            8: "block_ack_request", 9: "block_ack", 10: "power_save_poll",
            11: "rts", 12: "cts", 13: "ack", 14: "cf_end", 15: "cf_end_ack",
        },
        2: {
            0: "data", 4: "null", 8: "qos_data", 12: "qos_null",
        },
        3: {},
    }
    label = subtype_names[frame_type].get(subtype, f"type_{frame_type}_subtype_{subtype}")
    _increment(state["wireless_subtypes"], label)
    minimum_lengths = (24, 10, 24, 4)
    if len(packet) < minimum_lengths[frame_type]:
        state["malformed"] += 1


def _parse_packet(packet: bytes, link_type: int, state: dict) -> None:
    if link_type == 1:
        _ethernet(packet, state)
    elif link_type == 105:
        _wireless(packet, state)
    elif link_type == 113:
        _linux_cooked(packet, state, version=1)
    elif link_type == 276:
        _linux_cooked(packet, state, version=2)
    elif link_type == 127:
        if len(packet) < 8 or packet[0] != 0:
            state["malformed"] += 1
            return
        header_length = _integer(packet, 2, 2, "little")
        if header_length < 8 or header_length > len(packet):
            state["malformed"] += 1
            return
        _wireless(packet[header_length:], state)


def _sorted_counts(counter: Counter, *, numeric=False) -> dict:
    if numeric:
        return {key: counter[key] for key in sorted(counter, key=lambda item: int(item))}
    return {key: counter[key] for key in sorted(counter)}


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    encoded = payload.get("capture_base64")
    if not isinstance(encoded, str) or not encoded:
        raise ValueError("capture_base64 must contain a base64-encoded classic PCAP file")
    if len(encoded) > MAX_ENCODED_BYTES:
        raise ValueError(f"capture exceeds the {MAX_CAPTURE_BYTES}-byte file limit")
    try:
        capture = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as error:
        raise ValueError("capture_base64 must be valid standard base64") from error
    if not capture or len(capture) > MAX_CAPTURE_BYTES:
        raise ValueError(f"capture must contain between 1 and {MAX_CAPTURE_BYTES} decoded bytes")
    if len(capture) < 24:
        raise ValueError("capture is shorter than the 24-byte PCAP global header")

    magic = capture[:4]
    if magic not in MAGIC:
        raise ValueError("unsupported capture format; classic PCAP is required (PCAPNG is not supported)")
    byteorder, divisor, resolution = MAGIC[magic]
    major = _integer(capture, 4, 2, byteorder)
    minor = _integer(capture, 6, 2, byteorder)
    if (major, minor) != (2, 4):
        raise ValueError("PCAP version 2.4 is required")
    snaplen = _integer(capture, 16, 4, byteorder)
    link_type = _integer(capture, 20, 4, byteorder) & 0xFFFF
    if not 1 <= snaplen <= MAX_SNAPLEN:
        raise ValueError(f"PCAP snap length must be from 1 to {MAX_SNAPLEN} bytes")
    if link_type not in SUPPORTED_LINK_TYPES:
        raise ValueError("unsupported PCAP link type; supported types are Ethernet, IEEE 802.11 and radiotap")

    maximum_packets = payload.get("maximum_packets", MAX_PACKETS)
    if isinstance(maximum_packets, bool) or not isinstance(maximum_packets, int) or not 1 <= maximum_packets <= MAX_PACKETS:
        raise ValueError(f"maximum_packets must be an integer from 1 to {MAX_PACKETS}")

    state = {
        "malformed": 0,
        "truncated": 0,
        "ipv4": 0,
        "ipv6": 0,
        "arp": 0,
        "dscp": Counter(),
        "ip_protocols": Counter(),
        "ether_types": Counter(),
        "wireless_types": Counter(),
        "wireless_subtypes": Counter(),
        "destination_ports": Counter(),
    }
    cursor = 24
    packets_read = 0
    captured_bytes = 0
    wire_bytes = 0
    first_packet_at = None
    last_packet_at = None
    packet_header_size = 16

    while cursor < len(capture):
        if packets_read >= maximum_packets:
            raise ValueError(f"capture exceeds the {maximum_packets}-packet analysis limit")
        if len(capture) - cursor < packet_header_size:
            raise ValueError("capture ends with an incomplete packet record header")
        seconds = _integer(capture, cursor, 4, byteorder)
        fraction = _integer(capture, cursor + 4, 4, byteorder)
        included_length = _integer(capture, cursor + 8, 4, byteorder)
        original_length = _integer(capture, cursor + 12, 4, byteorder)
        cursor += packet_header_size
        if fraction >= divisor:
            raise ValueError("capture packet timestamp fraction exceeds its resolution")
        if included_length > snaplen or included_length > MAX_FRAME_BYTES:
            raise ValueError("capture packet exceeds the declared snap length or frame limit")
        if original_length < included_length:
            raise ValueError("capture packet original length is smaller than its captured length")
        if included_length > len(capture) - cursor:
            raise ValueError("capture ends with a truncated packet record")
        packet_time = _utc_timestamp(seconds, fraction, divisor)
        if first_packet_at is None:
            first_packet_at = packet_time
        last_packet_at = packet_time
        frame = capture[cursor:cursor + included_length]
        cursor += included_length
        packets_read += 1
        captured_bytes += included_length
        wire_bytes += original_length
        if included_length < original_length:
            state["truncated"] += 1
        _parse_packet(frame, link_type, state)

    top_ports = [
        {"port": port, "count": count}
        for port, count in sorted(
            state["destination_ports"].items(),
            key=lambda item: (-item[1], item[0]),
        )[:10]
    ]
    return {
        "status": "analysed",
        "capture": {
            "format": "pcap",
            "version": "2.4",
            "byte_order": byteorder,
            "timestamp_resolution": resolution,
            "link_type": link_type,
            "link_type_name": SUPPORTED_LINK_TYPES[link_type],
            "snap_length_bytes": snaplen,
            "capture_sha256": hashlib.sha256(capture).hexdigest(),
        },
        "summary": {
            "packet_count": packets_read,
            "captured_bytes": captured_bytes,
            "wire_bytes": wire_bytes,
            "truncated_packet_count": state["truncated"],
            "malformed_frame_count": state["malformed"],
            "ipv4_packet_count": state["ipv4"],
            "ipv6_packet_count": state["ipv6"],
            "arp_packet_count": state["arp"],
            "first_packet_at": first_packet_at,
            "last_packet_at": last_packet_at,
        },
        "ether_type_counts": _sorted_counts(state["ether_types"]),
        "ip_protocol_counts": _sorted_counts(state["ip_protocols"]),
        "dscp_counts": _sorted_counts(state["dscp"], numeric=True),
        "top_destination_ports": top_ports,
        "wireless_frame_type_counts": _sorted_counts(state["wireless_types"]),
        "wireless_subtype_counts": _sorted_counts(state["wireless_subtypes"]),
        "privacy": {
            "packet_payloads_returned": False,
            "source_and_destination_addresses_returned": False,
            "ssid_and_bssid_values_returned": False,
        },
        "note": (
            "This is offline classic-PCAP analysis only. It does not start a live capture, "
            "select interfaces, send traffic, or support PCAPNG. Use an operator-approved "
            "capture tool to create the input file; sensitive addresses and payloads are not returned."
        ),
    }


FEATURE = {
    "id": "F191",
    "slug": "pcap_capture_analyzer",
    "name": "Bounded PCAP capture analyzer",
    "category": "Packet analysis",
    "description": (
        "Analyse bounded classic PCAP files for Ethernet, Linux cooked, IPv4/IPv6, TCP/UDP, DSCP and "
        "802.11/radiotap frame statistics without returning packet payloads or endpoint addresses."
    ),
    "parameters": {
        "capture_base64": "standard-base64 classic PCAP file, decoded size up to 512 KiB",
        "maximum_packets": f"optional packet limit from 1 to {MAX_PACKETS}",
    },
    "run": run,
}
