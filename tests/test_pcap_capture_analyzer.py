"""Regression tests for the bounded offline PCAP analyzer."""
from __future__ import annotations

import base64
import struct
import unittest

from wifi_analyzer_backend.feature_plugins.feature_191_pcap_capture_analyzer import run


def make_capture(link_type, frames=(), *, byteorder="<", nano=False, snaplen=65535):
    magic = {
        ("<", False): bytes.fromhex("d4c3b2a1"),
        (">", False): bytes.fromhex("a1b2c3d4"),
        ("<", True): bytes.fromhex("4d3cb2a1"),
        (">", True): bytes.fromhex("a1b23c4d"),
    }[(byteorder, nano)]
    header = magic + struct.pack(byteorder + "HHIIII", 2, 4, 0, 0, snaplen, link_type)
    fraction = 123456789 if nano else 500000
    records = []
    for packet in frames:
        records.append(struct.pack(byteorder + "IIII", 1760000000, fraction, len(packet), len(packet)) + packet)
    return base64.b64encode(header + b"".join(records)).decode("ascii")


def pcapng_block(block_type, body, *, byteorder="<"):
    total_length = 8 + len(body) + 4
    return (
        struct.pack(byteorder + "II", block_type, total_length)
        + body
        + struct.pack(byteorder + "I", total_length)
    )


def pcapng_section(*, byteorder="<"):
    bom = bytes.fromhex("4d3c2b1a") if byteorder == "<" else bytes.fromhex("1a2b3c4d")
    body = bom + struct.pack(byteorder + "HHq", 1, 0, -1)
    return pcapng_block(0x0A0D0D0A, body, byteorder=byteorder)


def pcapng_option(code, value, *, byteorder="<"):
    padding = b"\x00" * ((-len(value)) % 4)
    return struct.pack(byteorder + "HH", code, len(value)) + value + padding


def pcapng_interface(link_type, *, snaplen=65535, options=b"", byteorder="<"):
    body = struct.pack(byteorder + "HHI", link_type, 0, snaplen) + options
    return pcapng_block(1, body, byteorder=byteorder)


def pcapng_enhanced_packet(interface_id, frame, *, timestamp=1760000000500000, byteorder="<"):
    high = (timestamp >> 32) & 0xFFFFFFFF
    low = timestamp & 0xFFFFFFFF
    padding = b"\x00" * ((-len(frame)) % 4)
    body = (
        struct.pack(byteorder + "IIIII", interface_id, high, low, len(frame), len(frame))
        + frame
        + padding
    )
    return pcapng_block(6, body, byteorder=byteorder)


def pcapng_simple_packet(frame, *, original_length=None, byteorder="<"):
    original_length = len(frame) if original_length is None else original_length
    padding = b"\x00" * ((-len(frame)) % 4)
    return pcapng_block(3, struct.pack(byteorder + "I", original_length) + frame + padding, byteorder=byteorder)


def ethernet_ipv4_udp():
    ethernet = bytes.fromhex("00112233445566778899aabb0800")
    ipv4 = (
        bytes([0x45, 0xB8, 0, 28, 0, 1, 0x40, 0, 64, 17, 0, 0])
        + bytes([192, 0, 2, 10, 198, 51, 100, 20])
    )
    udp = struct.pack("!HHHH", 12345, 53, 8, 0)
    return ethernet + ipv4 + udp


def beacon_frame():
    # Management beacon frame control (subtype 8, type 0), plus a 22-byte header tail.
    return bytes.fromhex("8000") + (b"\x00" * 22)


class PcapCaptureAnalyzerTests(unittest.TestCase):
    def test_analyses_ethernet_ipv4_udp_dscp_and_dns_port_without_exposing_addresses(self):
        result = run({"capture_base64": make_capture(1, [ethernet_ipv4_udp()])})
        self.assertEqual(result["status"], "analysed")
        self.assertEqual(result["capture"]["link_type_name"], "ethernet")
        self.assertEqual(result["summary"]["packet_count"], 1)
        self.assertEqual(result["summary"]["ipv4_packet_count"], 1)
        self.assertEqual(result["ip_protocol_counts"], {"udp": 1})
        self.assertEqual(result["dscp_counts"], {"46": 1})
        self.assertEqual(result["top_destination_ports"], [{"port": 53, "count": 1}])
        self.assertFalse(result["privacy"]["packet_payloads_returned"])
        self.assertFalse(result["privacy"]["source_and_destination_addresses_returned"])
        rendered = str(result)
        for secret in ("192.0.2.10", "198.51.100.20", "001122334455", "001122"):
            self.assertNotIn(secret, rendered)

    def test_supports_big_endian_and_nanosecond_pcap_headers(self):
        result = run({
            "capture_base64": make_capture(
                1, [ethernet_ipv4_udp()], byteorder=">", nano=True,
            )
        })
        self.assertEqual(result["capture"]["byte_order"], "big")
        self.assertEqual(result["capture"]["timestamp_resolution"], "nanosecond")
        self.assertEqual(result["summary"]["packet_count"], 1)

    def test_supports_linux_cooked_v1_and_v2_link_types(self):
        ipv4_payload = ethernet_ipv4_udp()[14:]
        cooked_v1 = (b"\x00" * 14) + bytes.fromhex("0800") + ipv4_payload
        cooked_v2 = bytes.fromhex("0800") + (b"\x00" * 18) + ipv4_payload
        first = run({"capture_base64": make_capture(113, [cooked_v1])})
        second = run({"capture_base64": make_capture(276, [cooked_v2])})
        self.assertEqual(first["capture"]["link_type_name"], "linux_cooked")
        self.assertEqual(second["capture"]["link_type_name"], "linux_cooked_v2")
        self.assertEqual(first["dscp_counts"], {"46": 1})
        self.assertEqual(second["ip_protocol_counts"], {"udp": 1})

    def test_analyses_raw_80211_management_beacons(self):
        result = run({"capture_base64": make_capture(105, [beacon_frame()])})
        self.assertEqual(result["capture"]["link_type_name"], "ieee80211")
        self.assertEqual(result["wireless_frame_type_counts"], {"management": 1})
        self.assertEqual(result["wireless_subtype_counts"], {"beacon": 1})

    def test_extracts_radiotap_signal_noise_and_channel_frequency(self):
        present = (1 << 3) | (1 << 5) | (1 << 6)
        radiotap = bytes((0, 0)) + struct.pack("<HIHHbb", 14, present, 2412, 0x00A0, -48, -95)
        result = run({"capture_base64": make_capture(127, [radiotap + beacon_frame()])})
        observations = result["radiotap_observations"]
        self.assertEqual(observations["signal"], {"sample_count": 1, "average_dbm": -48.0})
        self.assertEqual(observations["noise"], {"sample_count": 1, "average_dbm": -95.0})
        self.assertEqual(observations["channel_frequency_mhz_counts"], {"2412": 1})
        self.assertEqual(result["wireless_subtype_counts"], {"beacon": 1})

    def test_truncated_radiotap_field_metadata_is_rejected_as_malformed(self):
        present = (1 << 3) | (1 << 5) | (1 << 6)
        malformed = bytes((0, 0)) + struct.pack("<HI", 13, present) + b"\x00" * 5
        result = run({"capture_base64": make_capture(127, [malformed])})
        self.assertEqual(result["summary"]["malformed_frame_count"], 1)
        self.assertEqual(result["summary"]["packet_count"], 1)

    def test_skips_radiotap_header_and_parses_embedded_80211_frame(self):
        radiotap = bytes.fromhex("0000080000000000")
        result = run({"capture_base64": make_capture(127, [radiotap + beacon_frame()])})
        self.assertEqual(result["capture"]["link_type_name"], "radiotap")
        self.assertEqual(result["wireless_subtype_counts"], {"beacon": 1})

    def test_counts_truncated_wire_packets_and_malformed_frames(self):
        result = run({"capture_base64": make_capture(1, [b"short"])})
        self.assertEqual(result["summary"]["malformed_frame_count"], 1)

        frame = ethernet_ipv4_udp()
        header = bytes.fromhex("d4c3b2a1") + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
        record = struct.pack("<IIII", 1760000000, 500000, len(frame), len(frame) + 12) + frame
        truncated = run({"capture_base64": base64.b64encode(header + record).decode("ascii")})
        self.assertEqual(truncated["summary"]["truncated_packet_count"], 1)
        self.assertEqual(truncated["summary"]["wire_bytes"], len(frame) + 12)

    def test_parses_pcapng_enhanced_packet_with_nanosecond_interface_resolution(self):
        timestamp = 1760000000 * 1_000_000_000 + 123_456_789
        options = pcapng_option(9, b"\x09")
        capture = (
            pcapng_section()
            + pcapng_interface(1, options=options)
            + pcapng_enhanced_packet(0, ethernet_ipv4_udp(), timestamp=timestamp)
        )
        result = run({"capture_base64": base64.b64encode(capture).decode("ascii")})
        self.assertEqual(result["capture"]["format"], "pcapng")
        self.assertEqual(result["capture"]["version"], "1.0")
        self.assertEqual(result["capture"]["link_type_name"], "ethernet")
        self.assertEqual(result["capture"]["interface_count"], 1)
        self.assertEqual(result["summary"]["packet_count"], 1)
        self.assertEqual(result["summary"]["ipv4_packet_count"], 1)
        self.assertEqual(result["dscp_counts"], {"46": 1})
        self.assertTrue(result["summary"]["first_packet_at"].endswith(".123456Z"))
        self.assertEqual(result["capture"]["interfaces"][0]["timestamp_resolution"], "10^-9 seconds")

    def test_parses_big_endian_pcapng_and_per_interface_timestamp_offset(self):
        timestamp = 1760000000 * 1_000_000 + 500000
        offset = struct.pack(">" + "q", 60)
        options = pcapng_option(14, offset, byteorder=">")
        capture = (
            pcapng_section(byteorder=">")
            + pcapng_interface(105, options=options, byteorder=">")
            + pcapng_enhanced_packet(0, beacon_frame(), timestamp=timestamp, byteorder=">")
        )
        result = run({"capture_base64": base64.b64encode(capture).decode("ascii")})
        self.assertEqual(result["capture"]["byte_order"], "big")
        self.assertEqual(result["capture"]["link_type_name"], "ieee80211")
        self.assertEqual(result["capture"]["interfaces"][0]["timestamp_offset_seconds"], 60)
        self.assertEqual(result["wireless_subtype_counts"], {"beacon": 1})
        self.assertTrue(result["summary"]["first_packet_at"].endswith("Z"))

    def test_parses_pcapng_simple_packet_and_multiple_interface_link_types(self):
        ethernet = ethernet_ipv4_udp()
        radiotap = bytes.fromhex("0000080000000000") + beacon_frame()
        capture = (
            pcapng_section()
            + pcapng_interface(1)
            + pcapng_interface(127)
            + pcapng_simple_packet(ethernet)
            + pcapng_enhanced_packet(1, radiotap)
        )
        result = run({"capture_base64": base64.b64encode(capture).decode("ascii")})
        self.assertEqual(result["capture"]["interface_count"], 2)
        self.assertEqual(result["capture"]["link_type"], None)
        self.assertEqual(result["capture"]["link_type_name"], "multiple")
        self.assertEqual(result["summary"]["packet_count"], 2)
        self.assertEqual(result["summary"]["ipv4_packet_count"], 1)
        self.assertEqual(result["wireless_subtype_counts"], {"beacon": 1})
        self.assertEqual(result["summary"]["first_packet_at"], result["summary"]["last_packet_at"])

    def test_rejects_corrupt_pcapng_block_lengths_and_packet_limit(self):
        capture = (
            pcapng_section()
            + pcapng_interface(1)
            + pcapng_enhanced_packet(0, ethernet_ipv4_udp())
            + pcapng_enhanced_packet(0, ethernet_ipv4_udp())
        )
        with self.assertRaisesRegex(ValueError, "packet limit"):
            run({"capture_base64": base64.b64encode(capture).decode("ascii"), "maximum_packets": 1})

        corrupt = bytearray(pcapng_section() + pcapng_interface(1))
        corrupt[4:8] = struct.pack("<I", 24)
        with self.assertRaisesRegex(ValueError, "section header block has an invalid total length"):
            run({"capture_base64": base64.b64encode(corrupt).decode("ascii")})

    def test_rejects_pcapng_unsupported_interface_and_bad_timestamp_resolution(self):
        unsupported = pcapng_section() + pcapng_interface(999)
        with self.assertRaisesRegex(ValueError, "unsupported PCAPNG interface link type"):
            run({"capture_base64": base64.b64encode(unsupported).decode("ascii")})
        invalid_resolution = pcapng_section() + pcapng_interface(1, options=pcapng_option(9, b"\xff"))
        with self.assertRaisesRegex(ValueError, "binary timestamp resolution is out of range"):
            run({"capture_base64": base64.b64encode(invalid_resolution).decode("ascii")})

    def test_rejects_invalid_base64_format_link_type_version_and_snap_length(self):
        for payload, message in (
            ({"capture_base64": "not base64!"}, "valid standard base64"),
            ({"capture_base64": base64.b64encode(b"not a pcap header" * 2).decode()}, "classic PCAP"),
            ({"capture_base64": make_capture(999)}, "unsupported PCAP link type"),
            ({"capture_base64": base64.b64encode(
                bytes.fromhex("d4c3b2a1") + struct.pack("<HHIIII", 1, 0, 0, 0, 65535, 1)
            ).decode()}, "version 2.4"),
            ({"capture_base64": base64.b64encode(
                bytes.fromhex("d4c3b2a1") + struct.pack("<HHIIII", 2, 4, 0, 0, 0, 1)
            ).decode()}, "snap length"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                run(payload)

    def test_rejects_truncated_records_invalid_timestamp_and_packet_limit(self):
        header = bytes.fromhex("d4c3b2a1") + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
        partial = header + struct.pack("<IIII", 1760000000, 500000, 30, 30) + b"\x00" * 4
        with self.assertRaisesRegex(ValueError, "truncated packet record"):
            run({"capture_base64": base64.b64encode(partial).decode()})

        bad_fraction = header + struct.pack("<IIII", 1760000000, 1000000, 0, 0)
        with self.assertRaisesRegex(ValueError, "timestamp fraction"):
            run({"capture_base64": base64.b64encode(bad_fraction).decode()})

        two_packets = make_capture(1, [ethernet_ipv4_udp(), ethernet_ipv4_udp()])
        with self.assertRaisesRegex(ValueError, "packet limit"):
            run({"capture_base64": two_packets, "maximum_packets": 1})

    def test_rejects_non_object_input_and_invalid_packet_limit(self):
        with self.assertRaisesRegex(ValueError, "payload must be an object"):
            run([])
        for value in (0, 5001, True, "10"):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, "maximum_packets"):
                run({"capture_base64": make_capture(1), "maximum_packets": value})


if __name__ == "__main__":
    unittest.main()
