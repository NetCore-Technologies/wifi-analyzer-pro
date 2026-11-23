"""Strict WebSocket control-frame protocol validation tests."""
from __future__ import annotations

import socket
import struct
import unittest
from types import SimpleNamespace

from wifi_analyzer_backend import server


class WebSocketControlFrameTests(unittest.TestCase):
    @staticmethod
    def decode(opcode, payload=b"", *, masked=True, fin=True, rsv=0, extended=None):
        peer, server_socket = socket.socketpair()
        peer.settimeout(1)
        server_socket.settimeout(1)
        handler = SimpleNamespace(connection=server_socket)
        mask = b"\x11\x22\x33\x44"
        first = (0x80 if fin else 0) | rsv | opcode
        length = len(payload)
        if extended == 126:
            second = (0x80 if masked else 0) | 126
            header = bytes((first, second)) + struct.pack("!H", length)
        elif extended == 127:
            second = (0x80 if masked else 0) | 127
            header = bytes((first, second)) + struct.pack("!Q", length)
        else:
            if length >= 126:
                raise ValueError("test helper requires an extended length")
            second = (0x80 if masked else 0) | length
            header = bytes((first, second))
        body = bytes(value ^ mask[index % 4] for index, value in enumerate(payload)) if masked else payload
        peer.sendall(header + (mask if masked else b"") + body)
        try:
            return server.Handler.read_websocket_control_frame(handler)
        finally:
            peer.close()
            server_socket.close()

    def test_valid_ping_and_pong_frames_are_unmasked_for_the_handler(self):
        self.assertEqual(self.decode(0x9, b"probe"), (0x9, b"probe"))
        self.assertEqual(self.decode(0xA, b"probe"), (0xA, b"probe"))

    def test_valid_close_frame_accepts_registered_code_and_utf8_reason(self):
        payload = struct.pack("!H", 1000) + "client shutdown".encode("utf-8")
        self.assertEqual(self.decode(0x8, payload), (0x8, payload))

    def test_rejects_unmasked_nonfinal_reserved_and_data_frames(self):
        with self.assertRaisesRegex(ValueError, "masked"):
            self.decode(0x9, b"ping", masked=False)
        with self.assertRaisesRegex(ValueError, "masked"):
            self.decode(0x9, b"ping", fin=False)
        with self.assertRaisesRegex(ValueError, "masked"):
            self.decode(0x9, b"ping", rsv=0x40)
        with self.assertRaisesRegex(ValueError, "masked"):
            self.decode(0x2, b"binary")

    def test_rejects_noncanonical_extended_length_and_oversized_control_frame(self):
        with self.assertRaisesRegex(ValueError, "canonical"):
            self.decode(0x9, b"x" * 125, extended=126)
        with self.assertRaisesRegex(ValueError, "125 bytes"):
            self.decode(0x9, b"x" * 126, extended=126)

    def test_rejects_invalid_close_payloads_codes_and_utf8_reasons(self):
        with self.assertRaisesRegex(ValueError, "one-byte"):
            self.decode(0x8, b"\x03")
        with self.assertRaisesRegex(ValueError, "reserved or invalid"):
            self.decode(0x8, struct.pack("!H", 1005))
        with self.assertRaisesRegex(ValueError, "reserved or invalid"):
            self.decode(0x8, struct.pack("!H", 2000))
        with self.assertRaisesRegex(ValueError, "UTF-8"):
            self.decode(0x8, struct.pack("!H", 1000) + b"\xff")


if __name__ == "__main__":
    unittest.main()
