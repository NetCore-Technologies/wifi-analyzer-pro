from __future__ import annotations

import io
import json
import os
import stat
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from wifi_analyzer_backend.cli import (
    ApiClient,
    ApiError,
    build_parser,
    format_table,
    load_token,
    save_token,
    scan_csv,
    validate_base_url,
)


class FakeResponse:
    def __init__(self, payload: dict, status: int = 200):
        self.body = json.dumps(payload).encode("utf-8")
        self.status = status

    def read(self):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class CliTests(unittest.TestCase):
    def test_base_url_rejects_non_http_and_embedded_credentials(self):
        for value in ("file:///tmp/api", "http://user:pass@localhost:199", "http://localhost:199/?token=x"):
            with self.subTest(value=value), self.assertRaises(ApiError):
                validate_base_url(value)

    def test_api_client_sends_bearer_and_json_body(self):
        response = FakeResponse({"ok": True})
        with patch("urllib.request.urlopen", return_value=response) as open_url:
            result = ApiClient("http://127.0.0.1:199/", token="session-token").request(
                "POST", "/api/features/signal_quality", {"rssi": -55}
            )
        self.assertEqual(result, {"ok": True})
        request = open_url.call_args.args[0]
        self.assertEqual(request.get_header("Authorization"), "Bearer session-token")
        self.assertEqual(json.loads(request.data.decode("utf-8")), {"rssi": -55})
        self.assertEqual(request.full_url, "http://127.0.0.1:199/api/features/signal_quality")

    def test_api_client_surfaces_api_error_body_and_status(self):
        body = json.dumps({"error": "Authentication required"}).encode("utf-8")
        error = urllib.error.HTTPError(
            "http://127.0.0.1:199/api/scan", 401, "Unauthorized", {}, io.BytesIO(body)
        )
        with patch("urllib.request.urlopen", side_effect=error):
            with self.assertRaises(ApiError) as raised:
                ApiClient("http://127.0.0.1:199").request("GET", "/api/scan")
        self.assertEqual(raised.exception.status, 401)
        self.assertEqual(str(raised.exception), "Authentication required")

    def test_scan_csv_normalises_aliases_and_escapes_spreadsheet_formulas(self):
        rendered = scan_csv({
            "networks": [{
                "ssid": "=HYPERLINK(1)",
                "bssid": "aa:bb:cc:dd:ee:ff",
                "band": "5GHz",
                "ch": 36,
                "rssi": -51,
                "sec": "WPA3",
            }]
        })
        self.assertIn("'=HYPERLINK(1)", rendered)
        self.assertIn("5GHz,36,-51,,WPA3", rendered)

    def test_table_has_empty_state_and_bounds_cell_width(self):
        self.assertEqual(format_table([], [("ssid", "SSID")]), "No records returned.")
        rendered = format_table([{"ssid": "A" * 80}], [("ssid", "SSID")])
        self.assertLessEqual(max(map(len, rendered.splitlines())), 38)

    def test_session_file_is_created_with_owner_only_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config" / "session.json"
            save_token(path, "temporary-token")
            self.assertEqual(load_token(path), "temporary-token")
            if os.name != "nt":
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                path.chmod(0o644)
                with self.assertRaisesRegex(ApiError, "permissions are too broad"):
                    load_token(path)

    def test_parser_exposes_core_gui_parity_commands(self):
        args = build_parser().parse_args(["features", "run", "signal_quality", "--input", "-"])
        self.assertEqual(args.command, "features")
        self.assertEqual(args.feature_command, "run")
        self.assertEqual(args.slug, "signal_quality")
        self.assertEqual(args.input, "-")

    def test_tools_alias_and_operational_commands_are_registered(self):
        tools = build_parser().parse_args(["tools", "list", "--query", "roaming"])
        self.assertEqual(tools.command, "tools")
        self.assertEqual(tools.feature_command, "list")
        self.assertEqual(tools.query, "roaming")
        self.assertEqual(build_parser().parse_args(["speedtest"]).command, "speedtest")
        self.assertEqual(build_parser().parse_args(["capabilities"]).command, "capabilities")
        self.assertEqual(build_parser().parse_args(["adapters"]).command, "adapters")

    def test_table_colour_is_opt_in_and_terminal_specific(self):
        plain = format_table([{"name": "Network"}], [("name", "NAME")])
        coloured = format_table([{"name": "Network"}], [("name", "NAME")], color=True)
        self.assertNotIn("\\033[", plain)
        self.assertIn("\\033[1;38;2;255;131;89m", coloured)



if __name__ == "__main__":
    unittest.main()
