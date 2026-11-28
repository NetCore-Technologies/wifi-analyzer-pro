#!/usr/bin/env python3
"""Command-line client for a local WiFi Analyzer Pro server.

The CLI uses the same authenticated HTTP API as the dashboard. It never
silently falls back to demo data or invents measurements.
"""
from __future__ import annotations

import argparse
import csv
import getpass
import io
import json
import os
import re
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class ApiError(RuntimeError):
    def __init__(self, message: str, *, status: int | None = None, details: Any = None):
        super().__init__(message)
        self.status = status
        self.details = details


def default_token_path() -> Path:
    configured = os.environ.get("WIFI_ANALYZER_TOKEN_FILE")
    if configured:
        return Path(configured).expanduser()
    if os.name == "nt":
        root = Path(os.environ.get("APPDATA", Path.home()))
    else:
        root = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return root / "wifi-analyzer-pro" / "session.json"


def load_token(path: Path) -> str | None:
    if not path.exists():
        return None
    try:
        if os.name != "nt" and stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise ApiError(
                f"Session file permissions are too broad: {path}. Run chmod 600 on this file."
            )
        value = json.loads(path.read_text(encoding="utf-8"))
    except ApiError:
        raise
    except (OSError, json.JSONDecodeError) as error:
        raise ApiError(f"Unable to read the CLI session file: {error}") from error
    token = value.get("token") if isinstance(value, dict) else None
    if not isinstance(token, str) or not token.strip():
        raise ApiError(f"CLI session file does not contain a token: {path}")
    return token.strip()


def save_token(path: Path, token: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        path.parent.chmod(0o700)
    except OSError:
        pass
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump({"token": token}, handle)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    try:
        path.chmod(0o600)
    except OSError:
        pass


def validate_base_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ApiError("API URL must be an absolute http:// or https:// URL.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ApiError("API URL must not contain credentials, a query string or a fragment.")
    return value.rstrip("/")


class ApiClient:
    def __init__(self, base_url: str, token: str | None = None, timeout: float = 15.0):
        self.base_url = validate_base_url(base_url)
        self.token = token
        self.timeout = timeout

    def request(self, method: str, path: str, payload: dict[str, Any] | None = None) -> Any:
        if not path.startswith("/") or path.startswith("//"):
            raise ApiError("API paths must be absolute paths on the configured server.")
        headers = {"Accept": "application/json"}
        body = None
        if payload is not None:
            try:
                body = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
            except (TypeError, ValueError) as error:
                raise ApiError(f"Request payload is not valid finite JSON: {error}") from error
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(
            f"{self.base_url}{path}", data=body, headers=headers, method=method.upper()
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read()
                status = response.status
        except urllib.error.HTTPError as error:
            raw = error.read()
            try:
                details = json.loads(raw.decode("utf-8")) if raw else {}
            except (UnicodeDecodeError, json.JSONDecodeError):
                details = {}
            message = details.get("error") if isinstance(details, dict) else None
            raise ApiError(
                message or f"API request failed with HTTP {error.code}",
                status=error.code,
                details=details,
            ) from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            reason = getattr(error, "reason", error)
            raise ApiError(f"Cannot reach {self.base_url}: {reason}") from error
        if not 200 <= status < 300:
            raise ApiError(f"API request failed with HTTP {status}", status=status)
        if not raw:
            return {}
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ApiError("The API returned a response that was not valid UTF-8 JSON.") from error


def clean_cell(value: Any, limit: int = 38) -> str:
    if value is None:
        text = "—"
    elif isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False, sort_keys=True)
    else:
        text = str(value)
    text = "".join(character if character.isprintable() else " " for character in text)
    text = " ".join(text.split())
    if len(text) > limit:
        return text[: limit - 1] + "…"
    return text or "—"


def format_table(rows: list[dict[str, Any]], columns: list[tuple[str, str]]) -> str:
    if not rows:
        return "No records returned."
    widths = [
        min(max(len(label), *(len(clean_cell(row.get(key))) for row in rows)), 38)
        for key, label in columns
    ]
    header = "  ".join(label.ljust(width) for (_, label), width in zip(columns, widths))
    rule = "  ".join("─" * width for width in widths)
    body = [
        "  ".join(clean_cell(row.get(key), width).ljust(width) for (key, _), width in zip(columns, widths))
        for row in rows
    ]
    return "\n".join([header, rule, *body])


def network_rows(data: Any) -> list[dict[str, Any]]:
    rows = data.get("networks", []) if isinstance(data, dict) else data
    return [row for row in rows if isinstance(row, dict)] if isinstance(rows, list) else []


def scan_csv(data: Any) -> str:
    rows = network_rows(data)
    fields = ["ssid", "bssid", "band", "channel", "rssi", "snr", "security", "width_mhz", "vendor"]
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for row in rows:
        normalised = dict(row)
        normalised["channel"] = row.get("channel", row.get("ch"))
        normalised["security"] = row.get("security", row.get("sec"))
        for key in ("ssid", "bssid", "band", "security", "vendor"):
            value = normalised.get(key)
            if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
                normalised[key] = "'" + value
        writer.writerow({key: normalised.get(key) for key in fields})
    return output.getvalue()


def read_json_object(source: str) -> dict[str, Any]:
    try:
        raw = sys.stdin.read() if source == "-" else Path(source).expanduser().read_text(encoding="utf-8")
        value = json.loads(raw, parse_constant=lambda token: (_ for _ in ()).throw(ValueError(token)))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise ApiError(f"Unable to read a valid JSON input object: {error}") from error
    if not isinstance(value, dict):
        raise ApiError("Feature input must be a JSON object.")
    return value


def add_format_option(parser: argparse.ArgumentParser, choices: tuple[str, ...] = ("table", "json")) -> None:
    parser.add_argument("--format", choices=choices, default="table", help="Output format.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wifi-analyzer",
        description="Local-first Wi-Fi and RF diagnostics using the WiFi Analyzer Pro API.",
        epilog="Set WIFI_ANALYZER_TOKEN or run 'wifi-analyzer login' before authenticated commands.",
    )
    parser.add_argument("--url", default=os.environ.get("WIFI_ANALYZER_URL", "http://127.0.0.1:199"),
                        help="API base URL (default: http://127.0.0.1:199).")
    parser.add_argument("--token", default=os.environ.get("WIFI_ANALYZER_TOKEN"),
                        help="Bearer token. Prefer the secure CLI session file or environment variable.")
    parser.add_argument("--token-file", type=Path, default=default_token_path(),
                        help="Session token file (default: per-user config directory).")
    parser.add_argument("--timeout", type=float, default=15.0, help="HTTP timeout in seconds.")
    commands = parser.add_subparsers(dest="command")

    commands.add_parser("status", help="Show server and account status.")
    commands.add_parser("setup", help="Create the first local owner account.")
    login = commands.add_parser("login", help="Sign in and store a short-lived session token securely.")
    login.add_argument("--username", default="admin")
    commands.add_parser("logout", help="Revoke the current CLI session.")

    scan = commands.add_parser("scan", help="Run a scan and display or export observed access points.")
    add_format_option(scan, ("table", "json", "csv"))

    devices = commands.add_parser("devices", help="List devices visible to the current account.")
    add_format_option(devices)

    diagnostics = commands.add_parser("diagnostics", help="Run host and network diagnostics.")
    add_format_option(diagnostics)

    features = commands.add_parser("features", help="Browse and execute the built-in feature catalogue.")
    feature_commands = features.add_subparsers(dest="feature_command", required=True)
    listing = feature_commands.add_parser("list", help="List callable feature tools.")
    listing.add_argument("--query", default="", help="Filter by name, slug, category or description.")
    add_format_option(listing)
    run = feature_commands.add_parser("run", help="Execute a feature by slug with a JSON object.")
    run.add_argument("slug", help="Feature slug from the feature list.")
    run.add_argument("--input", default="-", help="JSON file path, or - to read JSON from stdin.")
    run.add_argument("--format", choices=("json",), default="json", help="Feature results are JSON.")

    report = commands.add_parser("report", help="Collect a point-in-time scan, device and diagnostics report.")
    report.add_argument("--output", type=Path, help="Write JSON to this file instead of stdout.")
    report.add_argument("--pretty", action="store_true", help="Indent the JSON report.")

    return parser


def output_json(value: Any, *, pretty: bool = True) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2 if pretty else None, allow_nan=False))


def run_command(args: argparse.Namespace, client: ApiClient) -> int:
    command = args.command
    if command == "status":
        output_json(client.request("GET", "/api/auth/status"))
        return 0
    if command in {"setup", "login"}:
        username = getattr(args, "username", "admin")
        if command == "setup":
            password = getpass.getpass("Choose local account password: ")
            confirmation = getpass.getpass("Confirm password: ")
            if password != confirmation:
                raise ApiError("Passwords do not match.")
            path = "/api/auth/setup"
        else:
            password = getpass.getpass("Password: ")
            path = "/api/auth/login"
        try:
            response = client.request("POST", path, {"username": username, "password": password})
        except ApiError as error:
            if command == "login" and isinstance(error.details, dict) and error.details.get("mfa_required"):
                code = getpass.getpass("Authenticator or recovery code: ")
                response = client.request(
                    "POST", path, {"username": username, "password": password, "code": code}
                )
            else:
                raise
        token = response.get("token") if isinstance(response, dict) else None
        if not isinstance(token, str) or not token:
            raise ApiError("Authentication endpoint did not return a session token.")
        save_token(args.token_file, token)
        print(f"Signed in successfully. Session stored in {args.token_file} with owner-only permissions.")
        if isinstance(response, dict) and response.get("status"):
            output_json(response["status"])
        return 0
    if command == "logout":
        response = client.request("POST", "/api/auth/logout", {})
        try:
            args.token_file.unlink(missing_ok=True)
        except OSError as error:
            raise ApiError(f"Session was revoked but the local token file could not be removed: {error}") from error
        output_json(response)
        return 0
    if command == "scan":
        data = client.request("GET", "/api/scan")
        if args.format == "json":
            output_json(data)
        elif args.format == "csv":
            print(scan_csv(data), end="")
        else:
            rows = network_rows(data)
            for row in rows:
                row.setdefault("channel", row.get("ch"))
                row.setdefault("security", row.get("sec"))
            columns = [
                ("ssid", "SSID"), ("bssid", "BSSID"), ("band", "BAND"),
                ("channel", "CH"), ("rssi", "RSSI"), ("security", "SECURITY"),
            ]
            print(format_table(rows, columns))
            source = data.get("source") if isinstance(data, dict) else None
            print(f"\n{len(rows)} access point(s) · observation source: {source or 'not reported'}")
        return 0
    if command == "devices":
        data = client.request("GET", "/api/devices")
        if args.format == "json":
            output_json(data)
        else:
            rows = data.get("devices", []) if isinstance(data, dict) else []
            columns = [("hostname", "HOST"), ("ip", "IP"), ("mac", "MAC"), ("vendor", "VENDOR"), ("online", "ONLINE")]
            print(format_table([row for row in rows if isinstance(row, dict)], columns))
        return 0
    if command == "diagnostics":
        data = client.request("GET", "/api/diagnostics")
        if args.format == "json":
            output_json(data)
        else:
            rows = [{"check": key, "result": value} for key, value in data.items()] if isinstance(data, dict) else []
            print(format_table(rows, [("check", "CHECK"), ("result", "RESULT")]))
        return 0
    if command == "features":
        if args.feature_command == "list":
            data = client.request("GET", "/api/features")
            rows = data.get("features", []) if isinstance(data, dict) else []
            query = args.query.strip().casefold()
            if query:
                rows = [
                    row for row in rows
                    if query in " ".join(
                        str(row.get(key, "")) for key in ("id", "slug", "name", "category", "description")
                    ).casefold()
                ]
            if args.format == "json":
                output_json({"count": len(rows), "features": rows})
            else:
                columns = [("id", "ID"), ("slug", "SLUG"), ("name", "NAME"), ("category", "CATEGORY")]
                print(format_table([row for row in rows if isinstance(row, dict)], columns))
                print(f"\n{len(rows)} tool(s)")
            return 0
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,127}", args.slug):
            raise ApiError("Feature slug contains unsupported characters.")
        payload = read_json_object(args.input)
        slug = urllib.parse.quote(args.slug, safe="")
        output_json(client.request("POST", f"/api/features/{slug}", payload))
        return 0
    if command == "report":
        report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "server": args.url,
            "scan": client.request("GET", "/api/scan"),
            "devices": client.request("GET", "/api/devices"),
            "diagnostics": client.request("GET", "/api/diagnostics"),
        }
        rendered = json.dumps(
            report, ensure_ascii=False, indent=2 if args.pretty else None, allow_nan=False
        ) + "\n"
        if args.output:
            destination = args.output.expanduser()
            destination.write_text(rendered, encoding="utf-8")
            print(f"Report written to {destination}")
        else:
            print(rendered, end="")
        return 0
    raise ApiError("Choose a command. Run wifi-analyzer --help for available commands.")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0
    try:
        token = args.token or load_token(args.token_file)
        client = ApiClient(args.url, token=token, timeout=args.timeout)
        return run_command(args, client)
    except ApiError as error:
        print(f"wifi-analyzer: {error}", file=sys.stderr)
        if error.status == 401:
            print("Sign in with wifi-analyzer login or configure WIFI_ANALYZER_TOKEN.", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
