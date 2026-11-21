"""Non-invasive host capability diagnostics for Wi-Fi scanning.

Only executable discovery and local permission-bit checks are performed. This
module does not run scans, change network state, inspect credentials, or claim
that an available executable guarantees OS privacy/privilege approval.
"""
from __future__ import annotations

import os
import shutil
import sys
from typing import Callable

_PROFILES = {
    "linux": {
        "display_name": "Linux",
        "required": [
            ("ip", "gateway and interface discovery", "Install iproute2 (ip)."),
            ("ping", "latency and packet-loss diagnostics", "Install iputils-ping or the distribution equivalent."),
        ],
        "wifi": [
            ("iw", "preferred wireless scan and radio telemetry", "Install iw; ensure the wireless driver exposes nl80211."),
            ("nmcli", "NetworkManager scan fallback", "Install NetworkManager and ensure NetworkManager manages the Wi-Fi adapter."),
            ("iwconfig", "legacy wireless scan fallback", "Install wireless-tools only for legacy drivers."),
        ],
        "optional": [
            ("rfkill", "radio block-state inspection", "Install rfkill to inspect software/hardware radio blocks."),
            ("arp", "legacy neighbour-table fallback", "Use ip neigh when arp is unavailable."),
        ],
        "permission_note": (
            "Executable presence does not prove nl80211 scan permission. Active scans may require "
            "CAP_NET_ADMIN or suitable network-manager privileges; container, sandbox and driver "
            "restrictions must be checked on the host."
        ),
    },
    "darwin": {
        "display_name": "macOS",
        "required": [
            ("system_profiler", "Wi-Fi inventory and scan metadata", "Use a supported macOS installation with system_profiler."),
            ("networksetup", "network service and interface inspection", "Restore the standard macOS networksetup utility."),
            ("ping", "latency and packet-loss diagnostics", "Restore the standard macOS ping utility."),
        ],
        "wifi": [
            ("system_profiler", "supported Wi-Fi inventory path", "Grant the app the macOS privacy permissions requested by the system."),
            ("airport", "legacy Wi-Fi scan fallback on older macOS releases", "The legacy airport utility may be absent on newer macOS releases; system_profiler is the fallback."),
            ("wdutil", "additional wireless diagnostics where available", "wdutil availability and output vary by macOS release and permissions."),
        ],
        "optional": [
            ("networksetup", "network service inspection", "Use the standard macOS networksetup utility."),
            ("netstat", "route inspection fallback", "Use the standard macOS netstat utility."),
        ],
        "permission_note": (
            "This check cannot determine TCC Location Services, Full Disk Access, entitlement or "
            "user-session approval. macOS may return reduced Wi-Fi scan detail until the user grants "
            "the required privacy permission to the packaged app or terminal host."
        ),
    },
    "windows": {
        "display_name": "Windows",
        "required": [
            ("netsh", "WLAN scan and interface diagnostics", "Enable the Windows WLAN stack and restore netsh."),
            ("ipconfig", "interface and gateway discovery", "Restore the standard Windows ipconfig utility."),
            ("ping", "latency and packet-loss diagnostics", "Restore the standard Windows ping utility."),
        ],
        "wifi": [
            ("netsh", "supported WLAN scan and interface path", "Ensure the WLAN AutoConfig service is running and the adapter is enabled."),
            ("powershell", "structured WLAN and service diagnostics", "Install or enable Windows PowerShell."),
        ],
        "optional": [
            ("arp", "neighbour-table inspection", "Use Get-NetNeighbor when arp is unavailable."),
            ("route", "route-table inspection", "Use Get-NetRoute when route is unavailable."),
        ],
        "permission_note": (
            "Executable discovery does not verify WLAN AutoConfig state, adapter driver health, "
            "Windows privacy settings or whether the current account can query the requested interface."
        ),
    },
}


def _profile_key(platform_name: str | None) -> str:
    value = (platform_name or sys.platform).strip().lower()
    if value in {"linux"} or value.startswith("linux"):
        return "linux"
    if value in {"darwin", "mac", "macos"}:
        return "darwin"
    if value in {"windows", "win32", "cygwin"} or value.startswith("win"):
        return "windows"
    return "unsupported"


def diagnose_host(
    platform_name: str | None = None,
    *,
    find_executable: Callable[[str], str | None] = shutil.which,
    executable_check: Callable[[str], bool] = os.access,
) -> dict:
    """Return a bounded, privacy-safe summary of local scanner prerequisites."""
    key = _profile_key(platform_name)
    if key == "unsupported":
        return {
            "platform": platform_name or sys.platform,
            "platform_supported": False,
            "scan_backend_status": "unsupported",
            "tools": [],
            "permission_status": "not_checked",
            "permission_note": "No host capability profile is registered for this operating system.",
            "summary": "Host scan prerequisites could not be assessed on this operating system.",
        }

    profile = _PROFILES[key]
    discovered = {}
    for group, entries in (
        ("required", profile["required"]),
        ("wireless", profile["wifi"]),
        ("optional", profile["optional"]),
    ):
        for name, purpose, remediation in entries:
            item = discovered.get(name)
            if item is None:
                path = find_executable(name)
                if not path:
                    status = "missing"
                elif not executable_check(path, os.X_OK):
                    status = "not_executable"
                else:
                    status = "available"
                item = {
                    "name": name,
                    "groups": [],
                    "purposes": [],
                    "status": status,
                    "available": status == "available",
                    "remediations": [],
                }
                discovered[name] = item
            if group not in item["groups"]:
                item["groups"].append(group)
            if purpose not in item["purposes"]:
                item["purposes"].append(purpose)
            if not item["available"] and remediation not in item["remediations"]:
                item["remediations"].append(remediation)

    tools = [
        {
            **item,
            "group": " + ".join(item["groups"]),
            "purpose": "; ".join(item["purposes"]),
            "remediation": "; ".join(item["remediations"]) if item["remediations"] else None,
        }
        for item in discovered.values()
    ]
    wireless = [item for item in tools if "wireless" in item["groups"]]
    available_wireless = [item for item in wireless if item["available"]]
    required_missing = [
        item["name"] for item in tools
        if "required" in item["groups"] and not item["available"]
    ]
    wifi_missing = [item["name"] for item in wireless if not item["available"]]

    if not available_wireless:
        scan_status = "unavailable"
        summary = "No supported Wi-Fi scan utility was found. Install or restore one of the listed wireless tools."
    elif wifi_missing:
        scan_status = "limited"
        summary = "At least one Wi-Fi utility is available, but one or more scan paths are missing."
    else:
        scan_status = "available"
        summary = "The host has the expected Wi-Fi utilities; actual scan permission and driver support are not verified."

    return {
        "platform": profile["display_name"],
        "platform_supported": True,
        "scan_backend_status": scan_status,
        "tools": tools,
        "missing_required_tools": required_missing,
        "missing_wireless_tools": wifi_missing,
        "available_wireless_tools": [item["name"] for item in available_wireless],
        "permission_status": "not_verified",
        "permission_note": profile["permission_note"],
        "summary": summary,
        "checks_performed": [
            "Executable lookup in the current process PATH.",
            "Executable permission-bit check where supported.",
        ],
        "checks_not_performed": [
            "No wireless scan or controller command was run by this report.",
            "No privilege escalation, entitlement query, driver probe or OS privacy prompt was attempted.",
            "Presence of a utility does not establish radio availability or scan permission.",
        ],
    }
