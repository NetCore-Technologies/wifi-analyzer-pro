# Host scan capability diagnostics

The live Diagnostics endpoint includes a `host_capabilities` object describing
which operating-system utilities are discoverable by the running WiFi Analyzer
Pro process.

The probe is intentionally non-invasive: it uses executable lookup in the
process PATH and an executable permission-bit check. It does not execute the
reported utilities, start a scan, request elevation, inspect credential stores,
or attempt to change network configuration. The response does not include
local executable paths.

## Platform coverage

| Platform | Preferred Wi-Fi tools | Fallback or supporting tools |
|---|---|---|
| Linux | `iw` | NetworkManager `nmcli`, legacy `iwconfig`, `rfkill` |
| macOS | `system_profiler` | legacy `airport` where present, `wdutil` where available, `networksetup` |
| Windows | `netsh` | PowerShell WLAN diagnostics, `ipconfig`, `arp`, `route` |

A missing preferred utility does not automatically mean scanning is impossible:
the result describes which fallback tools are present. `scan_backend_status`
is `available`, `limited`, `unavailable` or `unsupported` according to
the discovered profile tools.

## Permission limitations

Executable discovery is not a permission test for the Wi-Fi adapter.

- Linux active scans may require suitable nl80211 privileges, capabilities or
  NetworkManager access. Container isolation and driver support can still block
  scans even when `iw` is executable.
- macOS privacy controls, including Location Services/TCC and app signing or
  entitlement context, cannot be reliably established by checking binaries.
  The user may need to approve the packaged application or terminal host.
- Windows utility discovery does not establish WLAN AutoConfig service state,
  driver health, adapter availability or the current user's WLAN access.

The API therefore returns `permission_status: not_verified` and includes a
platform-specific explanation. It never reports permission as granted merely
because a command exists.

## Operational troubleshooting

1. Check the missing utility and its suggested remediation in the Diagnostics
   tab.
2. Install the utility using the operating system's supported package manager
   or restore the standard system component.
3. Restart WiFi Analyzer Pro after changing PATH or service state.
4. Review the operating system's privacy controls and wireless-driver status.
5. Run a new scan. A successful executable probe is not a substitute for a
   successful live scan.

The capability report is refreshed with the normal Diagnostics API response.
It performs only local executable lookup and does not send command output,
host executable paths, user account names or Wi-Fi credentials to the server.
