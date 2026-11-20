# Live packet capture

## Availability

The authenticated Packet Capture panel can enumerate interfaces reported by
the host's `tcpdump -D`, start one operator-requested capture, stop it early,
and load the resulting classic PCAP into the offline analyzer.

Live capture requires `tcpdump`/libpcap and OS packet-capture privileges. The
software does not install packet drivers, elevate privileges, enable monitor
mode or change network configuration. The operator must make any required
monitor-mode or host permission changes outside the application.

## Permission and limits

Every capture endpoint requires the `diagnostics.run` permission. Read-only
viewers cannot enumerate interfaces, inspect capture status, start or stop a
capture, or download the packet file.

Before starting, the operator must explicitly confirm that they are authorised
to capture traffic on the selected interface and network. Only a fixed set of
filter profiles is accepted: `all`, `dns`, `dhcp`, `arp`, `tcp`, `udp`
and `icmp`. Arbitrary BPF expressions and shell commands are rejected.

A capture is bounded to 60 seconds, 1,000 packets, a 256-byte snap length and
512 KiB on disk. Only one capture can run at a time. Files are kept in a
private local directory; files older than 24 hours are removed when the next
capture starts. A completed file is downloadable only through the authenticated
API and only after the operator explicitly requests it.

Packet capture can collect sensitive communications even when the analyzer
redacts addresses and payloads from its analysis summary. Use the tool only on
networks and devices you are authorised to monitor, and follow your
organisation's notice, privacy and retention requirements.

## Least-privilege deployment

Install `tcpdump`/libpcap through the operating system package manager and
grant the service account the minimum host capture capability available on
that platform. Do not run the entire dashboard as root just to enable packet
capture. Check the service logs and the operating system's capture permission
model when interface enumeration or capture startup fails.
