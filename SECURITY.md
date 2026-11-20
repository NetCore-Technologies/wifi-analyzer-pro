# Security Policy

## Reporting a Vulnerability

If you find a security vulnerability in WiFi Analyzer Pro, please do NOT open a public issue.

Email: manit6752025@gmail.com  
HackerOne: https://hackerone.com/irule675

I will respond within 48 hours.


## Local security audit trail

The application writes selected security events to a separate SQLite database under the local state directory. The default path is derived from the same platform state directory as site history and is named \`security-audit.sqlite3\`. Set \`WIFI_ANALYZER_HISTORY_DB\` to a custom database location to keep the audit ledger alongside a custom state database.

The endpoints and dashboard page require the \`users.manage\` permission, which is limited to the workspace owner and administrator roles. Events deliberately omit passwords, bearer tokens, webhook signing secrets and request bodies.

Rows are append-only through SQLite triggers. Each SHA-256 digest links a canonical JSON representation of the event to the previous event digest. Verification detects altered rows and deleted middle records. This is tamper-evident local storage, not a remote immutable archive: a privileged host administrator can replace the database, remove triggers or rewrite the full chain. For stronger evidence, export and sign periodic head-hash checkpoints or forward events to an independently administered SIEM.

Failed login attempts are not all written individually, to avoid turning unauthenticated traffic into unbounded disk writes. Account lockout events and authenticated permission denials are recorded. Audit writes are best-effort; monitor service logs and host storage. See [the audit trail operator guide](wifi_analyzer_backend/SECURITY_AUDIT.md) for details.
