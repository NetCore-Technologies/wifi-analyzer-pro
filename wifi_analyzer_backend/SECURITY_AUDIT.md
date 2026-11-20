# Security audit trail

WiFi Analyzer Pro stores selected security events in a separate local SQLite database. The default path is derived from the same platform state directory as site history and is named \`security-audit.sqlite3\`. Set \`WIFI_ANALYZER_HISTORY_DB\` to a custom database location to keep the audit ledger alongside a custom state database.

## Access

The endpoints and dashboard page require the \`users.manage\` permission, which is limited to the workspace owner and administrator roles:

- \`GET /api/security/audit\` — list events; supports \`limit\` (1–200), \`before_id\`, \`action\`, \`outcome\` and \`actor_username\` filters.
- \`GET /api/security/audit/verify\` — verify the complete local hash chain.
- \`GET /api/security/audit/summary\` — read event counts and the latest hash.

The Security Audit page includes outcome/action filters, pagination and a verification action.

## Recorded event classes

The current integration records successful setup/login/logout, authenticated permission denials, user creation/update and router-agent credential enrollment/rotation/revocation. Individual invalid-password attempts are intentionally not retained at this stage to avoid turning unauthenticated traffic into unbounded disk writes.

Each event includes a monotonic SQLite row ID, random event ID, UTC timestamp, optional request ID, actor user ID/name/role, action, target type/ID, outcome, allowlisted metadata, previous digest and current digest. The metadata allowlist intentionally excludes arbitrary request payloads. Passwords, bearer tokens, signing secrets, raw packet contents and HTTP request bodies are not audit fields.

## Integrity and limitations

Rows are append-only through SQLite triggers that reject ordinary \`UPDATE\` and \`DELETE\` statements. Each digest is calculated from a canonical JSON representation of the event and the previous event digest. Verification replays the chain from a fixed all-zero initial digest and checks each link. An altered row or deleted middle record breaks verification.

This is tamper-evident local storage, not cryptographic immutability against a privileged host administrator. A user who can replace the database, drop triggers or rewrite the full database can also rewrite the local chain. For stronger evidence, export and sign periodic head-hash checkpoints or forward events to a SIEM or immutable logging platform administered separately from the WiFi Analyzer Pro host.

The application does not yet provide external syslog/SIEM forwarding, per-tenant audit partitions, customer retention policy controls or regulatory compliance certification. Audit writes are best-effort so a disk/SQLite failure does not turn a completed user/agent operation into an ambiguous failed HTTP response; monitor host storage and service logs.


## Signed checkpoint export

Use **Export signed checkpoint** in the Security Audit panel, or request
`GET /api/security/audit/checkpoint`. The server first verifies the complete
local chain; it refuses to sign a ledger that fails verification. The exported
JSON contains the event count, latest event hash, issue time, Ed25519 public key,
its SHA-256 fingerprint and a detached signature over the checkpoint metadata.

The signing key is created on first export beside the audit database and is
stored as a raw Ed25519 private key with owner-only file permissions (0600 on
POSIX). An existing malformed key is treated as an error; it is never silently
replaced, because doing so would create a new signing identity.

**Pin the public-key fingerprint outside the appliance.** Keep the first
checkpoint and fingerprint in an independently administered location. Verify
a later checkpoint with the expected fingerprint pinned from that trusted
location:

```bash
python -m wifi_analyzer_backend.audit_checkpoint checkpoint.json \
  --expected-public-key-fingerprint YOUR_PINNED_SHA256_FINGERPRINT
```

The command validates the bundle signature and rejects a mismatched pinned
fingerprint. Without an independently pinned fingerprint, a self-contained
public key only proves internal consistency, not that the signing identity is
the one previously trusted. A checkpoint attests to a verified ledger head at
one point in time; it does not export the event bodies or provide a remote
append-only archive by itself.
