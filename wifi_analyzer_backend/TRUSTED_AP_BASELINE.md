# Shared trusted access-point baseline

The trusted AP baseline is a shared, site-scoped inventory used by the Rogue AP review panel. It is not tied to one browser profile.

## Access control

- GET /api/trusted-aps?site_id=SITE requires sites.read and an explicit site ID.
- POST /api/trusted-aps requires sites.manage and an explicit site ID.
- The caller must be assigned to the site, unless their role has all-site scope.
- Read-only analysts/viewers can inspect assigned inventories but cannot add or remove entries.
- Each mutation request is recorded before the database is changed. Successful changes also receive an outcome event in the tamper-evident security audit chain.
- If the audit ledger is unavailable, the mutation is not applied.

The write payload is a JSON object with operation equal to add or remove, site_id, ssid and bssid. Add is idempotent. Remove returns removed=false when the entry was not present. BSSIDs are canonicalised to uppercase colon notation and must be unicast six-octet MAC addresses. SSIDs are exact, case-sensitive values with a maximum of 32 UTF-8 bytes and no control characters.

The audit ledger stores a one-way fingerprint for a baseline entry; it does not duplicate raw SSID or BSSID values in audit metadata. The trusted inventory itself is stored in a local SQLite database, outside the repository. Set WIFI_ANALYZER_TRUSTED_AP_DB to override the default application state location. On POSIX systems, newly created state directories are set to mode 0700 and the database file to mode 0600.

## Inventory limits

Each site is limited to 256 exact SSIDs, 64 BSSIDs per SSID and 4096 BSSIDs in total. Duplicate additions do not create duplicate records. Changes are transactional and protected against concurrent writers.

## Detection semantics

The analyzer compares only an observed, valid BSSID under an exact visible SSID that has at least one trusted BSSID in the selected site inventory. An unlisted BSSID is classified as an untrusted review candidate, not as a confirmed rogue or evil-twin AP. Mesh systems, roaming, AP replacements, controller BSSID rotation and incomplete inventories can produce legitimate candidates. Validate against controller inventory and site survey evidence before escalating.