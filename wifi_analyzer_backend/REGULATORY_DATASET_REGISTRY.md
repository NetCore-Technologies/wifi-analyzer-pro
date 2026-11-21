# Site-scoped regulatory dataset registry

The registry retains immutable, versioned F206 results for use by F207. It
stores the normalized dataset, the exact reviewer acknowledgement, the F206
fingerprint and a second SHA-256 digest over the serialized stored document.
The registry does not fetch regulator URLs, authenticate original documents
or claim that a reviewer acknowledgement is a legal approval.

## API

All routes require an authenticated account and explicit site access.

- GET /api/sites/regulatory-datasets?site_id=SITE&limit=50&include_revoked=false
  lists retained versions. include_revoked defaults to true so administrators
  can inspect complete history.
- GET /api/sites/regulatory-datasets/REGISTRY_UUID?site_id=SITE retrieves the
  immutable dataset and reviewer acknowledgement. A revoked version returns
  HTTP 410 and its metadata, but not the dataset document.
- POST /api/sites/regulatory-datasets retains a dataset with
  {site_id, dataset, acknowledgement}. The operation may be omitted or set to
  retain.
- POST /api/sites/regulatory-datasets with
  {operation:"revoke", site_id, dataset_ref, reason} revokes one retained
  version. Revocation is irreversible through this API.

GET requires sites.read. Retain and revoke require sites.manage and explicit
site assignment (or an all-site role). Registry writes are rate-limited to
12 requests per minute per client.

## Retention and integrity

F206 validation is repeated at write time through the F207 validation
boundary. A dataset must be currently validated, in effect, from a currently
allowlisted jurisdiction/domain, have consistent source/rule counts and exact
source-clause references, and retain the same canonical fingerprint. The
review acknowledgement must bind to that exact fingerprint and be no older
than 90 days.

The identity tuple (site_id, jurisdiction, dataset_id, version) is unique.
Submitting the exact same fingerprint and acknowledgement is idempotent.
Reusing the same identity/version with different content or review metadata is
rejected; publish a new version instead. Each site can retain up to 100
versions. The registry never silently removes an old version to make room for
a new one.

Stored dataset content and review metadata are immutable in SQLite, enforced
by a database trigger. Revocation is stored separately from immutable content
with the revoking username, UTC timestamp and mandatory 12-512 character
reason. Every retain/revoke request is recorded before mutation in the
tamper-evident security audit chain, and a corresponding outcome event is
recorded afterward. If the request audit event cannot be written, the store is
not changed.

The database is outside the repository. Set
WIFI_ANALYZER_REGULATORY_DATASETS_DB to override its path. POSIX state
directories are mode 0700 and SQLite database, WAL and shared-memory files are
restricted to mode 0600. The normalized result is limited to 900 KiB; the
site registry is limited to 100 versions by default.

## Use from F207

The F207 feature endpoint accepts either:
- regulatory_dataset plus dataset_acknowledgement inline; or
- regulatory_dataset_ref together with site_id and radios.

For a registry reference, the server loads the exact dataset and
acknowledgement from the matching site, refuses a revoked or cross-site
version, and runs the normal F207 fingerprint/source/clause/effectiveness
checks again. If a version is later revoked, future F207 requests by reference
return HTTP 410. A caller who previously exported or copied a dataset may
still hold that old document; F207's inline-input mode cannot consult the
revocation registry. Use the registry-reference mode for centrally governed
production planning.
