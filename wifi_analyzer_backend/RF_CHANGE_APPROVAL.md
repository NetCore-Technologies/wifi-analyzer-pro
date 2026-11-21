# RF controller change approval (F208)

F208 creates a durable, site-scoped approval request from an F207 radio
capability/regulatory preview. The approval register is intentionally separate
from the controller adapters: registered OpenWrt, UniFi and MikroTik adapters
remain read-only.

## Create a request

POST /api/sites/rf-change-requests requires diagnostics.run, sites.manage and
explicit access to the requested site. The JSON body contains:

- site_id
- dataset_ref: UUID of an immutable, retained F206 regulatory dataset for the site
- adapter_id: openwrt, unifi or mikrotik
- radios: exact controller/agent capability records used for the F207 preview
- expiry_minutes: 1–1440, default 60
- maximum_capability_age_days: 1–30, default 7

The server retrieves the F206 dataset and reviewer acknowledgement from the
site registry; a client cannot replace them with unretained rule JSON. It runs
F207 and F208 on the same supplied radio capability snapshot. Partial or
ineligible plans, stale capabilities, no-op plans, mismatched dataset
fingerprints, malformed source records and empty change sets are rejected.

The canonical approval packet binds the retained dataset reference and
fingerprint, reviewer metadata, radio IDs, installation references, capability
timestamps, cited rule references and each proposed before/after channel,
width and EIRP value. A SHA-256 digest is checked whenever the packet is read.

## Approval lifecycle

A request begins as pending_approval and expires within 24 hours. Exactly two
distinct site managers must approve it. The requester cannot approve their own
request, and an approver can submit only one decision per request. A rejection
is terminal. The requester may cancel while the request is pending. State
transitions are serialized in SQLite; packet content is immutable and approval
and event records are append-only.

The lifecycle is:

pending_approval -> approved_not_applied
pending_approval -> rejected | cancelled | expired | invalidated
approved_not_applied -> invalidated

A missing or revoked retained F206 dataset invalidates a pending or approved
request. The server checks the retained dataset again when a decision or
deployment-gate action is submitted.

## Deployment gate

POST /api/sites/rf-change-requests/REQUEST_UUID/execute is available only to
site managers. It does not run shell commands or send controller writes.
While the registered adapter is read-only it returns HTTP 409 with
code=write_adapter_unavailable and records an execution_blocked event. The
request remains approved_not_applied and the response explicitly says
applied=false.

A write-capable adapter must not be enabled until it supports authenticated
transport, least-privilege credentials, live read-before-write state
revalidation, configuration transaction/rollback, post-write read-back
verification, timeout/retry/idempotency handling and a durable deployment
result. The registered adapters do not yet provide those capabilities.

F208 is an organisational approval record, not proof of legal compliance,
cryptographic regulator review, AFC grant validity at deployment, DFS radar
clearance or operational safety.
