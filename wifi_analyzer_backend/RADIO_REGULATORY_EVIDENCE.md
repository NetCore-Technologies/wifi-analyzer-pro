# Radio regulatory evidence validator (F206)

F206 validates an imported, jurisdiction-scoped dataset of wireless radio rules
and their source provenance. It is an evidence-ingestion and schema-validation
feature, not a rule publisher, legal interpretation engine or live regulatory
feed.

## Input contract

Run through the authenticated Feature Workbench or API:

- POST /api/features/radio_regulatory_evidence_validator
- Requires the normal diagnostics.run feature permission.
- JSON request size is bounded by the API's standard body limit.

Top-level fields:

- jurisdiction: uppercase ISO alpha-2 country code, or EU for the regional
  European standards/regulatory source set.
- dataset_id and version: stable import identity and revision.
- regulator: the named regulator or standards authority.
- retrieved_at: timezone-aware timestamp when the evidence was collected.
- effective_from and optional effective_to: date range claimed by the dataset.
- sources: 1-100 source-document records.
- rules: 1-5000 radio-rule records.
- as_of: optional assessment date used to report effective/expired status.

Each source record carries a stable source_id, source_type, title, authority,
document reference, revision, HTTPS URL, publication and effective dates,
retrieval timestamp, caller-provided SHA-256 digest and exact clause references.

Each rule carries a stable rule_id, band, frequency range, maximum EIRP,
optional EIRP density, channel widths and channel numbers, device classes,
indoor/outdoor, DFS and AFC flags, and one or more source_id/clause references.
The source clause must exist in the cited source record.

## Built-in authority-domain hints

The first allowlist release includes common regulator and standards host roots:

| Jurisdiction | Domain roots |
|---|---|
| AU | acma.gov.au, legislation.gov.au |
| CA | ised-isde.canada.ca, laws-lois.justice.gc.ca |
| EU | eur-lex.europa.eu, etsi.org, cept.org, ecc.coe.int |
| GB | ofcom.org.uk, legislation.gov.uk |
| IN | dot.gov.in, wpc.gov.in |
| JP | soumu.go.jp |
| NZ | rsm.govt.nz, legislation.govt.nz |
| SG | imda.gov.sg, sso.agc.gov.sg |
| US | fcc.gov, ecfr.gov |

The list is deliberately incomplete and versioned as 2026.11.21; this version is included in the dataset fingerprint. Unsupported jurisdictions and unlisted
domains return review_required rather than being treated as authoritative.
Domain matching accepts the exact host or a subdomain boundary match.

## Validation and output

The validator checks URL scheme/host safety, identifiers, source and rule
uniqueness, date ordering, effective periods, source digest syntax, rule numeric
ranges, supported widths/device classes, boolean restrictions, duplicate
references and exact source clause linkage. It emits a deterministic SHA-256
fingerprint over the normalised dataset.

Overall status is validated only when the effective date is in force and every
source host matches the built-in jurisdiction list. Unknown domains return
review_required. not_yet_effective and expired are reported as temporal states.
The result includes the source records, normalized rule records, allowlist
coverage and unverified host list.

## Security and interpretation limits

- The server does not fetch submitted URLs, preventing an evidence-import
  feature from becoming an arbitrary outbound request or SSRF proxy.
- The content_sha256 value is supplied by the operator. Because source document
  bytes are not uploaded, the digest is not independently verified.
- A domain allowlist match is a provenance hint, not a cryptographic signature,
  proof that the linked document is a current official instrument, or
  confirmation that a document applies to a particular device.
- The feature validates data structure, source metadata and clause links. It
  does not determine legal authority, interpret exceptions, calculate regional
  compliance or authorize radio transmissions.
- The rule dataset must be checked against the regulator's live published
  instrument and the actual AP hardware/radio capabilities before channel
  planning or configuration changes.
- The bundled test fixture is explicitly illustrative and is not an operational
  regulatory profile.

Regulatory rules are deliberately imported and versioned instead of embedded
as static universal channel/power values; source revisions and effective dates
can differ by jurisdiction and change over time.
