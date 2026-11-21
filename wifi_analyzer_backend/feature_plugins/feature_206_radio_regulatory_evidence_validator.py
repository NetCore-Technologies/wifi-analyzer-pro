"""Jurisdiction-aware regulatory source and radio-rule provenance validator (F206).

This feature validates supplied regulatory evidence and rule records. It does
not fetch URLs, verify document bytes/signatures or determine the law for a
jurisdiction. A known authority domain is a provenance hint, not proof that
the submitted document is genuine or current.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
from datetime import date, datetime, timedelta, timezone
from urllib.parse import urlsplit

MAX_SOURCES = 100
MAX_RULES = 5000
MAX_CHANNELS_PER_RULE = 64
MAX_SOURCE_REFS_PER_RULE = 20
MAX_DOCUMENT_BYTES = 8192
MAX_TEXT = 512
SUPPORTED_BANDS = {"2.4GHz", "5GHz", "6GHz"}
SUPPORTED_WIDTHS = {5, 10, 20, 40, 80, 160, 320}
DEVICE_CLASSES = {"LPI", "VLP", "SP"}
SOURCE_TYPES = {
    "legislation",
    "regulatory_decision",
    "technical_standard",
    "licence_condition",
    "official_guidance",
}
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
SHA256 = re.compile(r"^[a-f0-9]{64}$")
JURISDICTION = re.compile(r"^[A-Z]{2}$")
CLAUSE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9().,:/ _-]{0,127}$")

# Curated host roots for official regulators, official legislation portals and
# standards bodies. Changes to this allowlist must be reviewed and versioned.
# The list is intentionally incomplete: unknown authorities are review-required,
# never silently promoted to an authoritative source.
AUTHORITY_ALLOWLIST_VERSION = "2026.11.21"
AUTHORITY_DOMAIN_ALLOWLIST = {
    "AU": ("acma.gov.au", "legislation.gov.au"),
    "CA": ("ised-isde.canada.ca", "laws-lois.justice.gc.ca"),
    "EU": ("eur-lex.europa.eu", "etsi.org", "cept.org", "ecc.coe.int"),
    "GB": ("ofcom.org.uk", "legislation.gov.uk"),
    "IN": ("dot.gov.in", "wpc.gov.in"),
    "JP": ("soumu.go.jp",),
    "NZ": ("rsm.govt.nz", "legislation.govt.nz"),
    "SG": ("imda.gov.sg", "sso.agc.gov.sg"),
    "US": ("fcc.gov", "ecfr.gov"),
}


def _identifier(value: object, field: str) -> str:
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value.strip()):
        raise ValueError(f"{field} must be a valid 1 to 128 character identifier")
    return value.strip()


def _text(value: object, field: str, *, maximum: int = MAX_TEXT) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    value = value.strip()
    if not value or len(value) > maximum or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(f"{field} must contain 1 to {maximum} printable characters")
    return value


def _number(value: object, field: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool):
        raise ValueError(f"{field} must be a finite number from {minimum:g} to {maximum:g}")
    try:
        result = float(value)
    except (TypeError, ValueError) as error:
        raise ValueError(f"{field} must be numeric") from error
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise ValueError(f"{field} must be a finite number from {minimum:g} to {maximum:g}")
    return result


def _iso_datetime(value: object, field: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field} must be a timezone-aware ISO-8601 timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must include a timezone offset")
    return parsed.astimezone(timezone.utc)


def _iso_date(value: object, field: str) -> date:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be an ISO-8601 calendar date")
    try:
        return date.fromisoformat(value.strip())
    except ValueError as error:
        raise ValueError(f"{field} must be an ISO-8601 calendar date") from error


def _public_https_host(value: object, field: str) -> tuple[str, str]:
    if not isinstance(value, str) or len(value) > 2048:
        raise ValueError(f"{field} must be an HTTPS URL no longer than 2048 characters")
    try:
        parsed = urlsplit(value.strip())
        host = parsed.hostname
        port = parsed.port
    except ValueError as error:
        raise ValueError(f"{field} must be a valid HTTPS URL") from error
    if parsed.scheme.lower() != "https" or not host or parsed.username is not None or parsed.password is not None:
        raise ValueError(f"{field} must be HTTPS and must not contain credentials")
    if port not in {None, 443}:
        raise ValueError(f"{field} must use the standard HTTPS port")
    if parsed.fragment:
        raise ValueError(f"{field} must not contain a URL fragment")
    try:
        host = host.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ValueError(f"{field} contains an invalid internationalised hostname") from error
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        if not address.is_global:
            raise ValueError(f"{field} must not point to a private or reserved IP address")
        raise ValueError(f"{field} must use an authority hostname, not an IP address")
    if host in {"localhost", "localhost.localdomain"} or "." not in host:
        raise ValueError(f"{field} must use a fully qualified authority hostname")
    label_pattern = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    if len(host) > 253 or not re.fullmatch(rf"(?:{label_pattern}\.)+{label_pattern}", host):
        raise ValueError(f"{field} contains an invalid DNS hostname")
    return parsed.geturl(), host


def _is_allowlisted(host: str, jurisdiction: str) -> bool:
    for root in AUTHORITY_DOMAIN_ALLOWLIST.get(jurisdiction, ()):
        if host == root or host.endswith("." + root):
            return True
    return False


def _validate_source(source: object, index: int, jurisdiction: str) -> dict:
    prefix = f"sources[{index}]"
    if not isinstance(source, dict):
        raise ValueError(f"{prefix} must be an object")
    source_id = _identifier(source.get("source_id"), prefix + ".source_id")
    source_type = source.get("source_type")
    if not isinstance(source_type, str) or source_type not in SOURCE_TYPES:
        raise ValueError(f"{prefix}.source_type must be one of {sorted(SOURCE_TYPES)}")
    title = _text(source.get("title"), prefix + ".title")
    authority = _text(source.get("authority"), prefix + ".authority")
    reference = _text(source.get("document_reference"), prefix + ".document_reference")
    revision = _text(source.get("revision"), prefix + ".revision", maximum=128)
    url, host = _public_https_host(source.get("source_url"), prefix + ".source_url")
    published_at = _iso_date(source.get("published_at"), prefix + ".published_at")
    effective_from = _iso_date(source.get("effective_from"), prefix + ".effective_from")
    effective_to_raw = source.get("effective_to")
    effective_to = None if effective_to_raw is None or effective_to_raw == "" else _iso_date(effective_to_raw, prefix + ".effective_to")
    retrieved_at = _iso_datetime(source.get("retrieved_at"), prefix + ".retrieved_at")
    if retrieved_at > datetime.now(timezone.utc).replace(microsecond=0) + timedelta(minutes=5):
        raise ValueError(f"{prefix}.retrieved_at is too far in the future")
    if retrieved_at.date() < published_at:
        raise ValueError(f"{prefix}.retrieved_at cannot precede published_at")
    digest = source.get("content_sha256")
    if not isinstance(digest, str) or not SHA256.fullmatch(digest):
        raise ValueError(f"{prefix}.content_sha256 must be a lowercase SHA-256 hex digest")
    if effective_to is not None and effective_to < effective_from:
        raise ValueError(f"{prefix}.effective_to must not precede effective_from")
    clauses = source.get("clause_references")
    if not isinstance(clauses, list) or not 1 <= len(clauses) <= 100:
        raise ValueError(f"{prefix}.clause_references must contain 1 to 100 references")
    normalised_clauses = []
    for clause_index, clause in enumerate(clauses):
        if not isinstance(clause, str) or not CLAUSE.fullmatch(clause.strip()):
            raise ValueError(f"{prefix}.clause_references[{clause_index}] is invalid")
        normalised_clauses.append(clause.strip())
    domain_allowlisted = _is_allowlisted(host, jurisdiction)
    return {
        "source_id": source_id,
        "source_type": source_type,
        "title": title,
        "authority": authority,
        "document_reference": reference,
        "revision": revision,
        "source_url": url,
        "source_host": host,
        "source_domain_allowlisted": domain_allowlisted,
        "published_at": published_at.isoformat(),
        "effective_from": effective_from.isoformat(),
        "effective_to": effective_to.isoformat() if effective_to else None,
        "retrieved_at": retrieved_at.isoformat(timespec="seconds"),
        "content_sha256": digest,
        "clause_references": normalised_clauses,
        "content_digest_status": "provided_not_independently_verified",
    }


def _validate_rule(rule: object, index: int, source_map: dict) -> dict:
    prefix = f"rules[{index}]"
    if not isinstance(rule, dict):
        raise ValueError(f"{prefix} must be an object")
    rule_id = _identifier(rule.get("rule_id"), prefix + ".rule_id")
    band = rule.get("band")
    if not isinstance(band, str) or band not in SUPPORTED_BANDS:
        raise ValueError(f"{prefix}.band must be one of {sorted(SUPPORTED_BANDS)}")
    low = _number(rule.get("lower_frequency_mhz"), prefix + ".lower_frequency_mhz", 2300, 7125)
    high = _number(rule.get("upper_frequency_mhz"), prefix + ".upper_frequency_mhz", 2300, 7125)
    if low >= high:
        raise ValueError(f"{prefix} must have lower_frequency_mhz below upper_frequency_mhz")
    max_eirp = _number(rule.get("maximum_eirp_dbm"), prefix + ".maximum_eirp_dbm", -20, 60)
    density_raw = rule.get("maximum_eirp_density_dbm_per_mhz")
    density = None if density_raw is None else _number(density_raw, prefix + ".maximum_eirp_density_dbm_per_mhz", -60, 60)
    widths = rule.get("channel_widths_mhz")
    if not isinstance(widths, list) or not widths or len(widths) > len(SUPPORTED_WIDTHS):
        raise ValueError(f"{prefix}.channel_widths_mhz must contain supported channel widths")
    normalised_widths = []
    for width_index, width in enumerate(widths):
        if isinstance(width, bool) or not isinstance(width, int) or width not in SUPPORTED_WIDTHS:
            raise ValueError(f"{prefix}.channel_widths_mhz[{width_index}] is unsupported")
        if width not in normalised_widths:
            normalised_widths.append(width)
    channels = rule.get("channel_numbers")
    if not isinstance(channels, list) or not channels or len(channels) > MAX_CHANNELS_PER_RULE:
        raise ValueError(f"{prefix}.channel_numbers must contain 1 to {MAX_CHANNELS_PER_RULE} channel values")
    normalised_channels = []
    for channel_index, channel in enumerate(channels):
        if isinstance(channel, bool) or not isinstance(channel, int) or not 1 <= channel <= 255:
            raise ValueError(f"{prefix}.channel_numbers[{channel_index}] must be an integer from 1 to 255")
        if channel not in normalised_channels:
            normalised_channels.append(channel)
    device_classes = rule.get("device_classes")
    if (
        not isinstance(device_classes, list)
        or not device_classes
        or any(not isinstance(value, str) or value not in DEVICE_CLASSES for value in device_classes)
    ):
        raise ValueError(f"{prefix}.device_classes must contain one or more of {sorted(DEVICE_CLASSES)}")
    indoor_only = rule.get("indoor_only")
    outdoor_allowed = rule.get("outdoor_allowed")
    dfs_required = rule.get("dfs_required")
    afc_required = rule.get("afc_required")
    if not all(isinstance(value, bool) for value in (indoor_only, outdoor_allowed, dfs_required, afc_required)):
        raise ValueError(f"{prefix} regulatory restriction flags must be booleans")
    if indoor_only and outdoor_allowed:
        raise ValueError(f"{prefix} cannot be both indoor_only and outdoor_allowed")
    references = rule.get("source_references")
    if not isinstance(references, list) or not 1 <= len(references) <= MAX_SOURCE_REFS_PER_RULE:
        raise ValueError(f"{prefix}.source_references must contain 1 to {MAX_SOURCE_REFS_PER_RULE} references")
    normalised_references = []
    seen_refs = set()
    for ref_index, reference in enumerate(references):
        ref_prefix = f"{prefix}.source_references[{ref_index}]"
        if not isinstance(reference, dict):
            raise ValueError(f"{ref_prefix} must be an object")
        source_id = _identifier(reference.get("source_id"), ref_prefix + ".source_id")
        clause = reference.get("clause")
        if not isinstance(clause, str) or not CLAUSE.fullmatch(clause.strip()):
            raise ValueError(f"{ref_prefix}.clause is invalid")
        source = source_map.get(source_id)
        if source is None:
            raise ValueError(f"{ref_prefix} references an unknown source_id")
        if clause.strip() not in source["clause_references"]:
            raise ValueError(f"{ref_prefix}.clause is not listed by its source document")
        key = (source_id, clause.strip())
        if key in seen_refs:
            raise ValueError(f"{prefix} contains a duplicate source reference")
        seen_refs.add(key)
        normalised_references.append({"source_id": source_id, "clause": clause.strip()})
    return {
        "rule_id": rule_id,
        "band": band,
        "lower_frequency_mhz": low,
        "upper_frequency_mhz": high,
        "maximum_eirp_dbm": max_eirp,
        "maximum_eirp_density_dbm_per_mhz": density,
        "channel_widths_mhz": sorted(normalised_widths),
        "channel_numbers": sorted(normalised_channels),
        "device_classes": sorted(set(device_classes)),
        "indoor_only": indoor_only,
        "outdoor_allowed": outdoor_allowed,
        "dfs_required": dfs_required,
        "afc_required": afc_required,
        "source_references": normalised_references,
    }


def run(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise ValueError("payload must be an object")
    jurisdiction = payload.get("jurisdiction")
    if not isinstance(jurisdiction, str) or not JURISDICTION.fullmatch(jurisdiction):
        raise ValueError("jurisdiction must be an uppercase ISO alpha-2 code or EU")
    dataset_id = _identifier(payload.get("dataset_id"), "dataset_id")
    version = _text(payload.get("version"), "version", maximum=64)
    regulator = _text(payload.get("regulator"), "regulator")
    retrieved_at = _iso_datetime(payload.get("retrieved_at"), "retrieved_at")
    if retrieved_at > datetime.now(timezone.utc).replace(microsecond=0) + __import__("datetime").timedelta(minutes=5):
        raise ValueError("retrieved_at is too far in the future")
    effective_from = _iso_date(payload.get("effective_from"), "effective_from")
    effective_to_raw = payload.get("effective_to")
    effective_to = None if effective_to_raw is None or effective_to_raw == "" else _iso_date(effective_to_raw, "effective_to")
    if effective_to is not None and effective_to < effective_from:
        raise ValueError("effective_to must not precede effective_from")
    as_of = _iso_date(payload.get("as_of"), "as_of") if payload.get("as_of") is not None else datetime.now(timezone.utc).date()

    sources = payload.get("sources")
    if not isinstance(sources, list) or not 1 <= len(sources) <= MAX_SOURCES:
        raise ValueError(f"sources must contain 1 to {MAX_SOURCES} records")
    source_map = {}
    for index, source in enumerate(sources):
        normalised = _validate_source(source, index, jurisdiction)
        if normalised["source_id"] in source_map:
            raise ValueError("source_id values must be unique")
        source_map[normalised["source_id"]] = normalised

    rules = payload.get("rules")
    if not isinstance(rules, list) or not 1 <= len(rules) <= MAX_RULES:
        raise ValueError(f"rules must contain 1 to {MAX_RULES} records")
    rule_ids = set()
    normalised_rules = []
    for index, rule in enumerate(rules):
        normalised = _validate_rule(rule, index, source_map)
        if normalised["rule_id"] in rule_ids:
            raise ValueError("rule_id values must be unique")
        rule_ids.add(normalised["rule_id"])
        normalised_rules.append(normalised)

    allowlisted_sources = sum(source["source_domain_allowlisted"] for source in source_map.values())
    all_domains_allowlisted = allowlisted_sources == len(source_map)
    if as_of < effective_from:
        temporal_status = "not_yet_effective"
    elif effective_to is not None and as_of > effective_to:
        temporal_status = "expired"
    else:
        temporal_status = "in_effect"
    provenance_status = "allowlisted_domains" if all_domains_allowlisted else "review_required"
    overall_status = (
        "validated" if provenance_status == "allowlisted_domains" and temporal_status == "in_effect"
        else "review_required" if provenance_status == "review_required"
        else temporal_status
    )

    canonical = {
        "authority_allowlist_version": AUTHORITY_ALLOWLIST_VERSION,
        "jurisdiction": jurisdiction,
        "dataset_id": dataset_id,
        "version": version,
        "regulator": regulator,
        "retrieved_at": retrieved_at.isoformat(timespec="seconds"),
        "effective_from": effective_from.isoformat(),
        "effective_to": effective_to.isoformat() if effective_to else None,
        "sources": sorted(source_map.values(), key=lambda item: item["source_id"]),
        "rules": sorted(normalised_rules, key=lambda item: item["rule_id"]),
    }
    canonical_json = json.dumps(canonical, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    fingerprint = hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()
    return {
        "status": overall_status,
        "jurisdiction": jurisdiction,
        "dataset_id": dataset_id,
        "version": version,
        "regulator": regulator,
        "effective_status": temporal_status,
        "provenance_status": provenance_status,
        "source_count": len(source_map),
        "allowlisted_source_domain_count": allowlisted_sources,
        "unverified_source_domains": sorted({
            source["source_host"] for source in source_map.values()
            if not source["source_domain_allowlisted"]
        }),
        "rule_count": len(normalised_rules),
        "dataset_fingerprint_sha256": fingerprint,
        "authority_allowlist_version": AUTHORITY_ALLOWLIST_VERSION,
        "sources": [source_map[key] for key in sorted(source_map)],
        "rules": sorted(normalised_rules, key=lambda item: item["rule_id"]),
        "limitations": [
            "The supplied source URL and document metadata are not fetched or independently authenticated by this feature.",
            "content_sha256 is a caller-provided digest; the original document bytes are not supplied and cannot be verified here.",
            "A source domain matching this built-in authority list is a provenance hint, not proof that the linked document is official, current or applicable.",
            "Regulatory rules are validated for structure, time metadata and source references, not interpreted as legal advice or confirmed law.",
            "The validated dataset must be reviewed against the regulator's current published instrument before being used to plan or configure radios.",
            "Unlisted domains and jurisdictions remain review_required; do not infer authority from their names.",
        ],
    }


FEATURE = {
    "id": "F206",
    "slug": "radio_regulatory_evidence_validator",
    "name": "Radio regulatory evidence validator",
    "category": "RF assurance",
    "description": (
        "Validate jurisdiction-scoped radio rule datasets, effective dates, source citations, document digests and known regulator domains; report unverified provenance explicitly without asserting legal compliance."
    ),
    "parameters": {
        "jurisdiction": "Uppercase ISO alpha-2 code or EU",
        "dataset_id": "Stable identifier for the imported regulatory dataset",
        "version": "Publisher/source revision or operator's immutable import version",
        "regulator": "Name of the regulator or standards authority",
        "retrieved_at": "Timezone-aware timestamp when the source material was retrieved",
        "effective_from": "Dataset effective start date",
        "effective_to": "Optional dataset effective end date",
        "sources": "1-100 source documents with official URL, revision, dates, SHA-256 digest and clause references",
        "rules": "1-5000 radio restrictions linked to one or more exact source clauses",
        "as_of": "Optional assessment date; defaults to UTC today",
    },
    "run": run,
}
